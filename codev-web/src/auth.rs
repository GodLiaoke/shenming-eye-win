use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use sha2::{Digest, Sha256};

const MAX_TOKEN_BYTES: usize = 256;
// Version the cookie name when transport semantics change.  Browsers protect
// an existing Secure cookie from being overwritten by plaintext HTTP, and
// cookie scope does not include the port.  A distinct name lets the explicit
// staging-HTTP origin authenticate without colliding with the former TLS
// deployment's `codev_admin` cookie.
const COOKIE_NAME: &str = "codev_admin_v2";
const MAX_EXCHANGE_ATTEMPTS: usize = 32;
const EXCHANGE_WINDOW_SECS: u64 = 60;

/// 面板会话：**无状态签名 cookie**。
///
/// 以前会话存在进程内的 HashMap 里（`sessions.contains_key`），于是**引擎一重启，
/// 所有正在看雷达的页面立刻掉线**、跳出「请输入管理员令牌」；公网模式下客户端手里
/// 没有可交换的令牌，只能干等客户手输。
///
/// 现在改成自签：cookie = `hex(过期秒) . hex(随机数16B) . hex(HMAC-SHA256(密钥, 过期.随机数))`，
/// 密钥由**持久化的 bootstrap token** 派生（`panel-token.secret` / `panel-bootstrap.raw` 本来
/// 就常驻磁盘）。这样：
///   · 引擎重启 / 升级部署 → 老 cookie 照样验签通过，页面不掉线；
///   · 没有状态、不需要清理，天然支持水平扩展；
///   · 篡改过期时间或随机数 → 验签失败；
///   · 门禁本身没拆：没有 cookie 仍然要令牌，房间链接那一层也还在。
pub(crate) struct PublicAuth {
    session_key: [u8; 32],
    ttl_secs: u64,
    state: Mutex<AuthState>,
}

struct AuthState {
    exchange_attempts: VecDeque<u64>,
}

impl PublicAuth {
    pub(crate) fn new(bootstrap_token: &str, ttl_secs: u64) -> Option<Self> {
        if bootstrap_token.is_empty() || bootstrap_token.len() > MAX_TOKEN_BYTES || ttl_secs == 0 {
            return None;
        }
        Some(Self {
            // 派生签名密钥：即使以后换实现，只要 bootstrap token 不变，老会话依旧有效。
            session_key: hmac_sha256(b"codev-panel-session-v1", bootstrap_token.as_bytes()),
            ttl_secs,
            state: Mutex::new(AuthState {
                exchange_attempts: VecDeque::new(),
            }),
        })
    }

    pub(crate) fn exchange(&self, token: &str) -> Option<String> {
        if token.len() > MAX_TOKEN_BYTES {
            return None;
        }
        let now = epoch_seconds();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while state
            .exchange_attempts
            .front()
            .is_some_and(|observed| now.saturating_sub(*observed) >= EXCHANGE_WINDOW_SECS)
        {
            state.exchange_attempts.pop_front();
        }
        if state.exchange_attempts.len() >= MAX_EXCHANGE_ATTEMPTS {
            return None;
        }
        state.exchange_attempts.push_back(now);
        // 交换用的 bootstrap token 仍然必须匹配；签名密钥是它的 HMAC，不直接暴露。
        if !constant_time_eq(&self.session_key, &self.session_key_for(token)) {
            return None;
        }
        let mut nonce = [0_u8; 16];
        rand::rng().fill_bytes(&mut nonce);
        Some(self.sign_session(now.saturating_add(self.ttl_secs), &nonce))
    }

    pub(crate) fn is_authenticated(&self, headers: &axum::http::HeaderMap) -> bool {
        let Some(cookie) = headers
            .get(axum::http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
        else {
            return false;
        };
        cookie.split(';').any(|part| {
            let Some((name, value)) = part.trim().split_once('=') else {
                return false;
            };
            name == COOKIE_NAME && self.verify_session(value, epoch_seconds())
        })
    }

    pub(crate) fn cookie_header(&self, session: &str, secure: bool) -> String {
        let secure_attribute = if secure { "; Secure" } else { "" };
        format!(
            "{COOKIE_NAME}={session}; Path=/; Max-Age={}; HttpOnly{secure_attribute}; SameSite=Strict",
            self.ttl_secs
        )
    }

    fn session_key_for(&self, token: &str) -> [u8; 32] {
        hmac_sha256(b"codev-panel-session-v1", token.as_bytes())
    }

    fn sign_session(&self, expires_at: u64, nonce: &[u8; 16]) -> String {
        let payload = format!("{expires_at:016x}.{}", hex(nonce));
        let mac = hmac_sha256(&self.session_key, payload.as_bytes());
        format!("{payload}.{}", hex(&mac))
    }

    fn verify_session(&self, value: &str, now: u64) -> bool {
        let mut parts = value.split('.');
        let (Some(expires), Some(nonce), Some(mac), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        if expires.len() != 16 || nonce.len() != 32 || mac.len() != 64 {
            return false;
        }
        let Ok(expires_at) = u64::from_str_radix(expires, 16) else {
            return false;
        };
        if expires_at <= now {
            return false;
        }
        if decode_hex(nonce).is_none() {
            return false;
        }
        let Some(expected) = decode_fixed::<32>(mac) else {
            return false;
        };
        let payload = format!("{expires}.{nonce}");
        let actual = hmac_sha256(&self.session_key, payload.as_bytes());
        constant_time_eq(&actual, &expected)
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// 标准 HMAC-SHA256（只用已有的 sha2，不引入新依赖）。
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut padded = [0_u8; BLOCK];
    if key.len() > BLOCK {
        padded[..32].copy_from_slice(&hash(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + message.len());
    let mut outer = Vec::with_capacity(BLOCK + 32);
    for byte in padded {
        inner.push(byte ^ 0x36);
        outer.push(byte ^ 0x5c);
    }
    inner.extend_from_slice(message);
    let inner_hash = hash(&inner);
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

pub(crate) fn decode_hex(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        output.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Some(output)
}

fn decode_fixed<const N: usize>(value: &str) -> Option<[u8; N]> {
    let bytes = decode_hex(value)?;
    if bytes.len() != N {
        return None;
    }
    let mut output = [0_u8; N];
    output.copy_from_slice(&bytes);
    Some(output)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn cookie_headers(session: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("{COOKIE_NAME}={session}")).unwrap(),
        );
        headers
    }

    #[test]
    fn exchange_issues_expiring_cookie_session_without_echoing_bootstrap() {
        let auth = PublicAuth::new("bootstrap", 60).unwrap();
        assert!(!auth.is_authenticated(&HeaderMap::new()));
        let session = auth.exchange("bootstrap").unwrap();
        let mut wrong_name = HeaderMap::new();
        wrong_name.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_str(&format!("codev_admin={session}")).unwrap(),
        );
        assert!(!auth.is_authenticated(&wrong_name));
        assert!(auth.is_authenticated(&cookie_headers(&session)));
        assert!(!session.contains("bootstrap"));
        assert!(auth.exchange("wrong").is_none());
        let mut bearer = HeaderMap::new();
        bearer.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer bootstrap"),
        );
        assert!(!auth.is_authenticated(&bearer));
        assert!(auth.cookie_header(&session, false).starts_with(COOKIE_NAME));
        assert!(auth.cookie_header(&session, true).contains("; Secure;"));
        assert!(!auth.cookie_header(&session, false).contains("; Secure;"));
    }

    #[test]
    fn exchange_attempts_are_bounded() {
        let auth = PublicAuth::new("bootstrap", 60).unwrap();
        for _ in 0..MAX_EXCHANGE_ATTEMPTS {
            assert!(auth.exchange("wrong").is_none());
        }
        assert!(auth.exchange("bootstrap").is_none());
    }

    /// 本次修复的核心：**引擎重启后，老 cookie 依然有效**（会话不再随进程消失）。
    #[test]
    fn session_survives_engine_restart() {
        let before = PublicAuth::new("bootstrap-token", 3600).unwrap();
        let session = before.exchange("bootstrap-token").unwrap();
        // 模拟重启：全新实例，同一份磁盘上的 bootstrap token。
        let after = PublicAuth::new("bootstrap-token", 3600).unwrap();
        assert!(after.is_authenticated(&cookie_headers(&session)));
        // 换了一个 bootstrap token（等同换服务器/轮换密钥）→ 老会话必须失效。
        let rotated = PublicAuth::new("another-token", 3600).unwrap();
        assert!(!rotated.is_authenticated(&cookie_headers(&session)));
    }

    #[test]
    fn tampered_or_expired_sessions_are_rejected() {
        let auth = PublicAuth::new("bootstrap", 3600).unwrap();
        let session = auth.exchange("bootstrap").unwrap();
        let parts: Vec<&str> = session.split('.').collect();
        assert_eq!(parts.len(), 3);

        // 篡改过期时间（往后延）→ 验签失败
        let forged = format!("{:016x}.{}.{}", epoch_seconds() + 9000, parts[1], parts[2]);
        assert!(!auth.is_authenticated(&cookie_headers(&forged)));
        // 篡改随机数 → 验签失败
        let forged = format!("{}.{}.{}", parts[0], "00".repeat(16), parts[2]);
        assert!(!auth.is_authenticated(&cookie_headers(&forged)));
        // 篡改签名 → 验签失败
        let forged = format!("{}.{}.{}", parts[0], parts[1], "11".repeat(32));
        assert!(!auth.is_authenticated(&cookie_headers(&forged)));
        // 结构性垃圾 → 拒绝
        for junk in ["", "a", "1.2", "1.2.3.4", &"0".repeat(300)] {
            assert!(!auth.is_authenticated(&cookie_headers(junk)));
        }
        // 过期会话（直接签一个过去的过期时间）→ 拒绝
        let expired = auth.sign_session(epoch_seconds() - 1, &[7_u8; 16]);
        assert!(!auth.is_authenticated(&cookie_headers(&expired)));
        // 未过期、签名正确的会话 → 通过（对照组）
        let valid = auth.sign_session(epoch_seconds() + 60, &[7_u8; 16]);
        assert!(auth.is_authenticated(&cookie_headers(&valid)));
    }
}
