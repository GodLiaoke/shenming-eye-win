//! S2：会话密钥与「按会话加密的字段字典」。
//!
//! 目标：让客户端能拿到**短命**的解密材料，从而使「抄走客户端 ≠ 永久免费」。
//!
//! 设计要点
//!  · 会话密钥 K：32 字节随机，有效期 [`SESSION_TTL_SECS`]（35 分钟），**只存内存**。
//!  · 幂等：同一 (卡密指纹, 设备ID) 在有效期内重复请求 → 返回**同一把** K，
//!    避免客户端重试时反复占设备位、也避免自己把旧密钥作废。
//!  · 字典加密：ChaCha20 流密码 + HMAC-SHA256（Encrypt-then-MAC）。
//!    本机拿不到 AEAD crate，故自行组合；Encrypt-then-MAC 是标准做法，
//!    但由 [`tests`] 逐条证明：能解 / 换钥匙解不开 / 改一个字节被发现。
//!  · 主密钥（若将来启用）**不下发**；本模块只产生与分发会话材料。

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// 会话密钥有效期：35 分钟。
pub const SESSION_TTL_SECS: u64 = 35 * 60;

/// 提前续期窗口：到期前 5 分钟内允许换新钥匙。
pub const RENEW_WINDOW_SECS: u64 = 5 * 60;

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAC_BYTES: usize = 32;


/// 字段字典由 `codev-cli` 在启动时注入。
///
/// 为什么用注入而不是直接引用：字典在 `codev-cli` 里，而 `codev-cli` 依赖
/// `codev-web` —— web 层反向依赖会形成循环，编译不过。
/// 这是唯一不引入循环、也不复制字典的做法。
static DICTIONARY: OnceLock<Vec<u8>> = OnceLock::new();

/// 注入字段字典明文（进程内只需调用一次；重复调用忽略）。
pub fn set_dictionary(bytes: Vec<u8>) {
    let _ = DICTIONARY.set(bytes);
}

/// 取字段字典明文；未注入时返回 None（此时接口应答 503，而不是发空字典）。
pub fn dictionary() -> Option<&'static [u8]> {
    DICTIONARY.get().map(|bytes| bytes.as_slice())
}

/// 一次会话下发给客户端的材料。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionGrant {
    /// base64(32 字节会话密钥)
    pub session_key_b64: String,
    /// base64(12 字节 nonce)
    pub nonce_b64: String,
    /// base64(ChaCha20 加密后的字段字典)
    pub dictionary_blob_b64: String,
    /// base64(HMAC-SHA256 标签，覆盖 nonce ‖ 密文)
    pub dictionary_tag_b64: String,
    pub expires_unix: u64,
}

struct Entry {
    key: [u8; KEY_BYTES],
    expires_unix: u64,
}

/// 进程内的会话表。引擎重启即清空 —— 这与"只存内存"的设计一致。
static SESSIONS: Mutex<Option<HashMap<String, Entry>>> = Mutex::new(None);

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 会话表键：卡密指纹 + 设备ID。
/// 只存指纹不存卡密本身，避免卡密在内存里多留一份。
pub fn session_id(card: &str, device_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"phoenix.session.v1");
    hasher.update(card.as_bytes());
    hasher.update(b"\x00");
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest[..16])
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// HMAC-SHA256（RFC 2104）。本机没有 `hmac` crate，按标准实现。
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; MAC_BYTES] {
    const BLOCK: usize = 64;
    let mut block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK];
    let mut outer_pad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        inner_pad[i] ^= block[i];
        outer_pad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

/// 由会话密钥派生 MAC 子密钥（避免加解密与认证复用同一把）。
fn mac_key(session_key: &[u8; KEY_BYTES]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"phoenix.session.mac.v1");
    hasher.update(session_key);
    hasher.finalize().into()
}

/// 用会话密钥加密字典（Encrypt-then-MAC）。
pub fn seal_dictionary(
    session_key: &[u8; KEY_BYTES],
    dictionary_plaintext: &[u8],
) -> Result<(String, String, String), String> {
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce);

    let mut buffer = dictionary_plaintext.to_vec();
    let mut cipher = ChaCha20::new(session_key.into(), (&nonce).into());
    cipher.apply_keystream(&mut buffer);

    let mut mac_input = Vec::with_capacity(NONCE_BYTES + buffer.len());
    mac_input.extend_from_slice(&nonce);
    mac_input.extend_from_slice(&buffer);
    let tag = hmac_sha256(&mac_key(session_key), &mac_input);

    Ok((B64.encode(nonce), B64.encode(&buffer), B64.encode(tag)))
}

/// 解开字典并校验标签。任何一步不符都返回 Err（调用方据此拒绝使用）。
pub fn open_dictionary(
    session_key: &[u8; KEY_BYTES],
    nonce_b64: &str,
    blob_b64: &str,
    tag_b64: &str,
) -> Result<Vec<u8>, String> {
    let nonce = B64.decode(nonce_b64).map_err(|_| "nonce 不是合法 base64")?;
    let mut buffer = B64.decode(blob_b64).map_err(|_| "密文不是合法 base64")?;
    let tag = B64.decode(tag_b64).map_err(|_| "标签不是合法 base64")?;
    if nonce.len() != NONCE_BYTES {
        return Err("nonce 长度非法".into());
    }
    if tag.len() != MAC_BYTES {
        return Err("标签长度非法".into());
    }

    let mut mac_input = Vec::with_capacity(nonce.len() + buffer.len());
    mac_input.extend_from_slice(&nonce);
    mac_input.extend_from_slice(&buffer);
    let expected = hmac_sha256(&mac_key(session_key), &mac_input);
    if !constant_time_eq(&expected, &tag) {
        return Err("字典标签校验失败（密文被篡改或密钥不对）".into());
    }

    let mut cipher = ChaCha20::new(session_key.into(), nonce.as_slice().into());
    cipher.apply_keystream(&mut buffer);
    Ok(buffer)
}

/// 定长常数时间比较，避免用 == 泄漏时序。
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// 取或新建会话材料。**幂等**：有效期内同 id 返回同一把密钥。
pub fn issue(
    card: &str,
    device_id: &str,
    dictionary_plaintext: &[u8],
) -> Result<SessionGrant, String> {
    let id = session_id(card, device_id);
    let now = now_unix();

    let (key, expires) = {
        let mut guard = SESSIONS.lock().unwrap_or_else(|e| e.into_inner());
        let table = guard.get_or_insert_with(HashMap::new);
        // 顺手清理过期项，避免表无限增长
        table.retain(|_, entry| entry.expires_unix > now);

        match table.get(&id) {
            Some(entry) if entry.expires_unix > now + RENEW_WINDOW_SECS => {
                (entry.key, entry.expires_unix)
            }
            _ => {
                let mut key = [0u8; KEY_BYTES];
                rand::rng().fill_bytes(&mut key);
                let expires = now + SESSION_TTL_SECS;
                table.insert(id.clone(), Entry { key, expires_unix: expires });
                (key, expires)
            }
        }
    };

    let (nonce_b64, blob_b64, tag_b64) = seal_dictionary(&key, dictionary_plaintext)?;
    Ok(SessionGrant {
        session_key_b64: B64.encode(key),
        nonce_b64,
        dictionary_blob_b64: blob_b64,
        dictionary_tag_b64: tag_b64,
        expires_unix: expires,
    })
}

/// 仅供测试与运维：清空会话表。
pub fn reset_sessions() {
    *SESSIONS.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as TestMutex;

    /// 会话表是进程级共享状态，而 cargo 默认并行跑测试 ——
    /// 不串行化的话，别的用例调用 reset_sessions() 会把本用例的表清掉。
    static TEST_LOCK: TestMutex<()> = TestMutex::new(());

    const DICT: &[u8] = br#"{"fields":[{"name":"player_x","bit_offset":128,"bit_width":16}]}"#;

    fn key_of(grant: &SessionGrant) -> [u8; KEY_BYTES] {
        let raw = B64.decode(&grant.session_key_b64).unwrap();
        let mut key = [0u8; KEY_BYTES];
        key.copy_from_slice(&raw);
        key
    }

    #[test]
    fn round_trip_recovers_dictionary() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        let opened = open_dictionary(
            &key_of(&grant),
            &grant.nonce_b64,
            &grant.dictionary_blob_b64,
            &grant.dictionary_tag_b64,
        )
        .expect("同一把钥匙必须能解开");
        assert_eq!(opened, DICT);
    }

    #[test]
    fn wrong_key_cannot_open() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        let mut other = [0u8; KEY_BYTES];
        rand::rng().fill_bytes(&mut other);
        assert!(
            open_dictionary(&other, &grant.nonce_b64, &grant.dictionary_blob_b64, &grant.dictionary_tag_b64)
                .is_err(),
            "换一把钥匙必须解不开"
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        let mut blob = B64.decode(&grant.dictionary_blob_b64).unwrap();
        blob[0] ^= 0x01; // 改一个比特
        assert!(
            open_dictionary(&key_of(&grant), &grant.nonce_b64, &B64.encode(&blob), &grant.dictionary_tag_b64)
                .is_err(),
            "篡改密文必须被发现"
        );
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        let mut tag = B64.decode(&grant.dictionary_tag_b64).unwrap();
        tag[0] ^= 0x01;
        assert!(
            open_dictionary(&key_of(&grant), &grant.nonce_b64, &grant.dictionary_blob_b64, &B64.encode(&tag))
                .is_err(),
            "篡改标签必须被发现"
        );
    }

    #[test]
    fn issue_is_idempotent_within_ttl() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let a = issue("CARD-A", "DEV-1", DICT).unwrap();
        let b = issue("CARD-A", "DEV-1", DICT).unwrap();
        assert_eq!(a.session_key_b64, b.session_key_b64, "有效期内必须返回同一把钥匙");
        assert_eq!(a.expires_unix, b.expires_unix);
    }

    #[test]
    fn different_card_or_device_gets_different_key() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let a = issue("CARD-A", "DEV-1", DICT).unwrap();
        let b = issue("CARD-B", "DEV-1", DICT).unwrap();
        let c = issue("CARD-A", "DEV-2", DICT).unwrap();
        assert_ne!(a.session_key_b64, b.session_key_b64, "换卡必须换钥匙");
        assert_ne!(a.session_key_b64, c.session_key_b64, "换设备必须换钥匙");
    }

    #[test]
    fn ttl_is_35_minutes() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let before = now_unix();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        assert_eq!(SESSION_TTL_SECS, 2100);
        assert!(grant.expires_unix >= before + 2090);
        assert!(grant.expires_unix <= before + 2110);
    }

    #[test]
    fn session_key_never_appears_in_ciphertext_plain() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset_sessions();
        let grant = issue("CARD-A", "DEV-1", DICT).unwrap();
        let blob = B64.decode(&grant.dictionary_blob_b64).unwrap();
        let key = B64.decode(&grant.session_key_b64).unwrap();
        assert!(!blob.windows(key.len()).any(|w| w == key.as_slice()));
    }

    #[test]
    fn session_id_does_not_contain_raw_card() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let id = session_id("SECRET-CARD-123", "DEV-1");
        assert!(!id.contains("SECRET"));
        assert_eq!(id.len(), 32); // 16 字节 → 32 个十六进制字符
    }
}
