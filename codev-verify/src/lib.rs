//! Windows port of the 823 T3 + Loonie authorization chain.
//!
//! The implementation deliberately keeps the wire formats compatible with
//! the Objective-C/C++ source: Lex boot policy, RSA/3DES T3 transport, the
//! radar time side-channel, signed Core claims and the Loonie AES/emoji lane.

use aes::Aes128;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit};
use chrono::{Duration as ChronoDuration, TimeZone, Utc};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use rand_core::{OsRng, RngCore};
use reqwest::blocking::Client;
use reqwest::header::CONTENT_TYPE;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::form_urlencoded::Serializer;




/// 仅调试构建可用的排障开关；发布构建恒为 false。
fn debug_t3_only_flag() -> bool {
    #[cfg(debug_assertions)]
    {
        return std::env::var("CODEV_VERIFY_T3_ONLY").map(|v| v == "1").unwrap_or(false);
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// 当前进行到哪一段（给界面轮询显示；只读，不含任何卡密/密钥）。
static CURRENT_STAGE: Mutex<&'static str> = Mutex::new("idle");

/// 取当前验证阶段的中文名。界面可以每 300ms 轮询一次。
pub fn current_stage() -> &'static str {
    *CURRENT_STAGE.lock().unwrap_or_else(|e| e.into_inner())
}

/// 阶段英文名 → 中文（给界面显示）。
pub fn stage_label(stage: &str) -> &'static str {
    match stage {
        "card_format" => "1/7 检查卡密形态",
        "date_gate" => "2/7 校时（T3 授时）",
        "lex" | "lex_outer" | "lex_arm" => "3/7 取引导策略（lex）",
        "t3_meta" => "4/7 取公告/版本（metadata）",
        "t3_login" | "t3_login_retry" => "5/7 签名登录（T3 登录）",
        "loonie" | "loonie_health" => "6/7 客户端证明（loonie）",
        "loonie_handshake" => "6/7 loonie 握手",
        "heartbeat" => "7/7 心跳",
        "authorized" | "ready" => "完成",
        "idle" => "未开始",
        _ => "验证中",
    }
}

/// 最近一次网络错误的原文（DNS / TLS / 超时…），给客户端显示用。
static LAST_NET_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn net_err(error: reqwest::Error) -> KamiError {
    let text = format!("{error}");
    if let Ok(mut slot) = LAST_NET_ERROR.lock() {
        *slot = Some(text);
    }
    KamiError::Network
}

/// 取出并清空最近一次网络错误。
pub fn take_last_network_error() -> Option<String> {
    LAST_NET_ERROR.lock().ok().and_then(|mut slot| slot.take())
}

const T3_BASE: &str = "https://yz.t3yangzheng.xyz/";
const T3_LEX: &str = "D3A8F1E62B9C0475";
const T3_NOTICE: &str = "238EB6359CD08C17";
const T3_VERSION: &str = "FD3072BFD220DA66";
const T3_NETTIME: &str = "A9F3E2B81C4D0567";
const T3_LOGIN: &str = "C7B2618E4C22169A";
const T3_HEARTBEAT: &str = "7E4BD47D7395E1AB";
const T3_APP_KEY: &str = "192a2ca120f65071e2dd9f5fdf821ad9";
const T3_TDES_KEY: &[u8; 24] = b"RADAR887KFC3DESKEY2024!!";
const T3_CHAIN_BOOT: &str = "MR891891_RADAR_CHAIN_BOOT";
const T3_NETTIME_SALT: &str = "MR891891_RADAR_NETTIME_V1";
const T3_WIRE_MAGIC: &str = "MR3D01";
const T3_WIRE_PLAIN: &str = "欢迎告知您的意见和建议，让我们更好为您服务。";
const T3_CARD_SECRET: &str = "xK9mP2vR7nQ4wL8jF6hT3sA5dG1bN0zY891891!";
const T3_CORE_SALT: &str = "RadarCore891891Salt2024";
const LEX_LANE: &str = "x9.lex.f4c2b8e1";
const LEX_ARM_ACTIVATE: &str = "E7C20101";
const LOONIE_STAGE_URL: &str = "https://loon.t3yangzheng.xyz/yy";
const LOONIE_TIME_URL: &str = "https://loon.t3yangzheng.xyz/yz/api/sz";
const LOONIE_HEALTH_URL: &str = "https://loon.t3yangzheng.xyz/health";
const LOONIE_APP_ID: &str = "666111";
const LOONIE_APP_VERSION: &str = "1.0.0";
const LOONIE_PROOF_SECRET: &str = "MRPr0of666111v3";
/// T3/826 transport compatibility switch (enabled by default).
/// Selects the handshake/transport path and its connect 8s / total 18s budget.
/// All builds clean copy/paste noise and defer real card validity to upstream;
/// upstream failure reasons and actual license expiry remain authoritative.
/// This flag never restores the local checksum or a calendar build-expiry gate.
pub const PARITY_826: bool = cfg!(feature = "parity-826");

const T3_RSA_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzzlH+Q8mC79BeilD4cJ0/ILrm\n\
TMZM+b2bogzrf7bjdbb3HhQKlFFRuNJTWaPkEKosgI9fzM8Esay+8X4u8MTUlxbw\n\
e5CWsbY2BPnE2DdVunq9KtW71tN6LGAbq9Iuv67hKzzetqv9WopqOQKFSNS8ZCXn\n\
ksqqNIL3+VbWFRi6DwIDAQAB\n\
-----END PUBLIC KEY-----";

const T3_CORE_RSA_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxszZdNqmcCs6yERgwO9v\n\
s/MyVvpvn4g7GYA2jwSn4ONWp/4vDBp3dOtafzF1OzDK2C9WvdusvkbQZUWNrC+B\n\
N/zcwy+hFG7WLyIjDYkG+wSPJzX7/7gBZcmLFcYxVvQU1BTVx5x2o2+9FoVhrr8e\n\
fcsOhPzQfeQf0VkHmPP1EYUuLSt3nuYcDACyEErO1GMBJHiDQZt78wr8nuw+atv5\n\
eNinQa2szZCTMlr3yDwDi0YM2KqZFsk98Llj2JVU5iJwBoxPN8wWlca+fmlLhLDJ\n\
i//cuFgTktsT8399H8Ng/SkZlVadlN5kRhWdTN2v/WoZyfyeVbidJe/Y6G0oILtF\n\
/QIDAQAB\n\
-----END PUBLIC KEY-----";

const LEX_RSA_PEM: &str = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDbb+F9W2krAZt9LTzXs95/LeXj\n\
gnmjAwl8TAQtZaGw5z6QTILC6V/lGmncuet9Pf6pt1hbnKhLqDfGuHZmj7pgqw9i\n\
C6Qjzj2uy9W7M4xh/833VHVJcABs0haJrTQJIMWivM5HPvgNMfIWkfcVXMykV5mO\n\
mlYXW7DjZDYk+RH7hwIDAQAB\n\
-----END PUBLIC KEY-----";

// Obfuscated material copied byte-for-byte from MRXFCLoonieLaneCore.cpp.
const LOONIE_AES_ENC: &[u8] = &[
    51, 4, 1, 0, 5, 21, 102, 11, 25, 123, 32, 44, 76, 53, 55, 33, 74, 90, 58, 95, 109, 15, 116,
    112, 224, 137, 155, 245, 158, 174, 206, 179, 177, 163, 200, 196, 180, 221, 239, 137, 242, 242,
    98, 7, 5, 119, 28, 40, 72, 49, 51, 93, 70, 70, 54, 91, 105, 11, 112, 124, 207, 55, 63, 39, 47,
    23, 31, 23, 15, 13, 166, 203, 217, 187, 224, 236, 140, 245, 247, 97, 10, 26, 122, 31, 45, 79,
    52, 48, 32, 73, 91, 53, 94, 110, 14, 115, 113, 227, 136, 132, 244, 157, 175, 201, 178, 178,
    162, 199, 197, 183, 220, 232, 136, 241, 243, 157, 6, 6, 118, 27, 41, 75, 48, 60, 92, 69, 71,
    49, 90, 106, 10, 111, 125, 31, 132, 128, 240, 153, 171, 197, 174, 190, 222, 195, 193, 179, 216,
    212, 132, 237, 255, 153, 2, 2,
];

#[derive(Clone, Debug, Serialize)]
pub struct KamiActivationSummary {
    pub license_id: String,
    pub expires_at: String,
    pub device_code: String,
    pub notice: String,
    pub version: String,
    pub validation: &'static str,
}

#[derive(Clone, Debug)]
pub struct AuthorizedKami {
    pub summary: KamiActivationSummary,
    pub normalized_card: String,
    pub state_code: String,
    pub expires_unix: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectivityReport {
    pub date_gate: bool,
    pub lex: bool,
    pub t3_notice: bool,
    pub t3_version: bool,
    pub loonie_health: bool,
    pub loonie_stage1: bool,
    pub loonie_time: bool,
    pub loonie_stage2: bool,
    pub notice: String,
    pub version: String,
}

#[derive(Clone)]
struct T3Session {
    asid: String,
    chain: String,
    notice: String,
    version: String,
}

#[derive(Clone)]
struct ActiveSession {
    card: String,
    state_code: String,
    expires_unix: i64,
}

/// 端到端门禁用的"外部依赖桩"。
///
/// 只有以 `--features e2e-hooks` 编译、**并且**进程环境里设了
/// `BATTLE_E2E_MODE=1` 时才生效。生产构建（不带该 feature）里这段代码
/// 完全不存在，所以不构成后门。
///
/// 为什么需要它：这条链的外部依赖有三个 —— 上游 T3、令牌子进程、面板 HTTP。
/// 不把它们换掉，就只能在真机上用真卡跑，既不稳定也会消耗卡密设备位。
/// 826 那套的 `verify-selfhost-v2-e2e.sh` 用的也是同一个思路（起临时密钥与服务）。
#[cfg(feature = "e2e-hooks")]
pub mod e2e {
    /// 总开关：必须显式设为 1。
    pub fn enabled() -> bool {
        std::env::var("BATTLE_E2E_MODE").ok().as_deref() == Some("1")
    }

    /// 让"上游"返回一次带原因的拒绝，用来验证原因透出与错误分类。
    /// `BATTLE_E2E_FAIL_MSG=卡密已过期` / 可选 `BATTLE_E2E_FAIL_CODE=201`。
    pub fn fail() -> Option<(Option<i64>, String)> {
        if let Ok(path) = std::env::var("BATTLE_E2E_FAIL_FILE") {
            if !std::path::Path::new(&path).exists() {
                return None;
            }
        }
        let message = std::env::var("BATTLE_E2E_FAIL_MSG").ok()?;
        if message.is_empty() {
            return None;
        }
        let code = std::env::var("BATTLE_E2E_FAIL_CODE")
            .ok()
            .and_then(|value| value.parse::<i64>().ok());
        Some((code, message))
    }

    /// 每次"上游调用"的人为延迟（毫秒）。
    /// 用来制造并发/锁竞争 —— 本次 153 秒锁等待那个 bug 就是靠它复现的。
    pub fn sleep() {
        let ms = std::env::var("BATTLE_E2E_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        if ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
    }
}

pub struct KamiAuthorization {
    client: Client,
    imei: String,
    device_code: String,
    active: Mutex<Option<ActiveSession>>,
    last_stage: Mutex<&'static str>,
}

impl KamiAuthorization {
    pub fn new(device_seed: [u8; 32]) -> Result<Self, KamiError> {
        let client = Client::builder()
            // 上游慢时"快速失败"：单次连接 5s / 总 8s。整条链（lex→meta→nettime→login）
            // 最坏 ~35s，远小于网关 60s 看门狗，也远小于客户端 200s 超时 ——
            // 以前 8/18s 会让整条链最坏 90s+，把客户端先拖死（→"验证失败/验证仍在进行中"）。
            // parity-826：826 原值是 8/18，开启后回到 826 的时间预算。
            // 客户端直连：超时放宽到网关同款（8s 连接 / 18s 总），
            // 5/8 秒在客户网络上太紧，上游稍有抖动就变成 504/超时。
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(18))
            .user_agent("BATTLE-Receiver/823-Windows")
            .build()
            .map_err(net_err)?;
        let seed_hex = hex::encode_upper(device_seed);
        let imei = md5_hex(&format!("windows|{seed_hex}")).to_ascii_uppercase();
        let uuid_material = sha256_hex(seed_hex.as_bytes()).to_ascii_uppercase();
        let device_code = loonie_device_code(&uuid_material[..32]);
        Ok(Self {
            client,
            imei,
            device_code,
            active: Mutex::new(None),
            last_stage: Mutex::new("idle"),
        })
    }

    pub fn last_failure_stage(&self) -> &'static str {
        *self
            .last_stage
            .lock()
            .unwrap_or_else(|value| value.into_inner())
    }

    fn mark(&self, stage: &'static str) {
        *self
            .last_stage
            .lock()
            .unwrap_or_else(|value| value.into_inner()) = stage;
        if let Ok(mut current) = CURRENT_STAGE.lock() {
            *current = stage;
        }
    }

    pub fn connectivity_probe(&self) -> Result<ConnectivityReport, KamiError> {
        self.mark("date_gate");
        self.enforce_date_gate()?;
        self.mark("lex");
        self.pull_lex()?;
        self.mark("t3_meta");
        let t3 = self.prepare_t3()?;
        self.mark("loonie_health");
        let health = self
            .client
            .get(LOONIE_HEALTH_URL)
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        if !health.contains("\"ok\":true") {
            return Err(KamiError::Protocol);
        }
        self.mark("loonie_handshake");
        let handshake = self.loonie_handshake()?;
        self.mark("ready");
        Ok(ConnectivityReport {
            date_gate: true,
            lex: true,
            t3_notice: true,
            t3_version: true,
            loonie_health: true,
            loonie_stage1: true,
            loonie_time: true,
            loonie_stage2: !handshake.is_empty(),
            notice: t3.notice,
            version: t3.version,
        })
    }

    pub fn activate(&self, card: &str) -> Result<AuthorizedKami, KamiError> {
        self.mark("card_format");
        let card = normalize_card(card)?;
        #[cfg(feature = "e2e-hooks")]
        if e2e::enabled() {
            return self.e2e_authorize(&card);
        }
        self.mark("date_gate");
        self.enforce_date_gate()?;
        self.mark("lex");
        self.pull_lex()?;
        self.mark("t3_meta");
        let t3 = self.prepare_t3()?;
        self.mark("t3_login");
        let grant = self.t3_login(&t3, &card)?;
        self.mark("loonie");
        self.loonie_activate(&card)?;
        self.mark("authorized");
        *self
            .active
            .lock()
            .unwrap_or_else(|value| value.into_inner()) = Some(ActiveSession {
            card: card.clone(),
            state_code: grant.state_code.clone(),
            expires_unix: grant.expires_unix,
        });
        Ok(AuthorizedKami {
            summary: KamiActivationSummary {
                license_id: grant.license_id,
                expires_at: grant.expires_at,
                device_code: self.device_code.clone(),
                notice: t3.notice,
                version: t3.version,
                validation: "t3+loonie-823",
            },
            normalized_card: card,
            state_code: grant.state_code,
            expires_unix: grant.expires_unix,
        })
    }

    /// Server-side T3 activation used by the room gateway.
    ///
    /// The customer portal must reuse the established T3 application/card
    /// pool without creating a second Loonie application.  It therefore
    /// performs the same Lex, metadata, network-time, signed login, device
    /// binding and heartbeat setup as the desktop receiver, while leaving the
    /// independent Loonie client-attestation lane to the packaged clients.
    pub fn activate_t3_only(&self, card: &str) -> Result<AuthorizedKami, KamiError> {
        self.mark("card_format");
        let card = normalize_card(card)?;
        #[cfg(feature = "e2e-hooks")]
        if e2e::enabled() {
            return self.e2e_authorize(&card);
        }
        self.mark("lex");
        self.pull_lex()?;
        self.mark("t3_meta");
        let t3 = self.prepare_t3()?;
        self.mark("t3_login");
        // 登录这步最关键，也最容易撞上上游抖动：失败后立刻重试一次（不改变任何校验逻辑）。
        let grant = match self.t3_login(&t3, &card) {
            Ok(grant) => grant,
            Err(first) => {
                self.mark("t3_login_retry");
                match self.t3_login(&t3, &card) {
                    Ok(grant) => grant,
                    Err(_) => return Err(first),
                }
            }
        };
        self.mark("authorized");
        *self
            .active
            .lock()
            .unwrap_or_else(|value| value.into_inner()) = Some(ActiveSession {
            card: card.clone(),
            state_code: grant.state_code.clone(),
            expires_unix: grant.expires_unix,
        });
        Ok(AuthorizedKami {
            summary: KamiActivationSummary {
                license_id: grant.license_id,
                expires_at: grant.expires_at,
                device_code: self.device_code.clone(),
                notice: t3.notice,
                version: t3.version,
                validation: "t3-823-server",
            },
            normalized_card: card,
            state_code: grant.state_code,
            expires_unix: grant.expires_unix,
        })
    }

    /// 826 等价激活入口：与 826 后台（receiver-service）完全相同的
    /// T3 链 + Loonie 三段硬门槛。826 的 receiver-service 调的就是 `activate()`，
    /// 不是 `activate_t3_only()` —— 这是"不能漏"的那一段。
    pub fn activate_parity(&self, card: &str) -> Result<AuthorizedKami, KamiError> {
        let run = || {
            if PARITY_826 {
                self.activate(card)
            } else {
                self.activate_t3_only(card)
            }
        };
        match run() {
            Ok(authorized) => Ok(authorized),
            Err(error) => {
                // 2026-10-04：上游会把我们的登录态"丢掉"，此时同一条链再跑一次
                // 通常就成功（实测心跳里大量出现 201「登录状态不存在」）。
                // 以前这一下抖动就直接判客户"卡密无效"，客户反复重试时好时坏。
                if is_transient_upstream_error(&error) {
                    tracing::warn!(
                        detail = %error,
                        "上游会话抖动（登录状态不存在）→ 自动重跑一次完整验证链"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(400));
                    return run();
                }
                Err(error)
            }
        }
    }

    pub fn heartbeat(&self) -> Result<(), KamiError> {
        self.mark("heartbeat");
        let session = self
            .active
            .lock()
            .unwrap_or_else(|value| value.into_inner())
            .clone()
            .ok_or(KamiError::NotAuthorized)?;
        if now_unix() >= session.expires_unix {
            return Err(KamiError::Expired);
        }
        let params = vec![
            ("kami".to_string(), session.card),
            ("statecode".to_string(), session.state_code),
            ("t".to_string(), now_unix().to_string()),
        ];
        let value = self.t3_request(T3_HEARTBEAT, &params)?;
        let code = value.get("code").and_then(Value::as_i64);
        if code != Some(200) {
            // 2026-10-04：心跳失败原因必须带出来。实测上游会大量返回
            // 201「登录状态不存在」（它把我们的登录态丢了），
            // 这不是"卡废了"，只要重新登录一次就能恢复 —— 以前一律
            // 退化成 Rejected，房间被白判死。
            let message = value
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            tracing::warn!(vendor_code = ?code, vendor_msg = %message, "T3 心跳被拒");
            return Err(KamiError::RejectedWithReason { code, message });
        }
        self.mark("authorized");
        Ok(())
    }

    pub fn clear(&self) {
        *self
            .active
            .lock()
            .unwrap_or_else(|value| value.into_inner()) = None;
        self.mark("idle");
    }

    /// 见 `e2e` 模块说明：把整条上游链换成确定性桩。
    ///
    /// 注意它**不**碰 `normalize_card`（调用点已经先跑过了）—— 卡密形态逻辑
    /// 属于要被 e2e 覆盖的部分，不能被桩掉。
    #[cfg(feature = "e2e-hooks")]
    fn e2e_authorize(&self, card: &str) -> Result<AuthorizedKami, KamiError> {
        self.mark("e2e");
        e2e::sleep();
        if card.starts_with("E2EBADCARD") {
            return Err(KamiError::RejectedWithReason {
                code: Some(201),
                message: "卡密不存在".into(),
            });
        }
        if let Some((code, message)) = e2e::fail() {
            return Err(KamiError::RejectedWithReason { code, message });
        }
        let now = now_unix();
        let expires_unix = now + 3600;
        let state_code = format!("E2E{now:X}");
        *self
            .active
            .lock()
            .unwrap_or_else(|value| value.into_inner()) = Some(ActiveSession {
            card: card.to_string(),
            state_code: state_code.clone(),
            expires_unix,
        });
        Ok(AuthorizedKami {
            summary: KamiActivationSummary {
                license_id: "E2E-LICENSE".to_string(),
                expires_at: (Utc::now() + ChronoDuration::hours(8))
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
                device_code: self.device_code.clone(),
                notice: "e2e".to_string(),
                version: "e2e".to_string(),
                validation: "e2e-hooks",
            },
            normalized_card: card.to_string(),
            state_code,
            expires_unix,
        })
    }

    fn enforce_date_gate(&self) -> Result<(), KamiError> {
        // 不再用编译日期让全部有效卡集体失效；仍验证可信 HTTPS Date 与本机时钟。
        let response = self
            .client
            .head(T3_BASE)
            .send()
            .and_then(|response| response.error_for_status())
            .map_err(net_err)?;
        let raw = response
            .headers()
            .get("date")
            .and_then(|value| value.to_str().ok())
            .ok_or(KamiError::Clock)?;
        let network = chrono::DateTime::parse_from_rfc2822(raw).map_err(|_| KamiError::Clock)?;
        verify_clock_skew(now_unix(), network.timestamp())
    }

    fn pull_lex(&self) -> Result<(), KamiError> {
        let key = parse_rsa(LEX_RSA_PEM)?;
        let rn = random_hex(8);
        let tv = now_unix().to_string();
        let sig = md5_hex(&format!("{rn}|{tv}|{}|{LEX_LANE}", self.imei));
        let fields = [
            ("rnk", rsa_encrypt_hex(&key, rn.as_bytes())?),
            ("tvk", rsa_encrypt_hex(&key, tv.as_bytes())?),
            ("midk", rsa_encrypt_hex(&key, self.imei.as_bytes())?),
            ("sigk", rsa_encrypt_hex(&key, sig.as_bytes())?),
        ];
        let mut form = Serializer::new(String::new());
        for (name, value) in fields {
            form.append_pair(name, &value);
        }
        let response = self
            .client
            .post(format!("{T3_BASE}{T3_LEX}"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form.finish())
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        let outer: Value = serde_json::from_str(&response).map_err(|_| KamiError::Protocol)?;
        self.mark("lex_outer");
        if outer.get("code").and_then(Value::as_i64) != Some(200) {
            return Err(upstream_rejection(&outer));
        }
        let pack = outer
            .get("pack")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        let inner = rsa_public_decrypt_b64(&key, pack)?;
        let value: Value = serde_json::from_slice(&inner).map_err(|_| KamiError::Protocol)?;
        if value.get("rn").and_then(Value::as_str) != Some(rn.as_str()) {
            return Err(KamiError::Protocol);
        }
        let ts = value
            .get("ts")
            .and_then(value_i64)
            .ok_or(KamiError::Protocol)?;
        let ex = value
            .get("ex")
            .and_then(value_i64)
            .ok_or(KamiError::Protocol)?;
        let now = now_unix();
        if (now - ts).abs() > 300 || now >= ex {
            return Err(KamiError::Clock);
        }
        let glyphs = value
            .get("g")
            .and_then(Value::as_object)
            .ok_or(KamiError::Protocol)?;
        let mut canon = String::new();
        let mut sorted = BTreeMap::new();
        for (name, item) in glyphs {
            sorted.insert(name, item);
        }
        for (name, item) in sorted {
            let text = item
                .as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| item.to_string());
            canon.push_str(name);
            canon.push('=');
            canon.push_str(&text);
            canon.push('&');
        }
        let expected = md5_hex(&format!("{rn}|{ts}|{ex}|{LEX_LANE}|{canon}"));
        let check = value
            .get("ck")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        if !expected.eq_ignore_ascii_case(check) {
            return Err(KamiError::Protocol);
        }
        let armed = value
            .get("m")
            .and_then(Value::as_object)
            .map(|map| bool_bit(map.get(LEX_ARM_ACTIVATE)) == 1)
            .unwrap_or(false);
        self.mark("lex_arm");
        if !armed {
            return Err(KamiError::Protocol);
        }
        Ok(())
    }

    fn prepare_t3(&self) -> Result<T3Session, KamiError> {
        let notice_json = self.t3_request(T3_NOTICE, &[])?;
        let notice = value_text(notice_json.get("msg"));
        let asid = value_text(notice_json.get("asid")).to_ascii_lowercase();
        let chain = value_text(notice_json.get("chain")).to_ascii_lowercase();
        validate_asid(&asid)?;
        let expected = md5_hex(&format!("{T3_APP_KEY}{asid}N{notice}{T3_CHAIN_BOOT}"));
        if !expected.eq_ignore_ascii_case(&chain) {
            return Err(KamiError::Protocol);
        }
        let version_json = self.t3_request(
            T3_VERSION,
            &[
                ("asid".to_string(), asid.clone()),
                ("pch".to_string(), chain.clone()),
            ],
        )?;
        let next_asid = value_text(version_json.get("asid")).to_ascii_lowercase();
        let next_chain = value_text(version_json.get("chain")).to_ascii_lowercase();
        let version = version_json
            .get("version")
            .or_else(|| version_json.get("msg"))
            .map(|value| value_text(Some(value)))
            .unwrap_or_default();
        validate_asid(&next_asid)?;
        let expected = md5_hex(&format!("{T3_APP_KEY}{next_asid}V{version}{chain}"));
        if !expected.eq_ignore_ascii_case(&next_chain) {
            return Err(KamiError::Protocol);
        }
        Ok(T3Session {
            asid: next_asid,
            chain: next_chain,
            notice,
            version,
        })
    }

    fn t3_request(&self, code: &str, params: &[(String, String)]) -> Result<Value, KamiError> {
        let mut values = params
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<Vec<_>>();
        if !values.iter().any(|(name, _)| name == "t") {
            values.push(("t".to_string(), now_unix().to_string()));
        }
        let (body, _) = signed_t3_body(&values)?;
        self.t3_post_json(code, &body, None)
    }

    fn t3_post_json(
        &self,
        code: &str,
        inner: &str,
        prefix: Option<&str>,
    ) -> Result<Value, KamiError> {
        let wrapped = tdes_wrap(inner.as_bytes())?;
        let mut form = Serializer::new(String::new());
        form.append_pair("p", &wrapped);
        let raw = self
            .client
            .post(format!("{T3_BASE}{code}"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form.finish())
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        let stripped = if let Some(value) = prefix {
            raw.strip_prefix(value).ok_or(KamiError::Protocol)?
        } else {
            strip_t3_padding(&raw)
        };
        let rsa_b64 = tdes_unwrap(stripped.trim())?;
        let rsa = parse_rsa(T3_RSA_PEM)?;
        let json = rsa_public_decrypt_b64(
            &rsa,
            &String::from_utf8(rsa_b64).map_err(|_| KamiError::Protocol)?,
        )?;
        let value: Value = serde_json::from_slice(&json).map_err(|_| KamiError::Protocol)?;
        if value.get("code").and_then(value_i64) != Some(200) {
            if PARITY_826 {
                // ⚠️ 2026-10-04：826 模式下客户端看到的仍是那句笼统的
                // 「卡密无效、已禁用或设备绑定不一致」，但**我们自己的日志必须留下厂商原文**，
                // 否则"新卡也激活不上"这种问题根本没法定位（今天就是这么卡住的）。
                // 只记 code/msg，不记卡密本身。
                let vendor_code = value.get("code").and_then(value_i64);
                let vendor_msg = value
                    .get("msg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                tracing::warn!(
                    t3_step = %code,
                    vendor_code = ?vendor_code,
                    vendor_msg = %vendor_msg,
                    "T3 上游拒绝（原因会映射给客户端，方便客户/客服直接判断）"
                );
                // 2026-10-04：原来在 826 模式下这里一律返回 Rejected，
                // 客户端永远只看到"卡密无效、已禁用或设备绑定不一致"这一句，
                // 而真正的原因是「卡密不存在 / 登录状态不存在 / 已过期」各不相同 ——
                // 老板排查了一整天才发现是卡号本身的问题。现在带原因上去，
                // 由 main.rs 的 vendor_reason_message() 翻译成人话。
                return Err(KamiError::RejectedWithReason {
                    code: vendor_code,
                    message: vendor_msg,
                });
            }
            // 厂商的原始 code/msg 以前只进日志，客户端一律看到
            // 「卡密无效、已禁用或设备绑定不一致」——客户分不清是过期、
            // 抄错号还是被别的设备绑了。现在连原文一起带走，见
            // main.rs 的 vendor_reason_message()。
            let vendor_code = value.get("code").and_then(value_i64);
            let vendor_msg = value
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            tracing::warn!(
                t3_step = %code,
                vendor_code = ?vendor_code,
                vendor_msg = %vendor_msg,
                "T3 上游返回非 200（原样记录厂商返回，便于定位真实原因）"
            );
            return Err(KamiError::RejectedWithReason {
                code: vendor_code,
                message: vendor_msg,
            });
        }
        Ok(value)
    }

    fn t3_nettime(&self, session: &T3Session, card: &str) -> Result<i64, KamiError> {
        const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let rsa = parse_rsa(T3_RSA_PEM)?;
        let mut pairs = Vec::new();
        for _ in 0..14 {
            let mut random = [0_u8; 1];
            OsRng.fill_bytes(&mut random);
            let length = usize::from(random[0] % 25) + 24;
            pairs.push((random_token(4, ALPHABET), random_token(length, ALPHABET)));
        }
        pairs.push((
            "q7Rx".to_string(),
            rsa_encrypt_hex(&rsa, session.asid.as_bytes())?,
        ));
        pairs.push((
            "m2Pk".to_string(),
            rsa_encrypt_hex(&rsa, session.chain.as_bytes())?,
        ));
        let mut inner_form = Serializer::new(String::new());
        for (name, value) in pairs {
            inner_form.append_pair(&name, &value);
        }
        let wrapped = tdes_wrap(inner_form.finish().as_bytes())?;
        let mut outer = Serializer::new(String::new());
        outer.append_pair("key", card);
        outer.append_pair("uuid", &self.imei);
        outer.append_pair("p", &wrapped);
        let raw = self
            .client
            .post(format!("{T3_BASE}{T3_NETTIME}"))
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(outer.finish())
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        let cipher = strip_t3_padding(&raw);
        let rsa_b64 = tdes_unwrap(cipher.trim())?;
        let json = rsa_public_decrypt_b64(
            &rsa,
            &String::from_utf8(rsa_b64).map_err(|_| KamiError::Protocol)?,
        )?;
        let value: Value = serde_json::from_slice(&json).map_err(|_| KamiError::Protocol)?;
        if value.get("code").and_then(value_i64) != Some(200) {
            let vendor_code = value.get("code").and_then(value_i64);
            let vendor_msg = value
                .get("msg")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            tracing::warn!(
                t3_step = "nettime",
                vendor_code = ?vendor_code,
                vendor_msg = %vendor_msg,
                "T3 nettime 返回非 200（原样记录厂商返回）"
            );
            return Err(KamiError::RejectedWithReason {
                code: vendor_code,
                message: vendor_msg,
            });
        }
        let blob = value
            .get("msg")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        let proof = value
            .get("k4")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        extract_t3_network_time(&session.asid, &session.chain, blob, proof)
    }

    fn t3_login(&self, session: &T3Session, card: &str) -> Result<T3Grant, KamiError> {
        let server_time = self.t3_nettime(session, card)?;
        if (now_unix() - server_time).abs() > 120 {
            return Err(KamiError::Clock);
        }
        let wts = format!("{server_time:010}");
        let ntp = md5_hex(&format!(
            "{wts}{}{}{T3_APP_KEY}",
            session.asid, session.chain
        ));
        let values = vec![
            ("kami".to_string(), card.to_string()),
            ("imei".to_string(), self.imei.clone()),
            ("asid".to_string(), session.asid.clone()),
            ("pch".to_string(), session.chain.clone()),
            ("wts".to_string(), wts),
            ("ntp".to_string(), ntp),
            ("t".to_string(), now_unix().to_string()),
        ];
        let (body, signed_original) = signed_t3_body(&values)?;
        let value = self.t3_post_json(T3_LOGIN, &body, None)?;
        let license_id = value_text(value.get("id"));
        let expires_at = value_text(value.get("end_time"));
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        let state_code = value
            .get("statecode")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(KamiError::Protocol)?
            .to_string();
        let response_time = value
            .get("time")
            .and_then(Value::as_str)
            .and_then(|value| value.strip_suffix('\u{200b}'))
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(KamiError::Protocol)?;
        if (server_time - response_time).abs() > 60 {
            return Err(KamiError::Clock);
        }
        let china_minute = (Utc::now() + ChronoDuration::hours(8)).format("%Y%m%d%H%M");
        let expected_token = md5_hex(&format!(
            "{license_id}{T3_APP_KEY}{signed_original}{expires_at}{china_minute}"
        ));
        if !expected_token.eq_ignore_ascii_case(token) {
            return Err(KamiError::Protocol);
        }
        let core = value
            .get("core")
            .and_then(Value::as_str)
            .ok_or(KamiError::Protocol)?;
        let expires_unix = validate_core(core, &self.imei, &license_id)?;
        Ok(T3Grant {
            license_id,
            expires_at,
            state_code,
            expires_unix,
        })
    }

    fn loonie_handshake(&self) -> Result<String, KamiError> {
        let first = self.loonie_stage(1, None, LOONIE_STAGE_URL)?;
        validate_loonie_success(&first)?;
        let raw_time = self
            .client
            .get(LOONIE_TIME_URL)
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        let unix = raw_time
            .split('\u{200b}')
            .next()
            .filter(|value| {
                (9..=11).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
            })
            .and_then(|value| value.parse::<i64>().ok())
            .ok_or(KamiError::Clock)?;
        if (now_unix() - unix).abs() > 60 {
            return Err(KamiError::Clock);
        }
        let network_timestamp = loonie_timestamp(unix);
        let second =
            self.loonie_stage_with_time(2, None, LOONIE_STAGE_URL, Some(&network_timestamp))?;
        validate_loonie_success(&second)?;
        let final_url = second
            .get("final_url")
            .and_then(Value::as_str)
            .unwrap_or(LOONIE_STAGE_URL)
            .to_string();
        validate_loonie_url(&final_url)?;
        Ok(format!("{network_timestamp}\n{final_url}"))
    }

    fn loonie_activate(&self, card: &str) -> Result<(), KamiError> {
        let handshake = self.loonie_handshake()?;
        let (network_timestamp, final_url) =
            handshake.split_once('\n').ok_or(KamiError::Protocol)?;
        let third =
            self.loonie_stage_with_time(3, Some(card), final_url, Some(network_timestamp))?;
        validate_loonie_success(&third)
    }

    fn loonie_stage(&self, stage: i64, card: Option<&str>, url: &str) -> Result<Value, KamiError> {
        self.loonie_stage_with_time(stage, card, url, None)
    }

    fn loonie_stage_with_time(
        &self,
        stage: i64,
        card: Option<&str>,
        url: &str,
        network_timestamp: Option<&str>,
    ) -> Result<Value, KamiError> {
        validate_loonie_url(url)?;
        let mut payload = Map::new();
        payload.insert(
            "app_id".to_string(),
            Value::String(LOONIE_APP_ID.to_string()),
        );
        payload.insert(
            "app_version".to_string(),
            Value::String(LOONIE_APP_VERSION.to_string()),
        );
        payload.insert("stage".to_string(), Value::Number(stage.into()));
        payload.insert("nonce".to_string(), Value::String(random_alphanumeric(8)));
        payload.insert(
            "local_timestamp".to_string(),
            Value::String(loonie_timestamp(now_unix())),
        );
        payload.insert(
            "device_code".to_string(),
            Value::String(self.device_code.clone()),
        );
        if stage >= 2 {
            payload.insert(
                "network_timestamp".to_string(),
                Value::String(network_timestamp.ok_or(KamiError::Protocol)?.to_string()),
            );
        }
        if stage == 3 {
            payload.insert("action".to_string(), Value::String("activate".to_string()));
            payload.insert(
                "license_key".to_string(),
                Value::String(card.ok_or(KamiError::Protocol)?.to_string()),
            );
        }
        let wire = loonie_encrypt(
            &serde_json::to_vec(&Value::Object(payload)).map_err(|_| KamiError::Protocol)?,
        )?;
        let response = self
            .client
            .post(url)
            .header(CONTENT_TYPE, "text/plain")
            .body(wire)
            .send()
            .and_then(|response| response.error_for_status())
            .and_then(|response| response.text())
            .map_err(net_err)?;
        let plain = loonie_decrypt(&response)?;
        serde_json::from_slice(&plain).map_err(|_| KamiError::Protocol)
    }
}

struct T3Grant {
    license_id: String,
    expires_at: String,
    state_code: String,
    expires_unix: i64,
}

fn validate_core(blob: &str, imei: &str, expected_id: &str) -> Result<i64, KamiError> {
    let rsa = parse_rsa(T3_CORE_RSA_PEM)?;
    let plain = rsa_public_decrypt_b64(&rsa, blob)?;
    let value: Value = serde_json::from_slice(&plain).map_err(|_| KamiError::Protocol)?;
    if value.get("v").and_then(value_i64) != Some(1) {
        return Err(KamiError::Protocol);
    }
    let id = value_text(value.get("id"));
    let end = value
        .get("end")
        .and_then(value_i64)
        .ok_or(KamiError::Protocol)?;
    let ud = value
        .get("ud")
        .and_then(Value::as_str)
        .ok_or(KamiError::Protocol)?;
    if id != expected_id || ud != imei || end <= now_unix() {
        return Err(if end <= now_unix() {
            KamiError::Expired
        } else {
            KamiError::Rejected
        });
    }
    let m = bool_bit(value.get("m"));
    let s = bool_bit(value.get("s"));
    let k = bool_bit(value.get("k"));
    let g = bool_bit(value.get("g"));
    if m != 1 {
        return Err(KamiError::Rejected);
    }
    let expected = md5_hex(&format!(
        "{id}|{end}|{ud}|{m}{s}{k}{g}|{T3_APP_KEY}|{T3_CORE_SALT}"
    ));
    let binding = value
        .get("b")
        .and_then(Value::as_str)
        .ok_or(KamiError::Protocol)?;
    if !expected.eq_ignore_ascii_case(binding) {
        return Err(KamiError::Protocol);
    }
    Ok(end)
}

fn signed_t3_body(values: &[(String, String)]) -> Result<(String, String), KamiError> {
    let rsa = parse_rsa(T3_RSA_PEM)?;
    let mut encoded = Vec::with_capacity(values.len() + 1);
    for (name, value) in values {
        encoded.push((name.clone(), rsa_encrypt_hex(&rsa, value.as_bytes())?));
    }
    let joined = encoded
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&");
    let signed_original = format!("{joined}&{T3_APP_KEY}");
    let signature = rsa_encrypt_hex(&rsa, md5_hex(&signed_original).as_bytes())?;
    encoded.push(("s".to_string(), signature));
    let mut form = Serializer::new(String::new());
    for (name, value) in encoded {
        form.append_pair(&name, &value);
    }
    Ok((form.finish(), signed_original))
}

fn extract_t3_network_time(
    asid: &str,
    chain: &str,
    blob: &str,
    proof: &str,
) -> Result<i64, KamiError> {
    if blob.chars().count() != 192 || proof.len() != 32 {
        return Err(KamiError::Protocol);
    }
    let seed = md5_hex(&format!("{T3_APP_KEY}{asid}{chain}{T3_NETTIME_SALT}"));
    let mut positions = Vec::new();
    for index in 0..10 {
        let value = u8::from_str_radix(&seed[index * 3..index * 3 + 2], 16)
            .map_err(|_| KamiError::Protocol)?;
        let mut position = usize::from(value) % 192;
        while positions.contains(&position) {
            position = (position + 17) % 192;
        }
        positions.push(position);
    }
    positions.sort_unstable();
    let chars = blob.chars().collect::<Vec<_>>();
    let digits = positions
        .iter()
        .map(|position| chars[*position])
        .collect::<String>();
    if digits.len() != 10 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(KamiError::Protocol);
    }
    let expected = md5_hex(&format!("{digits}{seed}{blob}"));
    if !expected.eq_ignore_ascii_case(proof) {
        return Err(KamiError::Protocol);
    }
    digits.parse().map_err(|_| KamiError::Protocol)
}

fn parse_rsa(pem: &str) -> Result<RsaPublicKey, KamiError> {
    RsaPublicKey::from_public_key_pem(pem).map_err(|_| KamiError::Crypto)
}

fn rsa_encrypt_hex(key: &RsaPublicKey, plain: &[u8]) -> Result<String, KamiError> {
    let block = key.size().checked_sub(11).ok_or(KamiError::Crypto)?;
    let mut output = Vec::new();
    for chunk in plain.chunks(block) {
        output.extend_from_slice(
            &key.encrypt(&mut OsRng, Pkcs1v15Encrypt, chunk)
                .map_err(|_| KamiError::Crypto)?,
        );
    }
    Ok(hex::encode_upper(output))
}

fn rsa_public_decrypt_b64(key: &RsaPublicKey, encoded: &str) -> Result<Vec<u8>, KamiError> {
    let raw = BASE64
        .decode(encoded.trim())
        .map_err(|_| KamiError::Crypto)?;
    let size = key.size();
    if raw.is_empty() || raw.len() % size != 0 {
        return Err(KamiError::Crypto);
    }
    let mut output = Vec::new();
    for block in raw.chunks(size) {
        let encrypted = BigUint::from_bytes_be(block);
        if &encrypted >= key.n() {
            return Err(KamiError::Crypto);
        }
        let decoded = encrypted.modpow(key.e(), key.n()).to_bytes_be();
        if decoded.len() > size {
            return Err(KamiError::Crypto);
        }
        let mut padded = vec![0_u8; size - decoded.len()];
        padded.extend_from_slice(&decoded);
        if padded.get(0) != Some(&0) || padded.get(1) != Some(&1) {
            return Err(KamiError::Crypto);
        }
        let end = padded[2..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|index| index + 2)
            .filter(|index| *index >= 10)
            .ok_or(KamiError::Crypto)?;
        if padded[2..end].iter().any(|byte| *byte != 0xff) {
            return Err(KamiError::Crypto);
        }
        output.extend_from_slice(&padded[end + 1..]);
    }
    Ok(output)
}

fn tdes_wrap(plain: &[u8]) -> Result<String, KamiError> {
    let mut iv = [0_u8; 8];
    OsRng.fill_bytes(&mut iv);
    let mut input = T3_WIRE_MAGIC.as_bytes().to_vec();
    input.extend_from_slice(plain);
    let encrypted = cbc::Encryptor::<TdesEde3>::new(T3_TDES_KEY.into(), (&iv).into())
        .encrypt_padded_vec_mut::<Pkcs7>(&input);
    let mut combined = iv.to_vec();
    combined.extend_from_slice(&encrypted);
    Ok(BASE64.encode(combined))
}

fn tdes_unwrap(encoded: &str) -> Result<Vec<u8>, KamiError> {
    let raw = BASE64.decode(encoded).map_err(|_| KamiError::Crypto)?;
    if raw.len() <= 8 {
        return Err(KamiError::Crypto);
    }
    let plain = cbc::Decryptor::<TdesEde3>::new(T3_TDES_KEY.into(), (&raw[..8]).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&raw[8..])
        .map_err(|_| KamiError::Crypto)?;
    plain
        .strip_prefix(T3_WIRE_MAGIC.as_bytes())
        .map(ToOwned::to_owned)
        .ok_or(KamiError::Crypto)
}

fn strip_t3_padding(raw: &str) -> &str {
    if let Some(value) = raw.strip_prefix(T3_WIRE_PLAIN) {
        return value;
    }
    if raw.starts_with('{') {
        let bytes = raw.as_bytes();
        let mut depth = 0_u32;
        let mut string = false;
        let mut escape = false;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if string {
                if escape {
                    escape = false;
                } else if byte == b'\\' {
                    escape = true;
                } else if byte == b'"' {
                    string = false;
                }
                continue;
            }
            match byte {
                b'"' => string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return &raw[index + 1..];
                    }
                }
                _ => {}
            }
        }
    }
    raw
}

fn verify_clock_skew(local: i64, network: i64) -> Result<(), KamiError> {
    if local.abs_diff(network) > 120 {
        Err(KamiError::Clock)
    } else {
        Ok(())
    }
}

/// 上游"会话抖动"类错误：重跑一次大概率就好，不该直接判客户卡有问题。
fn upstream_rejection(value: &Value) -> KamiError {
    KamiError::RejectedWithReason {
        code: value.get("code").and_then(value_i64),
        message: value
            .get("msg")
            .or_else(|| value.get("message"))
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .chars()
            .take(256)
            .collect(),
    }
}

pub(crate) fn is_transient_upstream_error(error: &KamiError) -> bool {
    match error {
        KamiError::RejectedWithReason { code, message } => {
            let text = message.as_str();
            if text.contains("登录状态") || text.contains("状态不存在") || text.contains("会话")
            {
                return true;
            }
            // Card expiry/disable is terminal even if the vendor appends "retry".
            if text.contains("卡密")
                && ["过期", "到期", "不存在", "禁用"]
                    .iter()
                    .any(|s| text.contains(s))
            {
                return false;
            }
            *code == Some(429)
                || code.is_some_and(|v| v >= 500)
                || text.contains("请重试")
                || text.contains("繁忙")
                || text.contains("稍后")
        }
        _ => false,
    }
}

fn normalize_card(input: &str) -> Result<String, KamiError> {
    let trimmed = input.trim();
    // 只保留 0-9 / A-Z：把零宽空格、换行、空格、各种不可见字符全部去掉并统一大写。
    // 之前只过滤 U+200B，用户从微信/文档复制时夹带的换行或其它不可见字符会让长度对不上，
    // 于是明明合法的卡密也被判成"格式不正确"。
    let visible = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>();
    // 只做最基本的"这是不是一串卡密"体检。**不再自己判"格式不正确"**：
    // 以前这里要求"恰好 24 位 + 自研校验位匹配"，凡是厂商后来发的别的批次
    // （长度不同、或校验位规则不同的卡）会被网关直接拒掉，客户看到
    // 「卡密格式不正确」，而这张卡其实在厂商那边是好的 —— 卡密能不能用，
    // 一律交给上游判定（下面就有一次真实的上游验证），网关不越权替它下结论。
    if visible.chars().count() < 8 || visible.chars().count() > 40 {
        return Err(KamiError::Card);
    }
    // 24 位是已知的官方形态：按官方形态补上 4 个零宽占位符后送上上游。
    if visible.chars().count() != 24 {
        return Ok(visible);
    }
    let positions = card_mark_positions(&visible);
    let mut normalized = String::new();
    let mut visible_iter = visible.chars();
    for position in 0..28 {
        if positions.contains(&position) {
            normalized.push('\u{200b}');
        } else {
            normalized.push(visible_iter.next().ok_or(KamiError::Card)?);
        }
    }
    if trimmed.chars().count() == 28 && trimmed != normalized {
        // 卡密里那 4 个不可见字符（U+200B）的位置与我们重算的结果不一致。
        //
        // 以前这里直接判「卡密格式不正确」并拒掉。但客户从网页/QQ/微信复制时，
        // 零宽字符被丢、被替换、或者被换成别的不可见字符，都是常态 ——
        // 结果是一张真卡被网关自己挡在门外，客户还以为卡废了。
        // 现在只记日志，仍按我们重算出的官方形态送上游：卡密到底能不能用，
        // 一律由厂商判定，网关不越权替它下结论。
        tracing::warn!(
            pasted_len = trimmed.chars().count(),
            visible_len = visible.chars().count(),
            "卡密不可见字符位置与重算结果不一致，按重算出的官方形态送上游"
        );
    }
    Ok(normalized)
}

/// 826 原版卡密归一（逐行等价）：
/// 只去掉 U+200B，要求恰好 24 位 0-9A-Z、校验位匹配，然后按算法插回 4 个 U+200B。
///
/// `paste-clean`（默认开启）只放宽**输入清洗**，不放宽**卡密判据**：
/// 仍然要求 24 位可见字符 + 校验位匹配（与 826 完全相同），但把"复制粘贴夹带的
/// 任何非 0-9A-Z 字符"（U+200B/U+FEFF/U+00A0/换行/小写字母…）先清掉再判，
/// 避免真卡被粘贴噪声挡在门外。关闭该 feature = 826 原始行为（只过滤 U+200B）。
fn normalize_card_826(input: &str) -> Result<String, KamiError> {
    let trimmed = input.trim();
    #[cfg(feature = "paste-clean")]
    let visible = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect::<String>();
    #[cfg(not(feature = "paste-clean"))]
    let visible = trimmed
        .chars()
        .filter(|ch| *ch != '\u{200b}')
        .collect::<String>();
    if visible.chars().count() != 24
        || !visible
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        return Err(KamiError::Card);
    }
    let chars = visible.chars().collect::<Vec<_>>();
    let body = chars[..18].iter().collect::<String>();
    let checksum = chars[18..].iter().collect::<String>();
    if card_checksum(&body) != checksum {
        return Err(KamiError::Card);
    }
    let positions = card_mark_positions(&visible);
    let mut normalized = String::new();
    let mut visible_iter = visible.chars();
    for position in 0..28 {
        if positions.contains(&position) {
            normalized.push('\u{200b}');
        } else {
            normalized.push(visible_iter.next().ok_or(KamiError::Card)?);
        }
    }
    if trimmed.chars().count() == 28 && trimmed != normalized {
        // 位置与算法不符：826 原版直接拒；开了 paste-clean 只记日志，
        // 仍按重算出的官方形态送上游（卡密能不能用由厂商判定）。
        #[cfg(not(feature = "paste-clean"))]
        return Err(KamiError::Card);
        #[cfg(feature = "paste-clean")]
        tracing::warn!(
            pasted_len = trimmed.chars().count(),
            "卡密不可见字符位置与重算结果不一致，按重算出的官方形态送上游"
        );
    }
    Ok(normalized)
}

fn card_alphabet() -> Vec<char> {
    let mut alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        .chars()
        .collect::<Vec<_>>();
    let seed = Sha256::digest(T3_CARD_SECRET.as_bytes());
    for index in (1..alphabet.len()).rev() {
        let target = usize::from(seed[index % seed.len()]) % (index + 1);
        alphabet.swap(index, target);
    }
    alphabet
}

/// 官方 24 位卡密的校验位算法（保留作参考/诊断，不再用于拒绝卡密）。
#[allow(dead_code)]
fn card_checksum(body: &str) -> String {
    let alphabet = card_alphabet();
    let digest = sha256_hex(format!("{T3_CARD_SECRET}{body}").as_bytes());
    (0..6)
        .map(|index| {
            let value = u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16).unwrap_or(0);
            alphabet[usize::from(value) % 36]
        })
        .collect()
}

fn card_mark_positions(visible: &str) -> Vec<usize> {
    let digest = Sha256::digest(format!("{T3_CARD_SECRET}{visible}").as_bytes());
    let mut positions = Vec::new();
    for byte in digest.iter().take(8) {
        let position = usize::from(*byte) % 28;
        if !positions.contains(&position) {
            positions.push(position);
        }
        if positions.len() == 4 {
            break;
        }
    }
    while positions.len() < 4 {
        let mut position = (positions.len() * 7 + 11) % 28;
        if positions.contains(&position) {
            position = (position + 5) % 28;
        }
        if !positions.contains(&position) {
            positions.push(position);
        }
    }
    positions.sort_unstable();
    positions
}

fn loonie_material() -> Vec<u8> {
    LOONIE_AES_ENC
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ (0x5a_u8.wrapping_add((index as u8).wrapping_mul(7))))
        .collect()
}

const STANDARD_B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const CUSTOM_B64: &[u8] = b"xyz0123456789abcdefghijklmnopqrstuvwABCDEFGHIJKLMNOPQRSTUVWXYZ$#";

fn loonie_custom_b64_encode(input: &[u8]) -> String {
    let mut mapped = BASE64
        .encode(input)
        .bytes()
        .map(|byte| {
            if byte == b'=' {
                b'!'
            } else {
                STANDARD_B64
                    .iter()
                    .position(|value| *value == byte)
                    .map(|index| CUSTOM_B64[index])
                    .unwrap_or(byte)
            }
        })
        .collect::<Vec<_>>();
    for group in mapped.chunks_mut(3) {
        if group.len() == 3 {
            group.swap(0, 2);
        }
    }
    String::from_utf8(mapped).unwrap_or_default()
}

fn loonie_custom_b64_decode(input: &[u8]) -> Result<Vec<u8>, KamiError> {
    let mut rearranged = input.to_vec();
    for group in rearranged.chunks_mut(3) {
        if group.len() == 3 {
            group.swap(0, 2);
        }
    }
    let standard = rearranged
        .into_iter()
        .map(|byte| {
            if byte == b'!' {
                b'='
            } else {
                CUSTOM_B64
                    .iter()
                    .position(|value| *value == byte)
                    .map(|index| STANDARD_B64[index])
                    .unwrap_or(byte)
            }
        })
        .collect::<Vec<_>>();
    BASE64.decode(standard).map_err(|_| KamiError::Crypto)
}

const EMOJI: &[(u8, &str)] = &[
    (b'0', "🐶"),
    (b'1', "🐱"),
    (b'2', "🐭"),
    (b'3', "🐹"),
    (b'4', "🐰"),
    (b'5', "🦊"),
    (b'6', "🐻"),
    (b'7', "🐼"),
    (b'8', "🐨"),
    (b'9', "🐯"),
    (b'A', "🍎"),
    (b'B', "🍌"),
    (b'C', "🍒"),
    (b'D', "🍇"),
    (b'E', "🍉"),
    (b'F', "🍓"),
    (b'G', "🍑"),
    (b'H', "🍍"),
    (b'I', "🥭"),
    (b'J', "🍊"),
    (b'K', "🍋"),
    (b'L', "🍐"),
    (b'M', "🥝"),
    (b'N', "🍅"),
    (b'O', "🍆"),
    (b'P', "🥑"),
    (b'Q', "🌽"),
    (b'R', "🥕"),
    (b'S', "🥒"),
    (b'T', "🥬"),
    (b'U', "🥦"),
    (b'V', "🍄"),
    (b'W', "🥜"),
    (b'X', "🌰"),
    (b'Y', "🍞"),
    (b'Z', "🥐"),
    (b'a', "🚗"),
    (b'b', "🚕"),
    (b'c', "🚙"),
    (b'd', "🚌"),
    (b'e', "🚎"),
    (b'f', "🏎"),
    (b'g', "🚓"),
    (b'h', "🚑"),
    (b'i', "🚒"),
    (b'j', "🚐"),
    (b'k', "🛻"),
    (b'l', "🚚"),
    (b'm', "🚛"),
    (b'n', "🚜"),
    (b'o', "🏍"),
    (b'p', "🛵"),
    (b'q', "🚲"),
    (b'r', "🛴"),
    (b's', "🚁"),
    (b't', "✈️"),
    (b'u', "🚀"),
    (b'v', "🛸"),
    (b'w', "🚉"),
    (b'x', "🚊"),
    (b'y', "🚆"),
    (b'z', "🚄"),
    (b'+', "⭐"),
    (b'/', "🌟"),
    (b'=', "💫"),
    (b'$', "🔥"),
    (b'#', "❄️"),
    (b'!', "🌈"),
];

fn loonie_encrypt(json: &[u8]) -> Result<String, KamiError> {
    let custom = loonie_custom_b64_encode(json);
    let material = loonie_material();
    let encrypted = ecb::Encryptor::<Aes128>::new((&material[..16]).into())
        .encrypt_padded_vec_mut::<Pkcs7>(custom.as_bytes());
    let base = BASE64.encode(encrypted);
    let mut output = String::new();
    for byte in base.bytes() {
        if let Some((_, emoji)) = EMOJI.iter().find(|(key, _)| *key == byte) {
            output.push_str(emoji);
        } else {
            output.push(char::from(byte));
        }
    }
    Ok(output)
}

fn loonie_decrypt(wire: &str) -> Result<Vec<u8>, KamiError> {
    let mut decoded = Vec::new();
    let mut offset = 0;
    while offset < wire.len() {
        let tail = &wire[offset..];
        let (key, emoji) = EMOJI
            .iter()
            .filter(|(_, emoji)| tail.starts_with(*emoji))
            .max_by_key(|(_, emoji)| emoji.len())
            .ok_or(KamiError::Crypto)?;
        decoded.push(*key);
        offset += emoji.len();
    }
    let encrypted = BASE64.decode(decoded).map_err(|_| KamiError::Crypto)?;
    let material = loonie_material();
    let custom = ecb::Decryptor::<Aes128>::new((&material[..16]).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted)
        .map_err(|_| KamiError::Crypto)?;
    loonie_custom_b64_decode(&custom)
}

fn validate_loonie_success(value: &Value) -> Result<(), KamiError> {
    if value.get("success").and_then(Value::as_bool) != Some(true) {
        return Err(upstream_rejection(value));
    }
    let got = value
        .get("_proof")
        .and_then(Value::as_str)
        .ok_or(KamiError::Protocol)?;
    let object = value.as_object().ok_or(KamiError::Protocol)?;
    let mut names = object
        .keys()
        .filter(|name| *name != "_proof")
        .collect::<Vec<_>>();
    names.sort();
    let canonical = names
        .into_iter()
        .map(|name| format!("{name}={}", loonie_json_fragment(&object[name])))
        .collect::<Vec<_>>()
        .join("&");
    let material = loonie_material();
    let proof_key = Sha256::digest([LOONIE_PROOF_SECRET.as_bytes(), material.as_slice()].concat());
    let mut hmac =
        <Hmac<Sha256> as Mac>::new_from_slice(&proof_key).map_err(|_| KamiError::Crypto)?;
    hmac.update(canonical.as_bytes());
    let expected = hex::encode(hmac.finalize().into_bytes());
    if expected != got {
        return Err(KamiError::Protocol);
    }
    Ok(())
}

fn loonie_json_fragment(value: &Value) -> String {
    match value {
        Value::String(text) => {
            let mut output = String::from("\"");
            for unit in text.encode_utf16() {
                match unit {
                    0x08 => output.push_str("\\b"),
                    0x09 => output.push_str("\\t"),
                    0x0a => output.push_str("\\n"),
                    0x0c => output.push_str("\\f"),
                    0x0d => output.push_str("\\r"),
                    0x22 => output.push_str("\\\""),
                    0x5c => output.push_str("\\\\"),
                    0x20..=0x7f => output.push(char::from_u32(u32::from(unit)).unwrap_or_default()),
                    _ => output.push_str(&format!("\\u{unit:04x}")),
                }
            }
            output.push('"');
            output
        }
        _ => value.to_string(),
    }
}

fn validate_loonie_url(raw: &str) -> Result<(), KamiError> {
    let url = reqwest::Url::parse(raw).map_err(|_| KamiError::Protocol)?;
    if url.scheme() != "https" || url.host_str() != Some("loon.t3yangzheng.xyz") {
        return Err(KamiError::Protocol);
    }
    Ok(())
}

fn loonie_device_code(uuid_no_dash_upper: &str) -> String {
    let hash = sha256_hex(uuid_no_dash_upper.as_bytes()).to_ascii_uppercase();
    let reverse = uuid_no_dash_upper.chars().rev().collect::<String>();
    let salted = format!(
        "{}{}{}{}",
        &hash[16..],
        uuid_no_dash_upper,
        reverse,
        &hash[..16]
    );
    let final_hash = sha256_hex(salted.as_bytes()).to_ascii_uppercase();
    let mut code = final_hash
        .chars()
        .filter(|value| value.is_ascii_alphabetic())
        .take(12)
        .collect::<String>();
    const FIXED: &[u8] = b"KLMNPQRSTUV";
    while code.len() < 12 {
        code.push(char::from(FIXED[code.len() % FIXED.len()]));
    }
    code
}

fn loonie_timestamp(unix: i64) -> String {
    let china =
        Utc.timestamp_opt(unix, 0).single().unwrap_or_else(Utc::now) + ChronoDuration::hours(8);
    let mut random = [0_u8; 2];
    OsRng.fill_bytes(&mut random);
    format!(
        "{}|{:04}",
        china.format("%Y-%m-%d %H:%M:%S"),
        u16::from_le_bytes(random) % 9999
    )
}

fn validate_asid(value: &str) -> Result<(), KamiError> {
    if value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(KamiError::Protocol)
    }
}

fn md5_hex(input: &str) -> String {
    hex::encode(Md5::digest(input.as_bytes()))
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn random_hex(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    OsRng.fill_bytes(&mut value);
    hex::encode(value)
}

fn random_token(length: usize, alphabet: &[u8]) -> String {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .into_iter()
        .map(|byte| char::from(alphabet[usize::from(byte) % alphabet.len()]))
        .collect()
}

fn random_alphanumeric(length: usize) -> String {
    random_token(
        length,
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    )
}

fn value_i64(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_str()?.parse().ok())
}

fn value_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string().trim_matches('"').to_string(),
        None => String::new(),
    }
}

fn bool_bit(value: Option<&Value>) -> i32 {
    match value {
        Some(Value::Bool(true)) => 1,
        Some(Value::Number(value)) if value.as_i64().unwrap_or(0) != 0 => 1,
        Some(Value::String(value)) if value != "0" && !value.is_empty() => 1,
        _ => 0,
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[derive(Debug, thiserror::Error)]
pub enum KamiError {
    #[error("823 card format rejected")]
    Card,
    #[error("823 validation network unavailable")]
    Network,
    #[error("823 validation crypto failed")]
    Crypto,
    #[error("823 validation protocol rejected")]
    Protocol,
    #[error("823 validation rejected")]
    Rejected,
    /// 上游明确拒绝，并且带回了厂商原文（如「卡密已过期」「卡密不存在」）。
    /// 与笼统的 `Rejected` 区分开，界面才能告诉客户真实原因。
    #[error("823 validation rejected: {message}")]
    RejectedWithReason { code: Option<i64>, message: String },
    #[error("823 license expired")]
    Expired,
    #[error("823 build date gate expired")]
    BuildExpired,
    #[error("823 validation clock rejected")]
    Clock,
    #[error("823 validation session is not authorized")]
    NotAuthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loonie_wire_round_trip_matches_codec_shape() {
        let source = br#"{"app_id":"666111","stage":1,"success":true}"#;
        let wire = loonie_encrypt(source).expect("encrypt");
        assert!(wire.contains('🐶') || wire.contains('🍎') || wire.contains('🚗'));
        assert_eq!(loonie_decrypt(&wire).expect("decrypt"), source);
    }

    #[test]
    fn device_code_is_stable_and_twelve_letters() {
        let code = loonie_device_code("0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(code.len(), 12);
        assert!(code.bytes().all(|value| value.is_ascii_uppercase()));
        assert_eq!(code, loonie_device_code("0123456789ABCDEF0123456789ABCDEF"));
    }

    #[test]
    fn tdes_wire_round_trip() {
        let source = b"t=ABC&s=DEF";
        let wire = tdes_wrap(source).expect("wrap");
        assert_eq!(tdes_unwrap(&wire).expect("unwrap"), source);
    }

    #[test]
    #[ignore = "performs a read-only live 823 server probe"]
    fn live_connectivity_probe() {
        let verifier = KamiAuthorization::new([0x42; 32]).expect("verifier");
        let report = verifier.connectivity_probe().unwrap_or_else(|error| {
            panic!(
                "823 connectivity stage={} error={error}",
                verifier.last_failure_stage()
            )
        });
        assert!(report.lex && report.t3_notice && report.t3_version);
        assert!(report.loonie_health && report.loonie_stage1 && report.loonie_stage2);
        eprintln!("{}", serde_json::to_string(&report).unwrap());
    }

    #[test]
    #[ignore = "consumes and binds a disposable live 823 card from BATTLE_TEST_CARD"]
    fn live_card_activation_heartbeat_and_relogin() {
        let card = std::env::var("BATTLE_TEST_CARD").expect("BATTLE_TEST_CARD is required");
        let device_seed = [0x53; 32];

        let verifier = KamiAuthorization::new(device_seed).expect("verifier");
        let first = verifier.activate(&card).unwrap_or_else(|error| {
            panic!(
                "823 activation stage={} error={error}",
                verifier.last_failure_stage()
            )
        });
        verifier.heartbeat().unwrap_or_else(|error| {
            panic!(
                "823 heartbeat stage={} error={error}",
                verifier.last_failure_stage()
            )
        });
        assert_eq!(first.summary.validation, "t3+loonie-823");
        assert!(first.expires_unix > now_unix());
        verifier.clear();

        let restarted = KamiAuthorization::new(device_seed).expect("restarted verifier");
        let second = restarted.activate(&card).unwrap_or_else(|error| {
            panic!(
                "823 relogin stage={} error={error}",
                restarted.last_failure_stage()
            )
        });
        restarted.heartbeat().unwrap_or_else(|error| {
            panic!(
                "823 restarted heartbeat stage={} error={error}",
                restarted.last_failure_stage()
            )
        });
        assert_eq!(first.summary.license_id, second.summary.license_id);
        assert_eq!(first.expires_unix, second.expires_unix);
        eprintln!(
            "activation=ok heartbeat=ok relogin=ok restarted_heartbeat=ok expires_at={}",
            second.summary.expires_at
        );
    }
}

#[cfg(test)]
mod card_format_tests {
    use super::*;

    const ZWSP: char = '\u{200b}';

    fn zws_count(value: &str) -> usize {
        value.chars().filter(|c| *c == ZWSP).count()
    }

    /// 官方卡密是 28 位：24 位可见字符 + 4 个零宽占位符（U+200B）。
    ///
    /// 这个测试锁住三个性质：
    ///  ① 长度恰好 28；
    ///  ② 零宽字符恰好 4 个；
    ///  ③ 去掉零宽后与输入完全一致（不能凭空多字或少字）。
    ///
    /// 之所以重要：客户从 QQ / 微信 / 网页复制时这些零宽字符经常被丢掉，
    /// 网关必须能从 24 位可见部分重算并补回，否则一张真卡会被判"不存在"。
    #[test]
    fn twenty_four_char_card_gets_four_zero_width_marks() {
        let visible = "ID26B5M3PHKYSX7ALBLZNNMX";
        let out = normalize_card(visible).expect("normalize");
        assert_eq!(out.chars().count(), 28, "官方形态必须是 28 位");
        assert_eq!(zws_count(&out), 4, "必须有 4 个零宽占位符");
        let stripped: String = out.chars().filter(|c| *c != ZWSP).collect();
        assert_eq!(stripped, visible, "去掉零宽后必须与输入一致");
    }

    /// 幂等：把规范形态再喂回去必须得到同一结果。
    /// 不幂等的话，客户端重试会因为"零宽位置对不上"而拿到不同卡号。
    #[test]
    fn normalize_is_idempotent() {
        let canonical = normalize_card("ID26B5M3PHKYSX7ALBLZNNMX").expect("normalize");
        assert_eq!(
            normalize_card(&canonical).expect("normalize again"),
            canonical
        );
    }

    /// 零宽字符被 QQ / 微信丢掉后（只剩 24 位可见）仍要还原成同一个规范形态。
    #[test]
    fn stripped_card_rebuilds_to_same_canonical_form() {
        let canonical = normalize_card("ID26B5M3PHKYSX7ALBLZNNMX").expect("normalize");
        let stripped: String = canonical.chars().filter(|c| *c != ZWSP).collect();
        assert_eq!(stripped.chars().count(), 24);
        assert_eq!(normalize_card(&stripped).expect("normalize"), canonical);
    }

    /// 非 24 位的卡密原样送出：能不能用由厂商判定，网关不越权替它下结论。
    ///
    /// 仅在关闭 parity-826 时成立 —— 打开后走 826 原版严格归一（见下方
    /// `parity_826_*` 测试），23 位会被上游形态检查直接拒掉，这正是 826 的行为。
    #[test]
    fn non_twenty_four_char_cards_pass_through_unchanged() {
        let visible = "26B5M3PHKYSX7ALBLZNNMX";
        assert_eq!(normalize_card(visible).expect("normalize"), visible);
    }

    /// parity-826：卡密必须是 24 位 0-9A-Z，长度不符即拒（826 原版行为）。
    #[test]
    #[cfg(feature = "parity-826")]
    fn parity_826_requires_exactly_24_visible_chars() {
        assert!(normalize_card_826("26B5M3PHKYSX7ALBLZNNMX").is_err());
        assert!(normalize_card_826("ID26B5M3PHKYSX7ALBLZNNMXX").is_err());
        assert!(normalize_card_826("abcdefghijklmnopqrstuvwx").is_err());
    }

    /// parity-826：校验位必须匹配 `T3_CARD_SECRET` 派生值，不符即拒。
    #[test]
    #[cfg(feature = "parity-826")]
    fn parity_826_rejects_bad_checksum() {
        let canonical = normalize_card_826("ID26B5M3PHKYSX7ALBLZNNMX").expect("normalize");
        let mut chars: Vec<char> = canonical.chars().collect();
        let last = chars
            .iter()
            .rposition(|c| *c != ZWSP)
            .expect("visible char");
        chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
        let broken: String = chars.into_iter().collect();
        assert!(normalize_card_826(&broken).is_err());
    }

    /// parity-826：24 位官方形态照样补 4 个零宽占位符，且幂等。
    #[test]
    #[cfg(feature = "parity-826")]
    fn parity_826_canonical_form_is_unchanged() {
        let out = normalize_card_826("ID26B5M3PHKYSX7ALBLZNNMX").expect("normalize");
        assert_eq!(out.chars().count(), 28);
        assert_eq!(zws_count(&out), 4);
        assert_eq!(normalize_card_826(&out).expect("normalize again"), out);
    }

    /// paste-clean：复制粘贴夹带杂质（BOM / 不换行空格 / 小写）仍还原成官方形态。
    #[test]
    #[cfg(feature = "paste-clean")]
    fn paste_clean_tolerates_copy_paste_noise() {
        let canonical = normalize_card("ID26B5M3PHKYSX7ALBLZNNMX").expect("clean");
        for dirty in [
            "id26b5m3phkysx7alblznnmx",
            "\u{FEFF}ID26B5M3PHKYSX7ALBLZNNMX",
            "ID26\u{FEFF}B5M3PHKYSX7ALBLZNNMX\u{00A0}",
            "  ID26B5M3PHKYSX7ALBLZNNMX\n",
        ] {
            assert_eq!(
                normalize_card(dirty).expect("normalize dirty"),
                canonical,
                "粘贴杂质应被清洗：{dirty:?}"
            );
        }
    }

    /// paste-clean：零宽字符位置被换掉也不再误杀（仍按算法重算后送上游）。
    #[test]
    #[cfg(feature = "paste-clean")]
    fn paste_clean_ignores_mark_position_drift() {
        let pasted: String = format!("{ZWSP}{ZWSP}{ZWSP}{ZWSP}ID26B5M3PHKYSX7ALBLZNNMX");
        assert!(normalize_card(&pasted).is_ok());
    }

    /// 关闭 paste-clean 时保持 826 原样：夹带非 U+200B 的不可见字符、或小写，一律拒。
    #[test]
    #[cfg(not(feature = "paste-clean"))]
    fn strict_mode_rejects_copy_paste_noise_like_826() {
        assert!(normalize_card_826("ID26\u{FEFF}B5M3PHKYSX7ALBLZNNMX").is_err());
        assert!(normalize_card_826("id26b5m3phkysx7alblznnmx").is_err());
        let pasted = format!("{ZWSP}{ZWSP}{ZWSP}{ZWSP}ID26B5M3PHKYSX7ALBLZNNMX");
        assert!(normalize_card_826(&pasted).is_err());
    }
}

#[cfg(test)]
mod reliability_tests {
    use super::*;
    #[test]
    fn clock_validation_has_no_calendar_expiration() {
        for ymd in ["2026-10-19", "2026-10-20", "2026-10-21", "2027-01-01"] {
            let date = chrono::NaiveDate::parse_from_str(ymd, "%Y-%m-%d")
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap()
                .and_utc()
                .timestamp();
            assert!(verify_clock_skew(date, date + 1).is_ok());
        }
        assert!(matches!(
            verify_clock_skew(1000, 1121),
            Err(KamiError::Clock)
        ));
        assert!(verify_clock_skew(1000, 1120).is_ok());
    }
    #[test]
    fn session_loss_is_not_an_expired_card() {
        assert!(is_transient_upstream_error(
            &KamiError::RejectedWithReason {
                code: Some(201),
                message: "登录状态不存在".into()
            }
        ));
        assert!(!is_transient_upstream_error(&KamiError::Expired));
        assert!(!is_transient_upstream_error(
            &KamiError::RejectedWithReason {
                code: Some(201),
                message: "卡密已过期".into()
            }
        ));
    }
}

#[cfg(test)]
mod upstream_card_authority_tests {
    use super::*;
    #[test]
    fn local_checksum_cannot_reject_an_upstream_card() {
        assert!(normalize_card("A".repeat(24).as_str()).is_ok());
        assert!(normalize_card("TESTCARD12345678").is_ok());
        assert!(normalize_card("AB1").is_err());
    }
}

#[cfg(test)]
mod upstream_failure_tests {
    use super::*;
    #[test]
    fn lex_and_loonie_preserve_transient_reasons() {
        assert!(is_transient_upstream_error(&upstream_rejection(
            &serde_json::json!({"code":503,"msg":"服务繁忙"})
        )));
        assert!(is_transient_upstream_error(&upstream_rejection(
            &serde_json::json!({"success":false,"message":"登录状态不存在"})
        )));
        assert!(!is_transient_upstream_error(&upstream_rejection(
            &serde_json::json!({"code":201,"msg":"卡密已过期，请重试"})
        )));
    }
}

// ─────────────────────────────────────────────────────────────────────────
// 客户端直连入口（2026-10-20）
//
// 只做一件事：拿卡密 + 设备种子，直接向 T3 验证，返回到期时间。
// 不经过任何中间网关 —— 43/114 这类宿主机与客户端无关了。
// ─────────────────────────────────────────────────────────────────────────

/// 验证通过后的最小信息（客户端只用得到这几项）。
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyGrant {
    /// 到期时间（Unix 秒）
    pub expires_unix: i64,
    /// 到期时间的原始文本（T3 返回，展示用）
    pub expires_at: String,
    /// 服务端公告（可为空）
    pub notice: String,
    /// 卡密许可 id（脱敏展示用，不含卡密本身）
    pub license_id: String,
}

impl KamiAuthorization {
    /// 客户端入口：验证卡密并登记活跃会话。
    ///
    /// ⚠️ 2026-10-21：走 **t3-only**（和网关一直在用的那条路径一样）。
    /// 完整 `activate()` 还会跑 Loonie 客户端证明链（`loon.t3yangzheng.xyz` 三次往返），
    /// 那段在客户网络上经常 504，而卡密有效性在 T3 登录那一步就已经确定了。
    /// 需要跑完整链时设环境变量 `CODEV_VERIFY_FULL=1`。
    pub fn verify_card(&self, card: &str) -> Result<VerifyGrant, KamiError> {
        // 发布构建**固定跑完整链**（T3 五段 + loonie），和线上网关的
        // `activate_parity()`（PARITY_826=on）一致。
        //
        // 调试构建才认环境变量（`CODEV_VERIFY_T3_ONLY=1` 可只跑 T3，便于排障）：
        // 留一个运行期开关在发布包里，等于给破解者一个"跳过 loonie"的把手。
        let full = !debug_t3_only_flag();
        let outcome = if full { self.activate(card) } else { self.activate_t3_only(card) };
        let authorized = match outcome {
            Ok(value) => value,
            Err(KamiError::Network) => {
                let detail = take_last_network_error().unwrap_or_else(|| "连接失败".to_string());
                return Err(KamiError::RejectedWithReason {
                    code: Some(503),
                    message: format!("连不上卡密服务器：{detail}"),
                });
            }
            Err(other) => return Err(other),
        };
        Ok(VerifyGrant {
            expires_unix: authorized.expires_unix,
            expires_at: authorized.summary.expires_at.clone(),
            notice: authorized.summary.notice.clone(),
            license_id: authorized.summary.license_id.clone(),
        })
    }
}

/// 一步到位：用设备种子构造会话并验证卡密。
///
/// `device_seed` 由调用方提供（设备唯一、稳定，32 字节）；同一个种子换算出的
/// 设备号恒定，换机/重装不会因为随机种子导致"设备绑定不一致"。
pub fn verify_card(card: &str, device_seed: &[u8; 32]) -> Result<VerifyGrant, KamiError> {
    KamiAuthorization::new(*device_seed)?.verify_card(card)
}
