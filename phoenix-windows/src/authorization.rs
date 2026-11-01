//! Portable authorization contract and transport, shared by the Windows GUI
//! and native regression tests. No DPAPI or driver calls in this module.

use crate::lifecycle::Cancellation;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::time::Duration;
/// 验证服务器地址：**没有内置默认值**（不再指向任何固定 IP/域名）。
///
/// 解析顺序：
///   1. 环境变量 `PHOENIX_VERIFY_ORIGIN`（排障用）
///   2. `%LOCALAPPDATA%\不死鸟CodeV\verify-origin.txt`（一行地址，客户自己填）
///   3. 打包时 `PHOENIX_GATEWAY_ORIGIN`（可选，留空则必须靠 1/2）
///
/// 三个来源都没有 → 激活直接报错让用户去填，绝不回退到 43/114。
/// 内置默认验证服务器：**留空**。
/// 这样包不绑定任何固定主机，地址由用户/打包参数决定。
pub(crate) const DEFAULT_VERIFY_ORIGIN: &str = "";

pub(crate) fn gateway_origin() -> Option<String> {
    let clean = |s: String| {
        let s = s.trim().to_string();
        if s.is_empty() || !(s.starts_with("https://") || s.starts_with("http://")) {
            None
        } else {
            Some(s.trim_end_matches('/').to_string())
        }
    };
    if let Ok(value) = std::env::var("PHOENIX_VERIFY_ORIGIN") {
        if let Some(origin) = clean(value) {
            return Some(origin);
        }
    }
    for candidate in verify_origin_files() {
        if let Ok(value) = std::fs::read_to_string(&candidate) {
            if let Some(origin) = clean(value) {
                return Some(origin);
            }
        }
    }
    if let Some(origin) = option_env!("PHOENIX_GATEWAY_ORIGIN").and_then(|v| clean(v.to_string())) {
        return Some(origin);
    }
    // 源码内置默认（验证链路入口）。换地址用上面的环境变量/文件，不必重编。
    clean(DEFAULT_VERIFY_ORIGIN.to_string())
}

/// 可能存放验证服务器地址的文件（按顺序）。
fn verify_origin_files() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(dir) = crate::log::directory() {
        paths.push(dir.join("verify-origin.txt"));
    }
    if let Some(dir) = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from) {
        paths.push(dir.join("不死鸟CodeV").join("verify-origin.txt"));
        paths.push(dir.join("Phoenix").join("verify-origin.txt"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            paths.push(dir.join("verify-origin.txt"));
        }
    }
    paths
}

pub(crate) const MISSING_ORIGIN_HINT: &str = "还没有设置验证服务器地址。\n请在 %LOCALAPPDATA%\\不死鸟CodeV\\verify-origin.txt 里写一行你的卡密验证服务地址（例如 https://你的域名:8443），保存后点「重新验证」。";
/// 测试包专用：连自签证书（裸 IP）时必须打开，否则 TLS 直接失败。
/// 编译期 `PHOENIX_INSECURE_TLS=1` 才生效；正式包绝不注入。
pub(crate) const INSECURE_TLS: bool = tls_flag(option_env!("PHOENIX_INSECURE_TLS"));
const fn tls_flag(value: Option<&str>) -> bool {
    match value {
        Some(v) => v.as_bytes().len() == 1 && v.as_bytes()[0] == b'1',
        None => false,
    }
}

#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct G0Grant {
    pub(crate) room_id: String,
    pub(crate) room_url: String,
    pub(crate) radar_url: String,
    pub(crate) node_host: String,
    pub(crate) node_port: u16,
    pub(crate) node_username: String,
    pub(crate) node_password: String,
    pub(crate) expires_at: String,
    pub(crate) source_mode: String,
    /// 卡密真实到期时间；不是 /api/renew 的短期会话有效期。
    #[serde(default)]
    pub(crate) expires_unix: i64,
    #[serde(default)]
    pub(crate) notice: String,
}

impl std::fmt::Debug for G0Grant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("G0Grant")
            .field("room_id", &self.room_id)
            .field("expires_unix", &self.expires_unix)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Deserialize)]
struct E0Payload {
    error: Option<String>,
}

#[derive(Serialize)]
struct A1Request<'a> {
    card: &'a str,
    device_id: &'a str,
}

// ---------------------------------------------------------------- 版本签名门禁
//
// 保留请求签名头供兼容签名门禁的网关使用；当前 43 网关是否启用门禁
// 由服务端配置决定。这里不是 Windows Authenticode，也不保证防破解。

/// 云端模式已下线：新版**只做本机解析**，除卡密验证外不依赖任何服务器。
///
/// 这个函数保留下来是为了让调用点（ui.rs / app.rs）不必同时改形参；
/// 它现在恒为 false。`server-mode` feature 仍可编译，但不再改变运行行为。
pub(crate) fn server_mode() -> bool {
    false
}

/// 客户端版本标识（编译期注入）。
pub(crate) const CLIENT_BUILD: &str = match option_env!("PHOENIX_BUILD_ID") {
    Some(value) => value,
    None => "dev",
};
/// 本版本的请求签名密钥（编译期注入，生产构建必须提供）。
const CLIENT_BUILD_KEY: &str = match option_env!("PHOENIX_BUILD_KEY") {
    Some(value) => value,
    None => "codev-dev-local-only",
};

const HMAC_BLOCK_BYTES: usize = 64;

/// HMAC-SHA256（RFC 2104），与网关侧的 `hmac` crate 实现逐位一致。
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut block = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn signature_payload(action: &str, device_id: &str, extra: &str) -> String {
    format!("{action}\n{device_id}\n{extra}")
}

/// 每次请求一个随机 nonce，网关按窗口去重，防重放。
fn request_nonce() -> String {
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hex::encode(&hasher.finalize()[..16])
}

pub(crate) fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// 生成四个签名头，网关据此校验版本与完整性。
fn sign_headers(action: &str, device_id: &str, extra: &str) -> [(String, String); 4] {
    let nonce = request_nonce();
    let timestamp = now_unix();
    let payload = signature_payload(action, device_id, extra);
    let signed = format!("{CLIENT_BUILD}\n{nonce}\n{timestamp}\n{payload}");
    let signature = hex::encode(hmac_sha256(CLIENT_BUILD_KEY.as_bytes(), signed.as_bytes()));
    [
        ("x-client-build".to_string(), CLIENT_BUILD.to_string()),
        ("x-client-nonce".to_string(), nonce),
        ("x-client-ts".to_string(), timestamp.to_string()),
        ("x-client-sign".to_string(), signature),
    ]
}

/// 单次激活请求的超时。
///
/// T3 链路（lex → metadata → nettime → login）在上游拥塞时可能远超 25 秒。
/// 客户端提前超时、服务器随后其实成功，就是客户看到的"验证失败，请重试一次"
/// 之后又弹"验证仍在进行中"。给足 200 秒，让服务器先说话。
pub(crate) const ACTIVATION_TIMEOUT_SECS: u64 = 200;
/// 自动重试的退避（秒）；共重试 2 次。
pub(crate) const ACTIVATION_RETRY_BACKOFF: [u64; 3] = [3, 8, 15];

#[derive(Debug)]
pub(crate) struct AttemptError {
    pub(crate) status: Option<u16>,
    pub(crate) detail: String,
}
impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}
impl AttemptError {
    pub(crate) fn retryable(&self) -> bool {
        self.status
            .is_none_or(|code| code == 408 || code == 429 || code >= 500)
    }
}
fn protocol_error(detail: impl Into<String>) -> AttemptError {
    AttemptError {
        status: Some(502),
        detail: detail.into(),
    }
}
fn client(timeout: Duration) -> Result<reqwest::blocking::Client, AttemptError> {
    reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(8))
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(INSECURE_TLS)
        .build()
        .map_err(|e| AttemptError {
            status: None,
            detail: format!("授权客户端创建失败：{e}"),
        })
}
fn body(mut response: reqwest::blocking::Response) -> Result<Vec<u8>, AttemptError> {
    let mut bytes = Vec::new();
    response
        .by_ref()
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| protocol_error("授权响应读取中断，请重试"))?;
    if bytes.len() > 65536 {
        return Err(protocol_error("授权响应过大"));
    }
    Ok(bytes)
}
pub(crate) fn normalize_card(card: &str) -> String {
    card.chars()
        .filter(|c| {
            !c.is_whitespace() && !matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}')
        })
        .collect()
}
/// 取验证服务器地址；没配置就返回一条**不可重试**的错误（界面直接显示去填）。
fn origin_for_activation() -> Result<String, AttemptError> {
    gateway_origin().ok_or(AttemptError {
        status: Some(400),
        detail: MISSING_ORIGIN_HINT.to_string(),
    })
}

/// 神明之眼 1.0 的本机授权（无到期、不依赖服务器）。
pub(crate) fn local_grant() -> G0Grant {
    G0Grant {
        room_id: "SHENMING-LOCAL".into(),
        room_url: String::new(),
        radar_url: String::new(),
        node_host: "127.0.0.1".into(),
        node_port: 2025,
        node_username: "phoenix-local".into(),
        node_password: String::new(),
        expires_at: "永久".into(),
        source_mode: "local".into(),
        expires_unix: now_unix() + 100 * 365 * 24 * 3600,
        notice: String::new(),
    }
}
/// 激活：**客户端直连 T3 卡密平台**（2026-10-20 起不再经过任何网关）。
///
/// 设备种子由 `device_id` 派生（sha256 → 32 字节），同机同号恒定；
/// 这样换装/重装不会因为随机种子被判"设备绑定不一致"。
pub(crate) fn activate_with_progress(
    card: &str,
    device_id: &str,
    cancel: &Cancellation,
    on_retry: &mut dyn FnMut(usize),
) -> Result<G0Grant, AttemptError> {
    // ===== 神明之眼 1.0：卡密链路已移除 =====
    // 不再访问任何验证服务器：直接返回一份本机授权，后续启动流程
    // （保存状态 → 起本机引擎 → 出侧栏）与原来完全一致。
    let _ = (card, device_id, cancel, on_retry);
    return Ok(local_grant());
    if card.trim().is_empty() {
        return Err(AttemptError { status: Some(400), detail: "卡密不能为空".into() });
    }
    // 两种模式：
    //   ① 配了验证服务地址（环境变量/verify-origin.txt/打包参数）→ 打那个端口（T3 密钥留在服务器）
    //   ② 没配 → 客户端直连 T3（密钥随包，方便但可被抠）
    if let Some(origin) = gateway_origin() {
        crate::log::info(&format!("激活走验证服务：{origin}"));
        return activate_at(
            &origin,
            card,
            device_id,
            cancel,
            on_retry,
            &ACTIVATION_RETRY_BACKOFF.map(Duration::from_secs),
        );
    }
    let seed = device_seed(device_id);
    // T3 上游抖动时重试一次（网络/协议类错误才重试，卡密本身的问题立刻返回）。
    let mut last: Option<AttemptError> = None;
    for (attempt, wait) in std::iter::once(0u64)
        .chain(ACTIVATION_RETRY_BACKOFF.iter().copied())
        .enumerate()
    {
        if cancel.is_cancelled() {
            return Err(AttemptError { status: Some(408), detail: "已取消".into() });
        }
        if attempt > 0 {
            on_retry(attempt);
            std::thread::sleep(Duration::from_secs(wait));
        }
        match codev_verify::verify_card(card, &seed) {
            Ok(grant) => {
                return Ok(G0Grant {
                    // 新版没有房间/节点概念：字段留空，界面与状态文件仍然兼容。
                    room_id: String::new(),
                    room_url: String::new(),
                    radar_url: String::new(),
                    node_host: String::new(),
                    node_port: 0,
                    node_username: String::new(),
                    node_password: String::new(),
                    expires_at: grant.expires_at,
                    source_mode: "local".into(),
                    expires_unix: grant.expires_unix,
                    notice: grant.notice,
                })
            }
            Err(error) => {
                let (status, retryable, detail) = classify_verify_error(error);
                let attempt_error = AttemptError { status: Some(status), detail };
                if !retryable {
                    return Err(attempt_error);
                }
                last = Some(attempt_error);
            }
        }
    }
    Err(last.unwrap_or(AttemptError { status: Some(502), detail: "验证失败".into() }))
}

/// 设备号 → 32 字节种子（稳定、不可逆）。
fn device_seed(device_id: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"codev-verify-device-v1");
    hasher.update(device_id.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// T3 错误 → (HTTP 风格状态码, 是否值得重试, 给客户看的人话)。
fn classify_verify_error(error: codev_verify::KamiError) -> (u16, bool, String) {
    use codev_verify::KamiError as E;
    match error {
        E::Network => (503, true, "卡密验证网络不可用，请检查网络后重试".into()),
        E::Protocol => (502, true, "卡密服务器响应异常，正在重试".into()),
        E::RejectedWithReason { code, message } => {
            // 上游网关超时/限流（408/429/5xx）要重试，不能当成"卡密无效"直接判死。
            match code {
                Some(c) if c == 408 || c == 429 || c >= 500 => (
                    503,
                    true,
                    format!("卡密服务器暂时不可用（{c}），正在重试：{message}"),
                ),
                _ => (403, false, message),
            }
        }
        E::Rejected => (403, false, "卡密验证未通过（卡密无效或已过期）".into()),
        E::Card => (400, false, "卡密格式不正确".into()),
        E::Expired => (403, false, "卡密已到期".into()),
        E::Clock => (400, false, "本机时间不正确，请校准系统时间".into()),
        other => (500, false, format!("卡密验证失败：{other}")),
    }
}
fn activate_at(
    origin: &str,
    card: &str,
    device_id: &str,
    cancel: &Cancellation,
    on_retry: &mut dyn FnMut(usize),
    backoff: &[Duration],
) -> Result<G0Grant, AttemptError> {
    if card.is_empty() {
        return Err(AttemptError {
            status: Some(400),
            detail: "卡密不能为空".into(),
        });
    }
    let client = client(Duration::from_secs(ACTIVATION_TIMEOUT_SECS))?;
    let mut last = protocol_error("没有收到授权响应");
    for attempt in 0..=backoff.len() {
        if cancel.is_cancelled() {
            return Err(AttemptError {
                status: Some(499),
                detail: "验证已取消".into(),
            });
        }
        if attempt > 0 {
            on_retry(attempt);
            if !cancel.wait(backoff[attempt - 1]) {
                return Err(AttemptError {
                    status: Some(499),
                    detail: "验证已取消".into(),
                });
            }
        }
        let result = activate_once(&client, origin, card, device_id);
        if cancel.is_cancelled() {
            return Err(AttemptError {
                status: Some(499),
                detail: "验证已取消".into(),
            });
        }
        match result {
            Ok(grant) => return Ok(grant),
            Err(error) => {
                let retry = error.retryable();
                last = error;
                if !retry {
                    break;
                }
            }
        }
    }
    Err(last)
}
fn activate_once(
    client: &reqwest::blocking::Client,
    origin: &str,
    card: &str,
    device_id: &str,
) -> Result<G0Grant, AttemptError> {
    let mut request = client
        .post(format!("{origin}/api/activate"))
        .json(&A1Request { card, device_id });
    for (name, value) in sign_headers("activate", device_id, card) {
        request = request.header(name, value);
    }
    let response = request.send().map_err(|e| AttemptError {
        status: None,
        detail: format!("授权连接失败：{e}"),
    })?;
    let status = response.status();
    let bytes = body(response)?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<E0Payload>(&bytes)
            .ok()
            .and_then(|p| p.error)
            .unwrap_or_else(|| format!("激活失败（HTTP {}）", status.as_u16()));
        return Err(AttemptError {
            status: Some(status.as_u16()),
            detail,
        });
    }
    let grant: G0Grant =
        serde_json::from_slice(&bytes).map_err(|_| protocol_error("授权响应无效，请重试"))?;
    validate_grant_at(&grant, origin, now_unix()).map_err(|e| protocol_error(e.to_string()))?;
    Ok(grant)
}
fn private_url(url: &str, origin: &reqwest::Url, room_id: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(url)?;
    anyhow::ensure!(
        url.scheme() == origin.scheme()
            && url.host_str() == origin.host_str()
            && url.port_or_known_default() == origin.port_or_known_default(),
        "授权房间服务器不匹配"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "授权房间地址无效"
    );
    anyhow::ensure!(url.path() == format!("/r/{room_id}"), "授权房间号不匹配");
    let access: Vec<_> = url.query_pairs().filter(|(k, _)| k == "access").collect();
    anyhow::ensure!(
        access.len() == 1 && !access[0].1.trim().is_empty(),
        "授权房间令牌缺失"
    );
    Ok(())
}

/// The gateway's current `radar_url` is intentionally a short link without
/// `?access=`. Loading `/r/<room>` establishes the room/session cookies before
/// redirecting to `/radar`; older gateways may still return the tokenized form.
fn radar_url(url: &str, origin: &reqwest::Url, room_id: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(url)?;
    anyhow::ensure!(
        url.scheme() == origin.scheme()
            && url.host_str() == origin.host_str()
            && url.port_or_known_default() == origin.port_or_known_default(),
        "授权雷达服务器不匹配"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
        "授权雷达地址无效"
    );
    anyhow::ensure!(url.path() == format!("/r/{room_id}"), "授权雷达房间号不匹配");
    let access: Vec<_> = url.query_pairs().filter(|(k, _)| k == "access").collect();
    let only_access_query = url.query_pairs().all(|(k, v)| k == "access" && !v.trim().is_empty());
    anyhow::ensure!(
        (access.is_empty() && url.query().is_none()) || (access.len() == 1 && only_access_query),
        "授权雷达地址参数无效"
    );
    Ok(())
}
fn validate_grant_at(grant: &G0Grant, origin: &str, now: i64) -> anyhow::Result<()> {
    let origin = reqwest::Url::parse(origin)?;
    let secure = origin.scheme() == "https";
    #[cfg(test)]
    let secure = secure || (origin.scheme() == "http" && origin.host_str() == Some("127.0.0.1"));
    anyhow::ensure!(
        secure
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "网关地址无效"
    );
    anyhow::ensure!(
        !grant.room_id.is_empty()
            && grant.room_id.len() <= 64
            && grant
                .room_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "授权房间号无效"
    );
    anyhow::ensure!(
        grant.source_mode == "proxy" && grant.node_port > 0,
        "授权节点无效"
    );
    anyhow::ensure!(
        !grant.node_host.is_empty()
            && !grant
                .node_host
                .chars()
                .any(|c| c.is_whitespace() || matches!(c, '\0' | '/' | '@' | '?' | '#')),
        "授权节点地址无效"
    );
    anyhow::ensure!(
        [&grant.node_username, &grant.node_password]
            .iter()
            .all(|v| !v.is_empty() && !v.contains('\0')),
        "授权节点凭据无效"
    );
    anyhow::ensure!(grant.expires_unix > now, "授权已过期，请重新验证");
    private_url(&grant.room_url, &origin, &grant.room_id)?;
    radar_url(&grant.radar_url, &origin, &grant.room_id)?;
    Ok(())
}

#[derive(Debug, Deserialize)]
pub(crate) struct RenewInfo {
    pub(crate) room_id: String,
    #[serde(default)]
    pub(crate) valid_until_unix: i64,
    #[serde(default)]
    pub(crate) node_expires_unix: i64,
}
#[derive(Debug)]
pub(crate) enum RenewFailure {
    Fatal(String),
    RoomGone(String),
    Transient(String),
}
impl std::fmt::Display for RenewFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fatal(d) | Self::RoomGone(d) | Self::Transient(d) => f.write_str(d),
        }
    }
}
pub(crate) fn renew_session(device_id: &str, room_id: &str) -> Result<RenewInfo, RenewFailure> {
    // 没配置验证服务器 = 无法续期。按"暂时性"处理，别把客户踢下线。
    let Some(origin) = gateway_origin() else {
        return Err(RenewFailure::Transient("未设置验证服务器地址".to_string()));
    };
    renew_at(&origin, device_id, room_id)
}
fn renew_at(origin: &str, device_id: &str, room_id: &str) -> Result<RenewInfo, RenewFailure> {
    let client = client(Duration::from_secs(30)).map_err(|e| RenewFailure::Transient(e.detail))?;
    let mut request = client
        .post(format!("{origin}/api/renew"))
        .json(&serde_json::json!({"device_id":device_id,"room_id":room_id}));
    for (name, value) in sign_headers("renew", device_id, room_id) {
        request = request.header(name, value);
    }
    let response = request
        .send()
        .map_err(|e| RenewFailure::Transient(format!("续期连接失败：{e}")))?;
    let status = response.status();
    let bytes = body(response).map_err(|e| RenewFailure::Transient(e.detail))?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<E0Payload>(&bytes)
            .ok()
            .and_then(|p| p.error)
            .unwrap_or_else(|| format!("续期失败（HTTP {}）", status.as_u16()));
        return Err(match status.as_u16() {
            401 | 402 | 403 | 410 => RenewFailure::Fatal(detail),
            404 => RenewFailure::RoomGone(detail),
            _ => RenewFailure::Transient(detail),
        });
    }
    let info: RenewInfo = serde_json::from_slice(&bytes)
        .map_err(|_| RenewFailure::Transient("续期响应无效".into()))?;
    if info.room_id != room_id || info.valid_until_unix <= now_unix() {
        return Err(RenewFailure::Transient("续期房间或有效期不匹配".into()));
    }
    Ok(info)
}
/// Card expiry is not the 15-minute session lease. Renew the session before its
/// actual deadline; node credentials are rotated by reactivation, not /renew.
pub(crate) fn renewal_delay(deadline: i64, now: i64) -> Duration {
    Duration::from_secs(((deadline - now) / 2).clamp(1, 600) as u64)
}
pub(crate) fn session_deadline(card_expiry: i64, info: Option<&RenewInfo>, now: i64) -> i64 {
    let mut deadline = card_expiry.min(info.map_or(now + 900, |i| i.valid_until_unix));
    if let Some(i) = info
        && i.node_expires_unix > 0
    {
        deadline = deadline.min(i.node_expires_unix);
    }
    deadline
}

#[cfg(test)]
mod tests {
    const TEST_ORIGIN: &str = "https://verify.test:8443";
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
    };
    fn grant(origin: &str) -> G0Grant {
        G0Grant {
            room_id: "123456".into(),
            room_url: format!("{origin}/r/123456?access=test-cap"),
            radar_url: format!("{origin}/r/123456?access=test-cap"),
            node_host: "43.226.47.215".into(),
            node_port: 2041,
            node_username: "test-user".into(),
            node_password: "test-password".into(),
            expires_at: "2030-01-01".into(),
            source_mode: "proxy".into(),
            expires_unix: now_unix() + 3600,
            notice: String::new(),
        }
    }
    struct Fixture {
        origin: String,
        seen: Arc<Mutex<Vec<String>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Fixture {
        fn new(make: impl FnOnce(&str) -> Vec<(u16, String)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let origin = format!("http://{}", listener.local_addr().unwrap());
            let replies = make(&origin);
            let seen = Arc::new(Mutex::new(Vec::new()));
            let recorded = seen.clone();
            let thread = std::thread::spawn(move || {
                for (code, body) in replies {
                    let deadline = std::time::Instant::now() + Duration::from_secs(5);
                    let mut stream = loop {
                        match listener.accept() {
                            Ok((s, _)) => break s,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                if std::time::Instant::now() > deadline {
                                    return;
                                }
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            Err(e) => panic!("{e}"),
                        }
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = Vec::new();
                    let mut buf = [0; 2048];
                    loop {
                        let n = stream.read(&mut buf).unwrap();
                        if n == 0 {
                            break;
                        }
                        request.extend_from_slice(&buf[..n]);
                        if let Some(head) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            let header =
                                String::from_utf8_lossy(&request[..head]).to_ascii_lowercase();
                            let len: usize = header
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .unwrap_or("0")
                                .trim()
                                .parse()
                                .unwrap();
                            if request.len() >= head + 4 + len {
                                break;
                            }
                        }
                    }
                    recorded
                        .lock()
                        .unwrap()
                        .push(String::from_utf8(request).unwrap());
                    let location = if code == 307 {
                        format!("Location: {body}\r\n")
                    } else {
                        String::new()
                    };
                    write!(stream,"HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\n{location}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
                }
            });
            Self {
                origin,
                seen,
                thread: Some(thread),
            }
        }
        fn activate(&self, card: &str) -> Result<G0Grant, AttemptError> {
            activate_at(
                &self.origin,
                card,
                "fixture-device",
                &Cancellation::default(),
                &mut |_| {},
                &[Duration::ZERO, Duration::ZERO],
            )
        }
        fn requests(&mut self) -> Vec<String> {
            self.thread.take().unwrap().join().unwrap();
            self.seen.lock().unwrap().clone()
        }
    }
    #[test]
    fn valid_private_grant() {
        assert!(validate_grant_at(&grant(TEST_ORIGIN), TEST_ORIGIN, now_unix()).is_ok());
    }
    #[test]
    fn missing_access_is_rejected() {
        let mut g = grant(TEST_ORIGIN);
        // `room_url` remains the private/tokenized client contract. The
        // short-link exception applies only to `radar_url`.
        g.room_url = format!("{TEST_ORIGIN}/r/123456");
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
    }
    #[test]
    fn empty_or_duplicate_access_is_rejected() {
        for q in ["access=", "access=  ", "access=x&access=y"] {
            let mut g = grant(TEST_ORIGIN);
            g.radar_url = format!("{TEST_ORIGIN}/r/123456?{q}");
            assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        }
    }
    #[test]
    fn mismatched_room_is_rejected() {
        let mut g = grant(TEST_ORIGIN);
        g.radar_url = g.radar_url.replace("123456", "654321");
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
    }
    #[test]
    fn foreign_origin_or_prefix_or_port_is_rejected() {
        for origin in [
            "https://example.test",
            "https://43.226.47.215.evil.test:8443",
            "https://43.226.47.215:8444",
            "http://43.226.47.215:8443",
        ] {
            let mut g = grant(TEST_ORIGIN);
            g.radar_url = format!("{origin}/r/123456?access=x");
            assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        }
    }
    #[test]
    fn room_url_is_validated_too() {
        let mut g = grant(TEST_ORIGIN);
        g.room_url = "https://example.test/r/123456?access=x".into();
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
    }

    #[test]
    fn short_radar_link_without_access_is_accepted_but_room_url_still_requires_access() {
        let mut g = grant(TEST_ORIGIN);
        // The current gateway intentionally returns a public short radar link;
        // GET /r/<room> sets the room/session cookies before redirecting to /radar.
        g.radar_url = format!("{TEST_ORIGIN}/r/123456");
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_ok());

        let mut g = grant(TEST_ORIGIN);
        g.room_url = format!("{TEST_ORIGIN}/r/123456");
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
    }
    #[test]
    fn fragment_and_userinfo_are_rejected() {
        for url in [
            format!("{TEST_ORIGIN}/r/123456?access=x#extra"),
            format!("https://user@43.226.47.215:8443/r/123456?access=x"),
        ] {
            let mut g = grant(TEST_ORIGIN);
            g.radar_url = url;
            assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        }
    }
    #[test]
    fn expired_and_zero_expiry_are_rejected() {
        for exp in [0, now_unix() - 1] {
            let mut g = grant(TEST_ORIGIN);
            g.expires_unix = exp;
            assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        }
    }
    #[test]
    fn invalid_node_fields_are_rejected() {
        let mut g = grant(TEST_ORIGIN);
        g.node_password = "bad\0value".into();
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        g = grant(TEST_ORIGIN);
        g.node_host = "host/path".into();
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
        g = grant(TEST_ORIGIN);
        g.node_port = 0;
        assert!(validate_grant_at(&g, TEST_ORIGIN, now_unix()).is_err());
    }
    #[test]
    fn zero_tls_flag_does_not_disable_verification() {
        assert!(!tls_flag(Some("0")));
        assert!(!tls_flag(None));
        assert!(!tls_flag(Some("true")));
        assert!(tls_flag(Some("1")));
    }
    #[test]
    fn local_checksum_cannot_reject_server_card() {
        let mut f = Fixture::new(|o| vec![(200, serde_json::to_string(&grant(o)).unwrap())]);
        assert!(f.activate("valid-upstream-nonstandard-card").is_ok());
        assert!(f.requests()[0].contains("valid-upstream-nonstandard-card"));
    }
    #[test]
    fn busy_gateway_retries_and_recovers() {
        let mut f = Fixture::new(|o| {
            vec![
                (503, r#"{"error":"upstream busy"}"#.into()),
                (200, serde_json::to_string(&grant(o)).unwrap()),
            ]
        });
        assert!(f.activate("valid").is_ok());
        assert_eq!(f.requests().len(), 2);
    }
    #[test]
    fn malformed_success_retries_and_recovers() {
        let mut f = Fixture::new(|o| {
            vec![
                (200, "<html>proxy error</html>".into()),
                (200, serde_json::to_string(&grant(o)).unwrap()),
            ]
        });
        assert!(f.activate("valid").is_ok());
        assert_eq!(f.requests().len(), 2);
    }
    #[test]
    fn wrong_then_correct_card_has_no_failure_cache() {
        let mut f = Fixture::new(|o| {
            vec![
                (401, r#"{"error":"invalid card"}"#.into()),
                (200, serde_json::to_string(&grant(o)).unwrap()),
            ]
        });
        let error = f.activate("wrong").unwrap_err();
        assert!(!error.retryable());
        assert!(f.activate("correct").is_ok());
        let seen = f.requests();
        assert_eq!(seen.len(), 2);
        assert!(seen[0].contains("wrong"));
        assert!(seen[1].contains("correct"));
    }
    #[test]
    fn redirects_never_forward_credentials() {
        let mut f = Fixture::new(|_| vec![(307, "http://127.0.0.1:9/steal".into())]);
        let error = f.activate("private-fixture-card").unwrap_err();
        assert_eq!(error.status, Some(307));
        assert_eq!(f.requests().len(), 1);
    }
    #[test]
    fn cancelled_request_does_not_start_transport() {
        let c = Cancellation::default();
        c.cancel();
        assert_eq!(
            activate_at("http://127.0.0.1:9", "card", "device", &c, &mut |_| {}, &[])
                .unwrap_err()
                .status,
            Some(499)
        );
    }
    #[test]
    fn retry_classification() {
        for code in [400, 401, 402, 403, 404, 410, 307] {
            assert!(
                !AttemptError {
                    status: Some(code),
                    detail: String::new()
                }
                .retryable()
            );
        }
        for code in [408, 429, 500, 502, 503, 504] {
            assert!(
                AttemptError {
                    status: Some(code),
                    detail: String::new()
                }
                .retryable()
            );
        }
    }
    #[test]
    fn room_gone_reauthenticates_instead_of_failing_card() {
        let mut f = Fixture::new(|_| vec![(404, r#"{"error":"room gone"}"#.into())]);
        assert!(matches!(
            renew_at(&f.origin, "device", "123456"),
            Err(RenewFailure::RoomGone(_))
        ));
        f.requests();
    }
    #[test]
    fn invalid_renew_room_is_transient() {
        let mut f = Fixture::new(|_| {
            vec![(
                200,
                format!(
                    r#"{{"room_id":"wrong","valid_until_unix":{}}}"#,
                    now_unix() + 900
                ),
            )]
        });
        assert!(matches!(
            renew_at(&f.origin, "device", "123456"),
            Err(RenewFailure::Transient(_))
        ));
        f.requests();
    }
    #[test]
    fn renew_distinguishes_fatal_and_transient() {
        for code in [401, 402, 403, 410, 503] {
            let mut f = Fixture::new(|_| vec![(code, r#"{"error":"fixture error"}"#.into())]);
            let result = renew_at(&f.origin, "device", "123456");
            if code == 503 {
                assert!(matches!(result, Err(RenewFailure::Transient(_))));
            } else {
                assert!(matches!(result, Err(RenewFailure::Fatal(_))));
            }
            f.requests();
        }
    }
    #[test]
    fn long_card_renews_session_within_ten_minutes() {
        assert!(renewal_delay(now_unix() + 86400, now_unix()) <= Duration::from_secs(600));
        assert_eq!(session_deadline(50000, None, 1000), 1900);
    }
    #[test]
    fn session_is_capped_by_card_and_node_expiry() {
        let i = RenewInfo {
            room_id: "r".into(),
            valid_until_unix: 3000,
            node_expires_unix: 2000,
        };
        assert_eq!(session_deadline(5000, Some(&i), 1000), 2000);
        assert_eq!(session_deadline(1500, Some(&i), 1000), 1500);
    }
    #[test]
    fn short_card_does_not_wait_past_expiry() {
        assert_eq!(renewal_delay(1030, 1000), Duration::from_secs(15));
        assert_eq!(renewal_delay(999, 1000), Duration::from_secs(1));
    }
    #[test]
    fn normalize_only_removes_paste_artifacts() {
        assert_eq!(normalize_card(" AbC\u{200b}12\n 34\u{feff}"), "AbC1234");
        assert_eq!(
            normalize_card("nonstandard-valid-card"),
            "nonstandard-valid-card"
        );
    }
    #[test]
    fn hmac_matches_rfc4231_test_vector() {
        assert_eq!(
            hex::encode(hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }
    #[test]
    fn nonce_is_unique() {
        assert_ne!(request_nonce(), request_nonce());
    }
}
