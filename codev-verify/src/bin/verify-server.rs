//! 独立验证服务（新端口专用）
//!
//! 放在你自己的服务器上（例如 103 上另开一个端口），客户端只跟它说话：
//! T3 的 app_key / 3DES key **留在服务器**，客户端拿不到。
//!
//! ```text
//! VERIFY_LISTEN=0.0.0.0:19001 ./verify-server
//! curl -s -X POST http://127.0.0.1:19001/api/activate \
//!      -H 'content-type: application/json' -d '{"card":"...","device_id":"..."}'
//! ```
//!
//! 只用标准库：单文件、无运行时依赖、丢到任何 Linux 上就能跑。
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};


// ───────────────────────── 卡密 ↔ 设备绑定 ─────────────────────────
//
// 2026-10-22：客户问"一张卡能不能多台设备共用"。答案取决于这里 ——
// T3 那边只管卡本身，不会替我们数设备；不在这层做，就只能靠客户自觉。
//
// 规则：
//   · 每张卡最多绑定 `VERIFY_MAX_DEVICES` 台设备（默认 1）
//   · 已绑定的设备再来验证 → 放行
//   · 新设备超过上限 → 409，并返回已绑定台数
//   · 解除绑定：POST /admin/reset {card} + `VERIFY_ADMIN_TOKEN`
//
// 存储：`VERIFY_DB`（默认 ./bindings.json），原子写（写临时文件再 rename）。
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Bindings {
    cards: std::collections::BTreeMap<String, CardBinding>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct CardBinding {
    devices: Vec<String>,
    expires_unix: i64,
    first_seen: i64,
    last_seen: i64,
}

fn db_path() -> std::path::PathBuf {
    std::env::var("VERIFY_DB").map(std::path::PathBuf::from).unwrap_or_else(|_| "bindings.json".into())
}

fn max_devices() -> usize {
    std::env::var("VERIFY_MAX_DEVICES").ok().and_then(|v| v.parse().ok()).unwrap_or(1)
}

fn load_bindings() -> Bindings {
    std::fs::read(db_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_bindings(bindings: &Bindings) -> std::io::Result<()> {
    let path = db_path();
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(bindings).unwrap_or_default())?;
    std::fs::rename(tmp, path)
}

fn hash_hex(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// 卡密指纹（不落明文）：只保留 0-9A-Z 再哈希。
fn card_key(card: &str) -> String {
    let visible: String = card
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    hash_hex(&format!("codev-card-v1|{visible}"))
}

enum BindOutcome {
    Allowed,
    AllowedNewDevice(usize),
    Rejected { bound: usize },
}

fn check_and_bind(card: &str, device_hash: &str, expires_unix: i64) -> BindOutcome {
    let mut bindings = load_bindings();
    let key = card_key(card);
    let now = now_unix();
    let entry = bindings.cards.entry(key).or_default();
    if entry.first_seen == 0 {
        entry.first_seen = now;
    }
    entry.last_seen = now;
    entry.expires_unix = expires_unix;

    let outcome = if entry.devices.iter().any(|d| d == device_hash) {
        BindOutcome::Allowed
    } else if entry.devices.len() < max_devices() {
        entry.devices.push(device_hash.to_string());
        BindOutcome::AllowedNewDevice(entry.devices.len())
    } else {
        BindOutcome::Rejected { bound: entry.devices.len() }
    };
    let _ = save_bindings(&bindings);
    outcome
}

fn reset_card(card: &str) -> bool {
    let mut bindings = load_bindings();
    let removed = bindings.cards.remove(&card_key(card)).is_some();
    let _ = save_bindings(&bindings);
    removed
}

fn main() {
    // 自检：不联网、不验卡，只验证"一张卡能不能多设备共用"的判定逻辑。
    if std::env::args().any(|arg| arg == "--selftest-bindings") {
        selftest_bindings();
        return;
    }
    let listen = std::env::var("VERIFY_LISTEN").unwrap_or_else(|_| "0.0.0.0:19001".to_string());
    let listener = match TcpListener::bind(&listen) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("监听 {listen} 失败：{error}");
            std::process::exit(1);
        }
    };
    println!("verify-server listening on {listen}");
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(move || {
                    let _ = handle(stream);
                });
            }
            Err(error) => eprintln!("accept 失败：{error}"),
        }
    }
}

fn handle(mut stream: TcpStream) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(Duration::from_secs(30)))?;
    let peer = stream.peer_addr().ok();
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length.min(64 * 1024)];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    let started = std::time::Instant::now();
    let (status, payload) = route(&method, &path, &body);
    let response_body = serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec());
    let head = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        response_body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&response_body)?;
    let _ = stream.flush();
    println!(
        "{:?} {method} {path} → {status} ({}ms)",
        peer,
        started.elapsed().as_millis()
    );
    Ok(())
}

fn route(method: &str, path: &str, body: &[u8]) -> (u16, serde_json::Value) {
    let path = path.split('?').next().unwrap_or(path);
    match (method, path) {
        ("GET", "/healthz") => (
            200,
            serde_json::json!({ "ok": true, "unix": now_unix(), "service": "codev-verify" }),
        ),
        ("POST", "/api/activate") => activate(body),
        ("POST", "/admin/reset") => admin_reset(body),
        _ => (404, serde_json::json!({ "ok": false, "error": "not found" })),
    }
}

fn activate(body: &[u8]) -> (u16, serde_json::Value) {
    let parsed: serde_json::Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(error) => {
            return (
                422,
                serde_json::json!({ "ok": false, "error": format!("请求体不是合法 JSON：{error}") }),
            )
        }
    };
    let card = parsed.get("card").and_then(|v| v.as_str()).unwrap_or("").trim();
    let device = parsed.get("device_id").and_then(|v| v.as_str()).unwrap_or("").trim();
    if card.is_empty() {
        return (422, serde_json::json!({ "ok": false, "error": "缺少 card" }));
    }
    if device.is_empty() {
        return (422, serde_json::json!({ "ok": false, "error": "缺少 device_id" }));
    }

    // 设备种子：与客户端一致（sha256(前缀||device_id)），换机即换绑。
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"codev-verify-device-v1");
    hasher.update(device.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);

    match codev_verify::verify_card(card, &seed) {
        Ok(grant) => {
            // 卡密有效性 T3 已确认 → 再看"这台设备能不能用这张卡"。
            let device_hash = hash_hex(&format!("codev-device-v1|{device}"));
            match check_and_bind(card, &device_hash, grant.expires_unix) {
                BindOutcome::Allowed | BindOutcome::AllowedNewDevice(_) => (
                    200,
                    serde_json::json!({
                        "ok": true,
                        "expires_unix": grant.expires_unix,
                        "expires_at": grant.expires_at,
                        "notice": grant.notice,
                        "service": "codev-verify",
                        "max_devices": max_devices(),
                    }),
                ),
                BindOutcome::Rejected { bound } => (
                    409,
                    serde_json::json!({
                        "ok": false,
                        "error": format!(
                            "这张卡已绑定 {bound} 台设备（上限 {}）。换设备请先在后台解绑，或联系客服。",
                            max_devices()
                        ),
                        "bound_devices": bound,
                        "max_devices": max_devices(),
                    }),
                ),
            }
        }
        Err(error) => {
            let text = format!("{error}");
            // 卡密类问题 403；网络/上游问题 503（客户端会重试）。
            let status = if text.contains("network") || text.contains("protocol") { 503 } else { 403 };
            (status, serde_json::json!({ "ok": false, "error": text }))
        }
    }
}

fn admin_reset(body: &[u8]) -> (u16, serde_json::Value) {
    let token = std::env::var("VERIFY_ADMIN_TOKEN").unwrap_or_default();
    if token.is_empty() {
        return (403, serde_json::json!({ "ok": false, "error": "服务端未启用管理令牌" }));
    }
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let provided = parsed.get("token").and_then(|v| v.as_str()).unwrap_or("");
    if provided != token {
        return (401, serde_json::json!({ "ok": false, "error": "管理令牌不正确" }));
    }
    let card = parsed.get("card").and_then(|v| v.as_str()).unwrap_or("").trim();
    if card.is_empty() {
        return (422, serde_json::json!({ "ok": false, "error": "缺少 card" }));
    }
    let removed = reset_card(card);
    (
        200,
        serde_json::json!({ "ok": true, "removed": removed }),
    )
}


fn selftest_bindings() {
    let path = std::env::temp_dir().join(format!("bindings-selftest-{}.json", std::process::id()));
    // SAFETY: 单线程启动阶段设置环境变量。
    unsafe {
        std::env::set_var("VERIFY_DB", &path);
        std::env::set_var("VERIFY_MAX_DEVICES", "1");
    }
    let _ = std::fs::remove_file(&path);
    let card = "ABCDEFGHJKLMNPQRSTUVWX";
    let now = now_unix();
    let mut outcomes = Vec::new();

    match check_and_bind(card, "device-1", now + 86400) {
        BindOutcome::AllowedNewDevice(n) => outcomes.push(format!("设备1 首次绑定：允许（已绑 {n}）")),
        other => outcomes.push(format!("设备1 首次绑定：意外 {:?}", describe(other))),
    }
    match check_and_bind(card, "device-1", now + 86400) {
        BindOutcome::Allowed => outcomes.push("设备1 再次验证：允许".to_string()),
        other => outcomes.push(format!("设备1 再次验证：意外 {:?}", describe(other))),
    }
    match check_and_bind(card, "device-2", now + 86400) {
        BindOutcome::Rejected { bound } => outcomes.push(format!("设备2 新设备：拒绝（已绑 {bound}）")),
        other => outcomes.push(format!("设备2 新设备：意外 {:?}", describe(other))),
    }
    unsafe {
        std::env::set_var("VERIFY_MAX_DEVICES", "2");
    }
    match check_and_bind(card, "device-2", now + 86400) {
        BindOutcome::AllowedNewDevice(n) => outcomes.push(format!("上限调到 2 后设备2：允许（已绑 {n}）")),
        other => outcomes.push(format!("上限调到 2 后设备2：意外 {:?}", describe(other))),
    }
    let _ = std::fs::remove_file(&path);
    for line in outcomes {
        println!("  {line}");
    }
}

fn describe(outcome: BindOutcome) -> &'static str {
    match outcome {
        BindOutcome::Allowed => "允许",
        BindOutcome::AllowedNewDevice(_) => "允许新设备",
        BindOutcome::Rejected { .. } => "拒绝",
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
