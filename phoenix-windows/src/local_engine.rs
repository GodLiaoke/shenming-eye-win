//! Bundled local decode engine for the Windows client.
//!
//! Instead of mirroring captured game traffic to the protected server, the
//! Windows build now runs the repository's own `codev-net` binary locally. It
//! owns the phone-facing SOCKS5 listener on port 2025 (which also accepts the
//! `CVM1` copy-only ingest used by WinDivert passive capture) and serves the
//! private radar panel on loopback. The only remaining server dependency is the
//! `/api/activate` license check performed in `app.rs`.

use anyhow::{Context, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub(crate) const INGEST_PORT: u16 = 2026;
pub(crate) const PANEL_PORT: u16 = 18_080;
const TOKEN_TTL_SECS: &str = "315360000";
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 解密引擎（codev-net.exe）随主程序一起嵌入，客户只需拿到一个 exe。
/// 首次运行释放到 `%LOCALAPPDATA%\Phoenix\runtime-<引擎内容哈希>\`。
/// 放在主程序同目录的 codev-net.exe 只在释放失败时兜底，便于现场排障。
#[cfg(not(feature = "server-mode"))]
static EMBEDDED_ENGINE: &[u8] = include_bytes!("../embedded/codev-net.exe");
/// 服务端模式下**刻意不内嵌引擎**：客户端里既没有解码器也没有地图数据，
/// 就算被逆向也拿不到解析能力。该模式下 `locate_binary` 不会被调用。
#[cfg(feature = "server-mode")]
static EMBEDDED_ENGINE: &[u8] = &[];

/// 内嵌引擎的内容指纹（前 8 字节哈希，16 位十六进制）。
/// 用作运行时目录名：换包即换目录。
fn engine_fingerprint() -> String {
    let digest = Sha256::digest(EMBEDDED_ENGINE);
    hex::encode(&digest[..8])
}

pub(crate) struct LocalEngine {
    child: Child,
    pub(crate) proxy_username: String,
    pub(crate) proxy_password: String,
    pub(crate) panel_token: String,
}

/// 续期间隔：网关签发的会话有效期是 15 分钟，这里 10 分钟续一次。
const RENEW_INTERVAL: Duration = Duration::from_secs(600);
/// 网络类失败的宽限期：连续失败这么久仍未恢复，才判定授权已失效。
const MAX_TRANSIENT: Duration = Duration::from_secs(3600);

/// 短时会话续期看门狗：本地引擎必须周期性向网关续期。
///
/// 关键点在于**区分失败性质**。旧版任何一次失败都 taskkill 引擎，客户家里
/// 路由器抖一下、热点切个基站，雷达就被永久关掉还得重启软件。现在的策略：
///
/// - 401/402/403/410（卡密过期、被吊销、被禁用、设备绑定不一致）
///   → 立刻结束引擎，破解版无法长期离线运行；
/// - 断网 / 上游超时 / 5xx → 引擎继续跑，按 15s→30s→60s→120s→300s 退避重试，
///   恢复后自动回到正常周期（引擎从未中断，无需重新拉起）；
/// - 网络类失败连续超过 60 分钟 → 按失效处理，停止引擎并留记录。
///
/// 这样"卡密一过期就停"的安全属性不变，但客户不会再因为一次网络抖动掉线。
#[allow(dead_code)]
/// 已弃用：客户端直连 T3 后不再周期性续期（保留代码备查）。
pub(crate) fn spawn_authorization_watchdog(device_id: String, room_id: String, engine_pid: u32) {
    std::thread::Builder::new()
        .name("phoenix-authorization-watchdog".to_string())
        .spawn(move || {
            std::thread::sleep(RENEW_INTERVAL);
            let mut transient_since: Option<Instant> = None;
            let mut transient_count: u64 = 0;
            loop {
                match renew_outcome(&device_id, &room_id) {
                    RenewOutcome::Healthy => {
                        transient_since = None;
                        transient_count = 0;
                        std::thread::sleep(RENEW_INTERVAL);
                    }
                    RenewOutcome::Fatal(detail) => {
                        tracing_stop(engine_pid);
                        crate::app::record_authorization_failure(&device_id, &detail);
                        return;
                    }
                    RenewOutcome::Transient(detail) => {
                        transient_count += 1;
                        let since = *transient_since.get_or_insert_with(Instant::now);
                        let elapsed = since.elapsed();
                        if elapsed >= MAX_TRANSIENT {
                            tracing_stop(engine_pid);
                            crate::app::record_authorization_failure(
                                &device_id,
                                &format!(
                                    "网络异常持续超过 {} 分钟，按授权失效处理：{detail}",
                                    MAX_TRANSIENT.as_secs() / 60
                                ),
                            );
                            return;
                        }
                        let wait = transient_backoff(elapsed);
                        crate::app::record_authorization_failure(
                            &device_id,
                            &format!(
                                "续期暂时失败（第 {transient_count} 次，已持续 {} 秒），{} 秒后重试：{detail}",
                                elapsed.as_secs(),
                                wait.as_secs()
                            ),
                        );
                        std::thread::sleep(wait);
                    }
                }
            }
        })
        .ok();
}

enum RenewOutcome {
    Healthy,
    Fatal(String),
    Transient(String),
}

fn renew_outcome(device_id: &str, room_id: &str) -> RenewOutcome {
    match crate::app::renew_session(device_id, room_id) {
        Ok(_) => RenewOutcome::Healthy,
        Err(
            crate::app::RenewFailure::Fatal(detail) | crate::app::RenewFailure::RoomGone(detail),
        ) => RenewOutcome::Fatal(detail),
        Err(crate::app::RenewFailure::Transient(detail)) => RenewOutcome::Transient(detail),
    }
}

/// 退避阶梯：越拖越久，但上限 5 分钟，保证网络恢复后 5 分钟内必回正轨。
fn transient_backoff(elapsed: Duration) -> Duration {
    match elapsed.as_secs() {
        0..=60 => Duration::from_secs(15),
        61..=300 => Duration::from_secs(30),
        301..=900 => Duration::from_secs(60),
        901..=1800 => Duration::from_secs(120),
        _ => Duration::from_secs(300),
    }
}

#[cfg(windows)]
fn tracing_stop(engine_pid: u32) {
    use std::process::Command;
    // 引擎是本程序自己启动的子进程；这里用 taskkill 结束它，避免依赖句柄所有权。
    let _ = Command::new("taskkill")
        .args(["/PID", &engine_pid.to_string(), "/T", "/F"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .status();
}

#[cfg(not(windows))]
fn tracing_stop(_engine_pid: u32) {}

impl LocalEngine {
    /// 引擎进程号：授权失效时看门狗用它直接结束引擎。
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
}

#[derive(Deserialize)]
struct ProxyTokenOutput {
    username: String,
    secret: String,
}

#[derive(Deserialize)]
struct PanelTokenOutput {
    secret: String,
}

struct RuntimePaths {
    binary: PathBuf,
    config: PathBuf,
    proxy_tokens: PathBuf,
    panel_token: PathBuf,
    profiles: PathBuf,
    record: PathBuf,
    log: PathBuf,
}

impl LocalEngine {
    /// 抓包目录：本机引擎按 `[record] proxy_pcap = true` 把每局对战写成
/// `capture.pcap`（经典 PCAP，Wireshark 可直接打开），就落在这里。
pub(crate) fn capture_dir(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("local-engine").join("record")
}
pub(crate) fn start(data_dir: &Path) -> anyhow::Result<Self> {
        let paths = Self::runtime_paths(data_dir)?;
        Self::write_config(&paths)?;

        // A fresh token pair is minted per launch; both stores live only under
        // the current user's LOCALAPPDATA and never leave the machine.
        let _ = fs::remove_file(&paths.proxy_tokens);
        let _ = fs::remove_file(&paths.panel_token);
        let proxy = Self::create_proxy_token(&paths)?;
        let panel = Self::create_panel_token(&paths)?;

        let log = fs::File::create(&paths.log).context("本地引擎日志无法创建")?;
        let child = engine_command(&paths.binary)
            .arg("proxy")
            .arg("--config")
            .arg(&paths.config)
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()
            .with_context(|| format!("解密引擎启动失败（无法运行 {}）", paths.binary.display()))?;

        let engine = Self {
            child,
            proxy_username: proxy.username,
            proxy_password: proxy.secret,
            panel_token: panel.secret,
        };
        engine.wait_until_healthy(&paths)?;
        Ok(engine)
    }

    pub(crate) fn panel_url() -> String {
        format!("http://127.0.0.1:{PANEL_PORT}/")
    }

    fn runtime_paths(data_dir: &Path) -> anyhow::Result<RuntimePaths> {
        let directory = data_dir.join("local-engine");
        let record = directory.join("record");
        fs::create_dir_all(&record)?;
        Ok(RuntimePaths {
            binary: Self::locate_binary(data_dir)?,
            config: directory.join("config.toml"),
            proxy_tokens: directory.join("proxy-tokens.toml"),
            panel_token: directory.join("panel-token.secret"),
            profiles: directory.join("shadowrocket-profiles.toml"),
            record,
            log: directory.join("engine.log"),
        })
    }

    /// 内嵌引擎优先：释放到 `%LOCALAPPDATA%\Phoenix\runtime-<哈希>\codev-net.exe`。
    ///
    /// 目录名用**引擎内容哈希**而不是写死的 build 号：
    /// ① 换包必然换目录，老引擎绝不会被复用（客户拿到的引擎版本永远跟着 exe 走）；
    /// ② 同一次发布里哈希固定，重启不会重复写 10 MB。
    ///
    /// 刻意**不**优先使用主程序同目录的 `codev-net.exe`：客户升级单文件版时，
    /// 同目录很可能还留着旧版引擎，若让旧文件优先，地图就会退回旧标定。
    /// 只有内嵌引擎释放失败（例如目录只读）时才退回同目录副本。
    fn locate_binary(data_dir: &Path) -> anyhow::Result<PathBuf> {
        let runtime_dir = data_dir.join(format!("runtime-{}", engine_fingerprint()));
        fs::create_dir_all(&runtime_dir)?;
        let target = runtime_dir.join("codev-net.exe");

        if Self::extract_embedded(&target).is_ok() {
            Self::prune_stale_runtimes(data_dir, &runtime_dir);
            return Ok(target);
        }
        if let Ok(current) = std::env::current_exe()
            && let Some(parent) = current.parent()
        {
            let candidate = parent.join("codev-net.exe");
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
        Self::extract_embedded(&target)?;
        Self::prune_stale_runtimes(data_dir, &runtime_dir);
        Ok(target)
    }

    /// 释放内嵌引擎：大小与内容全等才跳过。
    ///
    /// 旧版只比 `metadata.len()`，于是"同大小但内容不同"的旧引擎会被当成
    /// 已释放而不更新 —— 这正是客户"换了新 exe 引擎却还是旧的"的原因。
    /// 现在按字节直接比对（10 MB 的 memcmp 在启动路径上可以忽略）。
    fn extract_embedded(target: &Path) -> anyhow::Result<()> {
        let up_to_date = fs::read(target)
            .map(|bytes| bytes.as_slice() == EMBEDDED_ENGINE)
            .unwrap_or(false);
        if !up_to_date {
            fs::write(target, EMBEDDED_ENGINE)
                .with_context(|| format!("解密引擎无法释放到 {}", target.display()))?;
        }
        if target.is_file() {
            return Ok(());
        }
        bail!("解密引擎不可用：无法写入 {}", target.display());
    }

    /// 清掉历史版本的引擎运行目录，避免硬盘上堆一堆 10 MB 引擎。
    ///
    /// 匹配规则刻意收得很严：只有 `runtime-` + 正好 16 位十六进制（也就是
    /// `engine_fingerprint()` 的形状）才会被删。Data 目录下还有别的东西
    /// （授权记录、WinDivert 运行时、webview2 缓存），宽匹配会误删。
    /// 正在运行的目录删不掉（Windows 文件锁），忽略失败即可。
    fn prune_stale_runtimes(data_dir: &Path, keep: &Path) {
        let Ok(entries) = fs::read_dir(data_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path == keep || !path.is_dir() {
                continue;
            }
            let is_engine_runtime = path
                .file_name()
                .and_then(|name| name.to_str())
                .map(|name| {
                    // 历史遗留：旧版引擎与旧版 WinDivert 运行的目录名，确认是我们自己的才清。
                    if name == "runtime-build45" {
                        return true;
                    }
                    name.strip_prefix("runtime-")
                        .map(|hash| {
                            hash.len() == 16 && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if is_engine_runtime {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }

    fn write_config(paths: &RuntimePaths) -> anyhow::Result<()> {
        let config = format!(
            "[proxy]\n\
             listen = \"127.0.0.1:{ingest_port}\"\n\
             token_store = \"{tokens}\"\n\
             advertised_host = \"127.0.0.1\"\n\
             advertised_port = {ingest_port}\n\
             profile_ttl_secs = 315360000\n\
             profile_store = \"{profiles}\"\n\
             token_ttl_secs = 315360000\n\
             udp_idle_secs = 60\n\
             udp_relay_ports = {{ start = 22000, end = 22063 }}\n\
             handshake_timeout_secs = 15\n\
             max_total_connections = 512\n\
             max_connections_per_token = 256\n\
             max_udp_flows_per_token = 128\n\
             bytes_per_second_per_token = 134217728\n\
             allow_any_public_target = true\n\
             # 放行策略：与 macOS/云端槽位实测能带游戏的组合一致。\n\
             # 旧的最小列表（只 80/443/8080/10000/10001 + *.qq.com）会把游戏\n\
             # 的 8013/8085/15806/17500/1883 等端口与腾讯游戏 IP 直接拒掉 ——\n\
             # 表现就是：手机连上了节点，但游戏上不去。\n\
             allow_hosts = [\"*.qq.com\", \"*.tencent.com\", \"*.codev.qq.com\", \"iospaste.mna.qq.com\", \"receiver.tdm.qq.com\", \"43.135.106.46\", \"43.135.106.108\", \"43.135.106.213\", \"43.135.106.226\", \"43.162.204.119\", \"43.162.204.121\", \"43.162.204.122\", \"43.162.204.128\", \"43.162.204.129\", \"43.162.204.134\", \"43.163.178.107\", \"140.206.161.148\"]\n\
             allow_ports = [80, 443, 1883, 8013, 8085, 10000, 10001, 15806, 17500]\n\
             \n\
             [mitm]\n\
             enabled = false\n\
             domains = []\n\
             block_quic = false\n\
             \n\
             [panel]\n\
             listen = \"0.0.0.0:{panel_port}\"\n\
             token_file = \"{panel_token}\"\n\
             token_ttl_secs = 315360000\n\
             public_base_url = \"http://127.0.0.1:{panel_port}\"\n\
             allow_lan_hosts = true\n\
             profile_store = \"{profiles}\"\n\
             staging = true\n\
             \n\
             [record]\n\
             directory = \"{record}\"\n\
             plaintext = false\n\
             proxy_pcap = true\n\
             max_bytes = 536870912\n\
             max_duration_secs = 1800\n\
             max_files = 5\n",
            ingest_port = INGEST_PORT,
            panel_port = PANEL_PORT,
            tokens = toml_path(&paths.proxy_tokens),
            profiles = toml_path(&paths.profiles),
            panel_token = toml_path(&paths.panel_token),
            record = toml_path(&paths.record),
        );
        fs::write(&paths.config, config).context("本地引擎配置写入失败")?;
        Ok(())
    }

    fn create_proxy_token(paths: &RuntimePaths) -> anyhow::Result<ProxyTokenOutput> {
        let output = Self::run_token(
            paths,
            &[
                "token",
                "create",
                "--username",
                "phoenix-local",
                "--scope",
                "proxy",
            ],
        )?;
        serde_json::from_slice(&output).context("代理令牌解析失败")
    }

    fn create_panel_token(paths: &RuntimePaths) -> anyhow::Result<PanelTokenOutput> {
        let output = Self::run_token(paths, &["token", "create", "--scope", "panel"])?;
        serde_json::from_slice(&output).context("面板令牌解析失败")
    }

    fn run_token(paths: &RuntimePaths, action: &[&str]) -> anyhow::Result<Vec<u8>> {
        let output = engine_command(&paths.binary)
            .args(action)
            .arg("--ttl-secs")
            .arg(TOKEN_TTL_SECS)
            .arg("--config")
            .arg(&paths.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| {
                format!(
                    "无法运行本地引擎（{}）。请确认 codev-net.exe 与主程序在同一目录",
                    paths.binary.display()
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            let detail = [stderr.trim(), stdout.trim()]
                .into_iter()
                .find(|text| !text.is_empty())
                .unwrap_or("exit error");
            bail!("本地引擎令牌创建失败：{detail}");
        }
        Ok(output.stdout)
    }

    fn wait_until_healthy(&self, paths: &RuntimePaths) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", PANEL_PORT)).is_ok()
                && TcpStream::connect(("127.0.0.1", INGEST_PORT)).is_ok()
            {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        let log = fs::read_to_string(&paths.log).unwrap_or_default();
        let tail = log
            .lines()
            .rev()
            .take(8)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join(" | ");
        if tail.is_empty() {
            bail!("解密引擎启动超时。日志：{}", paths.log.display());
        }
        bail!("解密引擎启动超时：{tail}");
    }
}

impl Drop for LocalEngine {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn engine_command(binary: &Path) -> Command {
    let mut command = Command::new(binary);
    command.stdin(Stdio::null());
    if let Some(dir) = binary.parent() {
        command.current_dir(dir);
    }
    #[cfg(windows)]
    {
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}
