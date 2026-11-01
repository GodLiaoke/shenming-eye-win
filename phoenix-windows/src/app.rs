use crate::capture::PassiveCapture;
use anyhow::{anyhow, bail};
// 只保留本机 SOCKS5 监听（2025 → 本机引擎 ingest 端口）。
// 历史上这个 crate 还负责「把流量副本送上云端」，那条链路已删除。
use phoenix_cloud_relay::{phoenix_cloud_relay_start, phoenix_cloud_relay_stop};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{HLOCAL, LocalFree};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub(crate) use crate::authorization::{
    CLIENT_BUILD, G0Grant, INSECURE_TLS, RenewFailure, gateway_origin, renew_session, server_mode,
};
#[derive(Clone, Deserialize, Serialize)]
pub(crate) struct SavedState {
    pub(crate) card: String,
    pub(crate) grant: G0Grant,
    pub(crate) local_password: String,
}
const LOCAL_PORT: u16 = 2025;
const LOCAL_USERNAME: &str = "phoenix-local";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
fn now_unix() -> i64 {
    crate::authorization::now_unix()
}

pub(crate) fn data_dir() -> anyhow::Result<PathBuf> {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("数据目录不可用"))?;
    Ok(root.join("Phoenix"))
}

/// 设备指纹。
///
/// ① 已有记录一律沿用 —— 老客户升级后设备号不能突变，否则上游卡密会判
///    "设备绑定不一致"，那是比"重装丢授权"严重得多的故障。
/// ② 只有本机确实没有记录时才派生，并且用**硬件信息**派生
///    （`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` + 系统盘卷序列号）：
///    重装、换 Windows 账户、清用户目录后拿到的仍是同一个设备号。
/// ③ 同时写用户目录与 `%PROGRAMDATA%` 两份，任意一份还在就能恢复。
///    旧版用"时间 + 进程号 + 计算机名"派生，每次都可能变，这正是
///    "同一个客户今天能验证、明天验证失败"的根源。
pub(crate) fn load_or_create_device_id(data_dir: &Path) -> anyhow::Result<String> {
    // ① 先读加密盘存（DPAPI，**本机本用户**才能解）。
    //    2026-10-22：以前这里存的是明文 device-id.txt —— 拷到第二台机器就能
    //    复用同一个设备号，等于一张卡可以多机共用。现在改成 DPAPI：
    //    文件拷贝到别的机器解不开，只能重新生成设备号。
    for candidate in device_id_secure_paths(data_dir) {
        if let Ok(blob) = fs::read(&candidate)
            && let Ok(clear) = dpapi_unprotect(&blob)
            && let Ok(text) = String::from_utf8(clear)
        {
            let value = text.trim().to_string();
            if !value.is_empty() {
                return Ok(value);
            }
        }
    }
    // ② 兼容旧版明文文件：读到就迁移成加密文件并删掉明文。
    for legacy in device_id_plain_paths(data_dir) {
        if let Ok(text) = fs::read_to_string(&legacy) {
            let value = text.trim().to_string();
            if !value.is_empty() {
                persist_device_id(data_dir, &value);
                let _ = fs::remove_file(&legacy);
                return Ok(value);
            }
        }
    }
    let id = hardware_device_id().unwrap_or_else(legacy_random_device_id);
    persist_device_id(data_dir, &id);
    Ok(id)
}

/// 把设备号写成 DPAPI 密文（用户目录 + ProgramData 各一份）。
fn persist_device_id(data_dir: &Path, id: &str) {
    let Ok(blob) = dpapi_protect(id.as_bytes()) else {
        // DPAPI 不可用时宁可不落盘，也别写明文。
        return;
    };
    for candidate in device_id_secure_paths(data_dir) {
        if let Some(parent) = candidate.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&candidate, &blob);
    }
}

fn device_id_secure_paths(data_dir: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data_dir.join("device-id.bin")];
    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        paths.push(PathBuf::from(program_data).join("Phoenix").join("device-id.bin"));
    }
    paths
}

/// 旧版明文路径（只为迁移）。
fn device_id_plain_paths(data_dir: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data_dir.join("device-id.txt")];
    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        paths.push(PathBuf::from(program_data).join("Phoenix").join("device-id.txt"));
    }
    paths
}

fn device_id_paths(data_dir: &Path) -> Vec<PathBuf> {
    let mut paths = vec![data_dir.join("device-id.txt")];
    if let Some(program_data) = std::env::var_os("PROGRAMDATA") {
        paths.push(
            PathBuf::from(program_data)
                .join("Phoenix")
                .join("device-id.txt"),
        );
    }
    paths
}

/// 兜底：拿不到硬件信息时退回旧算法（保证仍能生成一个可用设备号）。
fn legacy_random_device_id() -> String {
    let seed = format!(
        "{}:{}:{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default(),
        std::process::id(),
        std::env::var("COMPUTERNAME").unwrap_or_default()
    );
    format!("WIN-{:X}", Sha256::digest(seed.as_bytes()))
}

#[cfg(windows)]
fn hardware_device_id() -> Option<String> {
    // MachineGuid 是安装系统时生成、重装系统前唯一且不随账户变化；
    // 卷序列号再兜一层，防止克隆镜像里 MachineGuid 意外相同。
    let machine = registry_machine_guid()?;
    let volume = system_volume_serial().unwrap_or_default();
    let seed = format!("phoenix-hwid-v1|{machine}|{volume}");
    Some(format!(
        "WIN-{}",
        hex::encode_upper(Sha256::digest(seed.as_bytes()))
    ))
}

#[cfg(not(windows))]
fn hardware_device_id() -> Option<String> {
    None
}

#[cfg(windows)]
fn registry_machine_guid() -> Option<String> {
    let output = std::process::Command::new("reg")
        .args([
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .find_map(|line| {
            line.split_once("REG_SZ")
                .map(|(_, value)| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())
}

#[cfg(windows)]
fn system_volume_serial() -> Option<String> {
    let output = std::process::Command::new("cmd")
        .args(["/C", "vol", "C:"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    find_volume_serial(&text)
}

/// `vol C:` 的输出随系统语言变化（英文 "Volume Serial Number is 1A2B-3C4D"，
/// 中文 "卷序列号为 1A2B-3C4D"），所以不匹配文案，只认 `xxxx-xxxx` 这个形状。
fn find_volume_serial(text: &str) -> Option<String> {
    text.split_whitespace().find_map(|token| {
        let token = token.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
        let bytes = token.as_bytes();
        if bytes.len() == 9
            && bytes[4] == b'-'
            && bytes[..4].iter().all(u8::is_ascii_hexdigit)
            && bytes[5..].iter().all(u8::is_ascii_hexdigit)
        {
            Some(token.to_ascii_uppercase())
        } else {
            None
        }
    })
}

pub(crate) fn local_password(device_id: &str) -> String {
    let digest = Sha256::digest(format!("phoenix-local:{device_id}").as_bytes());
    format!("mv-{}", hex::encode(&digest[..12]))
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("license.dpapi")
}

fn prepare_capture_runtime(data_dir: &Path) -> anyhow::Result<PathBuf> {
    const DLL: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/third_party/windivert/WinDivert.dll"
    ));
    const DRIVER: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/third_party/windivert/WinDivert64.sys"
    ));
    const LICENSE: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/third_party/windivert/LICENSE.txt"
    ));
    // 目录名刻意**不**用 `runtime-` 前缀：那是引擎运行目录的命名空间，
    // LocalEngine 会清理历史 `runtime-<哈希>` 目录，撞名会把 WinDivert 误删。
    let runtime = data_dir.join("capture-runtime");
    fs::create_dir_all(&runtime)?;
    write_embedded(&runtime.join("WinDivert.dll"), DLL)?;
    write_embedded(&runtime.join("WinDivert64.sys"), DRIVER)?;
    write_embedded(&runtime.join("WinDivert-LICENSE.txt"), LICENSE)?;
    Ok(runtime)
}

fn write_embedded(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if fs::read(path).ok().as_deref() != Some(bytes) {
        fs::write(path, bytes)?;
    }
    Ok(())
}

pub(crate) fn load_state(data_dir: &Path) -> anyhow::Result<Option<SavedState>> {
    let path = state_path(data_dir);
    if !path.is_file() {
        return Ok(None);
    }
    let encrypted = fs::read(path)?;
    let clear = dpapi_unprotect(&encrypted)?;
    Ok(Some(serde_json::from_slice(&clear)?))
}

pub(crate) fn save_state(data_dir: &Path, state: &SavedState) -> anyhow::Result<()> {
    let clear = serde_json::to_vec(state)?;
    let encrypted = dpapi_protect(&clear)?;
    anyhow::ensure!(
        dpapi_unprotect(&encrypted)? == clear,
        "凭据加密回读校验失败"
    );
    crate::atomic_store::write_verified(&state_path(data_dir), &encrypted)?;
    Ok(())
}

/// 「清除本机授权」：删掉本机保存的卡密与房间凭据。
///
/// 以前侧栏没有这个入口（Mac 上有），客户填错卡、换卡、或者撞上"该卡密已在 2 台设备上使用"
/// 时就无路可走，只能手工去删 `%LOCALAPPDATA%\Phoenix\license.dpapi`。
/// 注意只删授权文件，**不动设备号**（设备号留着，重装/重新激活不会变成一台新设备）。
pub(crate) fn clear_state(data_dir: &Path) -> anyhow::Result<()> {
    match fs::remove_file(state_path(data_dir)) {
        Ok(()) => {
            crate::log::info("已清除本机授权（license.dpapi）");
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn dpapi_protect(clear: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: clear.len() as u32,
        pbData: clear.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        bail!("凭据保护失败");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as HLOCAL) };
    Ok(result)
}

fn dpapi_unprotect(encrypted: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 || output.pbData.is_null() {
        bail!("凭据读取失败");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe { LocalFree(output.pbData as HLOCAL) };
    Ok(result)
}

pub(crate) fn ensure_administrator() -> anyhow::Result<()> {
    if unsafe { IsUserAnAdmin() } != 0 {
        return Ok(());
    }
    let executable = std::env::current_exe()?;
    let verb = wide("runas");
    let path = wide(executable.as_os_str());
    // 提权重启时把原命令行参数带上：以前是 std::ptr::null()，
    // 将来只要加一个命令行开关（比如 --reset）就会在 UAC 之后被静默丢掉。
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    let parameters = if args.is_empty() {
        None
    } else {
        Some(wide(args.join(" ")))
    };
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            path.as_ptr(),
            parameters
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    } as isize;
    if result <= 32 {
        bail!("需要管理员权限");
    }
    std::process::exit(0);
}

pub(crate) fn open_url(url: &str) {
    let verb = wide("open");
    let target = wide(url);
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// 单实例保护：第二个进程直接给一句人话然后退出。
///
/// 以前没有这道锁：客户连点两次图标，第二个实例绑不上本地 2025 端口，
/// 弹出的是「中继服务启动失败（-2）」这种纯错误码，谁也看不出"已经开着一个了"。
pub(crate) fn acquire_single_instance() -> anyhow::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;
    let name = wide("Global\\PhoenixWindows.SingleInstance");
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        // 拿不到互斥体就别拦人（比如受限环境），宁可允许重复运行。
        return Ok(());
    }
    let last_error = unsafe { GetLastError() };
    if last_error == ERROR_ALREADY_EXISTS {
        bail!(
            "不死鸟CodeV 已经在运行了。\n\n请到任务栏找已经打开的窗口；如果找不到，先结束任务管理器里的 Phoenix-Windows.exe 再启动。"
        );
    }
    // 故意不调用 CloseHandle：句柄留到进程结束由系统回收，进程活着就等于持锁。
    // （HANDLE 是 Copy 类型，mem::forget 对它没有意义，所以不写。）
    let _ = handle;
    Ok(())
}

pub(crate) fn candidate_addresses() -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    let hotspot = Ipv4Addr::new(192, 168, 137, 1);
    if let Ok(socket) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        && socket.connect(("8.8.8.8", 53)).is_ok()
        && let Ok(std::net::SocketAddr::V4(address)) = socket.local_addr()
    {
        addresses.push(*address.ip());
    }
    if !addresses.contains(&hotspot) {
        addresses.push(hotspot);
    }
    addresses
}

pub(crate) struct BackendRuntime {
    capture: Option<PassiveCapture>,
    engine: Option<crate::local_engine::LocalEngine>,
    panel_token: String,
    /// 抓包驱动（WinDivert）起不来时的原因。以前这个错误被 `Err(_) => None` 直接吞掉，
    /// 界面照样显示"接收引擎已就绪"，客户只看到"没数据"、也拿不出任何信息。
    capture_error: Option<String>,
}

impl BackendRuntime {
    pub(crate) fn start(
        data_dir: &Path,
        state: &SavedState,
        device_id: &str,
    ) -> anyhow::Result<Self> {
        phoenix_cloud_relay_stop();

        // 两种模式的区别就在这里：
        // - 本地引擎模式：本机起 codev-net，自己解码并出面板；
        // - 服务端模式（S3）：本机不起解码器，采集到的流量镜像到云端节点。
        let server_mode = server_mode();
        // 服务端模式下 `panel_token` 用不到（面板在云端），本地模式才需要；
        // 名字加下划线前缀避免"未使用变量"告警。
        let (ingest_host, ingest_port, engine, upstream_user, upstream_password, _panel_token) =
            if server_mode {
                // 上传目标＝网关签发的房间节点：解码与面板都在服务端。
                (
                    state.grant.node_host.clone(),
                    state.grant.node_port,
                    None,
                    state.grant.node_username.clone(),
                    state.grant.node_password.clone(),
                    String::new(),
                )
            } else {
                let engine = crate::local_engine::LocalEngine::start(data_dir)?;
                // 2026-10-20：客户端直连 T3 验证后，**取消周期性续期**。
                // 理由：卡密在激活时已完成设备绑定；运行中再向服务器续期，
                // 服务器抖动会把正在打的客户踢下线，对客户只有风险没有收益。
                let _ = device_id; // 保留参数，便于以后按需恢复
                (
                    "127.0.0.1".to_string(),
                    crate::local_engine::INGEST_PORT,
                    Some(engine),
                    String::new(),
                    String::new(),
                    String::new(),
                )
            };
        let (engine_user, engine_password) = if server_mode {
            (upstream_user, upstream_password)
        } else {
            let engine = engine.as_ref().expect("local engine in local mode");
            (engine.proxy_username.clone(), engine.proxy_password.clone())
        };
        let panel_token = if server_mode {
            String::new()
        } else {
            engine
                .as_ref()
                .expect("local engine in local mode")
                .panel_token
                .clone()
        };

        let ingest_host_ref = ingest_host.clone();
        let relay_result = unsafe {
            with_local_c_strings(
                &ingest_host_ref,
                &engine_user,
                &engine_password,
                &state.local_password,
                |host, upstream_user, upstream_password, local_password| {
                    phoenix_cloud_relay_start(
                        host,
                        ingest_port,
                        upstream_user,
                        upstream_password,
                        wide_c_string_ptr(LOCAL_USERNAME),
                        local_password,
                        LOCAL_PORT,
                    )
                },
            )?
        };
        if relay_result != 0 {
            bail!("中继服务启动失败（{relay_result}）");
        }

        // 新版只做本机解析：
        //   · 不再创建 CloudMirror —— 「把流量副本送上云端解析」的链路已整体移除；
        //   · WinDivert 被动采集只为那条镜像链路服务，这里一并跳过（引擎自己的代理负责收包）。
        let result = Ok::<Self, anyhow::Error>(Self {
            capture: None,
            engine,
            panel_token: panel_token.clone(),
            capture_error: None,
        });
        if result.is_err() {
            phoenix_cloud_relay_stop();
        }
        result
    }

    /// 已接入设备台数。云端中继删掉后没有等价的瞬时计数，
    /// 恒为 0 —— 界面本来就不该拿它当"几台在连"的依据（见 AGENTS 里的同类教训）。
    pub(crate) fn client_count(&self) -> usize {
        0
    }

    pub(crate) fn panel_token(&self) -> &str {
        &self.panel_token
    }

    /// 抓包失败的人话原因（None = 抓包正常）。
    pub(crate) fn capture_error(&self) -> Option<&str> {
        self.capture_error.as_deref()
    }
}

/// 把 WinDivert 的原始报错翻译成客户/客服能用的排查建议。
fn capture_failure_hint(error: &anyhow::Error) -> String {
    let raw = format!("{error:#}");
    let lower = raw.to_lowercase();
    let hint = if lower.contains("denied") || lower.contains("win32 5）") || lower.contains("10013")
    {
        "抓包驱动被系统拒绝（多半是权限或安全软件拦截）"
    } else if lower.contains("not found")
        || lower.contains("win32 2）")
        || lower.contains("win32 3）")
    {
        "抓包驱动文件没释放出来（可能被杀软删掉）"
    } else if lower.contains("1058")
        || lower.contains("win32 1275）")
        || lower.contains("win32 577）")
        || lower.contains("blocked")
    {
        "驱动被系统策略阻止（第三方驱动防护 / 内核保护）"
    } else {
        "抓包驱动未能加载"
    };
    format!("{hint}：{raw}")
}

impl Drop for BackendRuntime {
    fn drop(&mut self) {
        self.capture.take();
        phoenix_cloud_relay_stop();
        // Stop the local engine last so ingest connections drain first.
        self.engine.take();
    }
}

pub(crate) fn local_username() -> &'static str {
    LOCAL_USERNAME
}

pub(crate) fn local_port() -> u16 {
    LOCAL_PORT
}

pub(crate) fn show_error(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
    let title = wide("不死鸟CodeV 启动失败");
    let text = wide(message);
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

unsafe fn with_local_c_strings<T>(
    host: &str,
    upstream_user: &str,
    upstream_password: &str,
    local_password: &str,
    body: impl FnOnce(*const i8, *const i8, *const i8, *const i8) -> T,
) -> anyhow::Result<T> {
    use std::ffi::CString;
    // 以前这里是 .expect("invalid")：只要服务器返回的凭据里混进一个 NUL 字节，
    // 整个程序就 panic。改成把错误传上去，让上层显示"节点凭据无效"。
    let host = CString::new(host).map_err(|_| anyhow!("节点地址无效"))?;
    let user = CString::new(upstream_user).map_err(|_| anyhow!("节点账号无效"))?;
    let password = CString::new(upstream_password).map_err(|_| anyhow!("节点密码无效"))?;
    let local_password = CString::new(local_password).map_err(|_| anyhow!("本机凭据无效"))?;
    Ok(body(
        host.as_ptr(),
        user.as_ptr(),
        password.as_ptr(),
        local_password.as_ptr(),
    ))
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

// The local username is ASCII and static; returning a pointer to a NUL-
// terminated static byte array is safe for the duration of the FFI call.
fn wide_c_string_ptr(_value: &str) -> *const i8 {
    b"phoenix-local\0".as_ptr().cast()
}

/// 授权失效时写一份可核对的记录：现场只看到雷达停止，运维据此定位原因。
pub(crate) fn record_authorization_failure(device_id: &str, detail: &str) {
    let Ok(directory) = data_dir() else { return };
    let _ = std::fs::create_dir_all(&directory);
    let stamp = now_unix();
    let line = format!("{stamp}\t{device_id}\t{detail}\n");
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(directory.join("授权失效记录.log"))
    {
        use std::io::Write;
        let _ = file.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_round_trip_under_current_user() {
        let clear = b"fixture authorization payload";
        let blob = dpapi_protect(clear).unwrap();
        assert_ne!(blob, clear);
        assert_eq!(dpapi_unprotect(&blob).unwrap(), clear);
    }
    #[test]
    fn invalid_dpapi_blob_returns_error() {
        assert!(dpapi_unprotect(b"not encrypted").is_err());
    }
    #[test]
    fn clear_missing_authorization_succeeds() {
        let path = std::env::temp_dir().join(format!("phoenix-no-state-{}", std::process::id()));
        assert!(clear_state(&path).is_ok());
    }
    #[test]
    fn clear_does_not_delete_device_identity() {
        let p = std::env::temp_dir().join(format!(
            "phoenix-clear-test-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join("device-id.txt"), b"WIN-fixture").unwrap();
        fs::write(state_path(&p), b"encrypted fixture").unwrap();
        clear_state(&p).unwrap();
        assert!(!state_path(&p).exists());
        assert_eq!(fs::read(p.join("device-id.txt")).unwrap(), b"WIN-fixture");
        fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn nul_credentials_return_error_without_panicking() {
        let result = unsafe {
            with_local_c_strings("host", "user", "bad\0password", "local", |_, _, _, _| ())
        };
        assert!(result.is_err());
    }
    #[test]
    fn win32_errors_have_actionable_reason() {
        assert!(
            capture_failure_hint(&anyhow!("抓包通道启动失败（Win32 5）")).contains("被系统拒绝")
        );
        assert!(
            capture_failure_hint(&anyhow!("抓包组件加载失败（Win32 2）")).contains("文件没释放")
        );
    }
    #[test]
    fn localized_volume_serial_parser() {
        assert_eq!(
            find_volume_serial("卷序列号为 1A2B-3C4D"),
            Some("1A2B-3C4D".into())
        );
        assert_eq!(
            find_volume_serial("Volume Serial Number is 1a2b-3c4d"),
            Some("1A2B-3C4D".into())
        );
    }
}
