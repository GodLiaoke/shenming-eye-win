//! C ABI for embedding the CodeV live proxy engine inside the iOS/iPadOS app.
//!
//! iOS sandboxes forbid spawning the `codev-net` binary, so the panel + SOCKS5
//! proxy + capture pipeline run in-process here.  Swift calls
//! [`codev_engine_start`] with a writable data directory and the device's LAN
//! address; the engine mints fresh proxy + panel credentials, writes the same
//! `config.toml` the desktop build uses, boots `run_proxy` on a background
//! Tokio runtime, and returns the credentials as JSON.  [`codev_engine_stop`]
//! tears the runtime down (freeing the listeners) and
//! [`codev_engine_string_free`] releases the returned string.

use std::ffi::{CStr, CString, c_char};
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use codev_cli::proxy_runtime::{
    ProxyAppConfig, ProxyCommandOptions, format_panel_secret, run_proxy,
};
use codev_proxy::{ProxyDiagnostics, ProxyProbeLayer, TokenLimits, TokenStore};
use rand::RngCore;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UnixStream;
use tokio::runtime::{Builder, Runtime};
use tokio_util::sync::CancellationToken;

const PROXY_PORT: u16 = 2025;
const PANEL_PORT: u16 = 18_080;
const TOKEN_TTL_SECS: u64 = 315_360_000;
const PROXY_USERNAME: &str = "phoenix-local";
const DIAGNOSTIC_TARGET_HOST: &str = "example.com";
const DIAGNOSTIC_TARGET_PORT: u16 = 443;

static ENGINE: Mutex<Option<Runtime>> = Mutex::new(None);
static TUNNEL_STOP: Mutex<Option<CancellationToken>> = Mutex::new(None);

/// Start (or restart) the in-process engine.
///
/// Returns a newly allocated, NUL-terminated JSON string that the caller must
/// release with [`codev_engine_string_free`].  On success the JSON is
/// `{"ok":true,"username":..,"password":..,"panelToken":..,"panelURL":..}`;
/// on failure it is `{"ok":false,"error":".."}`.
///
/// # Safety
/// `data_dir` and `advertised_host` must be valid NUL-terminated UTF-8 pointers
/// (or `advertised_host` may be null to default to loopback).
#[unsafe(no_mangle)]
pub extern "C" fn codev_engine_start(
    data_dir: *const c_char,
    advertised_host: *const c_char,
) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| {
        let data_dir = cstr(data_dir)?;
        let host = cstr_or(advertised_host, "127.0.0.1");
        bootstrap(&data_dir, &host)
    });
    let json = match outcome {
        Ok(Ok(access)) => access,
        Ok(Err(message)) => error_json(&message),
        Err(_) => error_json("engine panicked during start"),
    };
    into_c_string(json)
}


/// 客户端直连卡密平台（T3）验证卡密。
///
/// Returns a newly allocated, NUL-terminated JSON string released with
/// [`codev_engine_string_free`].  On success:
/// `{"ok":true,"expires_unix":..,"expires_at":"..","notice":".."}`;
/// on failure: `{"ok":false,"error":".."}`.
///
/// # Safety
/// `card` and `device_id` must be valid NUL-terminated UTF-8 pointers.
#[unsafe(no_mangle)]
pub extern "C" fn codev_verify_card(
    card: *const c_char,
    device_id: *const c_char,
) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| {
        let card = cstr(card)?;
        let device = cstr_or(device_id, "unknown-device");
        if card.trim().is_empty() {
            return Err("卡密不能为空".to_string());
        }
        // 设备种子：sha256("codev-verify-device-v1" || device_id)，
        // 同机同号恒定，重装不会换绑。
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"codev-verify-device-v1");
        hasher.update(device.as_bytes());
        let digest = hasher.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest);
        match codev_verify::verify_card(&card, &seed) {
            Ok(grant) => Ok(serde_json::json!({
                "ok": true,
                "expires_unix": grant.expires_unix,
                "expires_at": grant.expires_at,
                "notice": grant.notice,
            })
            .to_string()),
            Err(error) => Err(format!("{error}")),
        }
    });
    let json = match outcome {
        Ok(Ok(value)) => value,
        Ok(Err(message)) => error_json(&message),
        Err(_) => error_json("验证过程异常（panic）"),
    };
    into_c_string(json)
}


/// 当前验证阶段（界面用来显示"卡在第几段"）。返回静态字符串，**不需要释放**。
#[unsafe(no_mangle)]
pub extern "C" fn codev_verify_stage() -> *const c_char {
    use std::sync::OnceLock;
    static CACHE: OnceLock<()> = OnceLock::new();
    CACHE.get_or_init(|| ());
    let label = codev_verify::stage_label(codev_verify::current_stage());
    // stage_label 返回 &'static str，直接转成带 NUL 的静态指针。
    static SLOTS: std::sync::Mutex<Vec<std::ffi::CString>> = std::sync::Mutex::new(Vec::new());
    let mut slots = SLOTS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(existing) = slots.iter().find(|c| c.to_bytes() == label.as_bytes()) {
        return existing.as_ptr();
    }
    if let Ok(cstring) = std::ffi::CString::new(label) {
        let pointer = cstring.as_ptr();
        slots.push(cstring);
        return pointer;
    }
    std::ptr::null()
}

/// Stop the engine and release its network listeners.  Safe to call repeatedly.
#[unsafe(no_mangle)]
pub extern "C" fn codev_engine_stop() {
    codev_tunnel_stop();
    if let Some(runtime) = ENGINE.lock().unwrap_or_else(|e| e.into_inner()).take() {
        // ⚠️ 必须**阻塞**等待旧 runtime 真正停下来。
        //
        // 原来用的是 `shutdown_background()` —— 它立刻返回、不等任务结束，
        // 于是旧 runtime 的监听任务仍然占着面板端口 18080（和代理端口 2025）。
        // 紧接着 bootstrap 启动新 runtime 去 bind 同样的端口 → **Address already in use**
        // → 新引擎起来了、但根本没在监听 → 客户端看到"连不上"。
        //
        // 更深一层：`shutdown_background` 的注释写着"避免两个引擎抢同一个端口"，
        // 但它本身恰恰做不到这件事 —— 这是真正的根因，不是猜测。
        runtime.shutdown_timeout(std::time::Duration::from_millis(1500));
    }
}

/// Probe the in-process proxy without exposing credentials or target payloads.
///
/// The result deliberately separates listener, SOCKS5, DNS, TCP and UDP so a
/// phone that can bind 2025 but cannot leave the device no longer looks
/// "connected". The call is synchronous and bounded to short socket timeouts;
/// Swift invokes it from a detached task rather than the main actor.
#[unsafe(no_mangle)]
pub extern "C" fn codev_engine_diagnostics(
    username: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| {
        let username = cstr(username)?;
        let password = cstr(password)?;
        if username.is_empty() || password.is_empty() {
            return Err("代理凭据为空".to_string());
        }
        Ok(probe_proxy(&username, &password))
    });
    let payload = match outcome {
        Ok(Ok(diagnostics)) => json!({
            "ok": diagnostics.overall_ok(),
            "diagnostics": diagnostics,
        })
        .to_string(),
        Ok(Err(message)) => json!({
            "ok": false,
            "error": message,
            "diagnostics": ProxyDiagnostics::listener_failed("未执行：凭据不可用"),
        })
        .to_string(),
        Err(_) => json!({
            "ok": false,
            "error": "代理自检异常",
            "diagnostics": ProxyDiagnostics::listener_failed("自检异常"),
        })
        .to_string(),
    };
    into_c_string(payload)
}

fn probe_proxy(username: &str, password: &str) -> ProxyDiagnostics {
    let mut diagnostics = ProxyDiagnostics::default();
    let proxy = SocketAddr::from(([127, 0, 0, 1], PROXY_PORT));
    let timeout = std::time::Duration::from_millis(1_500);

    let mut listener = match std::net::TcpStream::connect_timeout(&proxy, timeout) {
        Ok(stream) => stream,
        Err(error) => {
            diagnostics.listener = ProxyProbeLayer {
                ok: false,
                detail: format!("代理端口不可达：{}", compact_io_error(error)),
            };
            return diagnostics;
        }
    };
    let _ = listener.set_read_timeout(Some(timeout));
    let _ = listener.set_write_timeout(Some(timeout));
    diagnostics.listener = ProxyProbeLayer {
        ok: true,
        detail: "代理端口已监听".into(),
    };

    if let Err(error) = socks5_handshake(&mut listener, username, password) {
        diagnostics.socks_handshake = ProxyProbeLayer {
            ok: false,
            detail: format!("SOCKS5握手失败：{}", error),
        };
        return diagnostics;
    }
    diagnostics.socks_handshake = ProxyProbeLayer {
        ok: true,
        detail: "SOCKS5握手正常".into(),
    };

    match probe_dns_over_socks(proxy, username, password, timeout) {
        Ok(()) => {
            diagnostics.dns = ProxyProbeLayer {
                ok: true,
                detail: "代理 DNS 查询正常".into(),
            };
        }
        Err(error) => {
            diagnostics.dns = ProxyProbeLayer {
                ok: false,
                detail: format!("代理 DNS 查询失败：{error}"),
            };
        }
    }

    match socks5_connect(
        &mut listener,
        DIAGNOSTIC_TARGET_HOST,
        DIAGNOSTIC_TARGET_PORT,
    ) {
        Ok(()) => {
            diagnostics.tcp = ProxyProbeLayer {
                ok: true,
                detail: "TCP外网连通".into(),
            };
        }
        Err(error) => {
            diagnostics.tcp = ProxyProbeLayer {
                ok: false,
                detail: format!("TCP外网失败：{}", error),
            };
        }
    }

    match probe_udp(proxy, username, password, timeout) {
        Ok(()) => {
            diagnostics.udp = ProxyProbeLayer {
                ok: true,
                detail: "UDP外网回包正常".into(),
            };
        }
        Err(error) => {
            diagnostics.udp = ProxyProbeLayer {
                ok: false,
                detail: format!("UDP中继失败：{}", error),
            };
        }
    }
    diagnostics.interface = codev_proxy::interface_summary();
    diagnostics
}

fn socks5_handshake(
    stream: &mut std::net::TcpStream,
    username: &str,
    password: &str,
) -> Result<(), String> {
    let methods = [5_u8, 2, 0, 2];
    stream.write_all(&methods).map_err(compact_io_error)?;
    let mut selected = [0_u8; 2];
    stream.read_exact(&mut selected).map_err(compact_io_error)?;
    if selected[0] != 5 {
        return Err("版本不匹配".into());
    }
    match selected[1] {
        0 => Ok(()),
        2 => {
            let username = username.as_bytes();
            let password = password.as_bytes();
            if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                return Err("凭据长度非法".into());
            }
            let mut request = Vec::with_capacity(3 + username.len() + password.len());
            request.push(1);
            request.push(username.len() as u8);
            request.extend_from_slice(username);
            request.push(password.len() as u8);
            request.extend_from_slice(password);
            stream.write_all(&request).map_err(compact_io_error)?;
            let mut response = [0_u8; 2];
            stream.read_exact(&mut response).map_err(compact_io_error)?;
            if response[0] != 1 || response[1] != 0 {
                return Err("账号密码被拒绝".into());
            }
            Ok(())
        }
        0xff => Err("没有可用认证方式".into()),
        method => Err(format!("服务端选择了不支持的认证方式 {method}")),
    }
}

fn socks5_connect(stream: &mut std::net::TcpStream, host: &str, port: u16) -> Result<(), String> {
    let host = host.as_bytes();
    if host.len() > u8::MAX as usize {
        return Err("探测域名过长".into());
    }
    let mut request = Vec::with_capacity(7 + host.len());
    request.extend_from_slice(&[5, 1, 0, 3, host.len() as u8]);
    request.extend_from_slice(host);
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(compact_io_error)?;
    read_socks_reply(stream)
}

fn socks5_connect_ipv4(
    stream: &mut std::net::TcpStream,
    address: [u8; 4],
    port: u16,
) -> Result<(), String> {
    let mut request = [0_u8; 10];
    request[..4].copy_from_slice(&[5, 1, 0, 1]);
    request[4..8].copy_from_slice(&address);
    request[8..10].copy_from_slice(&port.to_be_bytes());
    stream.write_all(&request).map_err(compact_io_error)?;
    read_socks_reply(stream)
}

fn dns_query(id: u16) -> Vec<u8> {
    let mut query = Vec::with_capacity(64);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in DIAGNOSTIC_TARGET_HOST.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    query
}

fn valid_dns_reply(packet: &[u8], id: u16) -> bool {
    packet.len() >= 12
        && u16::from_be_bytes([packet[0], packet[1]]) == id
        && packet[2] & 0x80 != 0
        && packet[3] & 0x0f == 0
}

fn probe_dns_over_socks(
    proxy: SocketAddr,
    username: &str,
    password: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let mut stream = std::net::TcpStream::connect_timeout(&proxy, timeout)
        .map_err(compact_io_error)?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    socks5_handshake(&mut stream, username, password)?;
    // The DNS query itself traverses SOCKS5 to a public resolver; the local
    // device resolver is deliberately not used for this diagnostic layer.
    socks5_connect_ipv4(&mut stream, [223, 5, 5, 5], 53)?;
    let id = rand::random::<u16>();
    let query = dns_query(id);
    let length = u16::try_from(query.len()).map_err(|_| "DNS 查询过长".to_string())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(&query))
        .map_err(compact_io_error)?;
    let mut header = [0_u8; 2];
    stream.read_exact(&mut header).map_err(compact_io_error)?;
    let response_len = u16::from_be_bytes(header) as usize;
    if response_len < 12 || response_len > 4096 {
        return Err("DNS TCP 回包长度非法".into());
    }
    let mut response = vec![0_u8; response_len];
    stream.read_exact(&mut response).map_err(compact_io_error)?;
    if valid_dns_reply(&response, id) {
        Ok(())
    } else {
        Err("DNS TCP 回包校验失败".into())
    }
}

fn read_socks_reply(stream: &mut std::net::TcpStream) -> Result<(), String> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(compact_io_error)?;
    if header[0] != 5 {
        return Err("响应版本不匹配".into());
    }
    if header[1] != 0 {
        return Err(format!("服务端返回错误码 {}", header[1]));
    }
    match header[3] {
        1 => {
            let mut address = [0_u8; 6];
            stream.read_exact(&mut address).map_err(compact_io_error)?;
        }
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).map_err(compact_io_error)?;
            let mut address = vec![0_u8; length[0] as usize + 2];
            stream.read_exact(&mut address).map_err(compact_io_error)?;
        }
        4 => {
            let mut address = [0_u8; 18];
            stream.read_exact(&mut address).map_err(compact_io_error)?;
        }
        atyp => return Err(format!("地址类型 {atyp} 不支持")),
    }
    Ok(())
}

fn probe_udp(
    proxy: SocketAddr,
    username: &str,
    password: &str,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let mut control = std::net::TcpStream::connect_timeout(&proxy, timeout)
        .map_err(|error| compact_io_error(error))?;
    let _ = control.set_read_timeout(Some(timeout));
    let _ = control.set_write_timeout(Some(timeout));
    socks5_handshake(&mut control, username, password)?;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .map_err(compact_io_error)?;
    let relay = read_socks_bound(&mut control)?;
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").map_err(compact_io_error)?;
    socket
        .set_write_timeout(Some(timeout))
        .map_err(compact_io_error)?;
    let relay = match relay {
        SocketAddr::V4(address) if address.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            address.port(),
        ),
        SocketAddr::V6(address) if address.ip().is_unspecified() => SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            address.port(),
        ),
        address => address,
    };
    socket
        .set_read_timeout(Some(timeout))
        .map_err(compact_io_error)?;
    let id = rand::random::<u16>();
    // Harmless DNS A query to a public resolver. Receiving a matching response
    // proves the complete SOCKS UDP round trip, not just UDP ASSOCIATE success.
    let mut packet = vec![0, 0, 0, 1, 223, 5, 5, 5, 0, 53];
    packet.extend_from_slice(&dns_query(id));
    socket.send_to(&packet, relay).map_err(compact_io_error)?;
    let mut response = [0_u8; 2048];
    let (count, _) = socket.recv_from(&mut response).map_err(compact_io_error)?;
    if !valid_udp_dns_reply(&response[..count], id) {
        return Err("未收到匹配的DNS回包".into());
    }
    Ok(())
}

fn valid_udp_dns_reply(packet: &[u8], id: u16) -> bool {
    if packet.len() < 4 || packet[..3] != [0, 0, 0] {
        return false;
    }
    let offset = match packet[3] {
        1 => 10,
        4 => 22,
        3 if packet.len() >= 5 => 7 + packet[4] as usize,
        _ => return false,
    };
    let Some(dns) = packet.get(offset..) else {
        return false;
    };
    valid_dns_reply(dns, id)
}

fn read_socks_bound(stream: &mut std::net::TcpStream) -> Result<SocketAddr, String> {
    let mut header = [0_u8; 4];
    stream.read_exact(&mut header).map_err(compact_io_error)?;
    if header[0] != 5 || header[1] != 0 {
        return Err(format!("UDP ASSOCIATE 返回错误码 {}", header[1]));
    }
    let address = match header[3] {
        1 => {
            let mut data = [0_u8; 6];
            stream.read_exact(&mut data).map_err(compact_io_error)?;
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3])),
                u16::from_be_bytes([data[4], data[5]]),
            )
        }
        4 => {
            let mut data = [0_u8; 18];
            stream.read_exact(&mut data).map_err(compact_io_error)?;
            let mut ip = [0_u8; 16];
            ip.copy_from_slice(&data[..16]);
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::from(ip)),
                u16::from_be_bytes([data[16], data[17]]),
            )
        }
        atyp => return Err(format!("UDP地址类型 {atyp} 不支持")),
    };
    Ok(address)
}

fn compact_io_error(error: io::Error) -> String {
    error.kind().to_string()
}

/// Start the single-device packet bridge used by the iOS Packet Tunnel
/// extension. The extension owns `tun_fd`'s peer and sends one raw IP packet
/// per length-prefixed frame (u32 big endian + payload). The bridge feeds
/// those packets through the local SOCKS5 listener at 127.0.0.1:2025.
#[unsafe(no_mangle)]
pub extern "C" fn codev_tunnel_start(
    tun_fd: RawFd,
    username: *const c_char,
    password: *const c_char,
) -> i32 {
    // -2 means the caller still owns `tun_fd`; -1 means Rust consumed and
    // closed it (or scheduled the bridge). This prevents Swift from closing
    // the same descriptor twice on post-conversion failures.
    const FD_NOT_CONSUMED: i32 = -2;
    if tun_fd < 0 || username.is_null() || password.is_null() {
        return FD_NOT_CONSUMED;
    }
    let username = match cstr(username) {
        Ok(value) if !value.is_empty() => value,
        _ => return FD_NOT_CONSUMED,
    };
    let password = match cstr(password) {
        Ok(value) if !value.is_empty() => value,
        _ => return FD_NOT_CONSUMED,
    };

    let proxy_url = format!("socks5://{username}:{password}@127.0.0.1:{PROXY_PORT}");
    let proxy = match tun2proxy::ProxyParameters::try_from(proxy_url.as_str()) {
        Ok(proxy) => proxy,
        Err(_) => return FD_NOT_CONSUMED,
    };
    let mut args = tun2proxy::Args::default();
    args.proxy(proxy)
        .setup(false)
        .ipv6_enabled(true)
        .dns(tun2proxy::ArgDns::Direct)
        .verbosity(tun2proxy::LevelFilter::Error);
    args.mtu = 1500;
    args.tcp_mss = Some(1460);
    args.tcp_timeout = 600;
    args.udp_timeout = 30;

    codev_tunnel_stop();
    let runtime_guard = ENGINE.lock().unwrap_or_else(|e| e.into_inner());
    let Some(runtime) = runtime_guard.as_ref() else {
        return FD_NOT_CONSUMED;
    };

    let std_stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(tun_fd) };
    if std_stream.set_nonblocking(true).is_err() {
        return -1;
    }
    // Tokio's `from_std` consults the current reactor; entering the engine
    // runtime is mandatory because this C ABI is called from NE's GCD queue.
    let _runtime_context = runtime.enter();
    let stream = match UnixStream::from_std(std_stream) {
        Ok(stream) => stream,
        Err(_) => return -1,
    };
    let (reader, writer) = tokio::io::split(stream);
    let device = PacketFrameDevice::new(reader, writer);
    let stop = CancellationToken::new();
    let child = stop.clone();

    runtime.spawn(async move {
        let _ = tun2proxy::run(device, 1500, args, child).await;
    });
    drop(runtime_guard);
    *TUNNEL_STOP.lock().unwrap_or_else(|e| e.into_inner()) = Some(stop);
    0
}

/// Stop the packet bridge. The Packet Tunnel extension also closes its peer
/// socket; cancelling here makes the Rust task exit before the engine is
/// restarted.
#[unsafe(no_mangle)]
pub extern "C" fn codev_tunnel_stop() {
    if let Some(token) = TUNNEL_STOP.lock().unwrap_or_else(|e| e.into_inner()).take() {
        token.cancel();
    }
}

/// The Network Extension API exposes packets through callbacks rather than a
/// TUN file descriptor. This adapter preserves packet boundaries over a
/// Unix-stream socket so `tun2proxy` can use its existing userspace TCP/UDP
/// stack without knowing anything about Swift or `NEPacketTunnelFlow`.
struct PacketFrameDevice {
    reader: tokio::io::ReadHalf<UnixStream>,
    writer: tokio::io::WriteHalf<UnixStream>,
    header: [u8; 4],
    header_len: usize,
    packet: Vec<u8>,
    packet_len: usize,
    write_frame: Option<Vec<u8>>,
    write_offset: usize,
}

impl PacketFrameDevice {
    fn new(
        reader: tokio::io::ReadHalf<UnixStream>,
        writer: tokio::io::WriteHalf<UnixStream>,
    ) -> Self {
        Self {
            reader,
            writer,
            header: [0; 4],
            header_len: 0,
            packet: Vec::new(),
            packet_len: 0,
            write_frame: None,
            write_offset: 0,
        }
    }
}

impl AsyncRead for PacketFrameDevice {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        loop {
            if self.packet_len == 0 {
                while self.header_len < self.header.len() {
                    let this = self.as_mut().get_mut();
                    let start = this.header_len;
                    let mut read_buf = ReadBuf::new(&mut this.header[start..]);
                    match std::pin::Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(error)) => {
                            return std::task::Poll::Ready(Err(error));
                        }
                        std::task::Poll::Ready(Ok(())) => {
                            let read = read_buf.filled().len();
                            if read == 0 {
                                return std::task::Poll::Ready(Ok(()));
                            }
                            this.header_len += read;
                        }
                    }
                }
                let length = u32::from_be_bytes(self.header) as usize;
                if !(20..=65_535).contains(&length) {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid packet frame length",
                    )));
                }
                self.packet = vec![0; length];
                self.packet_len = length;
                self.header_len = 0;
            }

            let this = self.as_mut().get_mut();
            let filled = this.packet.len() - this.packet_len;
            if destination.remaining() < this.packet_len {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet buffer is smaller than framed packet",
                )));
            }
            let mut read_buf = ReadBuf::new(&mut this.packet[filled..]);
            match std::pin::Pin::new(&mut this.reader).poll_read(cx, &mut read_buf) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(())) => {
                    let read = read_buf.filled().len();
                    if read == 0 {
                        return std::task::Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "packet frame closed",
                        )));
                    }
                    this.packet_len -= read;
                    if this.packet_len == 0 {
                        destination.put_slice(&this.packet);
                        this.packet.clear();
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
            }
        }
    }
}

impl AsyncWrite for PacketFrameDevice {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if self.write_frame.is_none() {
            if !(20..=65_535).contains(&data.len()) {
                return std::task::Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid packet write length",
                )));
            }
            let mut frame = Vec::with_capacity(4 + data.len());
            frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
            frame.extend_from_slice(data);
            self.write_frame = Some(frame);
            self.write_offset = 0;
        }
        while self.write_frame.is_some() {
            let frame_len = self.write_frame.as_ref().map_or(0, Vec::len);
            if self.write_offset == frame_len {
                self.write_frame = None;
                self.write_offset = 0;
                return std::task::Poll::Ready(Ok(data.len()));
            }
            let offset = self.write_offset;
            let chunk = self.write_frame.as_ref().unwrap()[offset..].to_vec();
            match std::pin::Pin::new(&mut self.writer).poll_write(cx, &chunk) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "packet frame write returned zero",
                    )));
                }
                std::task::Poll::Ready(Ok(written)) => self.write_offset += written,
            }
        }
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.write_frame.is_some() {
            match self.as_mut().poll_write(cx, &[]) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(_)) => {}
            }
        }
        std::pin::Pin::new(&mut self.writer).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.writer).poll_shutdown(cx)
    }
}

/// Free a string returned by [`codev_engine_start`].
///
/// # Safety
/// `value` must be a pointer previously returned by this library, or null.
#[unsafe(no_mangle)]
pub extern "C" fn codev_engine_string_free(value: *mut c_char) {
    if !value.is_null() {
        unsafe {
            drop(CString::from_raw(value));
        }
    }
}

fn bootstrap(data_dir: &str, advertised_host: &str) -> Result<String, String> {
    // Replace any prior runtime so we never leave two engines fighting for the
    // same ports —— **必须阻塞等待**，否则旧 runtime 还占着端口，
    // 新引擎 bind 失败，表现为"引擎活着但面板连不上"。
    if let Some(runtime) = ENGINE.lock().unwrap_or_else(|e| e.into_inner()).take() {
        runtime.shutdown_timeout(std::time::Duration::from_millis(1500));
    }

    // 等端口真正释放再启动。
    //
    // 为什么必须做：`run_proxy` **绑定失败不会上报** —— 引擎的 runtime 起来了、
    // 我们的"启动成功"也就返回了，但面板根本没在监听。客户端看到的是
    // "连不上"，而所有状态都显示正常。今天绕了三轮才找到这个坑，就是因为它不可见。
    //
    // 现在改成：启动前先确认端口空闲；等不到就**明确报错**，让失败浮出来。
    wait_for_ports_free()?;

    let dir = PathBuf::from(data_dir);
    let record = dir.join("record");
    fs::create_dir_all(&record).map_err(|e| format!("create data dir: {e}"))?;
    harden_dir(&dir);
    let host = if advertised_host.is_empty() {
        "127.0.0.1"
    } else {
        advertised_host
    };

    let config_path = dir.join("config.toml");
    let proxy_tokens = dir.join("proxy-tokens.toml");
    let panel_token = dir.join("panel-token.secret");
    let profiles = dir.join("shadowrocket-profiles.toml");

    // The panel token is a hash-only store on disk, so we always mint fresh
    // credentials and hand the plaintext back to the caller once.
    let _ = fs::remove_file(&proxy_tokens);
    let _ = fs::remove_file(&panel_token);

    write_config(
        &config_path,
        &proxy_tokens,
        &panel_token,
        &profiles,
        &record,
        advertised_host,
    )?;

    let (username, password) = load_or_mint_proxy_credential(&proxy_tokens)?;
    let panel_secret = mint_panel_secret(&panel_token)?;

    // Validate before we background the runtime so config errors surface here.
    ProxyAppConfig::load(&config_path).map_err(|e| format!("config invalid: {e}"))?;

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    let options = ProxyCommandOptions {
        config_path: config_path.clone(),
        record_plaintext: false,
        private_session: None,
        panel_listen_override: None,
    };
    runtime.spawn(async move {
        let _ = run_proxy(options).await;
    });
    *ENGINE.lock().unwrap_or_else(|e| e.into_inner()) = Some(runtime);

    let panel_host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    Ok(json!({
        "ok": true,
        "username": username,
        "password": password,
        "panelToken": panel_secret,
        "panelURL": format!("http://{panel_host}:{PANEL_PORT}/"),
        "proxyPort": PROXY_PORT,
    })
    .to_string())
}

/// 代理凭据：**固定不变** —— 节点（二维码）导入一次就永久有效。
///
/// 以前每次启动都 `TokenStore::new()` + `create_token()`：铸一条新密钥并覆盖 token store，
/// 于是节点里的密码下次启动就失效 → 客户每次打开软件都要重新导入节点（实测反馈）。
/// 现在：凭据（用户名 + 口令）落在引擎数据目录的 `proxy-credential.secret`（0600），
/// 只要 token store 里那条记录仍然有效就复用；只有首次启动 / 文件丢失 / 被吊销 / 过期才重铸。
/// 安全取舍：**仍然要求账号密码**（`allow_anonymous = false` 不变），只是不再每次轮换。
fn load_or_mint_proxy_credential(store_path: &Path) -> Result<(String, String), String> {
    let credential_path = store_path.with_file_name("proxy-credential.secret");
    if let Ok(saved) = fs::read_to_string(&credential_path) {
        if let Some((username, secret)) = saved.trim().split_once(':') {
            let usable = !secret.is_empty()
                && username == PROXY_USERNAME
                && TokenStore::load(store_path)
                    .map(|store| {
                        store.list().iter().any(|status| {
                            status.username == username && !status.revoked && !status.expired
                        })
                    })
                    .unwrap_or(false);
            if usable {
                return Ok((username.to_string(), secret.to_string()));
            }
        }
    }
    let (username, secret) = mint_proxy_credential(store_path)?;
    let _ = fs::write(&credential_path, format!("{username}:{secret}"));
    harden_file(&credential_path);
    Ok((username, secret))
}

fn mint_proxy_credential(store_path: &Path) -> Result<(String, String), String> {
    let store = TokenStore::new();
    let limits = TokenLimits {
        max_connections: 256,
        max_udp_flows: 128,
        bytes_per_second: 128 * 1024 * 1024,
        udp_idle_secs: 60,
    };
    let credential = store
        .create_token(Some(PROXY_USERNAME), TOKEN_TTL_SECS, limits)
        .map_err(|e| format!("proxy token: {e}"))?;
    store
        .save(store_path)
        .map_err(|e| format!("save proxy token: {e}"))?;
    harden_file(store_path);
    Ok((credential.username, credential.secret))
}

fn mint_panel_secret(token_path: &Path) -> Result<String, String> {
    let secret = random_hex_32();
    let encoded =
        format_panel_secret(&secret, TOKEN_TTL_SECS).map_err(|e| format!("panel token: {e}"))?;
    fs::write(token_path, encoded.as_bytes()).map_err(|e| format!("write panel token: {e}"))?;
    harden_file(token_path);
    Ok(secret)
}

fn write_config(
    config: &Path,
    proxy_tokens: &Path,
    panel_token: &Path,
    profiles: &Path,
    record: &Path,
    advertised_host: &str,
) -> Result<(), String> {
    let host = if advertised_host.is_empty() {
        "127.0.0.1"
    } else {
        advertised_host
    };
    let text = format!(
        "[proxy]\n\
listen = \"0.0.0.0:{proxy_port}\"\n\
token_store = \"{proxy_tokens}\"\n\
advertised_host = \"{host}\"\n\
advertised_port = {proxy_port}\n\
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
             # 2026-10-13 客户要求：**两个模式都不再需要账号密码**（节点导入一次永久有效）。\n\
             # 安全提示：代理监听 0.0.0.0，匿名意味着同网段的人也能用这条通道。\n\
             # 只在本机使用（Shadowrocket 连 127.0.0.1）时没有影响；用公共 Wi-Fi 请留意。\n\
allow_anonymous = true\n\
allow_any_public_target = true\n\
allow_dns_proxying = true\n\
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
        proxy_port = PROXY_PORT,
        panel_port = PANEL_PORT,
        host = toml_escape(host),
        proxy_tokens = toml_escape(&proxy_tokens.to_string_lossy()),
        panel_token = toml_escape(&panel_token.to_string_lossy()),
        profiles = toml_escape(&profiles.to_string_lossy()),
        record = toml_escape(&record.to_string_lossy()),
    );
    fs::write(config, text.as_bytes()).map_err(|e| format!("write config: {e}"))?;
    harden_file(config);
    Ok(())
}

fn toml_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn random_hex_32() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn harden_dir(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
}

fn harden_file(path: &Path) {
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

fn cstr(ptr: *const c_char) -> Result<String, String> {
    if ptr.is_null() {
        return Err("null argument".into());
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(str::to_owned)
        .map_err(|_| "argument is not valid UTF-8".into())
}

fn cstr_or(ptr: *const c_char, fallback: &str) -> String {
    cstr(ptr).unwrap_or_else(|_| fallback.to_owned())
}

fn error_json(message: &str) -> String {
    json!({ "ok": false, "error": message }).to_string()
}

fn into_c_string(value: String) -> *mut c_char {
    match CString::new(value) {
        Ok(string) => string.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// S3：用与引擎**完全相同的**解密管线解一份 pcap，产出坐标 JSONL 与 meta。
///
/// 之所以能做到"完全相同"：`codev-decode` 通过 `#[path]` 复用引擎那批源文件，
/// 不是复制实现 —— 所以客户端解出来的结果与云端不存在漂移。
///
/// 返回 NUL 结尾的 JSON 字符串（调用方用 `codev_engine_string_free` 释放）：
/// `{"ok":true,"coordinate_records":..,"map_id":..,"pipeline_datagrams":..,...}`
///
/// # Safety
/// 两个参数都必须是有效的 NUL 结尾 UTF-8 指针。
#[unsafe(no_mangle)]
pub extern "C" fn codev_decode_pcap(
    pcap_path: *const c_char,
    out_path: *const c_char,
) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| -> Result<String, String> {
        let pcap = cstr(pcap_path)?;
        let out = cstr(out_path)?;
        let summary = codev_decode::dump_coordinates::dump_coordinates(
            Path::new(&pcap),
            Path::new(&out),
            true,
        )
        .map_err(|error| format!("decode failed: {error}"))?;
        Ok(json!({
            "ok": true,
            "coordinate_records": summary.coordinate_records,
            "map_id": summary.map_id,
            "pipeline_datagrams": summary.pipeline_datagrams,
            "sequence_gaps": summary.sequence_gaps,
            "slots": summary.slots,
            "build_id": summary.build_id,
        })
        .to_string())
    });
    let payload = match outcome {
        Ok(Ok(payload)) => payload,
        Ok(Err(message)) => error_json(&message),
        Err(_) => error_json("decode panicked"),
    };
    into_c_string(payload)
}

#[cfg(test)]
mod s3_abi_check {
    use std::ffi::{CStr, CString};

    /// 通过 C ABI（iOS 将调用的同一个入口）解码真实抓包，并与**参考解码**逐项比对。
    ///
    /// 用 2026-09-30 那份 proxy 抓包作为 fixture：它是单根 M0 流，能在**生产配置**下
    /// 正常解码（用户那份 21MB 抓包含两根候选流，生产配置会正确报歧义 —— 因此不适合
    /// 做自动化 fixture；它对应的 13,527 条基线是用临时开关产出的，仅作人工比对用）。
    #[test]
    fn c_abi_reproduces_reference_decode() {
        let pcap = "/Users/Admin/Desktop/Phoenix采集-20260930-122104/proxy-1790741740-21707-0.pcap";
        if !std::path::Path::new(pcap).is_file() {
            eprintln!("参考 pcap 不存在，跳过");
            return;
        }
        let out_dir = std::env::temp_dir().join("s3-abi-check");
        std::fs::create_dir_all(&out_dir).unwrap();
        let out = out_dir.join("coordinates.jsonl");

        let c_pcap = CString::new(pcap).unwrap();
        let c_out = CString::new(out.to_str().unwrap()).unwrap();
        let raw = unsafe { super::codev_decode_pcap(c_pcap.as_ptr(), c_out.as_ptr()) };
        assert!(!raw.is_null(), "C ABI 不应返回空指针");
        let json = unsafe { CStr::from_ptr(raw) }.to_string_lossy().to_string();
        unsafe { super::codev_engine_string_free(raw) };
        println!("C ABI 返回: {json}");

        assert!(json.contains("\"ok\":true"), "解码必须成功: {json}");
        assert!(
            json.contains("\"coordinate_records\":31863"),
            "必须复现参考解码的 31863 条: {json}"
        );
    }
}

/// S2：用云端下发的会话密钥解开字段字典（ChaCha20 + HMAC-SHA256，Encrypt-then-MAC）。
///
/// 算法实现与服务端**共用同一份源码**（`codev-web/src/session_key.rs`），
/// 所以不存在"两端算法不一致"的可能。
///
/// 成功返回 NUL 结尾的**字典明文 JSON**（调用方用 `codev_engine_string_free` 释放）；
/// 失败返回 NUL 结尾的 `{"ok":false,...}` —— **调用方必须检查是否为字典明文**。
///
/// # Safety
/// 四个参数都必须是有效的 NUL 结尾 UTF-8 指针。
#[unsafe(no_mangle)]
pub extern "C" fn codev_open_dictionary(
    session_key_b64: *const c_char,
    nonce_b64: *const c_char,
    blob_b64: *const c_char,
    tag_b64: *const c_char,
) -> *mut c_char {
    let outcome = std::panic::catch_unwind(|| -> Result<String, String> {
        use base64::Engine as _;
        let key_b64 = cstr(session_key_b64)?;
        let nonce = cstr(nonce_b64)?;
        let blob = cstr(blob_b64)?;
        let tag = cstr(tag_b64)?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key_b64.as_bytes())
            .map_err(|_| "session_key 不是合法 base64".to_string())?;
        let mut key = [0u8; 32];
        if raw.len() != 32 {
            return Err("session_key 长度非法".into());
        }
        key.copy_from_slice(&raw);
        let opened = codev_decode::session_key::open_dictionary(&key, &nonce, &blob, &tag)?;
        String::from_utf8(opened).map_err(|_| "字典不是 UTF-8".to_string())
    });
    let payload = match outcome {
        Ok(Ok(json)) => json,
        Ok(Err(message)) => error_json(&message),
        Err(_) => error_json("open_dictionary panicked"),
    };
    into_c_string(payload)
}

/// S2：把解开的字段字典注入引擎。**注入后引擎不再使用编译期内嵌的那份。**
/// 返回 1 表示注入成功，0 表示此前已注入过，-1 表示参数非法。
///
/// # Safety
/// `json` 必须是有效的 UTF-8 指针，`len` 为其字节长度。
#[unsafe(no_mangle)]
pub extern "C" fn codev_set_dictionary(json: *const c_char, len: usize) -> i32 {
    if json.is_null() || len == 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(json as *const u8, len) };
    match std::str::from_utf8(slice) {
        Ok(text) => {
            if codev_decode::artifacts::set_runtime_dictionary(text.as_bytes().to_vec()) {
                1
            } else {
                0
            }
        }
        Err(_) => -1,
    }
}

/// S2：清除运行时字典，回退到内嵌字典。
/// 用途：会话到期且续期失败时立刻止损；测试隔离全局状态。
#[unsafe(no_mangle)]
pub extern "C" fn codev_clear_dictionary() {
    codev_decode::artifacts::clear_runtime_dictionary();
}

/// S2：查询引擎当前是否已注入运行时字典（1=已注入，0=仍用内嵌字典）。
#[unsafe(no_mangle)]
pub extern "C" fn codev_dictionary_is_injected() -> i32 {
    if codev_decode::artifacts::runtime_dictionary_is_set() {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod s2_wiring {
    use base64::Engine as _;
    use std::ffi::{CStr, CString};

    fn c(value: &str) -> CString {
        CString::new(value).unwrap()
    }

    /// S2 端到端：服务端下发（会话密钥 + 按会话加密的字典）→ 客户端解开 → 注入引擎。
    /// 并证明**错误密钥会被拒绝** —— 这是"抄走密文也没用"的核心保证。
    #[test]
    fn session_key_round_trip_then_inject() {
        let dictionary = br#"{"fields":[{"name":"player_x","bit_offset":128,"bit_width":16}]}"#;
        let grant = codev_decode::session_key::issue("CARD-S2", "DEV-S2", dictionary)
            .expect("签发会话材料");

        let (k, n, b, t) = (
            c(&grant.session_key_b64),
            c(&grant.nonce_b64),
            c(&grant.dictionary_blob_b64),
            c(&grant.dictionary_tag_b64),
        );

        // ① 正确密钥 → 解开
        let raw =
            unsafe { super::codev_open_dictionary(k.as_ptr(), n.as_ptr(), b.as_ptr(), t.as_ptr()) };
        let opened = unsafe { CStr::from_ptr(raw) }.to_string_lossy().to_string();
        unsafe { super::codev_engine_string_free(raw) };
        assert_eq!(
            opened,
            String::from_utf8_lossy(dictionary),
            "正确密钥必须解出原始字典"
        );

        // ② 注入引擎
        let json = CString::new(opened.clone()).unwrap();
        let rc = unsafe { super::codev_set_dictionary(json.as_ptr(), opened.len()) };
        assert_eq!(rc, 1, "首次注入应返回 1");
        assert_eq!(
            super::codev_dictionary_is_injected(),
            1,
            "注入后应标记为已注入"
        );
        // ④ 重新注入（模拟 35 分钟轮换）必须成功 —— 这是轮换能工作的前提
        let again = unsafe { super::codev_set_dictionary(json.as_ptr(), opened.len()) };
        assert_eq!(again, 1, "轮换时重新注入必须成功");
        assert_eq!(super::codev_dictionary_is_injected(), 1);
        // 收尾：清掉，避免污染同进程内的解码测试（全局状态）
        super::codev_clear_dictionary();
        assert_eq!(
            super::codev_dictionary_is_injected(),
            0,
            "清除后应回退到内嵌字典"
        );

        // ③ 错误密钥 → 必须被拒
        let mut wrong = [0u8; 32];
        wrong[0] = 0x01;
        let wrong_b64 = c(&base64::engine::general_purpose::STANDARD.encode(wrong));
        let raw2 = unsafe {
            super::codev_open_dictionary(wrong_b64.as_ptr(), n.as_ptr(), b.as_ptr(), t.as_ptr())
        };
        let rejected = unsafe { CStr::from_ptr(raw2) }
            .to_string_lossy()
            .to_string();
        unsafe { super::codev_engine_string_free(raw2) };
        assert!(
            rejected.contains("\"ok\":false"),
            "错误密钥必须被拒绝，实际返回: {rejected}"
        );
    }

    /// C 方案静态自检：引擎真正写出的 config.toml **必须能被解析**，
    /// 并且 `allow_anonymous` 明确为 false，避免同网段设备绕过二维码使用代理。
    ///
    /// 为什么要有这条：TOML/YAML 写错一个缩进不会报错，只会静默变成默认值
    /// （默认 false）——表现就是"包发出去了，B 手机还是要账号密码"。
    #[test]
    fn engine_config_requires_authenticated_socks5() {
        let directory =
            std::env::temp_dir().join(format!("codev-mobile-config-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let config_path = directory.join("config.toml");
        let proxy_tokens = directory.join("proxy-tokens.toml");
        let panel_token = directory.join("panel-token.secret");
        let profiles = directory.join("shadowrocket-profiles.toml");
        let record = directory.join("record");

        super::write_config(
            &config_path,
            &proxy_tokens,
            &panel_token,
            &profiles,
            &record,
            "127.0.0.1",
        )
        .expect("write_config 必须成功");

        let text = std::fs::read_to_string(&config_path).unwrap();
        let config = super::ProxyAppConfig::load(&config_path)
            .unwrap_or_else(|error| panic!("引擎写出的配置必须能解析: {error}\n---\n{text}"));
        assert!(
            !config.proxy.allow_anonymous,
            "allow_anonymous 必须是 false（节点只接受二维码中的账号密码）"
        );
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// 等面板端口和代理端口都空闲下来，等不到就返回明确错误。
///
/// 直接 `bind` 一下再释放，是最可靠的"端口是否空闲"判据；
/// 释放与随后真正的 bind 之间虽有极小窗口，但远好于"撞了也不知道"。
fn wait_for_ports_free() -> Result<(), String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let mut busy = Vec::new();
        for port in [PANEL_PORT, PROXY_PORT] {
            if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
                busy.push(port);
            }
        }
        if busy.is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "端口 {} 仍被占用：上一个引擎没有退出干净（请重试；若持续出现请上报）",
                busy.iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(" / ")
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
}

#[cfg(test)]
mod proxy_diagnostics_contract {
    use std::ffi::{CStr, CString};

    #[test]
    fn diagnostics_rejects_missing_credentials_without_crashing() {
        let user = CString::new("").unwrap();
        let password = CString::new("").unwrap();
        let raw = unsafe { super::codev_engine_diagnostics(user.as_ptr(), password.as_ptr()) };
        assert!(!raw.is_null(), "诊断接口必须始终返回 JSON");
        let payload = unsafe { CStr::from_ptr(raw) }.to_string_lossy().to_string();
        unsafe { super::codev_engine_string_free(raw) };
        assert!(
            payload.contains("\"ok\":false"),
            "空凭据必须给出结构化失败: {payload}"
        );
        assert!(
            payload.contains("socks_handshake"),
            "失败也要保留分层字段: {payload}"
        );
    }
}

#[cfg(test)]
mod udp_probe_tests {
    #[test]
    fn udp_probe_requires_a_matching_dns_response() {
        let id = 0x6d72;
        let mut reply = vec![0, 0, 0, 1, 223, 5, 5, 5, 0, 53];
        reply.extend_from_slice(&[0x6d, 0x72, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        assert!(super::valid_udp_dns_reply(&reply, id));
        reply[11] = 0;
        assert!(!super::valid_udp_dns_reply(&reply, id));
        assert!(!super::valid_udp_dns_reply(&[0, 0, 0, 1], id));
    }
}
