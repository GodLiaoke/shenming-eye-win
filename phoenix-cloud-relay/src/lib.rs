//! ⚠️ 2026-10-20「异地观看」下线说明：
//! 本 crate 里 `CloudMirror`（把游戏流量副本送上云端解析）已经**没有调用方** ——
//! Windows 端不再创建它，本机模式只用到下面的 SOCKS5 监听部分
//! （`phoenix_cloud_relay_start/stop`：2025 → 本机引擎 ingest 端口）。
//! 保留这段代码是为了让 C ABI 不变、Windows 包能照常编译；
//! 下次做破坏性清理时可以把 `CloudMirror` 与其 sink、C 导出函数一起删掉。
//!
//! Minimal authenticated split SOCKS5 relay used by the distributable Mac client.
//!
//! This crate deliberately contains no decryption, field dictionaries, map
//! data, or coordinate parsing. All real Internet traffic exits directly from
//! the Mac. A best-effort copy of game traffic is sent to the authenticated
//! upstream solely for protected server-side parsing, so a phone can still use
//! Shadowrocket's global mode without splitting a game session across exits.

use std::collections::HashMap;
use std::ffi::{CStr, c_char};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_USERNAME_PASSWORD: u8 = 2;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const GAME_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const GAME_STREAM_MAGIC: [u8; 6] = [0x33, 0x66, 0x00, 0x0b, 0x00, 0x0c];
const MIRROR_TARGET_PORT: u16 = 9;
const MIRROR_FLAG_CLOSE: u8 = 1;
const MIRROR_QUEUE_CAPACITY: usize = 512;
const MIRROR_TCP: u8 = 1;
const MIRROR_UDP: u8 = 2;
const MIRROR_CLIENT_TO_SERVER: u8 = 1;
const MIRROR_SERVER_TO_CLIENT: u8 = 2;

const GAME_IPV4: &[&str] = &[
    "43.135.106.46",
    "43.135.106.108",
    "43.135.106.213",
    "43.135.106.226",
    "43.162.204.119",
    "43.162.204.121",
    "43.162.204.122",
    "43.162.204.128",
    "43.162.204.129",
    "43.162.204.134",
    "43.163.178.107",
    "140.206.161.148",
];

#[derive(Clone)]
struct RelayConfig {
    upstream_host: String,
    upstream_port: u16,
    upstream_username: String,
    upstream_password: String,
    local_username: String,
    local_password: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Host {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Target {
    host: Host,
    port: u16,
}

impl Target {
    fn resolve(&self) -> io::Result<Vec<SocketAddr>> {
        match &self.host {
            Host::Ip(ip) => Ok(vec![SocketAddr::new(*ip, self.port)]),
            Host::Domain(host) => Ok((host.as_str(), self.port).to_socket_addrs()?.collect()),
        }
    }

    fn is_known_game_target(&self) -> bool {
        // Preselect known game/control ports before payload probing so their
        // traffic is copied to the protected parser from the first byte.
        if matches!(self.port, 1_883 | 8_013 | 8_085 | 15_806 | 17_500) {
            return true;
        }
        match &self.host {
            Host::Domain(host) => {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                host == "codev.qq.com"
                    || host.ends_with(".codev.qq.com")
                    || host == "iospaste.mna.qq.com"
                    || host == "receiver.tdm.qq.com"
            }
            Host::Ip(IpAddr::V4(ip)) => GAME_IPV4
                .iter()
                .any(|candidate| candidate == &ip.to_string()),
            Host::Ip(IpAddr::V6(_)) => false,
        }
    }

    fn is_private_or_local(&self) -> bool {
        match self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_multicast()
                    || ip.is_broadcast()
                    || ip.is_unspecified()
            }
            Host::Ip(IpAddr::V6(ip)) => {
                ip.is_loopback()
                    || ip.is_unicast_link_local()
                    || ip.is_multicast()
                    || ip.is_unspecified()
                    || (ip.segments()[0] & 0xfe00) == 0xfc00
            }
            Host::Domain(ref host) => {
                let host = host.trim_end_matches('.').to_ascii_lowercase();
                host == "localhost" || host.ends_with(".local")
            }
        }
    }

    fn should_mirror_tcp(&self) -> bool {
        self.is_known_game_target()
    }

    fn should_mirror_udp(&self) -> bool {
        if self.is_private_or_local() {
            return false;
        }

        // DNS and login/CDN QUIC do not contain the protected gameplay stream.
        // All other public UDP is copied to the parser while its real packets
        // continue to use the same residential Mac exit as the login traffic.
        !matches!(self.port, 53 | 443)
    }

    fn encode(&self, output: &mut Vec<u8>) -> io::Result<()> {
        match &self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                output.push(1);
                output.extend_from_slice(&ip.octets());
            }
            Host::Ip(IpAddr::V6(ip)) => {
                output.push(4);
                output.extend_from_slice(&ip.octets());
            }
            Host::Domain(host) => {
                let bytes = host.as_bytes();
                let length = u8::try_from(bytes.len())
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "domain too long"))?;
                output.extend_from_slice(&[3, length]);
                output.extend_from_slice(bytes);
            }
        }
        output.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }
}

struct RelayHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    clients: ClientRegistry,
    mirror: MirrorHandle,
}

type ClientRegistry = Arc<Mutex<HashMap<u64, TcpStream>>>;

static RELAY: OnceLock<Mutex<Option<RelayHandle>>> = OnceLock::new();
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_MIRROR_FLOW_ID: AtomicU64 = AtomicU64::new(1);

fn relay_slot() -> &'static Mutex<Option<RelayHandle>> {
    RELAY.get_or_init(|| Mutex::new(None))
}

struct ClientGuard {
    id: u64,
    clients: ClientRegistry,
}

impl ClientGuard {
    fn register(stream: &TcpStream, clients: ClientRegistry) -> io::Result<Self> {
        let id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
        clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, stream.try_clone()?);
        ACTIVE_CLIENTS.fetch_add(1, Ordering::Relaxed);
        Ok(Self { id, clients })
    }
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.id);
        ACTIVE_CLIENTS.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone)]
struct MirrorSink {
    sender: SyncSender<MirrorMessage>,
}

struct MirrorHandle {
    sender: SyncSender<MirrorMessage>,
    thread: JoinHandle<()>,
}

enum MirrorMessage {
    Record(MirrorRecord),
    Stop,
}

struct MirrorRecord {
    direction: u8,
    transport: u8,
    flags: u8,
    flow_id: u64,
    capture_ns: u64,
    remote: SocketAddr,
    payload: Vec<u8>,
}

impl MirrorSink {
    fn record(
        &self,
        direction: u8,
        transport: u8,
        flow_id: u64,
        remote: SocketAddr,
        payload: &[u8],
    ) {
        if payload.is_empty() || payload.len() > u16::MAX as usize {
            return;
        }
        let message = MirrorMessage::Record(MirrorRecord {
            direction,
            transport,
            flags: 0,
            flow_id,
            capture_ns: unix_time_ns(),
            remote,
            payload: payload.to_vec(),
        });
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.sender.try_send(message)
        {
            // Mirroring is deliberately best-effort: parser backpressure or a
            // cloud outage must never slow or disconnect the real game flow.
        }
    }

    fn close_tcp(&self, flow_id: u64, remote: SocketAddr) {
        let _ = self.sender.try_send(MirrorMessage::Record(MirrorRecord {
            direction: MIRROR_CLIENT_TO_SERVER,
            transport: MIRROR_TCP,
            flags: MIRROR_FLAG_CLOSE,
            flow_id,
            capture_ns: unix_time_ns(),
            remote,
            payload: Vec::new(),
        }));
    }
}

impl MirrorHandle {
    fn start(config: RelayConfig) -> (Self, MirrorSink) {
        let (sender, receiver) = mpsc::sync_channel(MIRROR_QUEUE_CAPACITY);
        let sink = MirrorSink {
            sender: sender.clone(),
        };
        let thread = thread::Builder::new()
            .name("phoenix-cloud-mirror".into())
            .spawn(move || mirror_worker(config, receiver))
            .expect("mirror worker must start");
        (Self { sender, thread }, sink)
    }

    fn stop(self) {
        let _ = self.sender.send(MirrorMessage::Stop);
        let _ = self.thread.join();
    }
}

/// Owns a protected cloud-mirror connection without starting the SOCKS5
/// listener.  Windows uses this for copy-only WinDivert capture (local PC and
/// Mobile Hotspot).  The public surface accepts only opaque packet bytes and
/// contains no game decoder, field dictionary, map data, or coordinate logic.
pub struct CloudMirror {
    handle: Option<MirrorHandle>,
    sink: CloudMirrorSink,
}

/// Cheap, thread-safe sender used by passive packet-capture workers.
#[derive(Clone)]
pub struct CloudMirrorSink {
    inner: MirrorSink,
}

impl CloudMirror {
    pub fn start(
        upstream_host: impl Into<String>,
        upstream_port: u16,
        upstream_username: impl Into<String>,
        upstream_password: impl Into<String>,
    ) -> io::Result<Self> {
        let config = RelayConfig {
            upstream_host: upstream_host.into(),
            upstream_port,
            upstream_username: upstream_username.into(),
            upstream_password: upstream_password.into(),
            local_username: String::new(),
            local_password: String::new(),
        };
        if config.upstream_host.is_empty()
            || config.upstream_port == 0
            || config.upstream_username.is_empty()
            || config.upstream_password.is_empty()
            || config.upstream_username.len() > u8::MAX as usize
            || config.upstream_password.len() > u8::MAX as usize
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid protected mirror credentials",
            ));
        }
        let (handle, sink) = MirrorHandle::start(config);
        Ok(Self {
            handle: Some(handle),
            sink: CloudMirrorSink { inner: sink },
        })
    }

    pub fn sink(&self) -> CloudMirrorSink {
        self.sink.clone()
    }

    pub fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

impl Drop for CloudMirror {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.stop();
        }
    }
}

impl CloudMirrorSink {
    pub fn record_udp(
        &self,
        client_to_server: bool,
        flow_id: u64,
        remote: SocketAddr,
        payload: &[u8],
    ) {
        self.inner.record(
            if client_to_server {
                MIRROR_CLIENT_TO_SERVER
            } else {
                MIRROR_SERVER_TO_CLIENT
            },
            MIRROR_UDP,
            flow_id,
            remote,
            payload,
        );
    }

    pub fn record_tcp(
        &self,
        client_to_server: bool,
        flow_id: u64,
        remote: SocketAddr,
        payload: &[u8],
    ) {
        self.inner.record(
            if client_to_server {
                MIRROR_CLIENT_TO_SERVER
            } else {
                MIRROR_SERVER_TO_CLIENT
            },
            MIRROR_TCP,
            flow_id,
            remote,
            payload,
        );
    }

    pub fn close_tcp(&self, flow_id: u64, remote: SocketAddr) {
        self.inner.close_tcp(flow_id, remote);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn phoenix_cloud_relay_start(
    upstream_host: *const c_char,
    upstream_port: u16,
    upstream_username: *const c_char,
    upstream_password: *const c_char,
    local_username: *const c_char,
    local_password: *const c_char,
    local_port: u16,
) -> i32 {
    let Some(upstream_host) = (unsafe { c_string(upstream_host) }) else {
        return -1;
    };
    let Some(upstream_username) = (unsafe { c_string(upstream_username) }) else {
        return -1;
    };
    let Some(upstream_password) = (unsafe { c_string(upstream_password) }) else {
        return -1;
    };
    let Some(local_username) = (unsafe { c_string(local_username) }) else {
        return -1;
    };
    let Some(local_password) = (unsafe { c_string(local_password) }) else {
        return -1;
    };
    if upstream_host.is_empty()
        || upstream_port == 0
        || local_port == 0
        || upstream_username.is_empty()
        || upstream_password.is_empty()
        || local_username.is_empty()
        || local_password.is_empty()
        || [
            upstream_username.len(),
            upstream_password.len(),
            local_username.len(),
            local_password.len(),
        ]
        .into_iter()
        .any(|length| length > u8::MAX as usize)
    {
        return -1;
    }

    phoenix_cloud_relay_stop();
    let listener = match TcpListener::bind((Ipv4Addr::UNSPECIFIED, local_port)) {
        Ok(listener) => listener,
        Err(_) => return -2,
    };
    if listener.set_nonblocking(true).is_err() {
        return -3;
    }

    let config = RelayConfig {
        upstream_host,
        upstream_port,
        upstream_username,
        upstream_password,
        local_username,
        local_password,
    };
    let (mirror, mirror_sink) = MirrorHandle::start(config.clone());
    let stop = Arc::new(AtomicBool::new(false));
    let clients = Arc::new(Mutex::new(HashMap::new()));
    let thread_stop = Arc::clone(&stop);
    let thread_clients = Arc::clone(&clients);
    let thread = thread::spawn(move || {
        accept_loop(listener, config, thread_stop, thread_clients, mirror_sink)
    });
    *relay_slot().lock().expect("relay mutex poisoned") = Some(RelayHandle {
        stop,
        thread,
        clients,
        mirror,
    });
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_cloud_relay_stop() {
    let existing = relay_slot().lock().expect("relay mutex poisoned").take();
    if let Some(handle) = existing {
        handle.stop.store(true, Ordering::Release);
        let _ = handle.thread.join();
        let clients = std::mem::take(
            &mut *handle
                .clients
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for stream in clients.into_values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        handle.mirror.stop();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_cloud_relay_is_running() -> i32 {
    i32::from(relay_slot().lock().expect("relay mutex poisoned").is_some())
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_cloud_relay_client_count() -> usize {
    ACTIVE_CLIENTS.load(Ordering::Relaxed)
}

unsafe fn c_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    let value = unsafe { CStr::from_ptr(pointer) };
    value.to_str().ok().map(ToOwned::to_owned)
}

fn accept_loop(
    listener: TcpListener,
    config: RelayConfig,
    stop: Arc<AtomicBool>,
    clients: ClientRegistry,
    mirror: MirrorSink,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !allowed_peer(peer.ip()) || stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let config = config.clone();
                let clients = Arc::clone(&clients);
                let mirror = mirror.clone();
                thread::spawn(move || {
                    let Ok(_guard) = ClientGuard::register(&stream, clients) else {
                        return;
                    };
                    let _ = serve_client(stream, peer.ip(), &config, &mirror);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn serve_client(
    mut client: TcpStream,
    client_ip: IpAddr,
    config: &RelayConfig,
    mirror: &MirrorSink,
) -> io::Result<()> {
    authenticate_local(&mut client, config)?;
    let request = read_request(&mut client)?;
    match request.command {
        COMMAND_CONNECT => serve_connect(client, request.target, mirror),
        COMMAND_UDP_ASSOCIATE => serve_udp_associate(client, client_ip, mirror),
        _ => {
            write_reply(&mut client, 7, unspecified_address())?;
            Ok(())
        }
    }
}

struct RequestWire {
    command: u8,
    target: Target,
}

fn read_request(reader: &mut impl Read) -> io::Result<RequestWire> {
    let mut head = [0_u8; 4];
    reader.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION || head[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request",
        ));
    }
    let target = read_target(reader, head[3])?;
    Ok(RequestWire {
        command: head[1],
        target,
    })
}

fn authenticate_local(client: &mut TcpStream, config: &RelayConfig) -> io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != SOCKS_VERSION || greeting[1] == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 greeting",
        ));
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&AUTH_USERNAME_PASSWORD) {
        client.write_all(&[SOCKS_VERSION, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 username/password authentication required",
        ));
    }
    client.write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD])?;

    let mut auth_head = [0_u8; 2];
    client.read_exact(&mut auth_head)?;
    if auth_head[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid auth version",
        ));
    }
    let mut username = vec![0_u8; auth_head[1] as usize];
    client.read_exact(&mut username)?;
    let mut password_length = [0_u8; 1];
    client.read_exact(&mut password_length)?;
    let mut password = vec![0_u8; password_length[0] as usize];
    client.read_exact(&mut password)?;
    let accepted = username == config.local_username.as_bytes()
        && password == config.local_password.as_bytes();
    client.write_all(&[1, if accepted { 0 } else { 1 }])?;
    if accepted {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid relay credentials",
        ))
    }
}

fn authenticate_upstream(config: &RelayConfig) -> io::Result<TcpStream> {
    let addresses: Vec<_> = (config.upstream_host.as_str(), config.upstream_port)
        .to_socket_addrs()?
        .collect();
    let mut stream = connect_any(&addresses)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let _ = stream.set_nodelay(true);
    stream.write_all(&[SOCKS_VERSION, 2, AUTH_NONE, AUTH_USERNAME_PASSWORD])?;
    let mut selection = [0_u8; 2];
    stream.read_exact(&mut selection)?;
    if selection[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream greeting",
        ));
    }
    match selection[1] {
        AUTH_NONE => Ok(stream),
        AUTH_USERNAME_PASSWORD => {
            let username = config.upstream_username.as_bytes();
            let password = config.upstream_password.as_bytes();
            let mut request = Vec::with_capacity(username.len() + password.len() + 3);
            request.extend_from_slice(&[1, username.len() as u8]);
            request.extend_from_slice(username);
            request.push(password.len() as u8);
            request.extend_from_slice(password);
            stream.write_all(&request)?;
            let mut response = [0_u8; 2];
            stream.read_exact(&mut response)?;
            if response == [1, 0] {
                Ok(stream)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upstream authentication failed",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream rejected authentication",
        )),
    }
}

fn mirror_worker(config: RelayConfig, receiver: mpsc::Receiver<MirrorMessage>) {
    let mut stream = None::<TcpStream>;
    while let Ok(message) = receiver.recv() {
        let MirrorMessage::Record(record) = message else {
            break;
        };
        let Ok(encoded) = encode_mirror_record(&record) else {
            continue;
        };
        let mut delivered = false;
        for _ in 0..2 {
            if stream.is_none() {
                stream = open_mirror_connection(&config).ok();
            }
            let Some(connection) = stream.as_mut() else {
                break;
            };
            if connection.write_all(&encoded).is_ok() {
                delivered = true;
                break;
            }
            let _ = connection.shutdown(Shutdown::Both);
            stream = None;
        }
        if !delivered {
            // The local relay remains a working Internet path even while the
            // protected parser is unavailable. A later record reconnects.
            stream = None;
        }
    }
    if let Some(connection) = stream {
        let _ = connection.shutdown(Shutdown::Both);
    }
}

fn open_mirror_connection(config: &RelayConfig) -> io::Result<TcpStream> {
    let target = Target {
        host: Host::Domain(codev_conceal::mirror_host().into()),
        port: MIRROR_TARGET_PORT,
    };
    let (stream, _, reply) = open_upstream_target(config, &target)?;
    if reply != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("upstream rejected mirror ingest with reply {reply}"),
        ));
    }
    Ok(stream)
}

fn encode_mirror_record(record: &MirrorRecord) -> io::Result<Vec<u8>> {
    let payload_len = u32::try_from(record.payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mirror payload too large"))?;
    let mut output = Vec::with_capacity(46 + record.payload.len());
    output.extend_from_slice(&codev_conceal::record_magic());
    output.extend_from_slice(&[
        record.direction,
        record.transport,
        record.flags,
        if record.remote.is_ipv4() { 4 } else { 6 },
    ]);
    output.extend_from_slice(&record.flow_id.to_be_bytes());
    output.extend_from_slice(&record.capture_ns.to_be_bytes());
    output.extend_from_slice(&record.remote.port().to_be_bytes());
    match record.remote.ip() {
        IpAddr::V4(ip) => {
            output.extend_from_slice(&ip.octets());
            output.extend_from_slice(&[0_u8; 12]);
        }
        IpAddr::V6(ip) => output.extend_from_slice(&ip.octets()),
    }
    output.extend_from_slice(&payload_len.to_be_bytes());
    output.extend_from_slice(&record.payload);
    Ok(output)
}

fn unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn open_upstream_target(
    config: &RelayConfig,
    target: &Target,
) -> io::Result<(TcpStream, Vec<u8>, u8)> {
    let mut upstream = authenticate_upstream(config)?;
    let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0];
    target.encode(&mut request)?;
    upstream.write_all(&request)?;
    let (response, reply, _) = read_reply(&mut upstream)?;
    Ok((upstream, response, reply))
}

fn read_game_probe(client: &mut TcpStream) -> io::Result<(bool, Vec<u8>)> {
    client.set_read_timeout(Some(GAME_PROBE_TIMEOUT))?;
    let mut probe = Vec::with_capacity(GAME_STREAM_MAGIC.len());
    let result = loop {
        let mut buffer = [0_u8; 64];
        match client.read(&mut buffer) {
            Ok(0) => break Ok((false, probe)),
            Ok(size) => {
                probe.extend_from_slice(&buffer[..size]);
                let prefix_length = probe.len().min(GAME_STREAM_MAGIC.len());
                if !GAME_STREAM_MAGIC.starts_with(&probe[..prefix_length]) {
                    break Ok((false, probe));
                }
                if probe.len() >= GAME_STREAM_MAGIC.len() {
                    break Ok((true, probe));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break Ok((false, probe));
            }
            Err(error) => break Err(error),
        }
    };
    let _ = client.set_read_timeout(None);
    result
}

fn serve_connect(mut client: TcpStream, target: Target, mirror: &MirrorSink) -> io::Result<()> {
    let known_game = target.should_mirror_tcp();
    if known_game {
        let addresses = target.resolve()?;
        let mut remote = connect_any(&addresses)?;
        let remote_address = remote.peer_addr()?;
        write_reply(
            &mut client,
            0,
            remote
                .local_addr()
                .unwrap_or_else(|_| unspecified_address()),
        )?;
        let flow = MirrorTcpFlow::new(mirror.clone(), remote_address);
        return copy_bidirectional_mirrored(&mut client, &mut remote, Vec::new(), flow);
    }

    // SOCKS clients do not send application bytes before CONNECT succeeds.
    // A bounded six-byte signature probe catches a rotated MNA control target
    // without embedding any decryption or parser in the distributable client.
    write_reply(&mut client, 0, unspecified_address())?;
    let (is_game, initial) = read_game_probe(&mut client)?;
    let addresses = target.resolve()?;
    let mut remote = connect_any(&addresses)?;
    if is_game {
        let flow = MirrorTcpFlow::new(mirror.clone(), remote.peer_addr()?);
        copy_bidirectional_mirrored(&mut client, &mut remote, initial, flow)
    } else {
        copy_bidirectional(&mut client, &mut remote, initial)
    }
}

#[derive(Clone)]
struct MirrorTcpFlow {
    sink: MirrorSink,
    id: u64,
    remote: SocketAddr,
}

impl MirrorTcpFlow {
    fn new(sink: MirrorSink, remote: SocketAddr) -> Self {
        Self {
            sink,
            id: NEXT_MIRROR_FLOW_ID.fetch_add(1, Ordering::Relaxed),
            remote,
        }
    }

    fn record(&self, direction: u8, payload: &[u8]) {
        self.sink
            .record(direction, MIRROR_TCP, self.id, self.remote, payload);
    }

    fn close(&self) {
        self.sink.close_tcp(self.id, self.remote);
    }
}

fn serve_udp_associate(
    mut client: TcpStream,
    client_ip: IpAddr,
    mirror: &MirrorSink,
) -> io::Result<()> {
    let local_udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?);
    local_udp.set_read_timeout(Some(IO_TIMEOUT))?;
    write_reply(&mut client, 0, local_udp.local_addr()?)?;

    // Every real datagram exits through the Mac. The cloud receives only an
    // authenticated best-effort copy, so it can decode without becoming a
    // second network identity for the same game session.
    let direct_udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?);
    direct_udp.set_read_timeout(Some(IO_TIMEOUT))?;
    let stopped = Arc::new(AtomicBool::new(false));
    let client_endpoint = Arc::new(Mutex::new(None::<SocketAddr>));
    let mirrored_flows = Arc::new(Mutex::new(HashMap::<SocketAddr, u64>::new()));

    let monitor_flag = Arc::clone(&stopped);
    let mut monitor_client = client.try_clone()?;
    let client_monitor_thread = thread::spawn(move || {
        let mut byte = [0_u8; 1];
        loop {
            match monitor_client.read(&mut byte) {
                Ok(0) | Err(_) => {
                    monitor_flag.store(true, Ordering::Release);
                    break;
                }
                Ok(_) => {}
            }
        }
    });

    let direct_flag = Arc::clone(&stopped);
    let direct_local = Arc::clone(&local_udp);
    let direct_endpoint = Arc::clone(&client_endpoint);
    let direct_reader = Arc::clone(&direct_udp);
    let direct_mirror = mirror.clone();
    let direct_flows = Arc::clone(&mirrored_flows);
    let direct_thread = thread::spawn(move || {
        let mut payload = vec![0_u8; 65_535];
        while !direct_flag.load(Ordering::Acquire) {
            match direct_reader.recv_from(&mut payload) {
                Ok((size, source)) => {
                    if let Some(flow_id) = direct_flows
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .get(&source)
                        .copied()
                    {
                        direct_mirror.record(
                            MIRROR_SERVER_TO_CLIENT,
                            MIRROR_UDP,
                            flow_id,
                            source,
                            &payload[..size],
                        );
                    }
                    if let Some(endpoint) =
                        *direct_endpoint.lock().expect("endpoint mutex poisoned")
                    {
                        let mut packet = vec![0, 0, 0];
                        if (Target {
                            host: Host::Ip(source.ip()),
                            port: source.port(),
                        })
                        .encode(&mut packet)
                        .is_ok()
                        {
                            packet.extend_from_slice(&payload[..size]);
                            let _ = direct_local.send_to(&packet, endpoint);
                        }
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
    });

    let mut datagram = vec![0_u8; 65_535];
    let result = loop {
        if stopped.load(Ordering::Acquire) {
            break Ok(());
        }
        match local_udp.recv_from(&mut datagram) {
            Ok((size, endpoint)) if endpoint.ip() == client_ip => {
                let mut known = client_endpoint.lock().expect("endpoint mutex poisoned");
                if known.is_none() {
                    *known = Some(endpoint);
                }
                if *known == Some(endpoint) {
                    let Ok((target, payload_offset)) = parse_udp_datagram(&datagram[..size]) else {
                        continue;
                    };
                    if let Ok(addresses) = target.resolve()
                        && let Some(destination) = addresses.first().copied()
                    {
                        if target.should_mirror_udp() {
                            let flow_id = *mirrored_flows
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .entry(destination)
                                .or_insert_with(|| {
                                    NEXT_MIRROR_FLOW_ID.fetch_add(1, Ordering::Relaxed)
                                });
                            mirror.record(
                                MIRROR_CLIENT_TO_SERVER,
                                MIRROR_UDP,
                                flow_id,
                                destination,
                                &datagram[payload_offset..size],
                            );
                        }
                        let _ = direct_udp.send_to(&datagram[payload_offset..size], destination);
                    }
                }
            }
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                break Err(error);
            }
        }
    };
    stopped.store(true, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = direct_thread.join();
    let _ = client_monitor_thread.join();
    result
}

fn parse_udp_datagram(datagram: &[u8]) -> io::Result<(Target, usize)> {
    if datagram.len() < 4 || datagram[0..3] != [0, 0, 0] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 UDP header",
        ));
    }
    let mut cursor = io::Cursor::new(&datagram[4..]);
    let target = read_target(&mut cursor, datagram[3])?;
    Ok((target, 4 + cursor.position() as usize))
}

fn read_target(reader: &mut impl Read, address_type: u8) -> io::Result<Target> {
    let host = match address_type {
        1 => {
            let mut bytes = [0_u8; 4];
            reader.read_exact(&mut bytes)?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        3 => {
            let mut length = [0_u8; 1];
            reader.read_exact(&mut length)?;
            let mut bytes = vec![0_u8; length[0] as usize];
            reader.read_exact(&mut bytes)?;
            Host::Domain(String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain encoding")
            })?)
        }
        4 => {
            let mut bytes = [0_u8; 16];
            reader.read_exact(&mut bytes)?;
            Host::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown address type",
            ));
        }
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port)?;
    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn read_reply(reader: &mut impl Read) -> io::Result<(Vec<u8>, u8, SocketAddr)> {
    let mut head = [0_u8; 4];
    reader.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION || head[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 reply",
        ));
    }
    let tail = read_address_tail(reader, head[3])?;
    let address = socket_address_from_wire(head[3], &tail)?;
    let mut response = head.to_vec();
    response.extend_from_slice(&tail);
    Ok((response, head[1], address))
}

fn read_address_tail(reader: &mut impl Read, address_type: u8) -> io::Result<Vec<u8>> {
    let address_length = match address_type {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            reader.read_exact(&mut length)?;
            let mut tail = vec![length[0]];
            let mut rest = vec![0_u8; length[0] as usize + 2];
            reader.read_exact(&mut rest)?;
            tail.extend_from_slice(&rest);
            return Ok(tail);
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unknown SOCKS5 address type",
            ));
        }
    };
    let mut tail = vec![0_u8; address_length + 2];
    reader.read_exact(&mut tail)?;
    Ok(tail)
}

fn socket_address_from_wire(address_type: u8, tail: &[u8]) -> io::Result<SocketAddr> {
    match address_type {
        1 if tail.len() == 6 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(tail[0], tail[1], tail[2], tail[3])),
            u16::from_be_bytes([tail[4], tail[5]]),
        )),
        4 if tail.len() == 18 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&tail[..16]);
            Ok(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([tail[16], tail[17]]),
            ))
        }
        3 if tail.len() >= 3 && tail.len() == tail[0] as usize + 3 => {
            let name_length = tail[0] as usize;
            let host = std::str::from_utf8(&tail[1..1 + name_length])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?;
            let port = u16::from_be_bytes([tail[1 + name_length], tail[2 + name_length]]);
            (host, port)
                .to_socket_addrs()?
                .next()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain did not resolve"))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed SOCKS5 address",
        )),
    }
}

fn write_reply(stream: &mut TcpStream, reply: u8, address: SocketAddr) -> io::Result<()> {
    let mut response = vec![SOCKS_VERSION, reply, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            response.push(1);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(4);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&address.port().to_be_bytes());
    stream.write_all(&response)
}

fn connect_any(addresses: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "upstream did not resolve")))
}

fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
    initial_left: Vec<u8>,
) -> io::Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let forward = thread::spawn(move || {
        if !initial_left.is_empty() {
            right_writer.write_all(&initial_left)?;
        }
        let result = io::copy(&mut left_reader, &mut right_writer);
        let _ = right_writer.shutdown(Shutdown::Write);
        result
    });
    let reverse = io::copy(right, left);
    let _ = left.shutdown(Shutdown::Write);
    forward
        .join()
        .map_err(|_| io::Error::other("relay worker panicked"))??;
    reverse?;
    Ok(())
}

fn copy_bidirectional_mirrored(
    left: &mut TcpStream,
    right: &mut TcpStream,
    initial_left: Vec<u8>,
    flow: MirrorTcpFlow,
) -> io::Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let forward_flow = flow.clone();
    let forward = thread::spawn(move || -> io::Result<()> {
        if !initial_left.is_empty() {
            forward_flow.record(MIRROR_CLIENT_TO_SERVER, &initial_left);
            right_writer.write_all(&initial_left)?;
        }
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let size = left_reader.read(&mut buffer)?;
            if size == 0 {
                break;
            }
            forward_flow.record(MIRROR_CLIENT_TO_SERVER, &buffer[..size]);
            right_writer.write_all(&buffer[..size])?;
        }
        let _ = right_writer.shutdown(Shutdown::Write);
        Ok(())
    });

    let mut buffer = [0_u8; 16 * 1024];
    let reverse = loop {
        match right.read(&mut buffer) {
            Ok(0) => break Ok(()),
            Ok(size) => {
                flow.record(MIRROR_SERVER_TO_CLIENT, &buffer[..size]);
                if let Err(error) = left.write_all(&buffer[..size]) {
                    break Err(error);
                }
            }
            Err(error) => break Err(error),
        }
    };
    let _ = left.shutdown(Shutdown::Write);
    let forward = forward
        .join()
        .map_err(|_| io::Error::other("relay worker panicked"))?;
    flow.close();
    forward?;
    reverse
}

fn allowed_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn unspecified_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn relay_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn start_test_relay_with_upstream(port: u16, upstream_port: u16) {
        let upstream_host = CString::new("127.0.0.1").unwrap();
        let upstream_username = CString::new("upstream-user").unwrap();
        let upstream_password = CString::new("upstream-password").unwrap();
        let local_username = CString::new("local-user").unwrap();
        let local_password = CString::new("local-password").unwrap();
        let started = unsafe {
            phoenix_cloud_relay_start(
                upstream_host.as_ptr(),
                upstream_port,
                upstream_username.as_ptr(),
                upstream_password.as_ptr(),
                local_username.as_ptr(),
                local_password.as_ptr(),
                port,
            )
        };
        assert_eq!(started, 0);
    }

    fn start_test_relay(port: u16) {
        start_test_relay_with_upstream(port, 9);
    }

    fn connect_test_client(port: u16) -> TcpStream {
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client.write_all(&[5, 1, AUTH_USERNAME_PASSWORD]).unwrap();
        let mut greeting = [0_u8; 2];
        client.read_exact(&mut greeting).unwrap();
        assert_eq!(greeting, [5, AUTH_USERNAME_PASSWORD]);

        let username = b"local-user";
        let password = b"local-password";
        let mut auth = vec![1, username.len() as u8];
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        client.write_all(&auth).unwrap();
        let mut response = [0_u8; 2];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response, [1, 0]);
        client
    }

    #[test]
    fn upstream_reply_is_forwarded_byte_for_byte() {
        let wire = [5, 0, 0, 1, 192, 0, 2, 1, 0x12, 0x34];
        let (response, reply, address) = read_reply(&mut io::Cursor::new(wire)).unwrap();
        assert_eq!(reply, 0);
        assert_eq!(response, wire);
        assert_eq!(address, "192.0.2.1:4660".parse().unwrap());
    }

    #[test]
    fn tcp_mirror_only_selects_known_game_targets() {
        for port in [1_883, 8_013, 8_085, 15_806, 17_500] {
            assert!(
                Target {
                    host: Host::Ip("140.207.121.12".parse().unwrap()),
                    port,
                }
                .should_mirror_tcp(),
                "dedicated game TCP port {port} must be copied to the parser"
            );
        }
        assert!(
            Target {
                host: Host::Domain("receiver.tdm.qq.com".into()),
                port: 443,
            }
            .should_mirror_tcp()
        );
        assert!(
            Target {
                host: Host::Ip("203.0.113.9".parse().unwrap()),
                port: 15_806,
            }
            .should_mirror_tcp()
        );
        assert!(
            !Target {
                host: Host::Domain("example.com".into()),
                port: 443,
            }
            .should_mirror_tcp()
        );
    }

    #[test]
    fn udp_mirror_excludes_dns_quic_and_local_targets() {
        assert!(
            !Target {
                host: Host::Ip("1.1.1.1".parse().unwrap()),
                port: 53,
            }
            .should_mirror_udp()
        );
        assert!(
            !Target {
                host: Host::Ip("1.1.1.1".parse().unwrap()),
                port: 443,
            }
            .should_mirror_udp()
        );
        for port in [123, 3_478, 5_349, 52_621] {
            assert!(
                Target {
                    host: Host::Ip("1.1.1.1".parse().unwrap()),
                    port,
                }
                .should_mirror_udp(),
                "public game-candidate UDP port {port} must be copied to the parser"
            );
        }
        assert!(
            Target {
                host: Host::Ip("118.182.226.83".parse().unwrap()),
                port: 52_621,
            }
            .should_mirror_udp()
        );
        assert!(
            !Target {
                host: Host::Ip("192.168.1.1".parse().unwrap()),
                port: 52_621,
            }
            .should_mirror_udp()
        );
        assert!(
            !Target {
                host: Host::Domain("printer.local".into()),
                port: 5_353,
            }
            .should_mirror_udp()
        );
    }

    #[test]
    fn parses_udp_domain_datagram_for_split_routing() {
        let packet = [
            0, 0, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0,
            53, 1, 2,
        ];
        let (target, offset) = parse_udp_datagram(&packet).unwrap();
        assert_eq!(
            target,
            Target {
                host: Host::Domain("example.com".into()),
                port: 53,
            }
        );
        assert_eq!(&packet[offset..], &[1, 2]);
    }

    #[test]
    fn ordinary_tcp_connects_directly_when_upstream_is_unavailable() {
        let _lock = relay_test_lock();
        let direct = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let direct_port = direct.local_addr().unwrap().port();
        let direct_thread = thread::spawn(move || {
            let (mut stream, _) = direct.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let relay_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        start_test_relay(relay_port);

        let mut client = connect_test_client(relay_port);
        let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&direct_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0);
        client.write_all(b"ping").unwrap();
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");

        phoenix_cloud_relay_stop();
        direct_thread.join().unwrap();
    }

    #[test]
    fn ordinary_udp_connects_directly_when_upstream_is_unavailable() {
        let _lock = relay_test_lock();
        let echo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        echo.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        let echo_thread = thread::spawn(move || {
            let mut payload = [0_u8; 64];
            let (size, peer) = echo.recv_from(&mut payload).unwrap();
            echo.send_to(&payload[..size], peer).unwrap();
        });

        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let relay_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        start_test_relay(relay_port);

        let mut control = connect_test_client(relay_port);
        control
            .write_all(&[SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])
            .unwrap();
        let (_, reply, mut relay) = read_reply(&mut control).unwrap();
        assert_eq!(reply, 0);
        if relay.ip().is_unspecified() {
            relay.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }

        let phone = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        phone
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut packet = vec![0, 0, 0];
        Target {
            host: Host::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: echo_port,
        }
        .encode(&mut packet)
        .unwrap();
        packet.extend_from_slice(b"dns-direct");
        phone.send_to(&packet, relay).unwrap();

        let mut response = [0_u8; 256];
        let (size, _) = phone.recv_from(&mut response).unwrap();
        let (_, offset) = parse_udp_datagram(&response[..size]).unwrap();
        assert_eq!(&response[offset..size], b"dns-direct");

        drop(control);
        phoenix_cloud_relay_stop();
        echo_thread.join().unwrap();
    }

    #[test]
    fn discovered_game_tcp_exits_locally_and_is_copied_to_mirror_ingest() {
        let _lock = relay_test_lock();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let direct = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let direct_port = direct.local_addr().unwrap().port();
        let direct_thread = thread::spawn(move || {
            let (mut stream, _) = direct.accept().unwrap();
            let mut payload = vec![0_u8; GAME_STREAM_MAGIC.len() + 4];
            stream.read_exact(&mut payload).unwrap();
            assert_eq!(&payload[..GAME_STREAM_MAGIC.len()], &GAME_STREAM_MAGIC);
            assert_eq!(&payload[GAME_STREAM_MAGIC.len()..], b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let upstream_thread = thread::spawn(move || {
            let (mut stream, _) = upstream.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut greeting = [0_u8; 4];
            stream.read_exact(&mut greeting).unwrap();
            assert_eq!(
                greeting,
                [SOCKS_VERSION, 2, AUTH_NONE, AUTH_USERNAME_PASSWORD]
            );
            stream
                .write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD])
                .unwrap();
            let mut auth_head = [0_u8; 2];
            stream.read_exact(&mut auth_head).unwrap();
            let mut username = vec![0_u8; auth_head[1] as usize];
            stream.read_exact(&mut username).unwrap();
            let mut password_length = [0_u8; 1];
            stream.read_exact(&mut password_length).unwrap();
            let mut password = vec![0_u8; password_length[0] as usize];
            stream.read_exact(&mut password).unwrap();
            assert_eq!(&username, b"upstream-user");
            assert_eq!(&password, b"upstream-password");
            stream.write_all(&[1, 0]).unwrap();

            let request = read_request(&mut stream).unwrap();
            assert_eq!(request.command, COMMAND_CONNECT);
            assert_eq!(
                request.target,
                Target {
                    host: Host::Domain(codev_conceal::mirror_host().into()),
                    port: MIRROR_TARGET_PORT,
                }
            );
            write_reply(&mut stream, 0, unspecified_address()).unwrap();

            let mut seen = Vec::new();
            for _ in 0..2 {
                let mut header = [0_u8; 46];
                stream.read_exact(&mut header).unwrap();
                assert_eq!(&header[..4], &codev_conceal::record_magic());
                assert_eq!(header[5], MIRROR_TCP);
                assert_eq!(header[6], 0);
                assert_eq!(header[7], 4);
                assert_eq!(u16::from_be_bytes([header[24], header[25]]), direct_port);
                assert_eq!(&header[26..30], &[127, 0, 0, 1]);
                let size = u32::from_be_bytes(header[42..46].try_into().unwrap()) as usize;
                let mut payload = vec![0_u8; size];
                stream.read_exact(&mut payload).unwrap();
                seen.push((header[4], payload));
            }
            assert_eq!(seen[0].0, MIRROR_CLIENT_TO_SERVER);
            assert_eq!(&seen[0].1[..GAME_STREAM_MAGIC.len()], &GAME_STREAM_MAGIC);
            assert_eq!(seen[1], (MIRROR_SERVER_TO_CLIENT, b"pong".to_vec()));
        });

        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let relay_port = reservation.local_addr().unwrap().port();
        drop(reservation);
        start_test_relay_with_upstream(relay_port, upstream_port);

        let mut client = connect_test_client(relay_port);
        let mut request = vec![SOCKS_VERSION, COMMAND_CONNECT, 0, 1, 127, 0, 0, 1];
        request.extend_from_slice(&direct_port.to_be_bytes());
        client.write_all(&request).unwrap();
        let mut response = [0_u8; 10];
        client.read_exact(&mut response).unwrap();
        assert_eq!(response[1], 0);
        let mut payload = GAME_STREAM_MAGIC.to_vec();
        payload.extend_from_slice(b"ping");
        client.write_all(&payload).unwrap();
        let mut reply = [0_u8; 4];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"pong");
        drop(client);
        phoenix_cloud_relay_stop();
        direct_thread.join().unwrap();
        upstream_thread.join().unwrap();
    }

    #[test]
    fn local_access_is_restricted_to_private_networks() {
        assert!(allowed_peer("127.0.0.1".parse().unwrap()));
        assert!(allowed_peer("172.20.10.2".parse().unwrap()));
        assert!(allowed_peer("192.168.1.8".parse().unwrap()));
        assert!(!allowed_peer("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn stopping_relay_closes_existing_clients() {
        let _lock = relay_test_lock();
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        start_test_relay(port);

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        for _ in 0..50 {
            if phoenix_cloud_relay_client_count() == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(phoenix_cloud_relay_client_count(), 1);

        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        phoenix_cloud_relay_stop();
        let mut byte = [0_u8; 1];
        match client.read(&mut byte) {
            Ok(0) => {}
            Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {}
            result => panic!("client socket stayed usable after relay stop: {result:?}"),
        }
        for _ in 0..50 {
            if phoenix_cloud_relay_client_count() == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(phoenix_cloud_relay_client_count(), 0);
    }
}
