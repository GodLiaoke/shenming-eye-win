use codev_stream::{
    MNA_DATA, MNA_MAGIC, MNA_SERVER_HELLO, W0Framer, decrypt_mna_frame, parse_enter_game_session,
    parse_mna_application, recover_mna_session_key, strip_mna_random_padding,
};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, c_char};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use zeroize::Zeroizing;

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_USERNAME_PASSWORD: u8 = 2;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const MNA_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_MNA_STREAM_BYTES: usize = 8 * 1024 * 1024;

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
    force_all_upstream: bool,
}

struct RelayHandle {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
    clients: ClientRegistry,
}

static RELAY: OnceLock<Mutex<Option<RelayHandle>>> = OnceLock::new();
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);
static FORCE_ALL_UPSTREAM: AtomicBool = AtomicBool::new(false);
static DYNAMIC_GAME_ROUTES: OnceLock<RwLock<DynamicGameRoutes>> = OnceLock::new();

type ClientRegistry = Arc<Mutex<HashMap<u64, TcpStream>>>;

#[derive(Default)]
struct DynamicGameRoutes {
    targets: HashSet<SocketAddr>,
    ports: HashSet<u16>,
}

fn dynamic_game_routes() -> &'static RwLock<DynamicGameRoutes> {
    DYNAMIC_GAME_ROUTES.get_or_init(|| RwLock::new(DynamicGameRoutes::default()))
}

fn replace_dynamic_game_routes(server_ip: &str, server_vip: Option<&str>, port: u16) {
    if port == 0 {
        return;
    }
    let mut routes = dynamic_game_routes()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    routes.targets.clear();
    routes.ports.clear();
    routes.ports.insert(port);
    for host in [Some(server_ip), server_vip].into_iter().flatten() {
        if let Ok(ip) = host.parse::<IpAddr>() {
            routes.targets.insert(SocketAddr::new(ip, port));
            continue;
        }
        if let Ok(addresses) = (host, port).to_socket_addrs() {
            routes.targets.extend(addresses);
        }
    }
}

fn is_dynamic_game_target(target: &Target) -> bool {
    let routes = dynamic_game_routes()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    match &target.host {
        Host::Ip(ip) => {
            routes.targets.contains(&SocketAddr::new(*ip, target.port))
                || routes.ports.contains(&target.port)
        }
        Host::Domain(_) => routes.ports.contains(&target.port),
    }
}

fn relay_slot() -> &'static Mutex<Option<RelayHandle>> {
    RELAY.get_or_init(|| Mutex::new(None))
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

    fn use_upstream(&self, force_all_upstream: bool) -> bool {
        if force_all_upstream {
            return true;
        }
        if is_dynamic_game_target(self) {
            return true;
        }
        if matches!(self.port, 15806 | 17500) {
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn phoenix_relay_start(
    upstream_host: *const c_char,
    upstream_port: u16,
    username: *const c_char,
    password: *const c_char,
    local_username: *const c_char,
    local_password: *const c_char,
    local_port: u16,
) -> i32 {
    let Some(upstream_host) = (unsafe { c_string(upstream_host) }) else {
        return -1;
    };
    let Some(username) = (unsafe { c_string(username) }) else {
        return -1;
    };
    let Some(password) = (unsafe { c_string(password) }) else {
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
        || username.len() > 255
        || password.len() > 255
        || local_username.is_empty()
        || local_password.is_empty()
        || local_username.len() > 255
        || local_password.len() > 255
    {
        return -1;
    }

    phoenix_relay_stop();
    *dynamic_game_routes()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = DynamicGameRoutes::default();
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
        upstream_username: username,
        upstream_password: password,
        local_username,
        local_password,
        force_all_upstream: FORCE_ALL_UPSTREAM.load(Ordering::Acquire),
    };
    let stop = Arc::new(AtomicBool::new(false));
    let clients = Arc::new(Mutex::new(HashMap::new()));
    let thread_stop = Arc::clone(&stop);
    let thread_clients = Arc::clone(&clients);
    let handle = thread::spawn(move || accept_loop(listener, config, thread_stop, thread_clients));
    *relay_slot().lock().expect("relay mutex poisoned") = Some(RelayHandle {
        stop,
        thread: handle,
        clients,
    });
    0
}

/// Select whether every SOCKS TCP/UDP target uses the authenticated CodeV
/// upstream. The normal production mode keeps only proven game traffic on the
/// cloud path; this diagnostic mode is used to detect source-IP split during
/// game login. The setting is captured by the next `phoenix_relay_start` call.
#[unsafe(no_mangle)]
pub extern "C" fn phoenix_relay_set_force_all_upstream(enabled: i32) {
    FORCE_ALL_UPSTREAM.store(enabled != 0, Ordering::Release);
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_relay_stop() {
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
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_relay_is_running() -> i32 {
    i32::from(relay_slot().lock().expect("relay mutex poisoned").is_some())
}

#[unsafe(no_mangle)]
pub extern "C" fn phoenix_relay_client_count() -> usize {
    ACTIVE_CLIENTS.load(Ordering::Relaxed)
}

unsafe fn c_string(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: The caller promises a valid, NUL-terminated C string for the duration of this call.
    let value = unsafe { CStr::from_ptr(pointer) };
    value.to_str().ok().map(ToOwned::to_owned)
}

fn accept_loop(
    listener: TcpListener,
    config: RelayConfig,
    stop: Arc<AtomicBool>,
    clients: ClientRegistry,
) {
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !allowed_peer(peer.ip()) {
                    continue;
                }
                if stream.set_nonblocking(false).is_err() {
                    continue;
                }
                let config = config.clone();
                let clients = Arc::clone(&clients);
                thread::spawn(move || {
                    let Ok(_guard) = ClientGuard::register(&stream, clients) else {
                        return;
                    };
                    if let Err(_error) = serve_client(stream, &config) {
                        #[cfg(debug_assertions)]
                        eprintln!("Phoenix LAN relay client failed: {_error}");
                    }
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(40));
            }
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn serve_client(mut client: TcpStream, config: &RelayConfig) -> io::Result<()> {
    authenticate_local(&mut client, config)?;
    let mut request_head = [0u8; 4];
    client.read_exact(&mut request_head)?;
    if request_head[0] != SOCKS_VERSION || request_head[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 request",
        ));
    }
    let target = read_target(&mut client, request_head[3])?;
    match request_head[1] {
        COMMAND_CONNECT => serve_connect(client, config, target),
        COMMAND_UDP_ASSOCIATE => serve_udp_associate(client, config),
        _ => {
            write_reply(&mut client, 7, unspecified_address())?;
            Ok(())
        }
    }
}

fn authenticate_local(client: &mut TcpStream, config: &RelayConfig) -> io::Result<()> {
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != SOCKS_VERSION || greeting[1] == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 greeting",
        ));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if methods.contains(&AUTH_NONE) {
        client.write_all(&[SOCKS_VERSION, AUTH_NONE])?;
        return Ok(());
    }
    if !methods.contains(&AUTH_USERNAME_PASSWORD) {
        client.write_all(&[SOCKS_VERSION, 0xff])?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 authentication required",
        ));
    }
    client.write_all(&[SOCKS_VERSION, AUTH_USERNAME_PASSWORD])?;

    let mut auth_head = [0u8; 2];
    client.read_exact(&mut auth_head)?;
    if auth_head[0] != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid auth version",
        ));
    }
    let mut username = vec![0u8; auth_head[1] as usize];
    client.read_exact(&mut username)?;
    let mut password_length = [0u8; 1];
    client.read_exact(&mut password_length)?;
    let mut password = vec![0u8; password_length[0] as usize];
    client.read_exact(&mut password)?;
    let accepted = username == config.local_username.as_bytes()
        && password == config.local_password.as_bytes();
    client.write_all(&[1, if accepted { 0 } else { 1 }])?;
    if !accepted {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid relay credentials",
        ));
    }
    Ok(())
}

fn allowed_peer(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn authenticate_upstream(config: &RelayConfig) -> io::Result<TcpStream> {
    let addresses: Vec<_> = (config.upstream_host.as_str(), config.upstream_port)
        .to_socket_addrs()?
        .collect();
    let mut stream = connect_any(&addresses)?;
    stream.write_all(&[SOCKS_VERSION, 2, 0, AUTH_USERNAME_PASSWORD])?;
    let mut selection = [0u8; 2];
    stream.read_exact(&mut selection)?;
    if selection[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid upstream greeting",
        ));
    }
    match selection[1] {
        0 => Ok(stream),
        AUTH_USERNAME_PASSWORD => {
            let username = config.upstream_username.as_bytes();
            let password = config.upstream_password.as_bytes();
            let mut request = Vec::with_capacity(username.len() + password.len() + 3);
            request.extend_from_slice(&[1, username.len() as u8]);
            request.extend_from_slice(username);
            request.push(password.len() as u8);
            request.extend_from_slice(password);
            stream.write_all(&request)?;
            let mut response = [0u8; 2];
            stream.read_exact(&mut response)?;
            if response != [1, 0] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "upstream authentication failed",
                ));
            }
            Ok(stream)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "upstream rejected authentication",
        )),
    }
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

fn read_mna_probe(client: &mut TcpStream) -> io::Result<(bool, Vec<u8>)> {
    client.set_read_timeout(Some(MNA_PROBE_TIMEOUT))?;
    let mut probe = Vec::with_capacity(MNA_MAGIC.len());
    let result = loop {
        let mut buffer = [0_u8; 64];
        match client.read(&mut buffer) {
            Ok(0) => break Ok((false, probe)),
            Ok(size) => {
                probe.extend_from_slice(&buffer[..size]);
                let prefix_length = probe.len().min(MNA_MAGIC.len());
                if !MNA_MAGIC.starts_with(&probe[..prefix_length]) {
                    break Ok((false, probe));
                }
                if probe.len() >= MNA_MAGIC.len() {
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

fn serve_connect(mut client: TcpStream, config: &RelayConfig, target: Target) -> io::Result<()> {
    if target.use_upstream(config.force_all_upstream) {
        let (mut upstream, response, reply) = open_upstream_target(config, &target)?;
        client.write_all(&response)?;
        if reply != 0 {
            return Ok(());
        }
        return copy_bidirectional(&mut client, &mut upstream, Vec::new(), true);
    }

    // A SOCKS client waits for CONNECT success before sending application
    // bytes. Reply first, then inspect only the bounded protocol prefix. MNA
    // control channels are sent to CodeV even when Tencent rotates their IP or
    // port; every other protocol keeps the direct path.
    write_reply(&mut client, 0, unspecified_address())?;
    let (is_mna, initial) = read_mna_probe(&mut client)?;
    if is_mna {
        let (mut upstream, _, reply) = open_upstream_target(config, &target)?;
        if reply != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("upstream rejected discovered MNA target with reply {reply}"),
            ));
        }
        return copy_bidirectional(&mut client, &mut upstream, initial, true);
    }

    let addresses = target.resolve()?;
    let mut remote = connect_any(&addresses)?;
    copy_bidirectional(&mut client, &mut remote, initial, false)
}

fn serve_udp_associate(mut client: TcpStream, config: &RelayConfig) -> io::Result<()> {
    let local_udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?);
    local_udp.set_read_timeout(Some(IO_TIMEOUT))?;
    write_reply(&mut client, 0, local_udp.local_addr()?)?;

    let mut upstream_control = authenticate_upstream(config)?;
    upstream_control.write_all(&[SOCKS_VERSION, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])?;
    let (_, reply, mut upstream_relay) = read_reply(&mut upstream_control)?;
    if reply != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "upstream UDP associate rejected",
        ));
    }
    if upstream_relay.ip().is_unspecified() {
        upstream_relay.set_ip(upstream_control.peer_addr()?.ip());
    }

    let upstream_udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?);
    upstream_udp.connect(upstream_relay)?;
    upstream_udp.set_read_timeout(Some(IO_TIMEOUT))?;
    let direct_udp = Arc::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?);
    direct_udp.set_read_timeout(Some(IO_TIMEOUT))?;

    let stopped = Arc::new(AtomicBool::new(false));
    let client_endpoint = Arc::new(Mutex::new(None::<SocketAddr>));

    let monitor_flag = Arc::clone(&stopped);
    let monitor_client = client.try_clone()?;
    thread::spawn(move || {
        let mut byte = [0u8; 1];
        let _ = (&monitor_client).read(&mut byte);
        monitor_flag.store(true, Ordering::Release);
    });

    let upstream_flag = Arc::clone(&stopped);
    let upstream_local = Arc::clone(&local_udp);
    let upstream_endpoint = Arc::clone(&client_endpoint);
    let upstream_reader = Arc::clone(&upstream_udp);
    let upstream_thread = thread::spawn(move || {
        let mut buffer = vec![0u8; 65_535];
        while !upstream_flag.load(Ordering::Acquire) {
            match upstream_reader.recv(&mut buffer) {
                Ok(size) => {
                    if let Some(endpoint) =
                        *upstream_endpoint.lock().expect("endpoint mutex poisoned")
                    {
                        let _ = upstream_local.send_to(&buffer[..size], endpoint);
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

    let direct_flag = Arc::clone(&stopped);
    let direct_local = Arc::clone(&local_udp);
    let direct_endpoint = Arc::clone(&client_endpoint);
    let direct_reader = Arc::clone(&direct_udp);
    let direct_thread = thread::spawn(move || {
        let mut payload = vec![0u8; 65_535];
        while !direct_flag.load(Ordering::Acquire) {
            match direct_reader.recv_from(&mut payload) {
                Ok((size, source)) => {
                    if let Some(endpoint) =
                        *direct_endpoint.lock().expect("endpoint mutex poisoned")
                    {
                        let mut packet = vec![0, 0, 0];
                        Target {
                            host: Host::Ip(source.ip()),
                            port: source.port(),
                        }
                        .encode(&mut packet)
                        .ok();
                        packet.extend_from_slice(&payload[..size]);
                        let _ = direct_local.send_to(&packet, endpoint);
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

    let mut datagram = vec![0u8; 65_535];
    while !stopped.load(Ordering::Acquire) {
        match local_udp.recv_from(&mut datagram) {
            Ok((size, endpoint)) => {
                *client_endpoint.lock().expect("endpoint mutex poisoned") = Some(endpoint);
                let Ok((target, payload_offset)) = parse_udp_datagram(&datagram[..size]) else {
                    continue;
                };
                if target.use_upstream(config.force_all_upstream) {
                    let _ = upstream_udp.send(&datagram[..size]);
                } else if let Ok(addresses) = target.resolve() {
                    if let Some(destination) = addresses.first() {
                        let _ = direct_udp.send_to(&datagram[payload_offset..size], destination);
                    }
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => {
                stopped.store(true, Ordering::Release);
                let _ = upstream_thread.join();
                let _ = direct_thread.join();
                return Err(error);
            }
        }
    }
    stopped.store(true, Ordering::Release);
    let _ = upstream_thread.join();
    let _ = direct_thread.join();
    let _ = upstream_control.shutdown(Shutdown::Both);
    Ok(())
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
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            Host::Ip(IpAddr::V4(Ipv4Addr::from(bytes)))
        }
        3 => {
            let mut length = [0u8; 1];
            reader.read_exact(&mut length)?;
            let mut bytes = vec![0u8; length[0] as usize];
            reader.read_exact(&mut bytes)?;
            Host::Domain(String::from_utf8(bytes).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid domain encoding")
            })?)
        }
        4 => {
            let mut bytes = [0u8; 16];
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
    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    Ok(Target {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn read_reply(stream: &mut impl Read) -> io::Result<(Vec<u8>, u8, SocketAddr)> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid SOCKS5 reply",
        ));
    }
    let target = read_target(stream, head[3])?;
    // `head[3]` is the address type consumed by `read_target`. `Target::encode`
    // writes that byte itself, so retaining all four head bytes would duplicate
    // ATYP and leave one byte of the SOCKS reply in the application stream.
    let mut response = head[..3].to_vec();
    target.encode(&mut response)?;
    let address = target
        .resolve()?
        .into_iter()
        .next()
        .unwrap_or_else(unspecified_address);
    Ok((response, head[1], address))
}

fn write_reply(stream: &mut TcpStream, reply: u8, address: SocketAddr) -> io::Result<()> {
    let mut response = vec![SOCKS_VERSION, reply, 0];
    Target {
        host: Host::Ip(address.ip()),
        port: address.port(),
    }
    .encode(&mut response)?;
    stream.write_all(&response)
}

fn connect_any(addresses: &[SocketAddr]) -> io::Result<TcpStream> {
    let mut last_error = None;
    for address in addresses {
        // Apple's iOS simulator can return EAGAIN from the non-blocking socket
        // sequence used by `connect_timeout`. Each client already has its own
        // worker thread, so a blocking connect is safe here and works on device.
        match TcpStream::connect(address) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address resolved")))
}

struct MnaRouteLearner {
    candidate: Option<bool>,
    probe: Vec<u8>,
    framer: W0Framer,
    key: Option<Zeroizing<[u8; 16]>>,
}

impl MnaRouteLearner {
    fn new() -> Self {
        Self {
            candidate: None,
            probe: Vec::with_capacity(MNA_MAGIC.len()),
            framer: W0Framer::new(MAX_MNA_STREAM_BYTES),
            key: None,
        }
    }

    fn observe_server_bytes(&mut self, payload: &[u8]) {
        if payload.is_empty() || self.candidate == Some(false) {
            return;
        }
        let bytes = if self.candidate.is_none() {
            let needed = MNA_MAGIC.len().saturating_sub(self.probe.len());
            let take = needed.min(payload.len());
            self.probe.extend_from_slice(&payload[..take]);
            if !MNA_MAGIC.starts_with(&self.probe) {
                self.candidate = Some(false);
                return;
            }
            if self.probe.len() < MNA_MAGIC.len() {
                return;
            }
            self.candidate = Some(true);
            let mut combined = Vec::with_capacity(self.probe.len() + payload.len() - take);
            combined.extend_from_slice(&self.probe);
            combined.extend_from_slice(&payload[take..]);
            combined
        } else {
            payload.to_vec()
        };

        let Ok(frames) = self.framer.feed(&bytes) else {
            self.candidate = Some(false);
            return;
        };
        for frame in frames {
            if frame.message_type == MNA_SERVER_HELLO {
                if let Ok(key) = recover_mna_session_key(std::slice::from_ref(&frame)) {
                    self.key = Some(key);
                }
                continue;
            }
            if frame.message_type != MNA_DATA {
                continue;
            }
            let Some(key) = self.key.as_deref() else {
                continue;
            };
            let Ok(mut plaintext) = decrypt_mna_frame(&frame, key) else {
                continue;
            };
            if strip_mna_random_padding(&mut plaintext).is_err() {
                continue;
            }
            let Ok(application) =
                parse_mna_application(&plaintext, frame.direction_marker, frame.sequence)
            else {
                continue;
            };
            let Ok(Some(session)) = parse_enter_game_session(&application) else {
                continue;
            };
            replace_dynamic_game_routes(
                &session.server_ip,
                session.server_vip.as_deref(),
                session.server_port,
            );
        }
    }
}

fn copy_bidirectional(
    left: &mut TcpStream,
    right: &mut TcpStream,
    initial_left: Vec<u8>,
    learn_mna_routes: bool,
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
    let reverse = if learn_mna_routes {
        let mut learner = MnaRouteLearner::new();
        let mut buffer = [0_u8; 16 * 1024];
        let mut copied = 0_u64;
        loop {
            let count = right.read(&mut buffer)?;
            if count == 0 {
                break Ok(copied);
            }
            learner.observe_server_bytes(&buffer[..count]);
            left.write_all(&buffer[..count])?;
            copied = copied.saturating_add(count as u64);
        }
    } else {
        io::copy(right, left)
    };
    let _ = left.shutdown(Shutdown::Write);
    let forward = forward
        .join()
        .map_err(|_| io::Error::other("relay worker panicked"))?;
    forward?;
    reverse?;
    Ok(())
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

    #[test]
    fn upstream_reply_is_reencoded_without_a_duplicate_address_type() {
        let wire = [5, 0, 0, 1, 192, 0, 2, 1, 0x12, 0x34];
        let (response, reply, address) = read_reply(&mut io::Cursor::new(wire)).unwrap();

        assert_eq!(reply, 0);
        assert_eq!(response, wire);
        assert_eq!(address, "192.0.2.1:4660".parse().unwrap());
    }

    #[test]
    fn routing_only_sends_game_traffic_upstream() {
        assert!(
            Target {
                host: Host::Domain("receiver.tdm.qq.com".into()),
                port: 443
            }
            .use_upstream(false)
        );
        assert!(
            Target {
                host: Host::Domain("foo.codev.qq.com".into()),
                port: 443
            }
            .use_upstream(false)
        );
        assert!(
            Target {
                host: Host::Ip("43.162.204.121".parse().unwrap()),
                port: 443
            }
            .use_upstream(false)
        );
        assert!(
            Target {
                host: Host::Ip("203.0.113.8".parse().unwrap()),
                port: 15806
            }
            .use_upstream(false)
        );
        assert!(
            !Target {
                host: Host::Domain("example.com".into()),
                port: 443
            }
            .use_upstream(false)
        );
        assert!(
            !Target {
                host: Host::Ip("1.1.1.1".parse().unwrap()),
                port: 443
            }
            .use_upstream(false)
        );
    }

    #[test]
    fn learned_session_port_routes_rotated_game_endpoint_upstream() {
        let _lock = relay_test_lock();
        replace_dynamic_game_routes("118.182.226.83", Some("112.193.78.91"), 52_621);
        assert!(
            Target {
                host: Host::Ip("112.193.78.91".parse().unwrap()),
                port: 52_621,
            }
            .use_upstream(false)
        );
        assert!(
            Target {
                host: Host::Ip("203.0.113.18".parse().unwrap()),
                port: 52_621,
            }
            .use_upstream(false)
        );
        assert!(
            !Target {
                host: Host::Ip("203.0.113.18".parse().unwrap()),
                port: 52_622,
            }
            .use_upstream(false)
        );
    }

    #[test]
    fn unified_cloud_exit_routes_other_targets_upstream() {
        assert!(
            Target {
                host: Host::Domain("example.com".into()),
                port: 443,
            }
            .use_upstream(true)
        );
        assert!(
            Target {
                host: Host::Ip("1.1.1.1".parse().unwrap()),
                port: 80,
            }
            .use_upstream(true)
        );
    }

    #[test]
    fn parses_udp_domain_datagram() {
        let packet = [
            0, 0, 0, 3, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0,
            53, 1, 2,
        ];
        let (target, offset) = parse_udp_datagram(&packet).unwrap();
        assert_eq!(
            target,
            Target {
                host: Host::Domain("example.com".into()),
                port: 53
            }
        );
        assert_eq!(&packet[offset..], &[1, 2]);
    }

    #[test]
    fn only_private_or_local_peers_can_use_the_relay() {
        assert!(allowed_peer("127.0.0.1".parse().unwrap()));
        assert!(allowed_peer("172.20.10.2".parse().unwrap()));
        assert!(allowed_peer("192.168.1.8".parse().unwrap()));
        assert!(!allowed_peer("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn stopping_relay_closes_existing_client_sockets() {
        let _lock = relay_test_lock();
        let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);

        let upstream_host = CString::new("127.0.0.1").unwrap();
        let upstream_username = CString::new("upstream-user").unwrap();
        let upstream_password = CString::new("upstream-password").unwrap();
        let local_username = CString::new("local-user").unwrap();
        let local_password = CString::new("local-password").unwrap();
        let started = unsafe {
            phoenix_relay_start(
                upstream_host.as_ptr(),
                9,
                upstream_username.as_ptr(),
                upstream_password.as_ptr(),
                local_username.as_ptr(),
                local_password.as_ptr(),
                port,
            )
        };
        assert_eq!(started, 0);

        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
        for _ in 0..50 {
            if phoenix_relay_client_count() == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(phoenix_relay_client_count(), 1);

        phoenix_relay_stop();
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).unwrap(), 0);
        for _ in 0..50 {
            if phoenix_relay_client_count() == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(phoenix_relay_client_count(), 0);
    }
}
