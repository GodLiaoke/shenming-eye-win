use anyhow::{Context, anyhow};
use phoenix_cloud_relay::{CloudMirrorSink, phoenix_cloud_relay_client_count};
use std::collections::{BTreeMap, HashMap, VecDeque, hash_map::DefaultHasher};
use std::ffi::c_void;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

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

type DivertOpen = unsafe extern "system" fn(*const u8, i32, i16, u64) -> HANDLE;
type DivertRecv = unsafe extern "system" fn(HANDLE, *mut c_void, u32, *mut u32, *mut c_void) -> i32;
type DivertShutdown = unsafe extern "system" fn(HANDLE, u32) -> i32;
type DivertClose = unsafe extern "system" fn(HANDLE) -> i32;
type DivertSetParam = unsafe extern "system" fn(HANDLE, i32, u64) -> i32;

#[derive(Clone, Copy)]
struct DivertApi {
    recv: DivertRecv,
    shutdown: DivertShutdown,
    close: DivertClose,
    set_param: DivertSetParam,
}

#[derive(Clone, Copy)]
enum Layer {
    Network = 0,
    Forward = 1,
}

pub struct PassiveCapture {
    module: usize,
    handles: Vec<usize>,
    threads: Vec<JoinHandle<()>>,
    stopping: Arc<AtomicBool>,
    api: DivertApi,
}

impl PassiveCapture {
    pub fn start(directory: &Path, sink: CloudMirrorSink) -> anyhow::Result<Self> {
        let dll = directory.join("WinDivert.dll");
        if !dll.is_file() {
            anyhow::bail!("抓包组件缺失");
        }
        if !directory.join("WinDivert64.sys").is_file() {
            anyhow::bail!("抓包组件缺失");
        }
        let dll_wide = dll
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect::<Vec<_>>();
        let module = unsafe { LoadLibraryW(dll_wide.as_ptr()) };
        if module.is_null() {
            anyhow::bail!("抓包组件加载失败（Win32 {}）", unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            });
        }
        let loaded = unsafe { load_api(module) };
        let (open, api) = match loaded {
            Ok(value) => value,
            Err(error) => {
                unsafe { FreeLibrary(module) };
                return Err(error);
            }
        };

        let mut handles = Vec::new();
        for layer in [Layer::Forward, Layer::Network] {
            let handle = unsafe {
                open(
                    b"tcp or udp\0".as_ptr(),
                    layer as i32,
                    0,
                    0x0001 | 0x0004, // SNIFF + RECV_ONLY: packet is never blocked/reinjected.
                )
            };
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                let last_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
                for &opened in &handles {
                    unsafe { (api.close)(opened as HANDLE) };
                }
                unsafe { FreeLibrary(module) };
                anyhow::bail!("抓包通道启动失败（Win32 {last_error}）");
            }
            unsafe {
                (api.set_param)(handle, 0, 16_384);
                (api.set_param)(handle, 1, 512);
                (api.set_param)(handle, 2, 16 * 1024 * 1024);
            }
            handles.push(handle as usize);
        }

        let stopping = Arc::new(AtomicBool::new(false));
        let deduper = Arc::new(PacketDeduper::default());
        let tcp = Arc::new(Mutex::new(TcpReassembler::default()));
        // Construct the owner BEFORE spawning: an early spawn error drops all
        // already-open handles/threads instead of leaking the driver module.
        let mut capture = Self {
            module: module as usize,
            handles,
            threads: Vec::new(),
            stopping: stopping.clone(),
            api,
        };
        for index in 0..capture.handles.len() {
            let handle = capture.handles[index];
            let stopping = Arc::clone(&stopping);
            let deduper = Arc::clone(&deduper);
            let tcp = Arc::clone(&tcp);
            let sink = sink.clone();
            let api_copy = api;
            capture.threads.push(
                std::thread::Builder::new()
                    .name(format!("capture-{index}"))
                    .spawn(move || {
                        capture_loop(handle as HANDLE, api_copy, stopping, deduper, tcp, sink)
                    })
                    .context("WinDivert 工作线程启动失败")?,
            );
        }
        Ok(capture)
    }
}

impl Drop for PassiveCapture {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        for &handle in &self.handles {
            unsafe {
                (self.api.shutdown)(handle as HANDLE, 0x1);
                (self.api.close)(handle as HANDLE);
            }
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
        unsafe { FreeLibrary(self.module as HMODULE) };
    }
}

unsafe fn load_api(module: HMODULE) -> anyhow::Result<(DivertOpen, DivertApi)> {
    unsafe fn symbol<T: Copy>(module: HMODULE, name: &'static [u8]) -> anyhow::Result<T> {
        let raw = unsafe { GetProcAddress(module, name.as_ptr()) }
            .ok_or_else(|| anyhow!("抓包接口不可用"))?;
        Ok(unsafe { std::mem::transmute_copy(&raw) })
    }
    Ok((
        unsafe { symbol(module, b"WinDivertOpen\0")? },
        DivertApi {
            recv: unsafe { symbol(module, b"WinDivertRecv\0")? },
            shutdown: unsafe { symbol(module, b"WinDivertShutdown\0")? },
            close: unsafe { symbol(module, b"WinDivertClose\0")? },
            set_param: unsafe { symbol(module, b"WinDivertSetParam\0")? },
        },
    ))
}

fn capture_loop(
    handle: HANDLE,
    api: DivertApi,
    stopping: Arc<AtomicBool>,
    deduper: Arc<PacketDeduper>,
    tcp: Arc<Mutex<TcpReassembler>>,
    sink: CloudMirrorSink,
) {
    let mut buffer = vec![0_u8; 65_575];
    while !stopping.load(Ordering::Acquire) {
        let mut received = 0_u32;
        let ok = unsafe {
            (api.recv)(
                handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut received,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            if !stopping.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(25));
            }
            continue;
        }
        // SOCKS5 mode is already mirrored by phoenix-cloud-relay. Ignoring
        // passive copies while a phone client is attached prevents duplicate
        // streams at the protected parser.
        if phoenix_cloud_relay_client_count() > 0 {
            continue;
        }
        let Some(packet) = parse_packet(&buffer[..received as usize]) else {
            continue;
        };
        if !deduper.accepts(&packet) || !should_mirror(&packet) {
            continue;
        }
        let remote = SocketAddr::new(packet.remote, packet.remote_port);
        let flow_id = flow_id(&packet);
        match packet.transport {
            Transport::Udp => {
                sink.record_udp(packet.client_to_server, flow_id, remote, packet.payload)
            }
            Transport::Tcp { sequence, close } => {
                let chunks = tcp
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .push(flow_id, packet.client_to_server, sequence, packet.payload);
                for chunk in chunks {
                    sink.record_tcp(packet.client_to_server, flow_id, remote, &chunk);
                }
                if close {
                    sink.close_tcp(flow_id, remote);
                    tcp.lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .remove(flow_id);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
enum Transport {
    Udp,
    Tcp { sequence: u32, close: bool },
}

#[derive(Clone, Debug)]
struct Packet<'a> {
    client: IpAddr,
    remote: IpAddr,
    client_port: u16,
    remote_port: u16,
    client_to_server: bool,
    transport: Transport,
    payload: &'a [u8],
}

fn private_client(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_unicast_link_local() || (ip.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn classify<'a>(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    transport: Transport,
    payload: &'a [u8],
) -> Option<Packet<'a>> {
    match (private_client(source), private_client(destination)) {
        (true, false) => Some(Packet {
            client: source,
            remote: destination,
            client_port: source_port,
            remote_port: destination_port,
            client_to_server: true,
            transport,
            payload,
        }),
        (false, true) => Some(Packet {
            client: destination,
            remote: source,
            client_port: destination_port,
            remote_port: source_port,
            client_to_server: false,
            transport,
            payload,
        }),
        _ => None,
    }
}

fn parse_packet(packet: &[u8]) -> Option<Packet<'_>> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4(packet),
        Some(6) => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<Packet<'_>> {
    if packet.len() < 20 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]])).min(packet.len());
    if header < 20 || total < header || packet[6] & 0x3f != 0 || packet[7] != 0 {
        return None;
    }
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    parse_transport(source, destination, packet[9], &packet[header..total])
}

fn parse_ipv6(packet: &[u8]) -> Option<Packet<'_>> {
    if packet.len() < 40 {
        return None;
    }
    let end = (40 + usize::from(u16::from_be_bytes([packet[4], packet[5]]))).min(packet.len());
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    let mut next = packet[6];
    let mut offset = 40_usize;
    loop {
        match next {
            6 | 17 => break,
            0 | 43 | 60 => {
                if offset + 2 > end {
                    return None;
                }
                next = packet[offset];
                offset += (usize::from(packet[offset + 1]) + 1) * 8;
            }
            44 => return None,
            51 => {
                if offset + 2 > end {
                    return None;
                }
                next = packet[offset];
                offset += (usize::from(packet[offset + 1]) + 2) * 4;
            }
            _ => return None,
        }
        if offset > end {
            return None;
        }
    }
    parse_transport(source, destination, next, &packet[offset..end])
}

fn parse_transport<'a>(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    segment: &'a [u8],
) -> Option<Packet<'a>> {
    match protocol {
        17 if segment.len() >= 8 => {
            let length = usize::from(u16::from_be_bytes([segment[4], segment[5]]));
            if !(8..=segment.len()).contains(&length) {
                return None;
            }
            classify(
                source,
                destination,
                u16::from_be_bytes([segment[0], segment[1]]),
                u16::from_be_bytes([segment[2], segment[3]]),
                Transport::Udp,
                &segment[8..length],
            )
        }
        6 if segment.len() >= 20 => {
            let header = usize::from(segment[12] >> 4) * 4;
            if header < 20 || header > segment.len() {
                return None;
            }
            let sequence = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
            let flags = segment[13];
            classify(
                source,
                destination,
                u16::from_be_bytes([segment[0], segment[1]]),
                u16::from_be_bytes([segment[2], segment[3]]),
                Transport::Tcp {
                    sequence,
                    close: flags & (0x01 | 0x04) != 0,
                },
                &segment[header..],
            )
        }
        _ => None,
    }
}

fn should_mirror(packet: &Packet<'_>) -> bool {
    match packet.transport {
        Transport::Udp => !matches!(packet.remote_port, 53 | 443) && !packet.payload.is_empty(),
        Transport::Tcp { .. } => {
            matches!(packet.remote_port, 1_883 | 8_013 | 8_085 | 15_806 | 17_500)
                || GAME_IPV4
                    .iter()
                    .any(|candidate| *candidate == packet.remote.to_string())
        }
    }
}

fn flow_id(packet: &Packet<'_>) -> u64 {
    let mut hasher = DefaultHasher::new();
    packet.client.hash(&mut hasher);
    packet.client_port.hash(&mut hasher);
    packet.remote.hash(&mut hasher);
    packet.remote_port.hash(&mut hasher);
    std::mem::discriminant(&packet.transport).hash(&mut hasher);
    hasher.finish()
}

#[derive(Default)]
struct PacketDeduper {
    recent: Mutex<VecDeque<(u64, Instant)>>,
}

impl PacketDeduper {
    fn accepts(&self, packet: &Packet<'_>) -> bool {
        const WINDOW: Duration = Duration::from_millis(12);
        let mut hasher = DefaultHasher::new();
        packet.remote.hash(&mut hasher);
        packet.remote_port.hash(&mut hasher);
        packet.client_to_server.hash(&mut hasher);
        packet.transport.hash(&mut hasher);
        packet.payload.hash(&mut hasher);
        let fingerprint = hasher.finish();
        let now = Instant::now();
        let mut recent = self.recent.lock().unwrap_or_else(|p| p.into_inner());
        while recent
            .front()
            .is_some_and(|(_, seen)| now.duration_since(*seen) > WINDOW)
        {
            recent.pop_front();
        }
        if recent.iter().any(|(value, _)| *value == fingerprint) {
            return false;
        }
        recent.push_back((fingerprint, now));
        while recent.len() > 1_024 {
            recent.pop_front();
        }
        true
    }
}

#[derive(Default)]
struct DirectionState {
    next: Option<u32>,
    pending: BTreeMap<u32, Vec<u8>>,
}

#[derive(Default)]
struct FlowState {
    outbound: DirectionState,
    inbound: DirectionState,
}

#[derive(Default)]
struct TcpReassembler {
    flows: HashMap<u64, FlowState>,
}

impl TcpReassembler {
    fn push(&mut self, flow: u64, outbound: bool, sequence: u32, payload: &[u8]) -> Vec<Vec<u8>> {
        if payload.is_empty() {
            return Vec::new();
        }
        let flow_state = self.flows.entry(flow).or_default();
        let state = if outbound {
            &mut flow_state.outbound
        } else {
            &mut flow_state.inbound
        };
        let next = state.next.get_or_insert(sequence);
        if sequence.wrapping_sub(*next) as i32 > 0 {
            if state.pending.len() < 128 {
                state
                    .pending
                    .entry(sequence)
                    .or_insert_with(|| payload.to_vec());
            }
            return Vec::new();
        }
        let already = next.wrapping_sub(sequence) as usize;
        if already >= payload.len() {
            return Vec::new();
        }
        let mut output = vec![payload[already..].to_vec()];
        *next = next.wrapping_add((payload.len() - already) as u32);
        while let Some(chunk) = state.pending.remove(next) {
            *next = next.wrapping_add(chunk.len() as u32);
            output.push(chunk);
        }
        output
    }

    fn remove(&mut self, flow: u64) {
        self.flows.remove(&flow);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_ipv4_udp_both_directions() {
        let payload = b"payload";
        let total = 20 + 8 + payload.len();
        let mut bytes = vec![0_u8; total];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        bytes[9] = 17;
        bytes[12..16].copy_from_slice(&[192, 168, 137, 9]);
        bytes[16..20].copy_from_slice(&[43, 135, 106, 46]);
        bytes[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
        bytes[22..24].copy_from_slice(&17_500_u16.to_be_bytes());
        bytes[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        bytes[28..].copy_from_slice(payload);
        let parsed = parse_packet(&bytes).expect("packet");
        assert!(parsed.client_to_server);
        assert_eq!(parsed.remote_port, 17_500);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn reassembles_and_deduplicates_tcp() {
        let mut reassembler = TcpReassembler::default();
        assert_eq!(
            reassembler.push(7, true, 100, b"abc"),
            vec![b"abc".to_vec()]
        );
        assert!(reassembler.push(7, true, 106, b"ghi").is_empty());
        assert_eq!(
            reassembler.push(7, true, 103, b"def"),
            vec![b"def".to_vec(), b"ghi".to_vec()]
        );
        assert!(reassembler.push(7, true, 100, b"abc").is_empty());
    }
}
