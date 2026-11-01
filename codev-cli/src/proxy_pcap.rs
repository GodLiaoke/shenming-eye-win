use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use codev_capture::{Direction, FrameEnvelope, Transport};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

const PCAP_QUEUE_CAPACITY: usize = 1_024;
const PCAP_LINKTYPE_RAW: u32 = 12;
const PCAP_SNAPLEN: u32 = 65_535;
const MAX_SYNTHETIC_PAYLOAD: usize = 65_495;

#[derive(Clone, Debug)]
pub struct ProxyPcapConfig {
    pub directory: PathBuf,
    pub max_bytes: u64,
    pub max_duration_secs: u64,
    pub max_files: usize,
}

#[derive(Default)]
struct RecorderStatus {
    finished: AtomicBool,
    dropped_items: AtomicU64,
    write_failures: AtomicU64,
}

enum RecorderItem {
    Frame(FrameEnvelope),
    TcpClosed { flow_id: u64, capture_ns: u64 },
    Finish,
}

#[derive(Clone)]
pub struct ProxyPcapRecorder {
    sender: SyncSender<RecorderItem>,
    status: Arc<RecorderStatus>,
    join: Arc<Mutex<Option<JoinHandle<io::Result<()>>>>>,
}

impl ProxyPcapRecorder {
    pub fn start(config: ProxyPcapConfig) -> io::Result<Self> {
        validate_config(&config)?;
        prepare_private_directory(&config.directory)?;
        let writer = RollingPcapWriter::new(config)?;
        let (sender, receiver) = mpsc::sync_channel(PCAP_QUEUE_CAPACITY);
        let status = Arc::new(RecorderStatus::default());
        let worker_status = Arc::clone(&status);
        let join = thread::Builder::new()
            .name("codev-proxy-pcap".into())
            .spawn(move || {
                let mut writer = writer;
                let flush_interval = Duration::from_millis(100);
                let mut next_flush = Instant::now() + flush_interval;
                let result = loop {
                    let wait = next_flush.saturating_duration_since(Instant::now());
                    let item_result = match receiver.recv_timeout(wait) {
                        Ok(RecorderItem::Frame(frame)) => {
                            if let Err(error) = writer.record_frame(&frame) {
                                worker_status.write_failures.fetch_add(1, Ordering::Relaxed);
                                break Err(error);
                            }
                            None
                        }
                        Ok(RecorderItem::TcpClosed {
                            flow_id,
                            capture_ns,
                        }) => {
                            if let Err(error) = writer.close_tcp_flow(flow_id, capture_ns) {
                                worker_status.write_failures.fetch_add(1, Ordering::Relaxed);
                                break Err(error);
                            }
                            None
                        }
                        Ok(RecorderItem::Finish) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                            break writer.finish();
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => Some(()),
                    };
                    if item_result.is_some() || Instant::now() >= next_flush {
                        if let Err(error) = writer.flush() {
                            worker_status.write_failures.fetch_add(1, Ordering::Relaxed);
                            break Err(error);
                        }
                        next_flush = Instant::now() + flush_interval;
                    }
                };
                worker_status.finished.store(true, Ordering::Release);
                result
            })?;
        Ok(Self {
            sender,
            status,
            join: Arc::new(Mutex::new(Some(join))),
        })
    }

    pub fn record(&self, frame: &FrameEnvelope) {
        if self.status.finished.load(Ordering::Acquire) {
            return;
        }
        if let Err(error) = self.sender.try_send(RecorderItem::Frame(frame.clone())) {
            if matches!(error, TrySendError::Full(_)) {
                self.status.dropped_items.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn tcp_closed(&self, flow_id: u64, capture_ns: u64) {
        if self.status.finished.load(Ordering::Acquire) {
            return;
        }
        if let Err(error) = self.sender.try_send(RecorderItem::TcpClosed {
            flow_id,
            capture_ns,
        }) && matches!(error, TrySendError::Full(_))
        {
            self.status.dropped_items.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn dropped_items(&self) -> u64 {
        self.status.dropped_items.load(Ordering::Relaxed)
    }

    pub fn finish(&self) -> io::Result<()> {
        let mut join = self
            .join
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(worker) = join.take() else {
            return Ok(());
        };
        let _ = self.sender.send(RecorderItem::Finish);
        worker
            .join()
            .map_err(|_| io::Error::other("proxy PCAP writer thread panicked"))?
    }
}

fn validate_config(config: &ProxyPcapConfig) -> io::Result<()> {
    if config.max_bytes < 1024 * 1024
        || config.max_duration_secs == 0
        || !(1..=100).contains(&config.max_files)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "proxy PCAP limits are invalid",
        ));
    }
    Ok(())
}

fn prepare_private_directory(directory: &Path) -> io::Result<()> {
    match directory.symlink_metadata() {
        Ok(metadata) if !metadata.is_dir() || metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "proxy PCAP directory must be a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            #[cfg(unix)]
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(directory)?;
            #[cfg(not(unix))]
            fs::create_dir_all(directory)?;
        }
        Err(error) => return Err(error),
    }
    #[cfg(unix)]
    fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

struct RollingPcapWriter {
    config: ProxyPcapConfig,
    writer: BufWriter<File>,
    created_ns: u64,
    bytes_written: u64,
    file_counter: u64,
    tcp_flows: HashMap<u64, TcpFlowState>,
}

#[derive(Clone, Copy)]
struct TcpFlowState {
    client: SocketAddr,
    server: SocketAddr,
    client_sequence: u32,
    server_sequence: u32,
}

impl RollingPcapWriter {
    fn new(config: ProxyPcapConfig) -> io::Result<Self> {
        let now_ns = unix_time_ns();
        let (writer, bytes_written) = create_pcap_file(&config.directory, now_ns, 0)?;
        rotate_old_pcaps(&config.directory, config.max_files)?;
        Ok(Self {
            config,
            writer,
            created_ns: now_ns,
            bytes_written,
            file_counter: 0,
            tcp_flows: HashMap::new(),
        })
    }

    fn record_frame(&mut self, frame: &FrameEnvelope) -> io::Result<()> {
        let Some(route) = frame.route else {
            return Ok(());
        };
        if self.should_rotate(frame.capture_ns) {
            self.rotate(frame.capture_ns)?;
        }
        match frame.transport {
            Transport::Tcp => self.record_tcp(frame, route.source, route.destination),
            Transport::Udp => self.record_udp(
                frame.capture_ns,
                route.source,
                route.destination,
                &frame.payload,
            ),
        }
    }

    fn should_rotate(&self, capture_ns: u64) -> bool {
        self.bytes_written >= self.config.max_bytes
            || capture_ns.saturating_sub(self.created_ns)
                >= self.config.max_duration_secs.saturating_mul(1_000_000_000)
    }

    fn rotate(&mut self, capture_ns: u64) -> io::Result<()> {
        self.finish_tcp_flows(capture_ns)?;
        self.writer.flush()?;
        self.file_counter = self.file_counter.saturating_add(1);
        let (writer, bytes_written) = create_pcap_file(
            &self.config.directory,
            capture_ns.max(unix_time_ns()),
            self.file_counter,
        )?;
        self.writer = writer;
        self.created_ns = capture_ns;
        self.bytes_written = bytes_written;
        rotate_old_pcaps(&self.config.directory, self.config.max_files)
    }

    fn record_tcp(
        &mut self,
        frame: &FrameEnvelope,
        source: SocketAddr,
        destination: SocketAddr,
    ) -> io::Result<()> {
        if frame.payload.len() > MAX_SYNTHETIC_PAYLOAD {
            return Ok(());
        }
        if !self.tcp_flows.contains_key(&frame.flow_id) {
            let (client, server) = match frame.direction {
                Direction::ClientToServer => (source, destination),
                Direction::ServerToClient => (destination, source),
            };
            self.write_tcp_handshake(frame.capture_ns, client, server)?;
            self.tcp_flows.insert(
                frame.flow_id,
                TcpFlowState {
                    client,
                    server,
                    client_sequence: 2,
                    server_sequence: 2,
                },
            );
        }
        let state = self.tcp_flows.get_mut(&frame.flow_id).unwrap();
        let (packet_source, packet_destination, sequence, acknowledgement) = match frame.direction {
            Direction::ClientToServer => {
                let sequence = state.client_sequence;
                state.client_sequence = state
                    .client_sequence
                    .wrapping_add(frame.payload.len() as u32);
                (state.client, state.server, sequence, state.server_sequence)
            }
            Direction::ServerToClient => {
                let sequence = state.server_sequence;
                state.server_sequence = state
                    .server_sequence
                    .wrapping_add(frame.payload.len() as u32);
                (state.server, state.client, sequence, state.client_sequence)
            }
        };
        let packet = tcp_packet(
            packet_source,
            packet_destination,
            sequence,
            acknowledgement,
            0x18,
            &frame.payload,
        )?;
        self.write_packet(frame.capture_ns, &packet)
    }

    fn write_tcp_handshake(
        &mut self,
        capture_ns: u64,
        client: SocketAddr,
        server: SocketAddr,
    ) -> io::Result<()> {
        let syn = tcp_packet(client, server, 1, 0, 0x02, &[])?;
        let syn_ack = tcp_packet(server, client, 1, 2, 0x12, &[])?;
        let ack = tcp_packet(client, server, 2, 2, 0x10, &[])?;
        self.write_packet(capture_ns.saturating_sub(3_000), &syn)?;
        self.write_packet(capture_ns.saturating_sub(2_000), &syn_ack)?;
        self.write_packet(capture_ns.saturating_sub(1_000), &ack)
    }

    fn close_tcp_flow(&mut self, flow_id: u64, capture_ns: u64) -> io::Result<()> {
        let Some(state) = self.tcp_flows.remove(&flow_id) else {
            return Ok(());
        };
        self.write_tcp_close(capture_ns, state)
    }

    fn write_tcp_close(&mut self, capture_ns: u64, state: TcpFlowState) -> io::Result<()> {
        let client_fin = tcp_packet(
            state.client,
            state.server,
            state.client_sequence,
            state.server_sequence,
            0x11,
            &[],
        )?;
        let server_fin = tcp_packet(
            state.server,
            state.client,
            state.server_sequence,
            state.client_sequence.wrapping_add(1),
            0x11,
            &[],
        )?;
        self.write_packet(capture_ns, &client_fin)?;
        self.write_packet(capture_ns.saturating_add(1_000), &server_fin)
    }

    fn finish_tcp_flows(&mut self, capture_ns: u64) -> io::Result<()> {
        let flows: Vec<_> = self.tcp_flows.drain().map(|(_, state)| state).collect();
        for (index, state) in flows.into_iter().enumerate() {
            self.write_tcp_close(capture_ns.saturating_add(index as u64 * 2_000), state)?;
        }
        Ok(())
    }

    fn record_udp(
        &mut self,
        capture_ns: u64,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        if payload.len() > MAX_SYNTHETIC_PAYLOAD {
            return Ok(());
        }
        let packet = udp_packet(source, destination, payload)?;
        self.write_packet(capture_ns, &packet)
    }

    fn write_packet(&mut self, timestamp_ns: u64, packet: &[u8]) -> io::Result<()> {
        let seconds = u32::try_from(timestamp_ns / 1_000_000_000)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PCAP timestamp overflow"))?;
        let micros = ((timestamp_ns % 1_000_000_000) / 1_000) as u32;
        let length = u32::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "PCAP packet too large"))?;
        self.writer.write_all(&seconds.to_le_bytes())?;
        self.writer.write_all(&micros.to_le_bytes())?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(&length.to_le_bytes())?;
        self.writer.write_all(packet)?;
        self.bytes_written = self
            .bytes_written
            .saturating_add(16)
            .saturating_add(u64::from(length));
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }

    fn finish(&mut self) -> io::Result<()> {
        self.finish_tcp_flows(unix_time_ns())?;
        self.writer.flush()
    }
}

fn create_pcap_file(
    directory: &Path,
    timestamp_ns: u64,
    counter: u64,
) -> io::Result<(BufWriter<File>, u64)> {
    let seconds = timestamp_ns / 1_000_000_000;
    let path = directory.join(format!(
        "proxy-{seconds}-{}-{counter}.pcap",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut writer = BufWriter::new(options.open(path)?);
    writer.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    writer.write_all(&2_u16.to_le_bytes())?;
    writer.write_all(&4_u16.to_le_bytes())?;
    writer.write_all(&0_i32.to_le_bytes())?;
    writer.write_all(&0_u32.to_le_bytes())?;
    writer.write_all(&PCAP_SNAPLEN.to_le_bytes())?;
    writer.write_all(&PCAP_LINKTYPE_RAW.to_le_bytes())?;
    writer.flush()?;
    Ok((writer, 24))
}

fn rotate_old_pcaps(directory: &Path, max_files: usize) -> io::Result<()> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("pcap") {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.is_file() && !entry.file_type()?.is_symlink() {
            paths.push(path);
        }
    }
    paths.sort();
    let remove_count = paths.len().saturating_sub(max_files);
    for path in paths.into_iter().take(remove_count) {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn tcp_packet(
    source: SocketAddr,
    destination: SocketAddr,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut segment = vec![0_u8; 20 + payload.len()];
    segment[..2].copy_from_slice(&source.port().to_be_bytes());
    segment[2..4].copy_from_slice(&destination.port().to_be_bytes());
    segment[4..8].copy_from_slice(&sequence.to_be_bytes());
    segment[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    segment[12] = 5 << 4;
    segment[13] = flags;
    segment[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    segment[20..].copy_from_slice(payload);
    raw_ip_packet(source.ip(), destination.ip(), 6, segment, 16)
}

fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let length = u16::try_from(8 + payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "UDP payload too large"))?;
    let mut datagram = vec![0_u8; usize::from(length)];
    datagram[..2].copy_from_slice(&source.port().to_be_bytes());
    datagram[2..4].copy_from_slice(&destination.port().to_be_bytes());
    datagram[4..6].copy_from_slice(&length.to_be_bytes());
    datagram[8..].copy_from_slice(payload);
    raw_ip_packet(source.ip(), destination.ip(), 17, datagram, 6)
}

fn raw_ip_packet(
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    mut transport: Vec<u8>,
    checksum_offset: usize,
) -> io::Result<Vec<u8>> {
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            let total_length = u16::try_from(20 + transport.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "IPv4 packet too large"))?;
            let transport_checksum = transport_checksum_ipv4(
                source.octets(),
                destination.octets(),
                protocol,
                &transport,
            );
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&transport_checksum.to_be_bytes());
            let mut packet = vec![0_u8; 20];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&total_length.to_be_bytes());
            packet[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&source.octets());
            packet[16..20].copy_from_slice(&destination.octets());
            let header_checksum = checksum(&packet);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
            packet.extend_from_slice(&transport);
            Ok(packet)
        }
        (source, destination) => {
            let source = mapped_ipv6(source).octets();
            let destination = mapped_ipv6(destination).octets();
            let payload_length = u16::try_from(transport.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "IPv6 packet too large"))?;
            let checksum = transport_checksum_ipv6(source, destination, protocol, &transport);
            transport[checksum_offset..checksum_offset + 2]
                .copy_from_slice(&checksum.to_be_bytes());
            let mut packet = vec![0_u8; 40];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
            packet[6] = protocol;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&source);
            packet[24..40].copy_from_slice(&destination);
            packet.extend_from_slice(&transport);
            Ok(packet)
        }
    }
}

fn mapped_ipv6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(address) => address.to_ipv6_mapped(),
        IpAddr::V6(address) => address,
    }
}

fn transport_checksum_ipv4(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + transport.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(transport.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(transport);
    nonzero_checksum(&pseudo)
}

fn transport_checksum_ipv6(
    source: [u8; 16],
    destination: [u8; 16],
    protocol: u8,
    transport: &[u8],
) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + transport.len());
    pseudo.extend_from_slice(&source);
    pseudo.extend_from_slice(&destination);
    pseudo.extend_from_slice(&(transport.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, protocol]);
    pseudo.extend_from_slice(transport);
    nonzero_checksum(&pseudo)
}

fn nonzero_checksum(bytes: &[u8]) -> u16 {
    let value = checksum(bytes);
    if value == 0 { u16::MAX } else { value }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.saturating_add(u32::from(last) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_capture::{FrameOrigin, FrameRoute};
    use codev_stream::{PacketSource, S0PcapSource, TransportKind, parse_transport};

    fn frame(
        capture_ns: u64,
        direction: Direction,
        transport: Transport,
        flow_id: u64,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> FrameEnvelope {
        FrameEnvelope::new_with_route(
            capture_ns,
            direction,
            transport,
            flow_id,
            if transport == Transport::Tcp {
                FrameOrigin::SocksTcp
            } else {
                FrameOrigin::SocksUdp
            },
            FrameRoute {
                source,
                destination,
            },
            payload.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn proxy_frames_are_written_as_parseable_private_raw_ip_pcap() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = ProxyPcapRecorder::start(ProxyPcapConfig {
            directory: directory.path().to_path_buf(),
            max_bytes: 8 * 1024 * 1024,
            max_duration_secs: 60,
            max_files: 3,
        })
        .unwrap();
        let base = unix_time_ns();
        let client: SocketAddr = "192.168.1.5:50000".parse().unwrap();
        let server: SocketAddr = "203.0.113.10:443".parse().unwrap();
        recorder.record(&frame(
            base,
            Direction::ClientToServer,
            Transport::Tcp,
            7,
            client,
            server,
            b"3f\0\x0b\0\x0c",
        ));
        recorder.record(&frame(
            base + 10_000,
            Direction::ServerToClient,
            Transport::Tcp,
            7,
            server,
            client,
            b"reply",
        ));
        recorder.tcp_closed(7, base + 20_000);
        recorder.record(&frame(
            base + 30_000,
            Direction::ClientToServer,
            Transport::Udp,
            8,
            client,
            "198.51.100.20:15806".parse().unwrap(),
            b"udp-game",
        ));
        recorder.finish().unwrap();
        assert_eq!(recorder.dropped_items(), 0);

        let path = fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("pcap"))
            .unwrap();
        let mut source = S0PcapSource::open(path).unwrap();
        let mut tcp_payloads = Vec::new();
        let mut udp_payloads = Vec::new();
        while let Some(packet) = source.next_packet().unwrap() {
            let transport = parse_transport(&packet).unwrap();
            match transport.kind {
                TransportKind::Tcp if !transport.payload.is_empty() => {
                    tcp_payloads.push(transport.payload.to_vec())
                }
                TransportKind::Udp => udp_payloads.push(transport.payload.to_vec()),
                _ => {}
            }
        }
        assert_eq!(
            tcp_payloads,
            [b"3f\0\x0b\0\x0c".to_vec(), b"reply".to_vec()]
        );
        assert_eq!(udp_payloads, [b"udp-game".to_vec()]);
    }

    #[test]
    fn rolling_capture_keeps_only_the_configured_number_of_files() {
        let directory = tempfile::tempdir().unwrap();
        let recorder = ProxyPcapRecorder::start(ProxyPcapConfig {
            directory: directory.path().to_path_buf(),
            max_bytes: 1024 * 1024,
            max_duration_secs: 1,
            max_files: 2,
        })
        .unwrap();
        let client: SocketAddr = "192.168.1.5:50000".parse().unwrap();
        let server: SocketAddr = "198.51.100.20:15806".parse().unwrap();
        let base = unix_time_ns();
        for index in 0..4 {
            recorder.record(&frame(
                base + index * 2_000_000_000,
                Direction::ClientToServer,
                Transport::Udp,
                index,
                client,
                server,
                b"rotate",
            ));
        }
        recorder.finish().unwrap();
        let count = fs::read_dir(directory.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().extension().and_then(|value| value.to_str()) == Some("pcap")
            })
            .count();
        assert_eq!(count, 2);
    }
}
