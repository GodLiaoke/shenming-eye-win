//! Strict, read-only MNA session recovery from a complete classic PCAP.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::Path;

use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    Direction, Endpoint, EnterGameSession, IpAddress, MNA_CLOSE, MNA_DATA, MNA_MAGIC,
    MNA_SERVER_HELLO, MnaFieldEvidence, PacketSource, S0PcapSource, SourceError, TcpReassembler,
    TcpSourceProvenance, TransportKind, W0Error, W0Frame, W0Framer, decrypt_mna_frame,
    parse_enter_game_session_with_evidence, parse_mna_application, parse_transport,
    recover_embedded_enter_game_session_with_evidence, recover_mna_session_key,
    strip_mna_random_padding,
};

const TCP_FIN: u16 = 0x001;
const TCP_SYN: u16 = 0x002;
const TCP_RST: u16 = 0x004;
const TCP_ACK: u16 = 0x010;
const MAX_MNA_TCP_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W0TcpFlow {
    pub client: Endpoint,
    pub server: Endpoint,
    pub packet_count: u64,
    pub payload_bytes: u64,
}

/// Latest descriptor-valid Enter/ReEnter notification plus non-sensitive
/// recovery provenance. `Debug` deliberately redacts session material.
pub struct W0SessionRecovery {
    pub session: EnterGameSession,
    pub flow: W0TcpFlow,
    pub mna_frame_count: u64,
    pub data_frame_count: u64,
    pub session_notification_count: u32,
    pub notification: W0Provenance,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct W0Provenance {
    pub source_frames: Vec<u64>,
    pub timestamp_ns: u64,
    pub map_id_evidence: MnaFieldEvidence,
    pub game_mode_evidence: MnaFieldEvidence,
    pub sub_game_mode_evidence: MnaFieldEvidence,
}

impl fmt::Debug for W0SessionRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("W0SessionRecovery")
            .field("session", &self.session)
            .field("flow", &"<redacted>")
            .field("mna_frame_count", &self.mna_frame_count)
            .field("data_frame_count", &self.data_frame_count)
            .field(
                "session_notification_count",
                &self.session_notification_count,
            )
            .field("notification", &self.notification)
            .finish()
    }
}

impl W0SessionRecovery {
    pub fn into_session(self) -> EnterGameSession {
        self.session
    }
}

#[derive(Debug, Error)]
pub enum W0CaptureError {
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("capture contains no M0 TCP flow")]
    NoMnaTcpFlow,
    #[error("capture contains {0} possible M0 TCP flows")]
    AmbiguousMnaTcpFlow(usize),
    #[error("M0 capture starts after the TCP handshake or first stream byte")]
    LateCaptureStart,
    #[error("M0 TCP handshake is ambiguous")]
    AmbiguousHandshake,
    #[error("M0 TCP direction {0:?} ends without a captured FIN")]
    TcpNotClosed(Direction),
    #[error("M0 TCP direction {0:?} was reset")]
    TcpReset(Direction),
    #[error("M0 TCP direction {0:?} has an unclosed byte gap")]
    TcpGap(Direction),
    #[error("M0 TCP direction {0:?} ends inside an M0 frame")]
    IncompleteMnaFrame(Direction),
    #[error("M0 frame direction marker disagrees with its TCP direction")]
    DirectionMismatch,
    #[error("M0 server hello is missing")]
    MissingServerHello,
    #[error("expected one M0 server hello, found {0}")]
    AmbiguousServerHello(usize),
    #[error("no descriptor-valid enter-game notification was found")]
    SessionNotificationMissing,
    #[error("M0 protocol error: {0}")]
    Protocol(#[from] W0Error),
}

/// Recover the latest descriptor-valid Enter/ReEnterGameNotify from a complete
/// classic PCAP without writing session material to disk.
///
/// The routine performs two bounded passes. The first identifies one complete
/// MNA TCP handshake/closure. The second anchors both reassemblers at their
/// SYN-derived initial sequences, rejects all unresolved byte/frame gaps,
/// recovers exactly one server-hello AES key, decrypts every DATA frame and
/// applies the descriptor-exact notification parser. If both Enter and ReEnter
/// occur, the later wire notification is the active returned session.
pub fn recover_enter_game_session_from_classic_pcap(
    pcap: impl AsRef<Path>,
) -> Result<W0SessionRecovery, W0CaptureError> {
    recover_enter_game_session_from_classic_pcap_with_end_policy(pcap, true)
}

/// 诊断用（坐标 dump / 采集包）：抓包跨了多局（多个 M0 流）时取**最新开始**
/// 的那一局，而不是直接判歧义失败。校验路径不受影响，仍走严格版本。
pub fn recover_latest_enter_game_session_from_classic_pcap(
    pcap: impl AsRef<Path>,
) -> Result<W0SessionRecovery, W0CaptureError> {
    recover_enter_game_session_from_classic_pcap_with_options(pcap, false, true)
}

/// Recover a session from a PCAP that ends while the game TCP flow is still
/// open. This is for offline replay of a live slice; it still rejects byte
/// gaps, partial MNA frames, and residual frame provenance.
pub fn recover_enter_game_session_from_classic_pcap_open_ended(
    pcap: impl AsRef<Path>,
) -> Result<W0SessionRecovery, W0CaptureError> {
    recover_enter_game_session_from_classic_pcap_with_end_policy(pcap, false)
}

fn recover_enter_game_session_from_classic_pcap_with_end_policy(
    pcap: impl AsRef<Path>,
    require_tcp_fin: bool,
) -> Result<W0SessionRecovery, W0CaptureError> {
    recover_enter_game_session_from_classic_pcap_with_options(pcap, require_tcp_fin, false)
}

fn recover_enter_game_session_from_classic_pcap_with_options(
    pcap: impl AsRef<Path>,
    require_tcp_fin: bool,
    prefer_latest: bool,
) -> Result<W0SessionRecovery, W0CaptureError> {
    let pcap = pcap.as_ref();
    let mut scan_source = S0PcapSource::open(pcap)?;
    let scans = scan_tcp_flows(&mut scan_source)?;
    let selected = select_mna_flow_with_end_policy(scans, require_tcp_fin, prefer_latest)?;

    let mut client = DirectionStream::new(selected.client_next_sequence)?;
    let mut server = DirectionStream::new(selected.server_next_sequence)?;
    let mut frames = Vec::new();
    let mut source = S0PcapSource::open(pcap)?;
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if transport.kind != TransportKind::Tcp {
            continue;
        }
        let (direction, stream, expected_marker) = if transport.source == selected.flow.client
            && transport.destination == selected.flow.server
        {
            (Direction::ClientToServer, &mut client, 0)
        } else if transport.source == selected.flow.server
            && transport.destination == selected.flow.client
        {
            (Direction::ServerToClient, &mut server, 1)
        } else {
            continue;
        };
        if transport.payload.is_empty() {
            continue;
        }
        let sequence = transport
            .tcp_sequence
            .expect("parsed TCP packets always carry a sequence")
            .wrapping_add(u32::from(transport.tcp_flags & TCP_SYN != 0));
        let released = stream.tcp.push_with_source(
            sequence,
            transport.payload,
            TcpSourceProvenance {
                capture_index: packet.index,
                timestamp_ns: packet.timestamp_ns,
            },
        )?;
        if released.is_empty() {
            continue;
        }
        let released = stream.append_released(&released);
        if !stream.started {
            if !released.starts_with(&MNA_MAGIC) {
                return Err(W0CaptureError::LateCaptureStart);
            }
            stream.started = true;
        }
        for frame in stream.framer.feed(&released)? {
            if frame.message_type != MNA_CLOSE && frame.direction_marker != expected_marker {
                return Err(W0CaptureError::DirectionMismatch);
            }
            let frame_length = frame.header.len() + frame.payload.len();
            let provenance = stream.consume_frame_provenance(frame_length)?;
            frames.push(CapturedMnaFrame {
                direction,
                frame,
                provenance,
            });
        }
    }

    validate_stream_end_policy(
        &client,
        selected.client_fin_sequence,
        Direction::ClientToServer,
    )?;
    validate_stream_end_policy(
        &server,
        selected.server_fin_sequence,
        Direction::ServerToClient,
    )?;
    recover_session(frames, selected.flow)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TcpFlowKey {
    endpoint_a: Endpoint,
    endpoint_b: Endpoint,
}

impl TcpFlowKey {
    fn new(left: Endpoint, right: Endpoint) -> Self {
        if endpoint_cmp(&left, &right) != Ordering::Greater {
            Self {
                endpoint_a: left,
                endpoint_b: right,
            }
        } else {
            Self {
                endpoint_a: right,
                endpoint_b: left,
            }
        }
    }
}

#[derive(Clone, Copy)]
struct ControlPacket {
    capture_index: u64,
    source: Endpoint,
    destination: Endpoint,
    sequence: u32,
    payload_length: usize,
    flags: u16,
}

impl ControlPacket {
    fn stream_end_sequence(self) -> u32 {
        self.sequence
            .wrapping_add(u32::from(self.flags & TCP_SYN != 0))
            .wrapping_add(self.payload_length as u32)
    }
}

#[derive(Default)]
struct FlowScan {
    packet_count: u64,
    payload_bytes: u64,
    magic_payloads: u64,
    first_payload_index: Option<u64>,
    syn: Vec<ControlPacket>,
    syn_ack: Vec<ControlPacket>,
    fin: Vec<ControlPacket>,
    reset_sources: HashSet<Endpoint>,
}

fn scan_tcp_flows<S: PacketSource>(
    source: &mut S,
) -> Result<HashMap<TcpFlowKey, FlowScan>, W0CaptureError> {
    let mut scans: HashMap<TcpFlowKey, FlowScan> = HashMap::new();
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if transport.kind != TransportKind::Tcp {
            continue;
        }
        let scan = scans
            .entry(TcpFlowKey::new(transport.source, transport.destination))
            .or_default();
        scan.packet_count += 1;
        scan.payload_bytes = scan
            .payload_bytes
            .saturating_add(transport.payload.len() as u64);
        if !transport.payload.is_empty() {
            scan.first_payload_index = Some(
                scan.first_payload_index
                    .map_or(transport.capture_index, |old| {
                        old.min(transport.capture_index)
                    }),
            );
            if transport
                .payload
                .windows(MNA_MAGIC.len())
                .any(|window| window == MNA_MAGIC)
            {
                scan.magic_payloads += 1;
            }
        }
        let control = ControlPacket {
            capture_index: transport.capture_index,
            source: transport.source,
            destination: transport.destination,
            sequence: transport
                .tcp_sequence
                .expect("parsed TCP packets always carry a sequence"),
            payload_length: transport.payload.len(),
            flags: transport.tcp_flags,
        };
        if transport.tcp_flags & TCP_SYN != 0 {
            if transport.tcp_flags & TCP_ACK != 0 {
                scan.syn_ack.push(control);
            } else {
                scan.syn.push(control);
            }
        }
        if transport.tcp_flags & TCP_FIN != 0 {
            scan.fin.push(control);
        }
        if transport.tcp_flags & TCP_RST != 0 {
            scan.reset_sources.insert(transport.source);
        }
    }
    Ok(scans)
}

struct SelectedMnaFlow {
    flow: W0TcpFlow,
    client_next_sequence: u32,
    server_next_sequence: u32,
    client_fin_sequence: Option<u32>,
    server_fin_sequence: Option<u32>,
}

fn select_mna_flow(
    scans: HashMap<TcpFlowKey, FlowScan>,
) -> Result<SelectedMnaFlow, W0CaptureError> {
    select_mna_flow_with_end_policy(scans, true, false)
}

fn select_mna_flow_with_end_policy(
    scans: HashMap<TcpFlowKey, FlowScan>,
    require_tcp_fin: bool,
    prefer_latest: bool,
) -> Result<SelectedMnaFlow, W0CaptureError> {
    let mut candidates: Vec<_> = scans
        .into_iter()
        .filter(|(_, scan)| scan.magic_payloads != 0)
        .collect();
    if candidates.is_empty() {
        return Err(W0CaptureError::NoMnaTcpFlow);
    }
    if candidates.len() > 1 && !prefer_latest {
        return Err(W0CaptureError::AmbiguousMnaTcpFlow(candidates.len()));
    }
    // 诊断路径（跨多局的滚动分片）取"最新开始"的那条 M0 流；
    // 校验路径保持严格：多流即判歧义。
    if prefer_latest {
        candidates.sort_by_key(|(_, scan)| {
            std::cmp::Reverse(
                scan.syn
                    .iter()
                    .map(|packet| packet.capture_index)
                    .min()
                    .unwrap_or_default(),
            )
        });
    }
    let (_key, scan) = candidates.pop().unwrap();
    let client_syn = scan
        .syn
        .iter()
        .min_by_key(|packet| packet.capture_index)
        .copied()
        .ok_or(W0CaptureError::LateCaptureStart)?;
    if scan.syn.iter().any(|packet| {
        packet.source != client_syn.source || packet.destination != client_syn.destination
    }) {
        return Err(W0CaptureError::AmbiguousHandshake);
    }
    let server_syn = scan
        .syn_ack
        .iter()
        .filter(|packet| {
            packet.source == client_syn.destination && packet.destination == client_syn.source
        })
        .min_by_key(|packet| packet.capture_index)
        .copied()
        .ok_or(W0CaptureError::LateCaptureStart)?;
    if scan
        .first_payload_index
        .is_some_and(|first| first < client_syn.capture_index || first < server_syn.capture_index)
    {
        return Err(W0CaptureError::LateCaptureStart);
    }
    let client = client_syn.source;
    let server = client_syn.destination;
    if scan.reset_sources.contains(&client) {
        return Err(W0CaptureError::TcpReset(Direction::ClientToServer));
    }
    if scan.reset_sources.contains(&server) {
        return Err(W0CaptureError::TcpReset(Direction::ServerToClient));
    }
    let client_fin = select_fin(
        &scan.fin,
        client,
        Direction::ClientToServer,
        require_tcp_fin,
    )?;
    let server_fin = select_fin(
        &scan.fin,
        server,
        Direction::ServerToClient,
        require_tcp_fin,
    )?;
    Ok(SelectedMnaFlow {
        flow: W0TcpFlow {
            client,
            server,
            packet_count: scan.packet_count,
            payload_bytes: scan.payload_bytes,
        },
        client_next_sequence: client_syn.sequence.wrapping_add(1),
        server_next_sequence: server_syn.sequence.wrapping_add(1),
        client_fin_sequence: client_fin.map(ControlPacket::stream_end_sequence),
        server_fin_sequence: server_fin.map(ControlPacket::stream_end_sequence),
    })
}

fn select_fin(
    packets: &[ControlPacket],
    source: Endpoint,
    direction: Direction,
    required: bool,
) -> Result<Option<ControlPacket>, W0CaptureError> {
    if required {
        return consistent_fin(packets, source, direction).map(Some);
    }
    let matching: Vec<_> = packets
        .iter()
        .copied()
        .filter(|packet| packet.source == source)
        .collect();
    if matching
        .windows(2)
        .any(|pair| pair[0].stream_end_sequence() != pair[1].stream_end_sequence())
    {
        return Err(W0CaptureError::AmbiguousHandshake);
    }
    Ok(matching.first().copied())
}

fn consistent_fin(
    packets: &[ControlPacket],
    source: Endpoint,
    direction: Direction,
) -> Result<ControlPacket, W0CaptureError> {
    let mut matching = packets
        .iter()
        .copied()
        .filter(|packet| packet.source == source);
    let first = matching
        .next()
        .ok_or(W0CaptureError::TcpNotClosed(direction))?;
    if matching.any(|packet| packet.stream_end_sequence() != first.stream_end_sequence()) {
        return Err(W0CaptureError::AmbiguousHandshake);
    }
    Ok(first)
}

struct DirectionStream {
    tcp: TcpReassembler,
    framer: W0Framer,
    provenance: VecDeque<PendingProvenance>,
    started: bool,
}

struct PendingProvenance {
    remaining: usize,
    source: TcpSourceProvenance,
}

#[derive(Clone, Debug)]
struct FrameProvenance {
    source_frames: Vec<u64>,
    timestamp_ns: u64,
}

impl DirectionStream {
    fn new(initial_sequence: u32) -> Result<Self, W0Error> {
        let mut tcp = TcpReassembler::new(MAX_MNA_TCP_BYTES);
        tcp.initialize(initial_sequence)?;
        Ok(Self {
            tcp,
            framer: W0Framer::new(MAX_MNA_TCP_BYTES),
            provenance: VecDeque::new(),
            started: false,
        })
    }

    fn append_released(&mut self, released: &[crate::TcpReleasedChunk]) -> Vec<u8> {
        let total = released.iter().map(|chunk| chunk.bytes.len()).sum();
        let mut bytes = Vec::with_capacity(total);
        for chunk in released {
            if !chunk.bytes.is_empty() {
                self.provenance.push_back(PendingProvenance {
                    remaining: chunk.bytes.len(),
                    source: chunk.source,
                });
                bytes.extend_from_slice(&chunk.bytes);
            }
        }
        bytes
    }

    fn consume_frame_provenance(
        &mut self,
        mut frame_length: usize,
    ) -> Result<FrameProvenance, W0CaptureError> {
        let mut source_frames = BTreeSet::new();
        let mut timestamp_ns = None::<u64>;
        while frame_length != 0 {
            let chunk = self.provenance.front_mut().ok_or(W0CaptureError::Protocol(
                W0Error::InvalidEnvelope("M0 frame provenance underflow"),
            ))?;
            let consumed = chunk.remaining.min(frame_length);
            source_frames.insert(chunk.source.capture_index + 1);
            timestamp_ns = Some(timestamp_ns.map_or(chunk.source.timestamp_ns, |old| {
                old.min(chunk.source.timestamp_ns)
            }));
            chunk.remaining -= consumed;
            frame_length -= consumed;
            if chunk.remaining == 0 {
                self.provenance.pop_front();
            }
        }
        Ok(FrameProvenance {
            source_frames: source_frames.into_iter().collect(),
            timestamp_ns: timestamp_ns.ok_or(W0CaptureError::Protocol(
                W0Error::InvalidEnvelope("empty M0 frame provenance"),
            ))?,
        })
    }
}

fn validate_stream_end(
    stream: &DirectionStream,
    fin_sequence: u32,
    direction: Direction,
) -> Result<(), W0CaptureError> {
    if stream.tcp.has_gap() || !stream.tcp.is_complete_at(fin_sequence) {
        return Err(W0CaptureError::TcpGap(direction));
    }
    if !stream.started {
        return Err(W0CaptureError::LateCaptureStart);
    }
    if stream.framer.has_partial_frame() {
        return Err(W0CaptureError::IncompleteMnaFrame(direction));
    }
    if !stream.provenance.is_empty() {
        return Err(W0CaptureError::Protocol(W0Error::InvalidEnvelope(
            "M0 provenance remains after complete framing",
        )));
    }
    Ok(())
}

fn validate_open_stream_end(
    stream: &DirectionStream,
    direction: Direction,
) -> Result<(), W0CaptureError> {
    if stream.tcp.has_gap() || !stream.tcp.pending_is_empty() {
        return Err(W0CaptureError::TcpGap(direction));
    }
    if !stream.started {
        return Err(W0CaptureError::LateCaptureStart);
    }
    if stream.framer.has_partial_frame() {
        return Err(W0CaptureError::IncompleteMnaFrame(direction));
    }
    if !stream.provenance.is_empty() {
        return Err(W0CaptureError::Protocol(W0Error::InvalidEnvelope(
            "M0 provenance remains after complete framing",
        )));
    }
    Ok(())
}

fn validate_stream_end_policy(
    stream: &DirectionStream,
    fin_sequence: Option<u32>,
    direction: Direction,
) -> Result<(), W0CaptureError> {
    match fin_sequence {
        Some(fin_sequence) => validate_stream_end(stream, fin_sequence, direction),
        None => validate_open_stream_end(stream, direction),
    }
}

struct CapturedMnaFrame {
    direction: Direction,
    frame: W0Frame,
    provenance: FrameProvenance,
}

fn recover_session(
    frames: Vec<CapturedMnaFrame>,
    flow: W0TcpFlow,
) -> Result<W0SessionRecovery, W0CaptureError> {
    let server_hello_count = frames
        .iter()
        .filter(|item| {
            item.direction == Direction::ServerToClient
                && item.frame.message_type == MNA_SERVER_HELLO
        })
        .count();
    if server_hello_count == 0 {
        return Err(W0CaptureError::MissingServerHello);
    }
    if server_hello_count != 1 {
        return Err(W0CaptureError::AmbiguousServerHello(server_hello_count));
    }
    let plain_frames: Vec<_> = frames.iter().map(|item| item.frame.clone()).collect();
    let key = recover_mna_session_key(&plain_frames).map_err(|error| match error {
        W0Error::SessionKeyCount(0) => W0CaptureError::MissingServerHello,
        W0Error::SessionKeyCount(count) => W0CaptureError::AmbiguousServerHello(count),
        other => W0CaptureError::Protocol(other),
    })?;
    let mut sessions = Vec::new();
    let mut data_frame_count = 0_u64;
    for item in &frames {
        if item.frame.message_type != MNA_DATA {
            continue;
        }
        data_frame_count += 1;
        let mut plaintext = decrypt_mna_frame(&item.frame, &key)?;
        strip_mna_random_padding(&mut plaintext)?;
        if let Some(path) = std::env::var_os("CODEV_MNA_DUMP") {
            use std::io::Write;
            let take = plaintext.len().min(2048);
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(
                    file,
                    "{},{:?},{}",
                    item.frame.sequence,
                    item.frame.direction_marker,
                    plaintext[..take]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
            }
        }
        let mut parsed = None;
        if let Ok(mut application) =
            parse_mna_application(&plaintext, item.frame.direction_marker, item.frame.sequence)
        {
            parsed = parse_enter_game_session_with_evidence(&application)
                .ok()
                .flatten();
            application.body.zeroize();
        }
        if parsed.is_none() {
            parsed = recover_embedded_enter_game_session_with_evidence(
                &plaintext,
                item.frame.direction_marker,
                item.frame.sequence,
            );
        }
        if let Some(session) = parsed {
            sessions.push((session, item.provenance.clone()));
        }
    }
    let session_notification_count = sessions.len() as u32;
    let (parsed, provenance) = sessions
        .pop()
        .ok_or(W0CaptureError::SessionNotificationMissing)?;
    let notification = W0Provenance {
        source_frames: provenance.source_frames,
        timestamp_ns: provenance.timestamp_ns,
        map_id_evidence: parsed.map_id_evidence,
        game_mode_evidence: parsed.game_mode_evidence,
        sub_game_mode_evidence: parsed.sub_game_mode_evidence,
    };
    Ok(W0SessionRecovery {
        session: parsed.session,
        flow,
        mna_frame_count: frames.len() as u64,
        data_frame_count,
        session_notification_count,
        notification,
    })
}

fn endpoint_cmp(left: &Endpoint, right: &Endpoint) -> Ordering {
    ip_cmp(left.ip, right.ip).then_with(|| left.port.cmp(&right.port))
}

fn ip_cmp(left: IpAddress, right: IpAddress) -> Ordering {
    match (left, right) {
        (IpAddress::V4(left), IpAddress::V4(right)) => left.cmp(&right),
        (IpAddress::V4(_), IpAddress::V6(_)) => Ordering::Less,
        (IpAddress::V6(_), IpAddress::V4(_)) => Ordering::Greater,
        (IpAddress::V6(left), IpAddress::V6(right)) => left.cmp(&right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(last: u8, port: u16) -> Endpoint {
        Endpoint {
            ip: IpAddress::V4([10, 0, 0, last]),
            port,
        }
    }

    #[test]
    fn missing_handshake_is_late_capture_and_missing_fin_is_not_closed() {
        let client = endpoint(1, 50_000);
        let server = endpoint(2, 17_500);
        let key = TcpFlowKey::new(client, server);
        let mut scans = HashMap::new();
        scans.insert(
            key,
            FlowScan {
                magic_payloads: 1,
                first_payload_index: Some(5),
                ..FlowScan::default()
            },
        );
        assert!(matches!(
            select_mna_flow(scans),
            Err(W0CaptureError::LateCaptureStart)
        ));

        let syn = ControlPacket {
            capture_index: 1,
            source: client,
            destination: server,
            sequence: 10,
            payload_length: 0,
            flags: TCP_SYN,
        };
        let syn_ack = ControlPacket {
            capture_index: 2,
            source: server,
            destination: client,
            sequence: 20,
            payload_length: 0,
            flags: TCP_SYN | TCP_ACK,
        };
        let mut scans = HashMap::new();
        scans.insert(
            key,
            FlowScan {
                magic_payloads: 1,
                first_payload_index: Some(3),
                syn: vec![syn],
                syn_ack: vec![syn_ack],
                ..FlowScan::default()
            },
        );
        assert!(matches!(
            select_mna_flow(scans),
            Err(W0CaptureError::TcpNotClosed(Direction::ClientToServer))
        ));
    }

    #[test]
    fn missing_server_hello_and_unclosed_byte_gap_are_distinct() {
        let flow = W0TcpFlow {
            client: endpoint(1, 50_000),
            server: endpoint(2, 17_500),
            packet_count: 0,
            payload_bytes: 0,
        };
        assert!(matches!(
            recover_session(Vec::new(), flow),
            Err(W0CaptureError::MissingServerHello)
        ));

        let mut stream = DirectionStream::new(100).unwrap();
        assert!(stream.tcp.push(101, b"x").unwrap().is_empty());
        assert!(matches!(
            validate_stream_end(&stream, 102, Direction::ClientToServer),
            Err(W0CaptureError::TcpGap(Direction::ClientToServer))
        ));

        let mut partial = DirectionStream::new(200).unwrap();
        let bytes = partial.tcp.push(200, &MNA_MAGIC[..3]).unwrap();
        partial.started = true;
        assert!(partial.framer.feed(&bytes).unwrap().is_empty());
        assert!(matches!(
            validate_stream_end(&partial, 203, Direction::ServerToClient),
            Err(W0CaptureError::IncompleteMnaFrame(
                Direction::ServerToClient
            ))
        ));
    }

    #[test]
    fn private_full_capture_retains_notification_frames_time_and_field_offsets() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !fixture.is_file() {
            return;
        }
        let recovery = recover_enter_game_session_from_classic_pcap(fixture).unwrap();
        assert_eq!(recovery.notification.source_frames, [7_891, 7_892, 7_895]);
        assert_eq!(
            recovery.notification.timestamp_ns,
            1_785_975_831_192_328_000
        );
        assert_eq!(
            (
                recovery.notification.map_id_evidence.plaintext_start,
                recovery.notification.map_id_evidence.plaintext_end,
                recovery.notification.map_id_evidence.value_start,
                recovery.notification.map_id_evidence.value_end,
            ),
            (3_529, 3_532, 3_530, 3_532)
        );
        assert_eq!(
            (
                recovery.notification.game_mode_evidence.plaintext_start,
                recovery.notification.game_mode_evidence.plaintext_end,
                recovery.notification.game_mode_evidence.value_start,
                recovery.notification.game_mode_evidence.value_end,
            ),
            (3_567, 3_569, 3_568, 3_569)
        );
        assert_eq!(
            (
                recovery.notification.sub_game_mode_evidence.plaintext_start,
                recovery.notification.sub_game_mode_evidence.plaintext_end,
                recovery.notification.sub_game_mode_evidence.value_start,
                recovery.notification.sub_game_mode_evidence.value_end,
            ),
            (3_659, 3_663, 3_660, 3_663)
        );
    }
}
