//! Cold-path compatibility flow accounting and gap-aware TCP summaries.
//!
//! The public Rust coordinate pipeline deliberately keeps no all-flow state.
//! This module performs one bounded PCAP pass only for the explicit
//! compatibility-artifact sink and reproduces the Python v2 oracle contract.

use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::path::Path;

use codev_stream::{
    CapturedPacket, Endpoint, IntegrityStatus, IpAddress, PacketError, PacketSource, S0PcapSource,
    SourceError, TransportKind, TransportPacket, parse_transport, validate_packet_integrity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

const PRIMARY_SELECTION: &str =
    "highest UDP packet count, then payload bytes, deterministic tie break";

#[derive(Debug, Error)]
pub enum CompatibilityNetworkError {
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("frame {frame} cannot be represented by the compatibility flow contract: {source}")]
    UnsupportedFrame {
        frame: u64,
        #[source]
        source: PacketError,
    },
    #[error("capture contains no UDP flow")]
    MissingPrimaryUdp,
    #[error("frame {0} has an invalid client WaterMark envelope")]
    InvalidWatermark(u64),
}

#[derive(Debug)]
pub struct CompatibilityNetworkArtifacts {
    pub flow_manifest: FlowManifest,
    pub tcp_streams: Vec<TcpStreamRecord>,
    pub facts: CompatibilityCaptureFacts,
}

#[derive(Clone, Debug)]
pub struct CompatibilityCaptureFacts {
    pub all_packets_accounted: bool,
    pub tcp_flow_count: usize,
    pub capture_end_ns: u64,
    pub primary_last_ns: u64,
    pub primary_packet_count: u64,
    pub client_watermark_tested: u64,
    pub client_watermark_validated: u64,
    pub client_watermark_counter_continuous: bool,
    pub primary_ipv4_checksums_valid: u64,
    pub primary_udp_checksums_valid_or_offload: u64,
    pub voice_room_count: usize,
}

#[derive(Debug, Serialize)]
pub struct FlowManifest {
    input_packet_count: u64,
    accounted_packet_count: u64,
    flow_count: usize,
    unclassified: Vec<UnclassifiedRecord>,
    flows: Vec<FlowRecord>,
    primary_flow_id: String,
    primary_selection: &'static str,
}

#[derive(Debug, Serialize)]
struct UnclassifiedRecord {
    packet_index: u64,
    reason: String,
}

#[derive(Debug, Serialize)]
struct FlowRecord {
    flow_id: String,
    ip_version: u8,
    protocol: &'static str,
    endpoint_a: String,
    endpoint_b: String,
    packet_count: u64,
    transport_payload_bytes: u64,
    captured_bytes: u64,
    original_bytes: u64,
    first_timestamp: String,
    last_timestamp: String,
    duration_seconds: f64,
    a_to_b_packets: u64,
    b_to_a_packets: u64,
    a_to_b_payload_bytes: u64,
    b_to_a_payload_bytes: u64,
    parse_issue_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    classification: Option<FlowClassification>,
}

#[derive(Debug, Serialize)]
struct FlowClassification {
    class: &'static str,
    confidence: &'static str,
}

#[derive(Debug, Serialize)]
pub struct TcpStreamRecord {
    flow_id: String,
    source: String,
    destination: String,
    initial_sequence: u32,
    complete: bool,
    assembled_bytes: Option<usize>,
    chunk_count: usize,
    gaps: Vec<TcpGapRecord>,
    conflict_count: usize,
    retransmitted_bytes: usize,
    saw_syn: bool,
    saw_fin: bool,
    saw_rst: bool,
    looks_like_tls: bool,
}

#[derive(Debug, Serialize)]
struct TcpGapRecord {
    relative_start: usize,
    relative_end: usize,
    length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: Protocol,
    endpoint_a: Endpoint,
    endpoint_b: Endpoint,
}

impl FlowKey {
    fn new(protocol: Protocol, left: Endpoint, right: Endpoint) -> Self {
        let (endpoint_a, endpoint_b) = if endpoint_cmp(&left, &right) != Ordering::Greater {
            (left, right)
        } else {
            (right, left)
        };
        Self {
            protocol,
            endpoint_a,
            endpoint_b,
        }
    }

    fn from_transport(transport: &TransportPacket<'_>) -> Self {
        let protocol = match transport.kind {
            TransportKind::Tcp => Protocol::Tcp,
            TransportKind::Udp => Protocol::Udp,
        };
        Self::new(protocol, transport.source, transport.destination)
    }

    fn id(self) -> String {
        format!(
            "{}:{}<->{}",
            self.protocol.name(),
            endpoint_text(self.endpoint_a),
            endpoint_text(self.endpoint_b)
        )
    }

    const fn ip_version(self) -> u8 {
        match self.endpoint_a.ip {
            IpAddress::V4(_) => 4,
            IpAddress::V6(_) => 6,
        }
    }
}

struct FlowAccumulator {
    key: FlowKey,
    packet_count: u64,
    captured_bytes: u64,
    original_bytes: u64,
    transport_payload_bytes: u64,
    first_timestamp_ns: u64,
    last_timestamp_ns: u64,
    a_to_b_packets: u64,
    b_to_a_packets: u64,
    a_to_b_payload_bytes: u64,
    b_to_a_payload_bytes: u64,
    packet_indices: Vec<u64>,
}

impl FlowAccumulator {
    fn new(key: FlowKey, packet: &CapturedPacket, transport: &TransportPacket<'_>) -> Self {
        let mut value = Self {
            key,
            packet_count: 0,
            captured_bytes: 0,
            original_bytes: 0,
            transport_payload_bytes: 0,
            first_timestamp_ns: packet.timestamp_ns,
            last_timestamp_ns: packet.timestamp_ns,
            a_to_b_packets: 0,
            b_to_a_packets: 0,
            a_to_b_payload_bytes: 0,
            b_to_a_payload_bytes: 0,
            packet_indices: Vec::new(),
        };
        value.add(packet, transport);
        value
    }

    fn add(&mut self, packet: &CapturedPacket, transport: &TransportPacket<'_>) {
        self.packet_count += 1;
        self.captured_bytes += packet.data.len() as u64;
        self.original_bytes += u64::from(packet.original_length);
        self.transport_payload_bytes += transport.payload.len() as u64;
        self.first_timestamp_ns = self.first_timestamp_ns.min(packet.timestamp_ns);
        self.last_timestamp_ns = self.last_timestamp_ns.max(packet.timestamp_ns);
        if transport.source == self.key.endpoint_a {
            self.a_to_b_packets += 1;
            self.a_to_b_payload_bytes += transport.payload.len() as u64;
        } else {
            self.b_to_a_packets += 1;
            self.b_to_a_payload_bytes += transport.payload.len() as u64;
        }
        self.packet_indices.push(packet.index);
    }
}

struct TcpDirection {
    flow: FlowKey,
    source: Endpoint,
    destination: Endpoint,
    segments: Vec<(i64, u64, Vec<u8>)>,
    first_sequence: u32,
    reference_sequence: i64,
    saw_syn: bool,
    saw_fin: bool,
    saw_rst: bool,
}

struct VoiceObservation {
    flow: FlowKey,
    frame: u64,
    room_id: String,
    access_ip: Vec<String>,
}

#[derive(Deserialize)]
struct RoomEnvelope {
    #[serde(rename = "type")]
    kind: String,
    info: Value,
}

pub fn build_compatibility_network_artifacts(
    pcap: &Path,
) -> Result<CompatibilityNetworkArtifacts, CompatibilityNetworkError> {
    let mut source = S0PcapSource::open(pcap)?;
    let mut flows = HashMap::<FlowKey, FlowAccumulator>::new();
    let mut tcp_directions = HashMap::<(FlowKey, Endpoint), TcpDirection>::new();
    let mut unclassified = Vec::new();
    let mut input_packet_count = 0_u64;
    let mut voice_observations = Vec::new();
    let mut capture_end_ns = None;

    while let Some(packet) = source.next_packet()? {
        input_packet_count += 1;
        capture_end_ns = Some(packet.timestamp_ns);
        let transport = match parse_transport(&packet) {
            Ok(transport) => transport,
            Err(error) => {
                if let Some(reason) = stable_unclassified_reason(&error) {
                    unclassified.push(UnclassifiedRecord {
                        packet_index: packet.index + 1,
                        reason,
                    });
                    continue;
                }
                return Err(CompatibilityNetworkError::UnsupportedFrame {
                    frame: packet.index + 1,
                    source: error,
                });
            }
        };
        let key = FlowKey::from_transport(&transport);
        if let Some(observation) = voice_observation(&transport, key, packet.index + 1) {
            voice_observations.push(observation);
        }
        match flows.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().add(&packet, &transport);
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(FlowAccumulator::new(key, &packet, &transport));
            }
        }
        if transport.kind == TransportKind::Tcp {
            collect_tcp_direction(&packet, &transport, key, &mut tcp_directions);
        }
    }

    let accounted_packet_count =
        flows.values().map(|flow| flow.packet_count).sum::<u64>() + unclassified.len() as u64;
    if accounted_packet_count != input_packet_count {
        return Err(CompatibilityNetworkError::Source(SourceError::Io(
            io::Error::other("flow analysis lost one or more packets"),
        )));
    }

    let primary = flows
        .values()
        .filter(|flow| flow.key.protocol == Protocol::Udp)
        .min_by(|left, right| {
            right
                .packet_count
                .cmp(&left.packet_count)
                .then_with(|| {
                    right
                        .transport_payload_bytes
                        .cmp(&left.transport_payload_bytes)
                })
                .then_with(|| flow_key_cmp(&left.key, &right.key))
        })
        .map(|flow| flow.key)
        .ok_or(CompatibilityNetworkError::MissingPrimaryUdp)?;
    let primary_flow = flows
        .get(&primary)
        .expect("the selected primary key came from the flow map");
    let client = choose_client(primary_flow);
    let primary_proof = validate_primary_flow(pcap, primary, client)?;
    let tcp_flow_count = flows
        .values()
        .filter(|flow| flow.key.protocol == Protocol::Tcp)
        .count();
    let mut facts = CompatibilityCaptureFacts {
        all_packets_accounted: accounted_packet_count == input_packet_count,
        tcp_flow_count,
        capture_end_ns: capture_end_ns.expect("a primary flow requires at least one packet"),
        primary_last_ns: primary_flow.last_timestamp_ns,
        primary_packet_count: primary_flow.packet_count,
        client_watermark_tested: primary_proof.watermark_tested,
        client_watermark_validated: primary_proof.watermark_validated,
        client_watermark_counter_continuous: primary_proof.watermark_counter_continuous,
        primary_ipv4_checksums_valid: primary_proof.ipv4_checksums_valid,
        primary_udp_checksums_valid_or_offload: primary_proof.udp_checksums_valid_or_offload,
        voice_room_count: 0,
    };

    let mut room_ids = BTreeSet::new();
    let mut signaling_frames = BTreeSet::new();
    let mut voice_endpoints = BTreeSet::new();
    for observation in voice_observations {
        if observation.flow == primary || !room_ids.insert(observation.room_id) {
            continue;
        }
        signaling_frames.insert(observation.frame);
        voice_endpoints.extend(observation.access_ip);
    }
    facts.voice_room_count = room_ids.len();

    let mut sorted_flows: Vec<_> = flows.into_values().collect();
    sorted_flows.sort_by(|left, right| {
        right
            .packet_count
            .cmp(&left.packet_count)
            .then_with(|| flow_key_cmp(&left.key, &right.key))
    });
    let flow_count = sorted_flows.len();
    let flow_records = sorted_flows
        .iter()
        .map(|flow| flow_record(flow, primary, &signaling_frames, &voice_endpoints))
        .collect();

    let mut tcp_streams: Vec<_> = tcp_directions.into_values().map(freeze_tcp).collect();
    tcp_streams.sort_by(|left, right| {
        flow_key_cmp(&left.flow, &right.flow)
            .then_with(|| endpoint_cmp(&left.source, &right.source))
    });
    let tcp_streams = tcp_streams
        .into_iter()
        .map(|stream| stream.record)
        .collect();

    Ok(CompatibilityNetworkArtifacts {
        flow_manifest: FlowManifest {
            input_packet_count,
            accounted_packet_count,
            flow_count,
            unclassified,
            flows: flow_records,
            primary_flow_id: primary.id(),
            primary_selection: PRIMARY_SELECTION,
        },
        tcp_streams,
        facts,
    })
}

struct PrimaryProof {
    watermark_tested: u64,
    watermark_validated: u64,
    watermark_counter_continuous: bool,
    ipv4_checksums_valid: u64,
    udp_checksums_valid_or_offload: u64,
}

fn validate_primary_flow(
    pcap: &Path,
    primary: FlowKey,
    client: Endpoint,
) -> Result<PrimaryProof, CompatibilityNetworkError> {
    let mut source = S0PcapSource::open(pcap)?;
    let mut proof = PrimaryProof {
        watermark_tested: 0,
        watermark_validated: 0,
        watermark_counter_continuous: true,
        ipv4_checksums_valid: 0,
        udp_checksums_valid_or_offload: 0,
    };
    let mut previous_counter: Option<u32> = None;
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if FlowKey::from_transport(&transport) != primary {
            continue;
        }
        let integrity = validate_packet_integrity(&packet).map_err(|source| {
            CompatibilityNetworkError::UnsupportedFrame {
                frame: packet.index + 1,
                source,
            }
        })?;
        proof.ipv4_checksums_valid +=
            u64::from(integrity.ipv4_header_checksum == IntegrityStatus::Valid);
        proof.udp_checksums_valid_or_offload += u64::from(matches!(
            integrity.udp_checksum,
            IntegrityStatus::Valid | IntegrityStatus::OffloadSeed | IntegrityStatus::Disabled
        ));
        if transport.source != client {
            continue;
        }
        if transport.payload.len() < 10 {
            return Err(CompatibilityNetworkError::InvalidWatermark(
                packet.index + 1,
            ));
        }
        let observed_crc = u32::from_le_bytes(transport.payload[..4].try_into().unwrap());
        let counter = u32::from_le_bytes(transport.payload[4..8].try_into().unwrap());
        proof.watermark_tested += 1;
        proof.watermark_validated +=
            u64::from(observed_crc == compute_watermark_crc32c(transport.destination, counter));
        if let Some(previous) = previous_counter {
            proof.watermark_counter_continuous &= previous.wrapping_add(1) == counter;
        }
        previous_counter = Some(counter);
    }
    Ok(proof)
}

fn choose_client(flow: &FlowAccumulator) -> Endpoint {
    let a_private = is_private(flow.key.endpoint_a.ip);
    let b_private = is_private(flow.key.endpoint_b.ip);
    if a_private != b_private {
        return if a_private {
            flow.key.endpoint_a
        } else {
            flow.key.endpoint_b
        };
    }
    if flow.key.endpoint_a.port >= flow.key.endpoint_b.port {
        flow.key.endpoint_a
    } else {
        flow.key.endpoint_b
    }
}

fn is_private(address: IpAddress) -> bool {
    match address {
        IpAddress::V4(bytes) => std::net::Ipv4Addr::from(bytes).is_private(),
        IpAddress::V6(bytes) => std::net::Ipv6Addr::from(bytes).is_unique_local(),
    }
}

pub(crate) fn compute_watermark_crc32c(destination: Endpoint, counter: u32) -> u32 {
    let IpAddress::V4(address) = destination.ip else {
        return u32::MAX;
    };
    let endpoint_mix =
        u32::from_le_bytes(address) ^ (u32::from(destination.port).swap_bytes() >> 16);
    let mut crc = 0_u32;
    for byte in (endpoint_mix ^ counter ^ 0xf468_dded).to_le_bytes() {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0x82f6_3b78 } else { 0 };
        }
    }
    crc
}

fn stable_unclassified_reason(error: &PacketError) -> Option<String> {
    match error {
        PacketError::UnsupportedEtherType(value) if *value != 0 => {
            Some(format!("non_ip_ethertype:0x{value:04x}"))
        }
        PacketError::UnsupportedEtherType(_) => Some("undecodable_link_layer".into()),
        PacketError::UnsupportedIpProtocol(protocol) => {
            Some(format!("unsupported_ip_protocol:{protocol}"))
        }
        PacketError::Truncated { layer, .. } if *layer == "TCP" => {
            Some("malformed_transport:6".into())
        }
        PacketError::Truncated { layer, .. } if *layer == "UDP" => {
            Some("malformed_transport:17".into())
        }
        PacketError::InvalidLength(layer) if *layer == "TCP header" => {
            Some("malformed_transport:6".into())
        }
        PacketError::InvalidLength(layer) if *layer == "UDP datagram" => {
            Some("malformed_transport:17".into())
        }
        _ => None,
    }
}

fn voice_observation(
    transport: &TransportPacket<'_>,
    flow: FlowKey,
    frame: u64,
) -> Option<VoiceObservation> {
    let envelope = json_envelope(transport.payload)?;
    if envelope.kind != "room_info" {
        return None;
    }
    let room_id = envelope.info.get("room_id").and_then(Value::as_str)?;
    if room_id.is_empty() {
        return None;
    }
    let access_ip = envelope
        .info
        .get("access_ip")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(|endpoint| {
            endpoint
                .strip_prefix("udp://")
                .unwrap_or(endpoint)
                .to_owned()
        })
        .collect();
    Some(VoiceObservation {
        flow,
        frame,
        room_id: room_id.to_owned(),
        access_ip,
    })
}

fn json_envelope(payload: &[u8]) -> Option<RoomEnvelope> {
    for (start, pair) in payload.windows(2).enumerate() {
        if pair != b"{\"" {
            continue;
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&payload[start..]);
        if let Ok(value) = RoomEnvelope::deserialize(&mut deserializer) {
            return Some(value);
        }
    }
    None
}

fn flow_record(
    flow: &FlowAccumulator,
    primary: FlowKey,
    signaling_frames: &BTreeSet<u64>,
    voice_endpoints: &BTreeSet<String>,
) -> FlowRecord {
    FlowRecord {
        flow_id: flow.key.id(),
        ip_version: flow.key.ip_version(),
        protocol: flow.key.protocol.name(),
        endpoint_a: endpoint_text(flow.key.endpoint_a),
        endpoint_b: endpoint_text(flow.key.endpoint_b),
        packet_count: flow.packet_count,
        transport_payload_bytes: flow.transport_payload_bytes,
        captured_bytes: flow.captured_bytes,
        original_bytes: flow.original_bytes,
        first_timestamp: shanghai_iso(flow.first_timestamp_ns),
        last_timestamp: shanghai_iso(flow.last_timestamp_ns),
        duration_seconds: (flow.last_timestamp_ns - flow.first_timestamp_ns) as f64
            / 1_000_000_000.0,
        a_to_b_packets: flow.a_to_b_packets,
        b_to_a_packets: flow.b_to_a_packets,
        a_to_b_payload_bytes: flow.a_to_b_payload_bytes,
        b_to_a_payload_bytes: flow.b_to_a_payload_bytes,
        parse_issue_count: 0,
        classification: (flow.key.protocol == Protocol::Udp)
            .then(|| classify_udp(flow, primary, signaling_frames, voice_endpoints)),
    }
}

fn classify_udp(
    flow: &FlowAccumulator,
    primary: FlowKey,
    signaling_frames: &BTreeSet<u64>,
    voice_endpoints: &BTreeSet<String>,
) -> FlowClassification {
    if flow.key == primary {
        return FlowClassification {
            class: "main_game_udp",
            confidence: "proven",
        };
    }
    if flow.key.endpoint_a.port == 53 || flow.key.endpoint_b.port == 53 {
        return FlowClassification {
            class: "dns",
            confidence: "proven",
        };
    }
    if flow
        .packet_indices
        .iter()
        .any(|index| signaling_frames.contains(&(index + 1)))
    {
        return FlowClassification {
            class: "gcloud_voice_signaling",
            confidence: "proven",
        };
    }
    if voice_endpoints.contains(&endpoint_text(flow.key.endpoint_a))
        || voice_endpoints.contains(&endpoint_text(flow.key.endpoint_b))
    {
        return FlowClassification {
            class: "gcloud_voice_transport_no_content_transcription",
            confidence: "proven_by_room_info_access_ip",
        };
    }
    if flow.key.endpoint_a.port == 9030 || flow.key.endpoint_b.port == 9030 {
        return FlowClassification {
            class: "qos_probe_candidate",
            confidence: "medium",
        };
    }
    FlowClassification {
        class: "auxiliary_udp_unclassified",
        confidence: "unknown",
    }
}

fn collect_tcp_direction(
    packet: &CapturedPacket,
    transport: &TransportPacket<'_>,
    flow: FlowKey,
    directions: &mut HashMap<(FlowKey, Endpoint), TcpDirection>,
) {
    let sequence = transport
        .tcp_sequence
        .expect("a parsed TCP transport always has a sequence number");
    let syn = transport.tcp_flags & 0x02 != 0;
    let state = directions
        .entry((flow, transport.source))
        .or_insert_with(|| TcpDirection {
            flow,
            source: transport.source,
            destination: transport.destination,
            segments: Vec::new(),
            first_sequence: sequence,
            reference_sequence: i64::from(sequence),
            saw_syn: false,
            saw_fin: false,
            saw_rst: false,
        });
    state.saw_syn |= syn;
    state.saw_fin |= transport.tcp_flags & 0x01 != 0;
    state.saw_rst |= transport.tcp_flags & 0x04 != 0;
    let payload_sequence = sequence.wrapping_add(u32::from(syn));
    let unwrapped = unwrap_tcp_sequence(payload_sequence, state.reference_sequence);
    if !transport.payload.is_empty() {
        state
            .segments
            .push((unwrapped, packet.index, transport.payload.to_vec()));
        state.reference_sequence = state
            .reference_sequence
            .max(unwrapped + transport.payload.len() as i64);
    }
}

fn unwrap_tcp_sequence(sequence: u32, reference: i64) -> i64 {
    const MODULUS: i64 = 1_i64 << 32;
    const HALF: i64 = MODULUS / 2;
    let mut candidate = (reference & !(MODULUS - 1)) | i64::from(sequence);
    if candidate - reference > HALF {
        candidate -= MODULUS;
    } else if reference - candidate > HALF {
        candidate += MODULUS;
    }
    candidate
}

struct TcpBlock {
    start: i64,
    data: Vec<u8>,
}

impl TcpBlock {
    fn end(&self) -> i64 {
        self.start + self.data.len() as i64
    }
}

struct FrozenTcp {
    flow: FlowKey,
    source: Endpoint,
    record: TcpStreamRecord,
}

fn freeze_tcp(mut state: TcpDirection) -> FrozenTcp {
    state
        .segments
        .sort_by_key(|(sequence, packet_index, _)| (*sequence, *packet_index));
    let mut blocks = Vec::<TcpBlock>::new();
    let mut conflict_count = 0_usize;
    let mut retransmitted_bytes = 0_usize;
    for (start, _packet_index, payload) in state.segments {
        let end = start + payload.len() as i64;
        if blocks.last().is_none_or(|block| start > block.end()) {
            blocks.push(TcpBlock {
                start,
                data: payload,
            });
            continue;
        }

        let block = blocks.last_mut().unwrap();
        let overlap_end = end.min(block.end());
        let overlap_length = usize::try_from((overlap_end - start).max(0)).unwrap();
        if overlap_length != 0 {
            let block_offset = usize::try_from(start - block.start).unwrap();
            let existing = &block.data[block_offset..block_offset + overlap_length];
            let observed = &payload[..overlap_length];
            let matching = existing
                .iter()
                .zip(observed)
                .filter(|(left, right)| left == right)
                .count();
            conflict_count += overlap_length - matching;
            retransmitted_bytes += matching;
        }

        let block_end = block.end();
        if end > block_end {
            let payload_offset = usize::try_from(block_end - start).unwrap();
            block.data.extend_from_slice(&payload[payload_offset..]);
        }
    }

    let minimum = blocks
        .first()
        .map_or(i64::from(state.first_sequence), |block| block.start);
    let mut gaps = Vec::new();
    for pair in blocks.windows(2) {
        let relative_start = usize::try_from(pair[0].end() - minimum).unwrap();
        let relative_end = usize::try_from(pair[1].start - minimum).unwrap();
        gaps.push(TcpGapRecord {
            relative_start,
            relative_end,
            length: relative_end - relative_start,
        });
    }
    let complete = gaps.is_empty();
    let assembled_bytes = complete.then(|| blocks.iter().map(|block| block.data.len()).sum());
    let prefix = blocks
        .first()
        .map_or(&[][..], |block| &block.data[..block.data.len().min(8)]);
    let looks_like_tls = prefix.len() >= 3 && matches!(prefix[0], 20..=23) && prefix[1] == 3;
    let initial_sequence = minimum.rem_euclid(1_i64 << 32) as u32;
    let flow = state.flow;
    let source = state.source;
    FrozenTcp {
        flow,
        source,
        record: TcpStreamRecord {
            flow_id: flow.id(),
            source: endpoint_text(source),
            destination: endpoint_text(state.destination),
            initial_sequence,
            complete,
            assembled_bytes,
            chunk_count: blocks.len(),
            gaps,
            conflict_count,
            retransmitted_bytes,
            saw_syn: state.saw_syn,
            saw_fin: state.saw_fin,
            saw_rst: state.saw_rst,
            looks_like_tls,
        },
    }
}

pub(crate) fn endpoint_text(endpoint: Endpoint) -> String {
    match endpoint.ip {
        IpAddress::V4(_) => format!("{}:{}", endpoint.ip, endpoint.port),
        IpAddress::V6(_) => format!("[{}]:{}", endpoint.ip, endpoint.port),
    }
}

fn flow_key_cmp(left: &FlowKey, right: &FlowKey) -> Ordering {
    left.ip_version()
        .cmp(&right.ip_version())
        .then_with(|| left.protocol.number().cmp(&right.protocol.number()))
        .then_with(|| endpoint_cmp(&left.endpoint_a, &right.endpoint_a))
        .then_with(|| endpoint_cmp(&left.endpoint_b, &right.endpoint_b))
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

pub(crate) fn shanghai_iso(timestamp_ns: u64) -> String {
    let seconds = (timestamp_ns / 1_000_000_000) as i64 + 8 * 60 * 60;
    let days = seconds.div_euclid(86_400);
    let seconds_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    let microsecond = timestamp_ns % 1_000_000_000 / 1_000;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{microsecond:06}+08:00"
    )
}

fn civil_from_days(days_since_unix_epoch: i64) -> (i64, i64, i64) {
    let shifted = days_since_unix_epoch + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_direction(segments: Vec<(i64, u64, Vec<u8>)>) -> TcpDirection {
        let source = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 1]),
            port: 40_000,
        };
        let destination = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 2]),
            port: 443,
        };
        TcpDirection {
            flow: FlowKey::new(Protocol::Tcp, source, destination),
            source,
            destination,
            segments,
            first_sequence: 100,
            reference_sequence: 100,
            saw_syn: true,
            saw_fin: false,
            saw_rst: false,
        }
    }

    #[test]
    fn timestamp_matches_python_shanghai_microsecond_contract() {
        assert_eq!(
            shanghai_iso(1_785_975_837_768_794_000),
            "2026-08-06T08:23:57.768794+08:00"
        );
    }

    #[test]
    fn tcp_summary_keeps_gaps_retransmissions_conflicts_and_empty_directions_explicit() {
        let gap = freeze_tcp(tcp_direction(vec![
            (100, 0, b"ab".to_vec()),
            (104, 1, b"ef".to_vec()),
        ]))
        .record;
        assert!(!gap.complete);
        assert_eq!(gap.assembled_bytes, None);
        assert_eq!(gap.chunk_count, 2);
        assert_eq!(gap.gaps.len(), 1);
        assert_eq!(gap.gaps[0].relative_start, 2);
        assert_eq!(gap.gaps[0].relative_end, 4);
        assert_eq!(gap.gaps[0].length, 2);

        let overlap = freeze_tcp(tcp_direction(vec![
            (100, 0, b"abcd".to_vec()),
            (101, 1, b"bXde".to_vec()),
        ]))
        .record;
        assert_eq!(overlap.assembled_bytes, Some(5));
        assert_eq!(overlap.retransmitted_bytes, 2);
        assert_eq!(overlap.conflict_count, 1);

        let empty = freeze_tcp(tcp_direction(Vec::new())).record;
        assert!(empty.complete);
        assert_eq!(empty.assembled_bytes, Some(0));
        assert_eq!(empty.chunk_count, 0);
        assert_eq!(empty.initial_sequence, 100);
        assert_eq!(unwrap_tcp_sequence(0, i64::from(u32::MAX)), 1_i64 << 32);
    }

    #[test]
    fn real_capture_matches_both_python_v2_network_artifacts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        let flow_oracle = root.join("output-20260806-formal/flow_manifest.json");
        let tcp_oracle = root.join("output-20260806-formal/tcp_streams.json");
        if !pcap.is_file() || !flow_oracle.is_file() || !tcp_oracle.is_file() {
            return;
        }
        let actual = build_compatibility_network_artifacts(&pcap).unwrap();
        assert!(actual.facts.all_packets_accounted);
        assert_eq!(actual.facts.tcp_flow_count, 56);
        assert_eq!(actual.facts.primary_packet_count, 12_414);
        assert_eq!(actual.facts.client_watermark_tested, 6_845);
        assert_eq!(actual.facts.client_watermark_validated, 6_845);
        assert!(actual.facts.client_watermark_counter_continuous);
        assert_eq!(actual.facts.primary_ipv4_checksums_valid, 12_414);
        assert_eq!(actual.facts.primary_udp_checksums_valid_or_offload, 12_414);
        assert_eq!(actual.facts.voice_room_count, 3);
        assert!(actual.facts.capture_end_ns > actual.facts.primary_last_ns);
        let expected_flow: Value =
            serde_json::from_reader(std::fs::File::open(flow_oracle).unwrap()).unwrap();
        let expected_tcp: Value =
            serde_json::from_reader(std::fs::File::open(tcp_oracle).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&actual.flow_manifest).unwrap(),
            expected_flow
        );
        assert_eq!(
            serde_json::to_value(&actual.tcp_streams).unwrap(),
            expected_tcp
        );
    }
}
