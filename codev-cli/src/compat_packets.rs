//! Rust-native, streaming `packets.jsonl` and `unresolved.jsonl` sink.
//!
//! Every known SGNet/PacketHandler/Unreal/PackageMap field is emitted from the
//! typed wire model that already proved its own compositional re-encode.  The
//! only copied bit ranges are explicitly named unknown channel/Oodle spans.
//! Channel 32 actor payloads are decoded transactionally by `codev-protocol`;
//! their original whole-payload unknown span is then refined to the exact
//! two-bit handle-5 value, when present.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use codev_protocol::{
    A0Property, A0Value, ActorMessage, D0Decoder, D0Update, DecodeError, MovementKind,
    MovementState, MovementUpdate, RotatorField, VectorField,
};
use codev_stream::{
    C0Cipher, FStringEncoding, IntegrityStatus, PacketError, PacketSource, S0PcapSource,
    SelectedUdpFlow, SerializedName, SourceError, TransportKind, WireError, extract_lsb_bits,
    parse_transport, prove_packet_handler_wire, reencode_package_map_exports,
    reencode_packet_handler_envelope, reencode_unreal_packet, validate_packet_integrity,
};
use serde::Serialize;
use serde_json::ser::{Formatter, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::compat_network::{compute_watermark_crc32c, endpoint_text, shanghai_iso};
use crate::record::open_private;

const CLIENT_PREFIX_BYTES: usize = codev_stream::SGNET_CLIENT_PREFIX_BYTES;
const BATCH_CHANNEL_INDEX: u32 = codev_protocol::BATCH_CHANNEL_INDEX;
const MAX_PARTIAL_CHANNELS: usize = 2_048;
const MAX_PARTIAL_FRAGMENTS: usize = 64;
const MAX_PARTIAL_BITS: usize = 64 * 8 * codev_stream::UNREAL_MAX_PACKET_BYTES as usize;
const MAX_PARTIAL_CORPUS_FRAGMENTS: usize = 4_096;
const MAX_PARTIAL_CORPUS_BITS: usize = 64 * 1024 * 1024 * 8;
const PACKET_BUFFER_BYTES: usize = 1024 * 1024;

const NON_PASS_THROUGH_REASON: &str =
    "PacketHandler flag-one control/compressed payload retained exactly; it is not a UE packet";
const CHANNEL_PAYLOAD_REASON: &str =
    "replication/RPC channel payload retained pending class semantics";
const PACKAGE_MAP_TAIL_REASON: &str = "channel payload after the exact PackageMap export prefix";

#[derive(Debug, Error)]
pub enum CompatibilityPacketError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("session pipeline error: {0}")]
    Session(#[from] codev_stream::SessionError),
    #[error("typed wire error: {0}")]
    Wire(#[from] WireError),
    #[error("bit encode error: {0}")]
    BitEncode(#[from] codev_protocol::BitWriteError),
    #[error("packet {frame} has unsupported transport evidence: {source}")]
    Packet {
        frame: u64,
        #[source]
        source: PacketError,
    },
    #[error("packet {frame} has an invalid Channel 32 actor: {source}")]
    Batch {
        frame: u64,
        #[source]
        source: DecodeError,
    },
    #[error("packet {frame} violates the compatibility contract: {detail}")]
    Contract { frame: u64, detail: String },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CompatibilityPacketReport {
    pub packet_count: u64,
    pub unresolved_span_count: u64,
    pub packet_handler_reencode_exact: u64,
    pub unreal_reencode_exact: u64,
    pub package_map_reencode_exact: u64,
    pub sgnet_wire_reencode_exact: u64,
    pub exact_bit_coverage: u64,
    pub bunch_count: u64,
    pub partial_payloads_completed: u64,
    pub batch_actor_count: u64,
    pub batch_property_count: u64,
    pub client_watermark_counter: CompatibilitySequenceReport,
    pub client_watermark_counter_low16: CompatibilitySequenceReport,
    pub client_watermark_crc32c_tested: u64,
    pub client_watermark_crc32c_validated: u64,
    pub encrypted_connection_id_raw_distribution: BTreeMap<String, u64>,
    pub plaintext_connection_id_distribution: BTreeMap<String, u64>,
    pub flag_one_raw_size_distribution: BTreeMap<String, u64>,
    pub partial_fragment_count: u64,
    pub partial_duplicate_fragments: u64,
    pub partial_fragments_per_payload: BTreeMap<String, u64>,
    pub partial_total_reassembled_bits: u64,
    pub client_watermark_counter_low14_relation: CompatibilityWatermarkRelation,
    pub ack_recent_peer_match: CompatibilityAckRecentPeerMatch,
    pub ack_history_low5_semantics: Value,
    pub control_exchange_validation: Value,
    pub packets_sha256: String,
    pub unresolved_sha256: String,
    pub packets_bytes: u64,
    pub unresolved_bytes: u64,
    pub client_to_server: CompatibilityDirectionReport,
    pub server_to_client: CompatibilityDirectionReport,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct CompatibilityDirectionReport {
    pub packet_count: u64,
    pub oodle_flag_one_packets: u64,
    pub oodle_pass_through_packets: u64,
    pub packet_handler_reencode_exact: u64,
    pub unreal_reencode_exact: u64,
    pub bunch_count: u64,
    pub package_map_reencode_exact: u64,
    pub sgnet_wire_reencode_exact: u64,
    pub duplicate_inner_packet_ids: u64,
    pub duplicate_packet_ids: Vec<String>,
    pub payload_bytes: u64,
    pub aggregate_entropy_bits_per_byte: f64,
    pub common_payload_lengths: Vec<CompatibilityPayloadLengthCount>,
    pub network_integrity: BTreeMap<String, u64>,
    pub control_packet_count: u64,
    pub normal_packet_count: u64,
    pub ack_history_byte_count_distribution: BTreeMap<String, u64>,
    pub packet_id_sequence: CompatibilitySequenceReport,
    pub packet_id_delta_counts: BTreeMap<String, u64>,
    pub missing_packet_ids: Vec<String>,
    pub missing_packet_id_count: u64,
    pub reorders: Vec<CompatibilityPacketReorder>,
    pub ack_first: Option<u64>,
    pub ack_last: Option<u64>,
    pub ack_backward_steps: Vec<CompatibilityBackwardStep>,
    pub packet_info: CompatibilityPacketInfoDirection,
    pub first_bunch_prefix: CompatibilityFirstBunchDirection,
    pub repeated_suffix_candidates: Vec<CompatibilityRepeatedSuffixCandidate>,
    pub peer_reported_missing: Value,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilitySequenceReport {
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last: Option<u64>,
    pub continuous_steps: u64,
    pub gaps: Vec<CompatibilitySequenceGap>,
    pub wraps: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilitySequenceGap {
    pub position: u64,
    pub previous: u64,
    pub current: u64,
    pub expected: u64,
    pub delta_modulo: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityPayloadLengthCount {
    pub length: u64,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityPacketReorder {
    pub frames: [u64; 2],
    pub packet_ids: [u64; 2],
    pub delta_modulo: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityBackwardStep {
    pub position: u64,
    pub previous: u64,
    pub current: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilityWatermarkRelation {
    pub offset: Option<u64>,
    pub formula: Option<String>,
    pub matches: u64,
    pub tested: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilityAckRecentPeerMatch {
    pub client_to_server: CompatibilityAckRecentDirection,
    pub server_to_client: CompatibilityAckRecentDirection,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilityAckRecentDirection {
    pub matched: u64,
    pub tested: u64,
    pub unmatched_source_frames: Vec<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct CompatibilityPacketInfoDirection {
    pub serialized_count: u64,
    pub present_count: u64,
    pub absent_count: u64,
    pub time_1023_sentinel_count: u64,
    pub timing_compensation_present_count: u64,
    pub timing_compensation_ms_distribution: BTreeMap<String, u64>,
    pub valid_time_value_count: u64,
    pub capture_delta_comparison_count: u64,
    pub capture_delta_error_median_ms: Option<f64>,
    pub capture_delta_within_2ms_count: u64,
    pub capture_delta_within_10ms_count: u64,
    pub capture_delta_outliers_over_10ms: Vec<CompatibilityPacketInfoOutlier>,
    pub validation: &'static str,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CompatibilityPacketInfoOutlier {
    pub frames: [u64; 2],
    pub capture_delta_ms: f64,
    pub packet_info_delta_ms: u16,
    pub signed_error_ms: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompatibilityFirstBunchDirection {
    pub parsed_first_bunch_count: u64,
    pub data_packet_count: u64,
    pub data_packets_without_prefix_room: u64,
    pub channel_index_unique_count: u64,
    pub channel_index_range: Option<[u32; 2]>,
    pub channel_index_distribution: BTreeMap<String, u64>,
    pub packed_channel_width_bytes: BTreeMap<String, u64>,
    pub control_count: u64,
    pub open_count: u64,
    pub close_count: u64,
    pub close_reason_distribution: BTreeMap<String, u64>,
    pub replication_paused_count: u64,
    pub reliable_count: u64,
    pub scope: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CompatibilityRepeatedSuffixCandidate {
    pub direction: &'static str,
    pub frames: [u64; 2],
    pub packet_ids: [u16; 2],
    pub inner_length: usize,
    pub identical_suffix_length: usize,
    pub classification: &'static str,
}

struct DirectionAccumulator {
    report: CompatibilityDirectionReport,
    inner_packet_ids: HashSet<u16>,
    duplicate_packet_ids: HashSet<u16>,
    payload_byte_counts: [u64; 256],
    payload_byte_order: Vec<u8>,
    payload_length_counts: HashMap<usize, u64>,
    payload_length_order: Vec<usize>,
    notifications: Vec<NotifyObservation>,
}

impl Default for DirectionAccumulator {
    fn default() -> Self {
        Self {
            report: CompatibilityDirectionReport::default(),
            inner_packet_ids: HashSet::new(),
            duplicate_packet_ids: HashSet::new(),
            payload_byte_counts: [0; 256],
            payload_byte_order: Vec::new(),
            payload_length_counts: HashMap::new(),
            payload_length_order: Vec::new(),
            notifications: Vec::new(),
        }
    }
}

#[derive(Default)]
struct ReportAccumulator {
    packet_count: u64,
    unresolved_span_count: u64,
    packet_handler_reencode_exact: u64,
    unreal_reencode_exact: u64,
    package_map_reencode_exact: u64,
    sgnet_wire_reencode_exact: u64,
    exact_bit_coverage: u64,
    bunch_count: u64,
    partial_payloads_completed: u64,
    batch_actor_count: u64,
    batch_property_count: u64,
    client_watermark_counters: Vec<u32>,
    client_watermark_crc32c_validated: u64,
    encrypted_connection_id_raw_distribution: BTreeMap<String, u64>,
    plaintext_connection_id_distribution: BTreeMap<String, u64>,
    flag_one_raw_size_distribution: BTreeMap<String, u64>,
    notifications: Vec<DirectedNotifyObservation>,
    control_observations: Vec<ControlObservation>,
    client_to_server: DirectionAccumulator,
    server_to_client: DirectionAccumulator,
}

#[derive(Clone)]
struct NotifyObservation {
    frame: u64,
    timestamp_ns: u64,
    packet_id: u16,
    ack_id: u16,
    history_byte_count: u8,
    history: Vec<u8>,
    watermark_counter_low14: Option<u16>,
    packet_info_present: bool,
    packet_info_timestamp_ms: Option<u16>,
    packet_info_timing_compensation_present: Option<bool>,
    packet_info_timing_compensation_ms: Option<u8>,
    first_bunch: Option<FirstBunchObservation>,
    inner: Vec<u8>,
}

#[derive(Clone)]
struct FirstBunchObservation {
    channel_index: u32,
    control: bool,
    open: bool,
    close: bool,
    close_reason: Option<u32>,
    replication_paused: bool,
    reliable: bool,
}

#[derive(Clone)]
struct DirectedNotifyObservation {
    direction: &'static str,
    notification: NotifyObservation,
}

struct ControlObservation {
    frame: u64,
    direction: &'static str,
    raw_size: Option<u16>,
    inner: Vec<u8>,
}

impl ReportAccumulator {
    fn direction_mut(&mut self, direction: &str) -> &mut DirectionAccumulator {
        if direction == "client_to_server" {
            &mut self.client_to_server
        } else {
            &mut self.server_to_client
        }
    }

    fn observe_transport_payload(
        &mut self,
        direction: &str,
        payload: &[u8],
        integrity: codev_stream::PacketIntegrity,
    ) {
        let accumulator = self.direction_mut(direction);
        accumulator.report.payload_bytes += payload.len() as u64;
        if !accumulator
            .payload_length_counts
            .contains_key(&payload.len())
        {
            accumulator.payload_length_order.push(payload.len());
        }
        *accumulator
            .payload_length_counts
            .entry(payload.len())
            .or_default() += 1;
        for &byte in payload {
            let count = &mut accumulator.payload_byte_counts[usize::from(byte)];
            if *count == 0 {
                accumulator.payload_byte_order.push(byte);
            }
            *count += 1;
        }
        increment_integrity(
            &mut accumulator.report.network_integrity,
            integrity.ipv4_header_checksum,
            false,
        );
        increment_integrity(
            &mut accumulator.report.network_integrity,
            integrity.udp_checksum,
            true,
        );
    }
}

impl DirectionAccumulator {
    fn finish(mut self, direction: &'static str) -> CompatibilityDirectionReport {
        self.report.aggregate_entropy_bits_per_byte = shannon_entropy(
            &self.payload_byte_counts,
            &self.payload_byte_order,
            self.report.payload_bytes,
        );
        let insertion_order: HashMap<usize, usize> = self
            .payload_length_order
            .iter()
            .copied()
            .enumerate()
            .map(|(index, length)| (length, index))
            .collect();
        let mut lengths: Vec<_> = self.payload_length_counts.into_iter().collect();
        lengths.sort_by(|(left_length, left_count), (right_length, right_count)| {
            right_count
                .cmp(left_count)
                .then_with(|| insertion_order[left_length].cmp(&insertion_order[right_length]))
        });
        self.report.common_payload_lengths = lengths
            .into_iter()
            .take(20)
            .map(|(length, count)| CompatibilityPayloadLengthCount {
                length: length as u64,
                count,
            })
            .collect();
        self.report.packet_info = packet_info_summary(&self.notifications);
        self.report.first_bunch_prefix = first_bunch_summary(&self.notifications);
        self.report.repeated_suffix_candidates =
            repeated_suffix_candidates(&self.notifications, direction);

        let packet_ids: Vec<u64> = self
            .notifications
            .iter()
            .map(|item| u64::from(item.packet_id))
            .collect();
        let ack_ids: Vec<u64> = self
            .notifications
            .iter()
            .map(|item| u64::from(item.ack_id))
            .collect();
        self.report.normal_packet_count = packet_ids.len() as u64;
        self.report.packet_id_sequence = sequence_report(&packet_ids, 0x4000);
        for notification in &self.notifications {
            *self
                .report
                .ack_history_byte_count_distribution
                .entry(notification.history_byte_count.to_string())
                .or_default() += 1;
        }
        for pair in packet_ids.windows(2) {
            let delta = (pair[1] + 0x4000 - pair[0]) % 0x4000;
            *self
                .report
                .packet_id_delta_counts
                .entry(format!("0x{delta:04x}"))
                .or_default() += 1;
        }
        let mut duplicates: Vec<_> = self.duplicate_packet_ids.into_iter().collect();
        duplicates.sort_unstable();
        self.report.duplicate_packet_ids = duplicates
            .into_iter()
            .map(|packet_id| format!("0x{packet_id:04x}"))
            .collect();

        if let (Some(&first), Some(&last)) = (packet_ids.first(), packet_ids.last())
            && first <= last
        {
            let observed: HashSet<_> = packet_ids.iter().copied().collect();
            self.report.missing_packet_ids = (first..=last)
                .filter(|packet_id| !observed.contains(packet_id))
                .map(|packet_id| format!("0x{packet_id:04x}"))
                .collect();
        }
        self.report.missing_packet_id_count = self.report.missing_packet_ids.len() as u64;
        self.report.reorders = self
            .notifications
            .windows(2)
            .filter_map(|pair| {
                let previous = u64::from(pair[0].packet_id);
                let current = u64::from(pair[1].packet_id);
                let delta = (current + 0x4000 - previous) % 0x4000;
                (delta > 0x2000).then_some(CompatibilityPacketReorder {
                    frames: [pair[0].frame, pair[1].frame],
                    packet_ids: [previous, current],
                    delta_modulo: delta,
                })
            })
            .collect();
        self.report.ack_first = ack_ids.first().copied();
        self.report.ack_last = ack_ids.last().copied();
        self.report.ack_backward_steps = ack_ids
            .windows(2)
            .enumerate()
            .filter_map(|(index, pair)| {
                let delta = (pair[1] + 0x4000 - pair[0]) % 0x4000;
                (delta > 0x2000).then_some(CompatibilityBackwardStep {
                    position: index as u64 + 1,
                    previous: pair[0],
                    current: pair[1],
                })
            })
            .collect();
        self.report
    }
}

fn repeated_suffix_candidates(
    notifications: &[NotifyObservation],
    direction: &'static str,
) -> Vec<CompatibilityRepeatedSuffixCandidate> {
    const PREFIX_BYTES: usize = 7;
    const MINIMUM_SUFFIX_BYTES: usize = 24;
    let mut seen = HashMap::<(usize, Vec<u8>), (u64, u16)>::new();
    let mut repeated = Vec::new();
    for item in notifications {
        if item.inner.len().saturating_sub(PREFIX_BYTES) < MINIMUM_SUFFIX_BYTES {
            continue;
        }
        let key = (item.inner.len(), item.inner[PREFIX_BYTES..].to_vec());
        if let Some(&(previous_frame, previous_packet_id)) = seen.get(&key)
            && previous_packet_id != item.packet_id
        {
            repeated.push(CompatibilityRepeatedSuffixCandidate {
                direction,
                frames: [previous_frame, item.frame],
                packet_ids: [previous_packet_id, item.packet_id],
                inner_length: item.inner.len(),
                identical_suffix_length: item.inner.len() - PREFIX_BYTES,
                classification: "new_packet_id_same_application_suffix_candidate",
            });
        } else {
            seen.insert(key, (item.frame, item.packet_id));
        }
    }
    repeated
}

fn packet_info_summary(notifications: &[NotifyObservation]) -> CompatibilityPacketInfoDirection {
    const VALIDATION: &str = "packet_info modulo-1000 deltas track PCAP time; this independently validates the capture-recovered keystream bits after ACK history";
    let present: Vec<_> = notifications
        .iter()
        .filter(|item| item.packet_info_present)
        .collect();
    let valid_time: Vec<_> = present
        .iter()
        .copied()
        .filter(|item| {
            item.packet_info_timestamp_ms
                .is_some_and(|value| value < 1_000)
        })
        .collect();
    let mut absolute_errors = Vec::<f64>::new();
    let mut outliers = Vec::new();
    for pair in valid_time.windows(2) {
        let capture_delta_ms =
            python_timestamp_ms(pair[1].timestamp_ns) - python_timestamp_ms(pair[0].timestamp_ns);
        if !(0.0..=900.0).contains(&capture_delta_ms) {
            continue;
        }
        let previous = pair[0]
            .packet_info_timestamp_ms
            .expect("valid-time observations have a timestamp");
        let current = pair[1]
            .packet_info_timestamp_ms
            .expect("valid-time observations have a timestamp");
        let value_delta = (current + 1_000 - previous) % 1_000;
        let signed_error_ms =
            (f64::from(value_delta) - capture_delta_ms + 500.0).rem_euclid(1_000.0) - 500.0;
        absolute_errors.push(signed_error_ms.abs());
        if signed_error_ms.abs() > 10.0 && outliers.len() < 32 {
            outliers.push(CompatibilityPacketInfoOutlier {
                frames: [pair[0].frame, pair[1].frame],
                capture_delta_ms,
                packet_info_delta_ms: value_delta,
                signed_error_ms,
            });
        }
    }
    absolute_errors.sort_by(f64::total_cmp);
    let mut compensation_distribution = BTreeMap::new();
    for value in present
        .iter()
        .filter_map(|item| item.packet_info_timing_compensation_ms)
    {
        *compensation_distribution
            .entry(value.to_string())
            .or_default() += 1;
    }
    CompatibilityPacketInfoDirection {
        serialized_count: notifications.len() as u64,
        present_count: present.len() as u64,
        absent_count: (notifications.len() - present.len()) as u64,
        time_1023_sentinel_count: present
            .iter()
            .filter(|item| item.packet_info_timestamp_ms == Some(0x3ff))
            .count() as u64,
        timing_compensation_present_count: present
            .iter()
            .filter(|item| item.packet_info_timing_compensation_present == Some(true))
            .count() as u64,
        timing_compensation_ms_distribution: compensation_distribution,
        valid_time_value_count: valid_time.len() as u64,
        capture_delta_comparison_count: absolute_errors.len() as u64,
        capture_delta_error_median_ms: absolute_errors.get(absolute_errors.len() / 2).copied(),
        capture_delta_within_2ms_count: absolute_errors
            .iter()
            .filter(|&&value| value <= 2.0)
            .count() as u64,
        capture_delta_within_10ms_count: absolute_errors
            .iter()
            .filter(|&&value| value <= 10.0)
            .count() as u64,
        capture_delta_outliers_over_10ms: outliers,
        validation: VALIDATION,
    }
}

fn python_timestamp_ms(timestamp_ns: u64) -> f64 {
    // Python's integer true-division rounds the exact rational directly; a
    // prior u64→f64 cast loses low timestamp bits. Splitting quotient and
    // remainder reproduces that observable compatibility behavior.
    (timestamp_ns / 1_000_000) as f64 + (timestamp_ns % 1_000_000) as f64 / 1_000_000.0
}

fn first_bunch_summary(notifications: &[NotifyObservation]) -> CompatibilityFirstBunchDirection {
    const SCOPE: &str = "the first bunch prefix of each build-pinned, fully decoded Unreal packet";
    let bunches: Vec<_> = notifications
        .iter()
        .filter_map(|item| item.first_bunch.as_ref())
        .collect();
    let mut channel_distribution = BTreeMap::<String, u64>::new();
    let mut packed_width_distribution = BTreeMap::<String, u64>::new();
    let mut close_reason_distribution = BTreeMap::<String, u64>::new();
    let mut minimum = None::<u32>;
    let mut maximum = None::<u32>;
    for bunch in &bunches {
        *channel_distribution
            .entry(bunch.channel_index.to_string())
            .or_default() += 1;
        let mut packed_value = bunch.channel_index;
        let mut packed_width = 1_u8;
        while packed_value > 0x7f {
            packed_value >>= 7;
            packed_width += 1;
        }
        *packed_width_distribution
            .entry(packed_width.to_string())
            .or_default() += 1;
        if let Some(close_reason) = bunch.close_reason {
            *close_reason_distribution
                .entry(close_reason.to_string())
                .or_default() += 1;
        }
        minimum = Some(minimum.map_or(bunch.channel_index, |value| value.min(bunch.channel_index)));
        maximum = Some(maximum.map_or(bunch.channel_index, |value| value.max(bunch.channel_index)));
    }
    CompatibilityFirstBunchDirection {
        parsed_first_bunch_count: bunches.len() as u64,
        data_packet_count: notifications.len() as u64,
        data_packets_without_prefix_room: (notifications.len() - bunches.len()) as u64,
        channel_index_unique_count: channel_distribution.len() as u64,
        channel_index_range: minimum.zip(maximum).map(|(left, right)| [left, right]),
        channel_index_distribution: channel_distribution,
        packed_channel_width_bytes: packed_width_distribution,
        control_count: bunches.iter().filter(|item| item.control).count() as u64,
        open_count: bunches.iter().filter(|item| item.open).count() as u64,
        close_count: bunches.iter().filter(|item| item.close).count() as u64,
        close_reason_distribution,
        replication_paused_count: bunches
            .iter()
            .filter(|item| item.replication_paused)
            .count() as u64,
        reliable_count: bunches.iter().filter(|item| item.reliable).count() as u64,
        scope: SCOPE,
    }
}

fn increment_integrity(counts: &mut BTreeMap<String, u64>, status: IntegrityStatus, udp: bool) {
    let name = match status {
        IntegrityStatus::Valid => "valid",
        IntegrityStatus::Invalid => "invalid",
        IntegrityStatus::OffloadSeed => "offload_seed",
        IntegrityStatus::Disabled => "disabled",
        IntegrityStatus::NotApplicable => "not_applicable",
        IntegrityStatus::NotValidated => "not_validated",
    };
    let key = if udp {
        format!("udp:{name}")
    } else {
        name.to_owned()
    };
    *counts.entry(key).or_default() += 1;
}

fn shannon_entropy(counts: &[u64; 256], order: &[u8], total: u64) -> f64 {
    if total == 0 {
        return 0.0;
    }
    // CPython 3.12+ uses compensated summation for float `sum()`. Preserve
    // that observable JSON value instead of accumulating platform-sized ULP
    // drift in this compatibility projection.
    let mut sum = 0.0_f64;
    let mut compensation = 0.0_f64;
    for &byte in order {
        let probability = counts[usize::from(byte)] as f64 / total as f64;
        let term = -probability * probability.log2();
        let adjusted = term - compensation;
        let next = sum + adjusted;
        compensation = (next - sum) - adjusted;
        sum = next;
    }
    sum
}

fn sequence_report(values: &[u64], modulus: u64) -> CompatibilitySequenceReport {
    let mut report = CompatibilitySequenceReport {
        count: values.len() as u64,
        first: values.first().copied(),
        last: values.last().copied(),
        ..CompatibilitySequenceReport::default()
    };
    for (index, pair) in values.windows(2).enumerate() {
        let expected = (pair[0] + 1) % modulus;
        if pair[1] == expected {
            report.continuous_steps += 1;
            report.wraps += u64::from(pair[0] == modulus - 1);
        } else {
            report.gaps.push(CompatibilitySequenceGap {
                position: index as u64 + 1,
                previous: pair[0],
                current: pair[1],
                expected,
                delta_modulo: (pair[1] + modulus - pair[0]) % modulus,
            });
        }
    }
    report
}

fn watermark_relation(
    observations: &[DirectedNotifyObservation],
) -> CompatibilityWatermarkRelation {
    let client: Vec<_> = observations
        .iter()
        .filter(|item| item.direction == "client_to_server")
        .filter_map(|item| {
            item.notification
                .watermark_counter_low14
                .map(|watermark| (watermark, item.notification.packet_id))
        })
        .collect();
    let Some(&(first_watermark, first_packet_id)) = client.first() else {
        return CompatibilityWatermarkRelation::default();
    };
    let offset = (u64::from(first_watermark) + 0x4000 - u64::from(first_packet_id)) % 0x4000;
    let matches = client
        .iter()
        .filter(|(watermark, packet_id)| {
            (u64::from(*watermark) + 0x4000 - offset) % 0x4000 == u64::from(*packet_id)
        })
        .count() as u64;
    CompatibilityWatermarkRelation {
        offset: Some(offset),
        formula: Some(format!(
            "packet_id = (watermark_counter - 0x{offset:04x}) & 0x3fff"
        )),
        matches,
        tested: client.len() as u64,
    }
}

fn ack_recent_peer_match(
    observations: &[DirectedNotifyObservation],
) -> CompatibilityAckRecentPeerMatch {
    let mut client_history = Vec::<u16>::new();
    let mut server_history = Vec::<u16>::new();
    let mut result = CompatibilityAckRecentPeerMatch::default();
    for item in observations {
        let (peer_history, history, direction) = if item.direction == "client_to_server" {
            (
                &server_history,
                &mut client_history,
                &mut result.client_to_server,
            )
        } else {
            (
                &client_history,
                &mut server_history,
                &mut result.server_to_client,
            )
        };
        direction.tested += 1;
        if peer_history
            .iter()
            .rev()
            .take(16)
            .any(|&packet_id| packet_id == item.notification.ack_id)
        {
            direction.matched += 1;
        } else {
            direction
                .unmatched_source_frames
                .push(item.notification.frame);
        }
        history.push(item.notification.packet_id);
    }
    result
}

struct Low5Analysis {
    client_peer_reported_missing: Value,
    server_peer_reported_missing: Value,
    semantics: Value,
}

fn ack_history_low5_analysis(observations: &[DirectedNotifyObservation]) -> Low5Analysis {
    let client: Vec<_> = observations
        .iter()
        .filter(|item| item.direction == "client_to_server")
        .map(|item| &item.notification)
        .collect();
    let server: Vec<_> = observations
        .iter()
        .filter(|item| item.direction == "server_to_client")
        .map(|item| &item.notification)
        .collect();
    let client_missing = missing_packet_id_set(&client);
    let server_missing = missing_packet_id_set(&server);
    let mut captured_but_peer_reported_missing = Vec::<Value>::new();
    let client_report = peer_reported_missing(
        "client_to_server",
        "server_to_client",
        &client,
        &server,
        &server_missing,
        &mut captured_but_peer_reported_missing,
    );
    let server_report = peer_reported_missing(
        "server_to_client",
        "client_to_server",
        &server,
        &client,
        &client_missing,
        &mut captured_but_peer_reported_missing,
    );
    captured_but_peer_reported_missing.sort_by(|left, right| {
        let left_direction = left["peer_packet_direction"].as_str().unwrap_or_default();
        let right_direction = right["peer_packet_direction"].as_str().unwrap_or_default();
        left_direction.cmp(right_direction).then_with(|| {
            left["packet_id"]
                .as_str()
                .unwrap_or_default()
                .cmp(right["packet_id"].as_str().unwrap_or_default())
        })
    });
    let capture_gap_confirmation = json!({
        "client_to_server": capture_gap_confirmation(
            "server_to_client",
            &server,
            &client_missing,
            &server_report,
        ),
        "server_to_client": capture_gap_confirmation(
            "client_to_server",
            &client,
            &server_missing,
            &client_report,
        )
    });
    let semantics = json!({
        "status": "plaintext_capture_causally_validated",
        "scope": "plaintext ack_history[0] bits 0..4 only",
        "formula": "plaintext bit k == 0 means (ack_id - k) mod 0x4000 was not accepted by the peer",
        "legacy_ciphertext_projection": "wire-projection bit k == 1 because recovered keystream bits 33..37 are 0x1f",
        "bit_offsets": [0, 1, 2, 3, 4],
        "higher_bits_status": "plaintext_preserved_wider_index_mapping_unresolved",
        "by_reporter_direction": {
            "client_to_server": client_report.clone(),
            "server_to_client": server_report.clone()
        },
        "capture_gap_confirmation": capture_gap_confirmation,
        "captured_but_peer_reported_missing": captured_but_peer_reported_missing
    });
    Low5Analysis {
        client_peer_reported_missing: client_report,
        server_peer_reported_missing: server_report,
        semantics,
    }
}

fn missing_packet_id_set(notifications: &[&NotifyObservation]) -> HashSet<u16> {
    let Some(first) = notifications.first() else {
        return HashSet::new();
    };
    let last = notifications.last().expect("the first observation exists");
    if first.packet_id > last.packet_id {
        return HashSet::new();
    }
    let observed: HashSet<_> = notifications.iter().map(|item| item.packet_id).collect();
    (first.packet_id..=last.packet_id)
        .filter(|packet_id| !observed.contains(packet_id))
        .collect()
}

fn peer_reported_missing(
    reporter_direction: &'static str,
    peer_direction: &'static str,
    reports: &[&NotifyObservation],
    peer_packets: &[&NotifyObservation],
    peer_missing: &HashSet<u16>,
    captured_contexts: &mut Vec<Value>,
) -> Value {
    let mut peer_frames = BTreeMap::<u16, Vec<u64>>::new();
    for packet in peer_packets {
        peer_frames
            .entry(packet.packet_id)
            .or_default()
            .push(packet.frame);
    }
    let mut assertions = BTreeMap::<u16, Vec<Value>>::new();
    let mut report_frames_with_missing = HashSet::<u64>::new();
    for report in reports {
        let history_byte_0 = report.history.first().copied().unwrap_or_default();
        for bit_offset in 0..5_u8 {
            if history_byte_0 & (1 << bit_offset) != 0 {
                continue;
            }
            report_frames_with_missing.insert(report.frame);
            let packet_id = report.ack_id.wrapping_sub(u16::from(bit_offset)) & 0x3fff;
            assertions.entry(packet_id).or_default().push(json!({
                "source_frame": report.frame,
                "ack_id": format!("0x{:04x}", report.ack_id),
                "history_byte_0": format!("0x{history_byte_0:02x}"),
                "bit_offset": bit_offset
            }));
        }
    }

    let mut by_packet_id = Vec::new();
    let mut capture_gap_ids = Vec::new();
    let mut captured_ids = Vec::new();
    let mut outside_ids = Vec::new();
    for (packet_id, packet_assertions) in &assertions {
        let (classification, destination) = if peer_frames.contains_key(packet_id) {
            (
                "captured_peer_packet_reported_not_accepted",
                &mut captured_ids,
            )
        } else if peer_missing.contains(packet_id) {
            ("capture_gap_confirmed_by_peer_report", &mut capture_gap_ids)
        } else {
            ("outside_observed_peer_packet_id_span", &mut outside_ids)
        };
        destination.push(*packet_id);
        let report_source_frames: Vec<_> = packet_assertions
            .iter()
            .filter_map(|value| value["source_frame"].as_u64())
            .collect();
        by_packet_id.push(json!({
            "packet_id": format!("0x{packet_id:04x}"),
            "classification": classification,
            "peer_capture_frames": peer_frames.get(packet_id).cloned().unwrap_or_default(),
            "report_source_frames": report_source_frames,
            "assertions": packet_assertions
        }));
        if let Some(packet_index) = peer_packets
            .iter()
            .position(|packet| packet.packet_id == *packet_id)
        {
            let reordered = packet_index > 0
                && modulo_backward(peer_packets[packet_index - 1].packet_id, *packet_id);
            captured_contexts.push(json!({
                "peer_packet_direction": peer_direction,
                "packet_id": format!("0x{packet_id:04x}"),
                "packet_source_frames": peer_frames[packet_id],
                "reporter_direction": reporter_direction,
                "report_source_frames": report_source_frames,
                "capture_context": if reordered {
                    "captured_as_backward_reorder"
                } else {
                    "captured_in_sender_side_sequence_without_gap"
                }
            }));
        }
    }
    let hexadecimal = |values: &[u16]| {
        values
            .iter()
            .map(|value| Value::String(format!("0x{value:04x}")))
            .collect::<Vec<_>>()
    };
    json!({
        "peer_packet_direction": peer_direction,
        "report_packet_count": reports.len(),
        "report_packets_with_missing_low5": report_frames_with_missing.len(),
        "assertion_count": assertions.values().map(Vec::len).sum::<usize>(),
        "unique_peer_reported_missing_packet_id_count": assertions.len(),
        "unique_peer_reported_missing_packet_ids": hexadecimal(&assertions.keys().copied().collect::<Vec<_>>()),
        "capture_gap_packet_ids": hexadecimal(&capture_gap_ids),
        "captured_but_reported_not_accepted_packet_ids": hexadecimal(&captured_ids),
        "outside_observed_peer_span_packet_ids": hexadecimal(&outside_ids),
        "by_packet_id": by_packet_id
    })
}

fn capture_gap_confirmation(
    reporter_direction: &'static str,
    reporter_packets: &[&NotifyObservation],
    actual_gaps: &HashSet<u16>,
    reporter_summary: &Value,
) -> Value {
    let reported: HashSet<u16> = reporter_summary["capture_gap_packet_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|value| u16::from_str_radix(value.trim_start_matches("0x"), 16).ok())
        .collect();
    let mut confirmed: Vec<_> = actual_gaps.intersection(&reported).copied().collect();
    let mut unconfirmed: Vec<_> = actual_gaps.difference(&reported).copied().collect();
    confirmed.sort_unstable();
    unconfirmed.sort_unstable();
    let last = reporter_packets.last();
    let beyond: Vec<_> = unconfirmed
        .iter()
        .copied()
        .filter(|packet_id| {
            last.is_some_and(|report| {
                let delta = (u32::from(*packet_id) + 0x4000 - u32::from(report.ack_id)) & 0x3fff;
                0 < delta && delta < 0x2000
            })
        })
        .collect();
    let hexadecimal = |values: &[u16]| {
        values
            .iter()
            .map(|value| Value::String(format!("0x{value:04x}")))
            .collect::<Vec<_>>()
    };
    json!({
        "reporter_direction": reporter_direction,
        "actual_capture_gap_count": actual_gaps.len(),
        "confirmed_by_low5_count": confirmed.len(),
        "confirmed_packet_ids": hexadecimal(&confirmed),
        "unconfirmed_packet_ids": hexadecimal(&unconfirmed),
        "last_report_source_frame": last.map(|item| item.frame),
        "last_report_ack_id": last.map(|item| format!("0x{:04x}", item.ack_id)),
        "unconfirmed_beyond_last_report_ack_ids": hexadecimal(&beyond)
    })
}

fn modulo_backward(previous: u16, current: u16) -> bool {
    (u32::from(current) + 0x4000 - u32::from(previous)) % 0x4000 > 0x2000
}

fn control_exchange_validation(observations: &[ControlObservation]) -> Value {
    let directions: Vec<_> = observations.iter().map(|item| item.direction).collect();
    let canonical_pattern = directions
        == [
            "client_to_server",
            "server_to_client",
            "client_to_server",
            "server_to_client",
        ];
    let echo = observations.len() >= 3 && observations[1].inner == observations[2].inner;
    json!({
        "status": if canonical_pattern && echo { "passed" } else { "observed_noncanonical_control_exchange" },
        "source_frames": observations.iter().map(|item| item.frame).collect::<Vec<_>>(),
        "inner_lengths": observations.iter().map(|item| item.inner.len()).collect::<Vec<_>>(),
        "packet_handler_oodle_flags": vec![1_u8; observations.len()],
        "packet_handler_raw_sizes": observations.iter().filter_map(|item| item.raw_size).collect::<Vec<_>>(),
        "first_plaintext_sha256": observations.first().map(|item| format!("{:x}", Sha256::digest(&item.inner))),
        "server_plaintext_echoes_to_client": echo,
        "wire_roundtrip": true
    })
}

struct DigestWriter<W> {
    inner: W,
    digest: Sha256,
    bytes: u64,
}

impl<W> DigestWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            digest: Sha256::new(),
            bytes: 0,
        }
    }

    fn sha256(&self) -> String {
        format!("{:x}", self.digest.clone().finalize())
    }
}

impl<W: Write> Write for DigestWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(bytes)?;
        self.digest.update(&bytes[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// `json.dumps(..., ensure_ascii=False)` uses a space after separators.
/// Keeping this formatter local avoids materializing a `serde_json::Value`.
#[derive(Default)]
struct PythonLineFormatter;

impl Formatter for PythonLineFormatter {
    fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        if first {
            Ok(())
        } else {
            writer.write_all(b", ")
        }
    }

    fn begin_object_value<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        writer.write_all(b": ")
    }
}

fn write_python_json_line<W: Write, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<(), CompatibilityPacketError> {
    let mut serializer = Serializer::with_formatter(&mut *writer, PythonLineFormatter);
    value.serialize(&mut serializer)?;
    writer.write_all(b"\n")?;
    Ok(())
}

struct AtomicArtifactPair {
    packet_temp: PathBuf,
    unresolved_temp: PathBuf,
    committed: bool,
}

impl AtomicArtifactPair {
    fn new(output: &Path) -> Self {
        let nonce = rand::random::<u128>();
        Self {
            packet_temp: output.join(format!(".packets.jsonl.{nonce:032x}.tmp")),
            unresolved_temp: output.join(format!(".unresolved.jsonl.{nonce:032x}.tmp")),
            committed: false,
        }
    }

    fn commit(mut self, output: &Path) -> io::Result<()> {
        let packets = output.join("packets.jsonl");
        let unresolved = output.join("unresolved.jsonl");
        let nonce = rand::random::<u128>();
        let packet_backup = output.join(format!(".packets.jsonl.{nonce:032x}.bak"));
        let unresolved_backup = output.join(format!(".unresolved.jsonl.{nonce:032x}.bak"));
        let had_packets = packets.exists();
        let had_unresolved = unresolved.exists();

        if had_packets {
            fs::rename(&packets, &packet_backup)?;
        }
        if had_unresolved && let Err(error) = fs::rename(&unresolved, &unresolved_backup) {
            if had_packets {
                let _ = fs::rename(&packet_backup, &packets);
            }
            return Err(error);
        }

        let install_packets = fs::rename(&self.packet_temp, &packets);
        if let Err(error) = install_packets {
            restore_pair(
                &packets,
                &unresolved,
                &packet_backup,
                &unresolved_backup,
                had_packets,
                had_unresolved,
            );
            return Err(error);
        }
        if let Err(error) = fs::rename(&self.unresolved_temp, &unresolved) {
            let _ = fs::remove_file(&packets);
            restore_pair(
                &packets,
                &unresolved,
                &packet_backup,
                &unresolved_backup,
                had_packets,
                had_unresolved,
            );
            return Err(error);
        }

        if had_packets {
            fs::remove_file(packet_backup)?;
        }
        if had_unresolved {
            fs::remove_file(unresolved_backup)?;
        }
        self.committed = true;
        Ok(())
    }
}

impl Drop for AtomicArtifactPair {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.packet_temp);
            let _ = fs::remove_file(&self.unresolved_temp);
        }
    }
}

fn restore_pair(
    packets: &Path,
    unresolved: &Path,
    packet_backup: &Path,
    unresolved_backup: &Path,
    had_packets: bool,
    had_unresolved: bool,
) {
    if had_packets {
        let _ = fs::rename(packet_backup, packets);
    }
    if had_unresolved {
        let _ = fs::rename(unresolved_backup, unresolved);
    }
}

#[derive(Serialize)]
struct PacketRecord {
    packet_index: u64,
    timestamp: f64,
    timestamp_iso: String,
    direction: &'static str,
    source: String,
    destination: String,
    transport: &'static str,
    wire_length: u32,
    payload_length: usize,
    payload_hex: String,
    flow_id: String,
    classification: &'static str,
    layers: Vec<PacketLayer>,
    messages: Vec<PacketMessage>,
    validation: PacketValidation,
    unknown_spans: Vec<UnknownSpan>,
    source_refs: [String; 1],
}

#[derive(Clone, Serialize)]
struct UnknownSpan {
    layer: &'static str,
    bit_offset: usize,
    bit_length: usize,
    raw_hex: String,
    reason: String,
}

#[derive(Serialize)]
struct UnresolvedRecord<'a> {
    packet_index: u64,
    timestamp: &'a str,
    direction: &'static str,
    flow_id: &'a str,
    layer: &'static str,
    bit_offset: usize,
    bit_length: usize,
    raw_hex: &'a str,
    reason: &'a str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PacketLayer {
    ClientOuter(Layer<ClientOuterFields, ClientOuterValidation>),
    SgNet(Layer<SgNetFields, SgNetValidation>),
    PacketHandler(Layer<PacketHandlerFields, PacketHandlerValidation>),
    Notify(Layer<NotifyFields, ReaderValidation>),
    PacketInfo(Layer<PacketInfoFields, ReaderValidation>),
    Bunch(Layer<BunchFields, ReaderValidation>),
    PackageMap(Layer<PackageMapFields, PackageMapValidation>),
    BatchActor(Layer<BatchActorFields, BatchActorValidation>),
    BatchProperty(Layer<BatchPropertyFields, BatchPropertyValidation>),
}

#[derive(Serialize)]
struct Layer<F, V> {
    name: &'static str,
    fields: F,
    raw_hex: String,
    consumed_bits: usize,
    validation: V,
}

#[derive(Serialize)]
struct ClientOuterFields {
    watermark_crc32c_raw: u32,
    watermark_crc32c_wire_hex: String,
    watermark_counter: u32,
    watermark_counter_wire_hex: String,
    encrypted_connection_id_raw: u16,
    encrypted_connection_id_wire_hex: String,
    observed_connection_id_ciphertext_phase: &'static str,
}

#[derive(Serialize)]
struct ClientOuterValidation {
    structure: &'static str,
    watermark_crc32c: &'static str,
    watermark_algorithm: &'static str,
    watermark_coverage: &'static str,
    payload_authentication: &'static str,
    bytes_8_9_encryption: &'static str,
}

#[derive(Serialize)]
struct SgNetFields {
    algorithm: &'static str,
    rounds: u8,
    initial_block_counter: u8,
    authentication_tag: Option<u8>,
    copy_layout: Vec<CopyLayout>,
    connection_id: Option<u16>,
    session_material_status: &'static str,
}

#[derive(Serialize)]
struct CopyLayout {
    wire_bytes: &'static str,
    transform: &'static str,
}

#[derive(Serialize)]
struct SgNetValidation {
    decryption: &'static str,
    initial_exchange: &'static str,
}

#[derive(Serialize)]
struct PacketHandlerFields {
    bit_order: &'static str,
    oodle_flag: bool,
    pass_through: bool,
    raw_size: Option<u16>,
    archive_bit_length: usize,
    header_bit_length: usize,
    payload_bit_length: usize,
}

#[derive(Serialize)]
struct PacketHandlerValidation {
    structure: &'static str,
    reencode: &'static str,
    wire_bit_offset: usize,
    reader: &'static str,
}

#[derive(Serialize)]
struct NotifyFields {
    history_byte_count: u8,
    ack_id: u16,
    packet_id: u16,
    ack_history_hex: String,
    payload_bit_offset: usize,
}

#[derive(Serialize)]
struct PacketInfoFields {
    serialized: bool,
    present: bool,
    timestamp_ms_mod_1024: Option<u16>,
    timing_compensation_present: Option<bool>,
    timing_compensation_ms: Option<u8>,
}

#[derive(Serialize)]
struct ReaderValidation {
    structure: &'static str,
    wire_bit_offset: usize,
    reader: &'static str,
}

#[derive(Serialize)]
struct BunchFields {
    bunch_index: usize,
    channel_index: u32,
    control: bool,
    open: bool,
    close: bool,
    close_reason: Option<u32>,
    dormant: bool,
    replication_paused: bool,
    reliable: bool,
    reliable_sequence_raw: Option<u16>,
    partial: bool,
    partial_initial: bool,
    partial_final: bool,
    has_package_map_exports: bool,
    has_must_be_mapped_guids: bool,
    channel_name: Option<ChannelName>,
    data_bit_length: usize,
}

#[derive(Serialize)]
struct ChannelName {
    hard_coded: bool,
    comparison_index: Option<u32>,
    number: i32,
    string_value: Option<String>,
    string_encoding: Option<&'static str>,
    string_raw_hex: Option<String>,
    raw_bit_offset: usize,
    raw_bit_length: usize,
}

#[derive(Clone, Serialize)]
struct PackageMapBinding {
    netguid: u32,
    outer_netguid: Option<u32>,
    path: String,
    network_checksum: Option<u32>,
    flags: u8,
    bunch_index: usize,
    channel_index: u32,
}

#[derive(Serialize)]
struct PackageMapFields {
    bunch_index: usize,
    alternate_layout: bool,
    export_count: u32,
    binding_count: usize,
    bindings: Vec<PackageMapBinding>,
}

#[derive(Serialize)]
struct PackageMapValidation {
    structure: &'static str,
    reencode: &'static str,
    wire_bit_offset: usize,
    reader: &'static str,
}

#[derive(Serialize)]
struct BatchPropertyDescription {
    property_handle: u32,
    property_handle_bit_offset: usize,
    property_handle_bit_length: usize,
    property_payload_bit_offset: usize,
    property_payload_bit_length: usize,
    two_bit_value: Option<u8>,
    is_batch_data: bool,
}

#[derive(Serialize)]
struct BatchActorFields {
    bunch_index: usize,
    channel_index: u32,
    has_rep_layout: bool,
    is_actor: bool,
    content_payload_bit_offset: usize,
    content_payload_bit_length: usize,
    checksum_present: bool,
    property_handle: u32,
    property_count: usize,
    properties: Vec<BatchPropertyDescription>,
    property_handle_bit_offset: usize,
    property_handle_bit_length: usize,
    property_payload_bit_offset: usize,
    property_payload_bit_length: usize,
    property_terminator: u8,
    property_terminator_bit_offset: usize,
}

#[derive(Serialize)]
struct BatchActorValidation {
    structure: &'static str,
    exact_consumption: bool,
    wire_bit_offset: usize,
    property_payload_wire_bit_offset: usize,
    reader: &'static str,
}

#[derive(Serialize)]
struct BatchPropertyFields {
    property_handle: u32,
    character_count: u8,
    present_slots: Vec<u8>,
    update_count: usize,
    identity_binding: &'static str,
}

#[derive(Serialize)]
struct BatchPropertyValidation {
    structure: &'static str,
    exact_consumption: bool,
    wire_bit_offset: usize,
    reader: &'static str,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PacketMessage {
    PacketHandler(PacketHandlerMessage),
    UnrealPacket(UnrealPacketMessage),
    Bunch(BunchMessage),
    Reassembled(ReassembledMessage),
    Batch(BatchActorMessage),
}

#[derive(Serialize)]
struct PacketHandlerMessage {
    message_type: &'static str,
    oodle_flag: bool,
    pass_through: bool,
    raw_size: Option<u16>,
    payload_bit_length: usize,
}

#[derive(Serialize)]
struct UnrealPacketMessage {
    message_type: &'static str,
    ack_id: u16,
    packet_id: u16,
    history_byte_count: u8,
    bunch_count: usize,
    archive_bit_length: usize,
}

#[derive(Serialize)]
struct BunchMessage {
    message_type: &'static str,
    bunch_index: usize,
    channel_index: u32,
    open: bool,
    close: bool,
    reliable: bool,
    reliable_sequence_raw: Option<u16>,
    partial: bool,
    partial_initial: bool,
    partial_final: bool,
    has_package_map_exports: bool,
    data_bit_offset: usize,
    data_bit_length: usize,
    data_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_map_export_prefix_bits: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    package_map_bindings: Option<Vec<PackageMapBinding>>,
}

#[derive(Serialize)]
struct ReassembledMessage {
    message_type: &'static str,
    direction: &'static str,
    channel_index: u32,
    fragment_count: usize,
    source_frames: Vec<u64>,
    packet_sequences: Vec<u64>,
    reliable_sequences: Vec<u16>,
    data_bit_length: usize,
    data_hex: String,
    data_sha256: String,
}

#[derive(Serialize)]
struct BatchActorMessage {
    message_type: &'static str,
    bunch_index: usize,
    channel_index: u32,
    wire_bit_offset: usize,
    data_bit_length: usize,
    property_handle: u32,
    property_count: usize,
    property_handles: Vec<u32>,
    property_payload_bit_offset: usize,
    property_payload_wire_bit_offset: usize,
    property_payload_bit_length: usize,
    property_terminator: u8,
    bit_exact: bool,
    semantic_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    character_count: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    present_slots: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    update_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updates: Option<Vec<BatchUpdateRecord>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_binding: Option<&'static str>,
}

#[derive(Serialize)]
struct PacketValidation {
    network_integrity: NetworkIntegrity,
    reencode: &'static str,
    decrypted: bool,
    sgnet_cipher_status: &'static str,
    sgnet_wire_reencode_exact: bool,
    packet_handler_reencode_exact: bool,
    unreal_reencode_exact: Option<bool>,
    unresolved_boundary: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_sync: Option<BatchValidation>,
}

#[derive(Serialize)]
struct NetworkIntegrity {
    ipv4_header_checksum: &'static str,
    udp_checksum: &'static str,
    ipv4_header_checksum_value: Option<u16>,
    udp_checksum_value: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    udp_checksum_reason: Option<&'static str>,
}

#[derive(Serialize)]
struct BatchValidation {
    decoded_actor_messages: u64,
    character_updates: u64,
    exact_consumption: bool,
}

#[derive(Clone, Copy, Serialize)]
struct UnitVector {
    x: f64,
    y: f64,
    z: f64,
    unit: &'static str,
}

#[derive(Clone, Copy, Serialize)]
struct CompatibilityState {
    position: [f64; 3],
    velocity: [f64; 3],
    acceleration: [f64; 3],
    rotation_degrees: [f64; 3],
    movement_flags: u8,
    has_movement_mode: bool,
    movement_mode: u16,
    delta_counter: i32,
    minimal_word: u32,
    extra_state: u8,
}

#[derive(Clone, Copy, Serialize)]
struct CompatibilityVector {
    x: f64,
    y: f64,
    z: f64,
    unit: &'static str,
    bit_offset: usize,
    wire_bit_offset: usize,
    bit_length: usize,
    quantization_decimals: u8,
    absolute_xy: bool,
    xy_width: u8,
    z_width: u8,
}

#[derive(Clone, Copy, Serialize)]
struct CompatibilityRotator {
    degrees: [f64; 3],
    bit_offset: usize,
    wire_bit_offset: usize,
    bit_length: usize,
}

#[derive(Clone, Copy, Serialize)]
struct CompatibilityMovement {
    kind: &'static str,
    bit_offset: usize,
    wire_bit_offset: usize,
    bit_length: usize,
    position: CompatibilityVector,
    velocity: CompatibilityVector,
    acceleration: Option<CompatibilityVector>,
    rotation: Option<CompatibilityRotator>,
}

#[derive(Serialize)]
struct BatchUpdateRecord {
    batch_slot: u8,
    track_id: String,
    identity_binding: &'static str,
    state_index: u8,
    change_mask: u8,
    use_baseline: bool,
    source_baseline: Option<u8>,
    store_baseline: bool,
    destination_baseline: Option<u8>,
    bit_offset: usize,
    wire_bit_offset: usize,
    bit_length: usize,
    position_changed: bool,
    position: UnitVector,
    state: CompatibilityState,
    movement: Option<CompatibilityMovement>,
    extra_state: Option<u8>,
}

#[derive(Clone)]
struct LogicalBunch {
    bunch_index: usize,
    channel_index: u32,
    open: bool,
    partial: bool,
    partial_initial: bool,
    partial_final: bool,
    reliable: bool,
    reliable_sequence_raw: Option<u16>,
    data_bit_offset: usize,
    data_bit_length: usize,
    data: Vec<u8>,
}

#[derive(Clone)]
struct PartialFragment {
    direction: &'static str,
    packet_sequence: u64,
    source_frame: u64,
    bunch_index: usize,
    bunch: LogicalBunch,
}

#[derive(Default)]
struct PartialChain {
    fragments: Vec<PartialFragment>,
    bits: usize,
}

#[derive(Default)]
struct CompatibilityPartialReassembler {
    active: HashMap<(&'static str, u32), PartialChain>,
    duplicate_fragments: u64,
}

impl CompatibilityPartialReassembler {
    fn feed_fragment(
        &mut self,
        fragment: PartialFragment,
    ) -> Result<Option<ReassembledMessage>, CompatibilityPacketError> {
        let key = (fragment.direction, fragment.bunch.channel_index);
        if !self.active.contains_key(&key) && self.active.len() >= MAX_PARTIAL_CHANNELS {
            return Err(CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: "partial channel bound exceeded".into(),
            });
        }
        if fragment.bunch.partial_initial {
            if self
                .active
                .get(&key)
                .and_then(|chain| chain.fragments.first())
                .is_some_and(|previous| same_partial_fragment(previous, &fragment))
            {
                self.duplicate_fragments += 1;
                return Ok(None);
            }
            if self.active.contains_key(&key) {
                return Err(CompatibilityPacketError::Contract {
                    frame: fragment.source_frame,
                    detail: format!(
                        "overlapping partial initial on channel {}",
                        fragment.bunch.channel_index
                    ),
                });
            }
            self.active.insert(key, PartialChain::default());
        }
        let Some(chain) = self.active.get_mut(&key) else {
            return Err(CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: format!(
                    "orphan partial fragment on channel {}",
                    fragment.bunch.channel_index
                ),
            });
        };
        if chain
            .fragments
            .last()
            .is_some_and(|previous| same_partial_fragment(previous, &fragment))
        {
            self.duplicate_fragments += 1;
            return Ok(None);
        }
        if chain.fragments.len() >= MAX_PARTIAL_FRAGMENTS {
            return Err(CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: "partial fragment bound exceeded".into(),
            });
        }
        if let Some(previous) = chain.fragments.last()
            && previous.bunch.reliable != fragment.bunch.reliable
        {
            return Err(CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: "reliability changed inside a partial chain".into(),
            });
        }
        if let Some(previous) = chain.fragments.last()
            && let (Some(left), Some(right)) = (
                previous.bunch.reliable_sequence_raw,
                fragment.bunch.reliable_sequence_raw,
            )
            && right != (left + 1) % 1024
        {
            return Err(CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: format!("partial reliable sequence gap {left}->{right}"),
            });
        }
        chain.bits = chain
            .bits
            .checked_add(fragment.bunch.data_bit_length)
            .filter(|bits| *bits <= MAX_PARTIAL_BITS)
            .ok_or_else(|| CompatibilityPacketError::Contract {
                frame: fragment.source_frame,
                detail: "partial payload bit bound exceeded".into(),
            })?;
        let final_fragment = fragment.bunch.partial_final;
        chain.fragments.push(fragment);
        if !final_fragment {
            return Ok(None);
        }
        let chain = self.active.remove(&key).expect("borrow ended above");
        let mut writer = codev_protocol::Lsb0Writer::with_capacity(chain.bits);
        for fragment in &chain.fragments {
            writer.write_bit_slice(&fragment.bunch.data, 0, fragment.bunch.data_bit_length)?;
        }
        let data = writer.into_bytes();
        let source_frames = chain
            .fragments
            .iter()
            .map(|item| item.source_frame)
            .collect();
        let packet_sequences = chain
            .fragments
            .iter()
            .map(|item| item.packet_sequence)
            .collect();
        let reliable_sequences = chain
            .fragments
            .iter()
            .filter_map(|item| item.bunch.reliable_sequence_raw)
            .collect();
        Ok(Some(ReassembledMessage {
            message_type: "reassembled_partial_bunch",
            direction: key.0,
            channel_index: key.1,
            fragment_count: chain.fragments.len(),
            source_frames,
            packet_sequences,
            reliable_sequences,
            data_bit_length: chain.bits,
            data_hex: hex(&data),
            data_sha256: format!("{:x}", Sha256::digest(&data)),
        }))
    }

    fn finish(&self, frame: u64) -> Result<(), CompatibilityPacketError> {
        if !self.active.is_empty() {
            return Err(CompatibilityPacketError::Contract {
                frame,
                detail: "partial chains or reordered packet sequences remain at EOF".into(),
            });
        }
        Ok(())
    }
}

fn same_partial_fragment(left: &PartialFragment, right: &PartialFragment) -> bool {
    left.bunch.reliable_sequence_raw.is_some()
        && left.bunch.reliable_sequence_raw == right.bunch.reliable_sequence_raw
        && left.bunch.data_bit_length == right.bunch.data_bit_length
        && left.bunch.data == right.bunch.data
        && left.bunch.partial_initial == right.bunch.partial_initial
        && left.bunch.partial_final == right.bunch.partial_final
}

fn unwrap_sequence(raw: u16, maximum: Option<u64>) -> u64 {
    const MODULUS: i64 = 0x4000;
    const HALF: i64 = MODULUS / 2;
    let Some(maximum) = maximum else {
        return u64::from(raw);
    };
    let maximum = maximum as i64;
    let mut candidate = maximum.div_euclid(MODULUS) * MODULUS + i64::from(raw);
    while candidate < maximum - HALF {
        candidate += MODULUS;
    }
    while candidate > maximum + HALF {
        candidate -= MODULUS;
    }
    candidate as u64
}

struct ReassembledCollection {
    messages: HashMap<u64, Vec<ReassembledMessage>>,
    fragment_count: u64,
    duplicate_fragments: u64,
    fragments_per_payload: BTreeMap<String, u64>,
    total_reassembled_bits: u64,
}

fn collect_reassembled_messages(
    pcap: &Path,
    cipher: &C0Cipher,
    flow: SelectedUdpFlow,
) -> Result<ReassembledCollection, CompatibilityPacketError> {
    let mut source = S0PcapSource::open(pcap)?;
    let mut client_maximum = None;
    let mut server_maximum = None;
    let mut client_fragments = Vec::new();
    let mut server_fragments = Vec::new();
    let mut retained_bits = 0_usize;
    let mut retained_fragments = 0_usize;
    let mut last_frame = 0_u64;
    while let Some(captured) = source.next_packet()? {
        let transport = match parse_transport(&captured) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if transport.kind != TransportKind::Udp
            || !flow.key.contains(transport.source, transport.destination)
        {
            continue;
        }
        let frame = captured.index + 1;
        last_frame = frame;
        let (direction, maximum, fragments) =
            if transport.source == flow.client && transport.destination == flow.server {
                (
                    "client_to_server",
                    &mut client_maximum,
                    &mut client_fragments,
                )
            } else if transport.source == flow.server && transport.destination == flow.client {
                (
                    "server_to_client",
                    &mut server_maximum,
                    &mut server_fragments,
                )
            } else {
                return Err(contract(
                    frame,
                    "selected tuple does not have the authenticated orientation",
                ));
            };
        let logical = if direction == "client_to_server" {
            cipher.crypt_client_datagram(transport.payload)?
        } else {
            cipher.crypt_server_datagram(transport.payload)
        };
        let inner = if direction == "client_to_server" {
            &logical[CLIENT_PREFIX_BYTES..]
        } else {
            &logical
        };
        let proof = prove_packet_handler_wire(inner)?;
        let Some(unreal) = proof.unreal.as_ref() else {
            continue;
        };
        let sequence = unwrap_sequence(unreal.notify.packet_raw, *maximum);
        *maximum = Some((*maximum).map_or(sequence, |value| value.max(sequence)));
        for bunch in logical_bunches(unreal, &proof)?
            .into_iter()
            .filter(|bunch| bunch.partial)
        {
            retained_bits = retained_bits
                .checked_add(bunch.data_bit_length)
                .filter(|bits| *bits <= MAX_PARTIAL_CORPUS_BITS)
                .ok_or_else(|| contract(frame, "partial corpus bit bound exceeded"))?;
            if retained_fragments >= MAX_PARTIAL_CORPUS_FRAGMENTS {
                return Err(contract(frame, "partial corpus fragment bound exceeded"));
            }
            retained_fragments += 1;
            fragments.push(PartialFragment {
                direction,
                packet_sequence: sequence,
                source_frame: frame,
                bunch_index: bunch.bunch_index,
                bunch,
            });
        }
    }

    client_fragments
        .sort_by_key(|item| (item.packet_sequence, item.source_frame, item.bunch_index));
    server_fragments
        .sort_by_key(|item| (item.packet_sequence, item.source_frame, item.bunch_index));
    let mut reassembler = CompatibilityPartialReassembler::default();
    let mut messages = HashMap::<u64, Vec<ReassembledMessage>>::new();
    let mut fragments_per_payload = BTreeMap::<String, u64>::new();
    let mut total_reassembled_bits = 0_u64;
    for fragment in client_fragments.into_iter().chain(server_fragments) {
        if let Some(message) = reassembler.feed_fragment(fragment)? {
            *fragments_per_payload
                .entry(message.fragment_count.to_string())
                .or_default() += 1;
            total_reassembled_bits = total_reassembled_bits
                .checked_add(message.data_bit_length as u64)
                .ok_or_else(|| contract(last_frame, "partial reassembled bit total overflow"))?;
            let destination = message
                .source_frames
                .last()
                .copied()
                .ok_or_else(|| contract(last_frame, "empty partial completion"))?;
            messages.entry(destination).or_default().push(message);
        }
    }
    reassembler.finish(last_frame)?;
    Ok(ReassembledCollection {
        messages,
        fragment_count: retained_fragments as u64,
        duplicate_fragments: reassembler.duplicate_fragments,
        fragments_per_payload,
        total_reassembled_bits,
    })
}

pub fn write_compatibility_packet_artifacts(
    pcap: &Path,
    cipher: &C0Cipher,
    flow: SelectedUdpFlow,
    output: &Path,
) -> Result<CompatibilityPacketReport, CompatibilityPacketError> {
    // A compact first pass is required solely for oracle-compatible partial
    // messages: the UE receive path orders fragments by unwrapped PacketNotify
    // sequence, while `packets.jsonl` itself remains in capture order. Only
    // partial fragments are retained and both count and bit size are bounded.
    let mut reassembled = collect_reassembled_messages(pcap, cipher, flow)?;
    let temporary = AtomicArtifactPair::new(output);
    let packet_file = DigestWriter::new(open_private(&temporary.packet_temp, true)?);
    let unresolved_file = DigestWriter::new(open_private(&temporary.unresolved_temp, true)?);
    let mut packet_writer = BufWriter::with_capacity(PACKET_BUFFER_BYTES, packet_file);
    let mut unresolved_writer = BufWriter::with_capacity(PACKET_BUFFER_BYTES, unresolved_file);
    let mut source = S0PcapSource::open(pcap)?;
    let mut batch = D0Decoder::new();
    let mut report = ReportAccumulator::default();
    let mut last_frame = 0_u64;

    while let Some(captured) = source.next_packet()? {
        let transport = match parse_transport(&captured) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if transport.kind != TransportKind::Udp
            || !flow.key.contains(transport.source, transport.destination)
        {
            continue;
        }
        let frame = captured.index + 1;
        last_frame = frame;
        let direction = if transport.source == flow.client && transport.destination == flow.server {
            "client_to_server"
        } else if transport.source == flow.server && transport.destination == flow.client {
            "server_to_client"
        } else {
            return Err(CompatibilityPacketError::Contract {
                frame,
                detail: "selected tuple does not have the authenticated orientation".into(),
            });
        };
        report.direction_mut(direction).report.packet_count += 1;
        let integrity = validate_packet_integrity(&captured)
            .map_err(|source| CompatibilityPacketError::Packet { frame, source })?;
        report.observe_transport_payload(direction, transport.payload, integrity);
        if direction == "client_to_server" {
            if transport.payload.len() < CLIENT_PREFIX_BYTES {
                return Err(contract(frame, "client watermark prefix is truncated"));
            }
            let observed_crc = u32::from_le_bytes(transport.payload[..4].try_into().unwrap());
            let watermark_counter = u32::from_le_bytes(transport.payload[4..8].try_into().unwrap());
            report.client_watermark_counters.push(watermark_counter);
            report.client_watermark_crc32c_validated += u64::from(
                observed_crc == compute_watermark_crc32c(transport.destination, watermark_counter),
            );
            let encrypted_connection_id =
                u16::from_le_bytes(transport.payload[8..10].try_into().unwrap());
            *report
                .encrypted_connection_id_raw_distribution
                .entry(format!("0x{encrypted_connection_id:04x}"))
                .or_default() += 1;
        }
        let mut logical = if direction == "client_to_server" {
            cipher.crypt_client_datagram(transport.payload)?
        } else {
            cipher.crypt_server_datagram(transport.payload)
        };
        let base_offset = if direction == "client_to_server" {
            CLIENT_PREFIX_BYTES * 8
        } else {
            0
        };
        let inner = if direction == "client_to_server" {
            let plaintext_connection_id = u16::from_le_bytes(logical[8..10].try_into().unwrap());
            *report
                .plaintext_connection_id_distribution
                .entry(format!("0x{plaintext_connection_id:04x}"))
                .or_default() += 1;
            &logical[CLIENT_PREFIX_BYTES..]
        } else {
            &logical[..]
        };
        let proof = prove_packet_handler_wire(inner)?;
        if reencode_packet_handler_envelope(&proof.handler)? != inner {
            return Err(contract(frame, codev_obf::s("08e762f08787261b36e26dfe90d31a0328e365bb9096431f36e56eff87d303132beb60ef819b")));
        }
        report.packet_handler_reencode_exact += 1;
        {
            let direction_report = &mut report.direction_mut(direction).report;
            direction_report.packet_handler_reencode_exact += 1;
            if proof.handler.pass_through() {
                direction_report.oodle_pass_through_packets += 1;
            } else {
                direction_report.oodle_flag_one_packets += 1;
                direction_report.control_packet_count += 1;
            }
        }
        if let Some(raw_size) = proof.handler.raw_size {
            *report
                .flag_one_raw_size_distribution
                .entry(raw_size.to_string())
                .or_default() += 1;
        }
        if !proof.handler.pass_through() {
            report.control_observations.push(ControlObservation {
                frame,
                direction,
                raw_size: proof.handler.raw_size,
                inner: inner.to_vec(),
            });
        }
        let mut record = build_base_record(
            &captured, &transport, direction, flow, integrity, &logical, &proof,
        )?;

        if direction == "client_to_server" {
            logical.truncate(CLIENT_PREFIX_BYTES);
            logical.extend_from_slice(&proof.rebuilt_inner);
            if cipher.crypt_client_datagram(&logical)? != transport.payload {
                return Err(contract(frame, codev_obf::s("524299cfc71e31986860b9de93493b866425a5cf9e5b3c976e61b28ade5721996071b4c2")));
            }
        } else if cipher.crypt_server_datagram(&proof.rebuilt_inner) != transport.payload {
            return Err(contract(frame, codev_obf::s("524299cfc71e21917373b2d893493b866425a5cf9e5b3c976e61b28ade5721996071b4c2")));
        }
        report.sgnet_wire_reencode_exact += 1;
        report
            .direction_mut(direction)
            .report
            .sgnet_wire_reencode_exact += 1;

        if let Some(unreal) = proof.unreal.as_ref() {
            if reencode_unreal_packet(unreal)? != proof.handler.payload {
                return Err(contract(frame, "Unreal typed re-encode mismatch"));
            }
            report.unreal_reencode_exact += 1;
            report.bunch_count += unreal.bunches.len() as u64;
            report.package_map_reencode_exact += proof.package_map_export_prefixes;
            let notification = NotifyObservation {
                frame,
                timestamp_ns: captured.timestamp_ns,
                packet_id: unreal.notify.packet_raw,
                ack_id: unreal.notify.ack_raw,
                history_byte_count: unreal.notify.history_byte_count,
                history: unreal.notify.history.clone(),
                watermark_counter_low14: (direction == "client_to_server").then(|| {
                    u16::from_le_bytes(transport.payload[4..6].try_into().unwrap()) & 0x3fff
                }),
                packet_info_present: unreal.has_packet_info_payload,
                packet_info_timestamp_ms: unreal.packet_info_timestamp_ms,
                packet_info_timing_compensation_present: unreal
                    .packet_info_timing_compensation_present,
                packet_info_timing_compensation_ms: unreal.packet_info_timing_compensation_ms,
                first_bunch: unreal.bunches.first().map(|bunch| FirstBunchObservation {
                    channel_index: bunch.channel_index,
                    control: bunch.control,
                    open: bunch.open,
                    close: bunch.close,
                    close_reason: bunch.close_reason,
                    replication_paused: bunch.replication_paused,
                    reliable: bunch.reliable,
                }),
                inner: proof.handler.payload.clone(),
            };
            {
                let direction = report.direction_mut(direction);
                direction.report.unreal_reencode_exact += 1;
                direction.report.bunch_count += unreal.bunches.len() as u64;
                direction.report.package_map_reencode_exact += proof.package_map_export_prefixes;
                if !direction.inner_packet_ids.insert(unreal.notify.packet_raw) {
                    direction.report.duplicate_inner_packet_ids += 1;
                    direction
                        .duplicate_packet_ids
                        .insert(unreal.notify.packet_raw);
                }
                direction.notifications.push(notification.clone());
            }
            report.notifications.push(DirectedNotifyObservation {
                direction,
                notification,
            });
            let logical_bunches = logical_bunches(unreal, &proof)?;
            for message in reassembled.messages.remove(&frame).unwrap_or_default() {
                report.partial_payloads_completed += 1;
                record.messages.push(PacketMessage::Reassembled(message));
            }
            append_batch_semantics(
                frame,
                direction,
                base_offset + proof.handler.header_bit_length,
                &logical_bunches,
                &mut batch,
                &mut record,
                &mut report,
            )?;
        }

        record
            .unknown_spans
            .sort_by_key(|span| (span.bit_offset, span.bit_length));
        if exact_coverage(transport.payload.len() * 8, &record)? {
            report.exact_bit_coverage += 1;
        } else {
            return Err(contract(
                frame,
                "known and explicit unknown spans do not cover the packet",
            ));
        }
        for span in &record.unknown_spans {
            write_python_json_line(
                &mut unresolved_writer,
                &UnresolvedRecord {
                    packet_index: record.packet_index,
                    timestamp: &record.timestamp_iso,
                    direction: record.direction,
                    flow_id: &record.flow_id,
                    layer: span.layer,
                    bit_offset: span.bit_offset,
                    bit_length: span.bit_length,
                    raw_hex: &span.raw_hex,
                    reason: &span.reason,
                },
            )?;
            report.unresolved_span_count += 1;
        }
        write_python_json_line(&mut packet_writer, &record)?;
        report.packet_count += 1;
    }
    if !reassembled.messages.is_empty() {
        return Err(contract(
            last_frame,
            "one or more partial completion messages target a missing packet",
        ));
    }
    if report.packet_count != flow.packet_count {
        return Err(contract(
            last_frame,
            format!(
                "selected flow emitted {} packets; expected {}",
                report.packet_count, flow.packet_count
            ),
        ));
    }
    packet_writer.flush()?;
    unresolved_writer.flush()?;
    let packets_sha256 = packet_writer.get_ref().sha256();
    let unresolved_sha256 = unresolved_writer.get_ref().sha256();
    let packets_bytes = packet_writer.get_ref().bytes;
    let unresolved_bytes = unresolved_writer.get_ref().bytes;
    drop(packet_writer);
    drop(unresolved_writer);
    temporary.commit(output)?;
    let client_watermark_counter = sequence_report(
        &report
            .client_watermark_counters
            .iter()
            .map(|&value| u64::from(value))
            .collect::<Vec<_>>(),
        0x1_0000_0000,
    );
    let client_watermark_counter_low16 = sequence_report(
        &report
            .client_watermark_counters
            .iter()
            .map(|&value| u64::from(value & 0xffff))
            .collect::<Vec<_>>(),
        0x1_0000,
    );
    let client_watermark_counter_low14_relation = watermark_relation(&report.notifications);
    let ack_recent_peer_match = ack_recent_peer_match(&report.notifications);
    let low5 = ack_history_low5_analysis(&report.notifications);
    let control_exchange_validation = control_exchange_validation(&report.control_observations);
    let mut client_to_server =
        std::mem::take(&mut report.client_to_server).finish("client_to_server");
    let mut server_to_client =
        std::mem::take(&mut report.server_to_client).finish("server_to_client");
    client_to_server.peer_reported_missing = low5.client_peer_reported_missing;
    server_to_client.peer_reported_missing = low5.server_peer_reported_missing;
    Ok(CompatibilityPacketReport {
        packet_count: report.packet_count,
        unresolved_span_count: report.unresolved_span_count,
        packet_handler_reencode_exact: report.packet_handler_reencode_exact,
        unreal_reencode_exact: report.unreal_reencode_exact,
        package_map_reencode_exact: report.package_map_reencode_exact,
        sgnet_wire_reencode_exact: report.sgnet_wire_reencode_exact,
        exact_bit_coverage: report.exact_bit_coverage,
        bunch_count: report.bunch_count,
        partial_payloads_completed: report.partial_payloads_completed,
        batch_actor_count: report.batch_actor_count,
        batch_property_count: report.batch_property_count,
        client_watermark_counter,
        client_watermark_counter_low16,
        client_watermark_crc32c_tested: report.client_watermark_counters.len() as u64,
        client_watermark_crc32c_validated: report.client_watermark_crc32c_validated,
        encrypted_connection_id_raw_distribution: report.encrypted_connection_id_raw_distribution,
        plaintext_connection_id_distribution: report.plaintext_connection_id_distribution,
        flag_one_raw_size_distribution: report.flag_one_raw_size_distribution,
        partial_fragment_count: reassembled.fragment_count,
        partial_duplicate_fragments: reassembled.duplicate_fragments,
        partial_fragments_per_payload: reassembled.fragments_per_payload,
        partial_total_reassembled_bits: reassembled.total_reassembled_bits,
        client_watermark_counter_low14_relation,
        ack_recent_peer_match,
        ack_history_low5_semantics: low5.semantics,
        control_exchange_validation,
        packets_sha256,
        unresolved_sha256,
        packets_bytes,
        unresolved_bytes,
        client_to_server,
        server_to_client,
    })
}

fn build_base_record(
    captured: &codev_stream::CapturedPacket,
    transport: &codev_stream::TransportPacket<'_>,
    direction: &'static str,
    flow: SelectedUdpFlow,
    integrity: codev_stream::PacketIntegrity,
    logical: &[u8],
    proof: &codev_stream::PacketWireProof,
) -> Result<PacketRecord, CompatibilityPacketError> {
    let frame = captured.index + 1;
    let base_offset = if direction == "client_to_server" {
        CLIENT_PREFIX_BYTES * 8
    } else {
        0
    };
    let inner = if direction == "client_to_server" {
        &logical[CLIENT_PREFIX_BYTES..]
    } else {
        logical
    };
    let mut layers = Vec::new();
    let mut messages = Vec::new();
    let mut unknown_spans = Vec::new();

    if direction == "client_to_server" {
        if transport.payload.len() < CLIENT_PREFIX_BYTES {
            return Err(contract(
                frame,
                "client datagram is shorter than its prefix",
            ));
        }
        let crc = u32::from_le_bytes(transport.payload[..4].try_into().unwrap());
        let counter = u32::from_le_bytes(transport.payload[4..8].try_into().unwrap());
        let encrypted_connection_id =
            u16::from_le_bytes(transport.payload[8..10].try_into().unwrap());
        let watermark_valid = crc == compute_watermark_crc32c(transport.destination, counter);
        layers.push(PacketLayer::ClientOuter(Layer {
            name: "codev_client_outer",
            fields: ClientOuterFields {
                watermark_crc32c_raw: crc,
                watermark_crc32c_wire_hex: hex(&transport.payload[..4]),
                watermark_counter: counter,
                watermark_counter_wire_hex: hex(&transport.payload[4..8]),
                encrypted_connection_id_raw: encrypted_connection_id,
                encrypted_connection_id_wire_hex: hex(&transport.payload[8..10]),
                observed_connection_id_ciphertext_phase: connection_phase(encrypted_connection_id),
            },
            raw_hex: hex(&transport.payload[..CLIENT_PREFIX_BYTES]),
            consumed_bits: CLIENT_PREFIX_BYTES * 8,
            validation: ClientOuterValidation {
                structure: "passed",
                watermark_crc32c: if watermark_valid { "passed" } else { "failed" },
                watermark_algorithm: "crc32c_raw_init0_no_xorout",
                watermark_coverage: "destination_endpoint_and_clear_counter_not_payload",
                payload_authentication: "not_present_in_this_wrapper",
                bytes_8_9_encryption: "sgnet_chacha20_separate_copy_counter_1",
            },
        }));
    }

    let (raw_crypto, copy_layout, connection_id) = if direction == "client_to_server" {
        (
            &transport.payload[8..],
            vec![
                CopyLayout {
                    wire_bytes: "0..7",
                    transform: "clear_watermark",
                },
                CopyLayout {
                    wire_bytes: "8..9",
                    transform: "chacha20_copy_counter_1_restart",
                },
                CopyLayout {
                    wire_bytes: "10..end",
                    transform: "chacha20_copy_counter_1_restart",
                },
            ],
            Some(u16::from_le_bytes(logical[8..10].try_into().unwrap())),
        )
    } else {
        (
            transport.payload,
            vec![CopyLayout {
                wire_bytes: "0..end",
                transform: "chacha20_copy_counter_1",
            }],
            None,
        )
    };
    layers.push(PacketLayer::SgNet(Layer {
        name: "sgnet_chacha20",
        fields: SgNetFields {
            algorithm: "IETF_ChaCha20",
            rounds: 20,
            initial_block_counter: 1,
            authentication_tag: None,
            copy_layout,
            connection_id,
            session_material_status: "available_from_server_travel",
        },
        raw_hex: hex(raw_crypto),
        consumed_bits: raw_crypto.len() * 8,
        validation: SgNetValidation {
            decryption: "passed",
            initial_exchange: "passed",
        },
    }));
    layers.push(PacketLayer::PacketHandler(Layer {
        name: "packet_handler_oodle",
        fields: PacketHandlerFields {
            bit_order: "lsb0",
            oodle_flag: proof.handler.oodle_flag,
            pass_through: proof.handler.pass_through(),
            raw_size: proof.handler.raw_size,
            archive_bit_length: proof.handler.archive_bit_length,
            header_bit_length: proof.handler.header_bit_length,
            payload_bit_length: proof.handler.payload_bit_length,
        },
        raw_hex: hex(&extract_lsb_bits(
            inner,
            0,
            proof.handler.header_bit_length,
        )?),
        consumed_bits: proof.handler.header_bit_length,
        validation: PacketHandlerValidation {
            structure: "passed",
            reencode: "exact",
            wire_bit_offset: base_offset,
            reader: "CodeV 0x101F602B4",
        },
    }));
    messages.push(PacketMessage::PacketHandler(PacketHandlerMessage {
        message_type: "packet_handler_envelope",
        oodle_flag: proof.handler.oodle_flag,
        pass_through: proof.handler.pass_through(),
        raw_size: proof.handler.raw_size,
        payload_bit_length: proof.handler.payload_bit_length,
    }));

    let (classification, unreal_exact, unresolved_boundary) =
        if let Some(unreal) = proof.unreal.as_ref() {
            let ue_offset = base_offset + proof.handler.header_bit_length;
            let notify = &unreal.notify;
            let packet_info_end = unreal
                .bunches
                .first()
                .map_or(unreal.archive_bit_length, |bunch| bunch.bit_offset);
            layers.push(PacketLayer::Notify(Layer {
                name: "unreal_packet_notify",
                fields: NotifyFields {
                    history_byte_count: notify.history_byte_count,
                    ack_id: notify.ack_raw,
                    packet_id: notify.packet_raw,
                    ack_history_hex: hex(&notify.history),
                    payload_bit_offset: notify.payload_bit_offset,
                },
                raw_hex: hex(&extract_lsb_bits(
                    &proof.handler.payload,
                    notify.bit_offset,
                    notify.bit_length,
                )?),
                consumed_bits: notify.bit_length,
                validation: ReaderValidation {
                    structure: "passed",
                    wire_bit_offset: ue_offset + notify.bit_offset,
                    reader: "CodeV 0x1064A4EA0",
                },
            }));
            let packet_info_bits = packet_info_end - notify.payload_bit_offset;
            layers.push(PacketLayer::PacketInfo(Layer {
                name: "unreal_packet_info",
                fields: PacketInfoFields {
                    serialized: unreal.packet_info_serialized,
                    present: unreal.has_packet_info_payload,
                    timestamp_ms_mod_1024: unreal.packet_info_timestamp_ms,
                    timing_compensation_present: unreal.packet_info_timing_compensation_present,
                    timing_compensation_ms: unreal.packet_info_timing_compensation_ms,
                },
                raw_hex: hex(&extract_lsb_bits(
                    &proof.handler.payload,
                    notify.payload_bit_offset,
                    packet_info_bits,
                )?),
                consumed_bits: packet_info_bits,
                validation: ReaderValidation {
                    structure: "passed",
                    wire_bit_offset: ue_offset + notify.payload_bit_offset,
                    reader: "CodeV 0x1064AC7EC",
                },
            }));
            messages.push(PacketMessage::UnrealPacket(UnrealPacketMessage {
                message_type: "unreal_packet",
                ack_id: notify.ack_raw,
                packet_id: notify.packet_raw,
                history_byte_count: notify.history_byte_count,
                bunch_count: unreal.bunches.len(),
                archive_bit_length: unreal.archive_bit_length,
            }));

            for (bunch_index, bunch) in unreal.bunches.iter().enumerate() {
                let data_wire_offset = ue_offset + bunch.data_bit_offset;
                layers.push(PacketLayer::Bunch(Layer {
                    name: "unreal_bunch_header",
                    fields: BunchFields {
                        bunch_index,
                        channel_index: bunch.channel_index,
                        control: bunch.control,
                        open: bunch.open,
                        close: bunch.close,
                        close_reason: bunch.close_reason,
                        dormant: bunch.dormant,
                        replication_paused: bunch.replication_paused,
                        reliable: bunch.reliable,
                        reliable_sequence_raw: bunch.reliable_sequence_raw,
                        partial: bunch.partial,
                        partial_initial: bunch.partial_initial,
                        partial_final: bunch.partial_final,
                        has_package_map_exports: bunch.has_package_map_exports,
                        has_must_be_mapped_guids: bunch.has_must_be_mapped_guids,
                        channel_name: bunch.channel_name.as_ref().map(channel_name),
                        data_bit_length: bunch.data_bit_length,
                    },
                    raw_hex: hex(&extract_lsb_bits(
                        &proof.handler.payload,
                        bunch.bit_offset,
                        bunch.header_bit_length,
                    )?),
                    consumed_bits: bunch.header_bit_length,
                    validation: ReaderValidation {
                        structure: "passed",
                        wire_bit_offset: ue_offset + bunch.bit_offset,
                        reader: "CodeV 0x1064AC7EC",
                    },
                }));
                let package = proof
                    .package_map_exports
                    .iter()
                    .find(|candidate| candidate.bunch_index == bunch_index);
                let (prefix_bits, bindings) = if let Some(package) = package {
                    if reencode_package_map_exports(&package.prefix)?
                        != extract_lsb_bits(&bunch.data, 0, package.prefix.bit_length)?
                    {
                        return Err(contract(frame, "PackageMap typed re-encode mismatch"));
                    }
                    let bindings =
                        package_bindings(&package.prefix.exports, bunch_index, bunch.channel_index);
                    let prefix_raw = extract_lsb_bits(&bunch.data, 0, package.prefix.bit_length)?;
                    layers.push(PacketLayer::PackageMap(Layer {
                        name: "unreal_package_map_exports",
                        fields: PackageMapFields {
                            bunch_index,
                            alternate_layout: package.prefix.alternate_layout,
                            export_count: package.prefix.export_count,
                            binding_count: bindings.len(),
                            bindings: bindings.clone(),
                        },
                        raw_hex: hex(&prefix_raw),
                        consumed_bits: package.prefix.bit_length,
                        validation: PackageMapValidation {
                            structure: "passed",
                            reencode: "exact",
                            wire_bit_offset: data_wire_offset,
                            reader: "CodeV 0x106500668 / 0x1064FB260",
                        },
                    }));
                    let tail_bits = bunch.data_bit_length - package.prefix.bit_length;
                    if tail_bits != 0 {
                        unknown_spans.push(UnknownSpan {
                            layer: "unreal_channel_payload",
                            bit_offset: data_wire_offset + package.prefix.bit_length,
                            bit_length: tail_bits,
                            raw_hex: hex(&extract_lsb_bits(
                                &bunch.data,
                                package.prefix.bit_length,
                                tail_bits,
                            )?),
                            reason: PACKAGE_MAP_TAIL_REASON.into(),
                        });
                    }
                    (Some(package.prefix.bit_length), Some(bindings))
                } else {
                    if bunch.data_bit_length != 0 {
                        unknown_spans.push(UnknownSpan {
                            layer: "unreal_channel_payload",
                            bit_offset: data_wire_offset,
                            bit_length: bunch.data_bit_length,
                            raw_hex: hex(&bunch.data),
                            reason: CHANNEL_PAYLOAD_REASON.into(),
                        });
                    }
                    (None, None)
                };
                messages.push(PacketMessage::Bunch(BunchMessage {
                    message_type: "unreal_bunch",
                    bunch_index,
                    channel_index: bunch.channel_index,
                    open: bunch.open,
                    close: bunch.close,
                    reliable: bunch.reliable,
                    reliable_sequence_raw: bunch.reliable_sequence_raw,
                    partial: bunch.partial,
                    partial_initial: bunch.partial_initial,
                    partial_final: bunch.partial_final,
                    has_package_map_exports: bunch.has_package_map_exports,
                    data_bit_offset: data_wire_offset,
                    data_bit_length: bunch.data_bit_length,
                    data_hex: hex(&bunch.data),
                    package_map_export_prefix_bits: prefix_bits,
                    package_map_bindings: bindings,
                }));
            }
            (
                if unreal.bunches.is_empty() {
                    "codev_unreal_ack_only_plaintext"
                } else {
                    "codev_unreal_bunches_plaintext"
                },
                Some(true),
                "unreal_channel_replication_or_rpc_payload",
            )
        } else {
            if proof.handler.payload_bit_length != 0 {
                unknown_spans.push(UnknownSpan {
                    layer: "packet_handler_non_passthrough_payload",
                    bit_offset: base_offset + proof.handler.header_bit_length,
                    bit_length: proof.handler.payload_bit_length,
                    raw_hex: hex(&proof.handler.payload),
                    reason: NON_PASS_THROUGH_REASON.into(),
                });
            }
            (
                "codev_packet_handler_non_passthrough_control_or_oodle",
                None,
                "packet_handler_non_passthrough_control_or_oodle",
            )
        };

    Ok(PacketRecord {
        packet_index: frame,
        timestamp: timestamp_seconds(captured.timestamp_ns),
        timestamp_iso: shanghai_iso(captured.timestamp_ns),
        direction,
        source: endpoint_text(transport.source),
        destination: endpoint_text(transport.destination),
        transport: "udp",
        wire_length: captured.original_length,
        payload_length: transport.payload.len(),
        payload_hex: hex(transport.payload),
        flow_id: format!(
            "udp:{}<->{}",
            endpoint_text(flow.key.endpoint_a),
            endpoint_text(flow.key.endpoint_b)
        ),
        classification,
        layers,
        messages,
        validation: PacketValidation {
            network_integrity: NetworkIntegrity {
                ipv4_header_checksum: integrity_status(integrity.ipv4_header_checksum),
                udp_checksum: integrity_status(integrity.udp_checksum),
                ipv4_header_checksum_value: integrity.ipv4_header_checksum_value,
                udp_checksum_value: integrity.udp_checksum_value,
                udp_checksum_reason: integrity.udp_checksum_reason,
            },
            reencode: "exact",
            decrypted: true,
            sgnet_cipher_status: "available_from_server_travel",
            sgnet_wire_reencode_exact: true,
            packet_handler_reencode_exact: true,
            unreal_reencode_exact: unreal_exact,
            unresolved_boundary,
            batch_sync: None,
        },
        unknown_spans,
        source_refs: [format!("pcap:frame:{frame}")],
    })
}

fn logical_bunches(
    unreal: &codev_stream::UnrealPacketEnvelope,
    proof: &codev_stream::PacketWireProof,
) -> Result<Vec<LogicalBunch>, CompatibilityPacketError> {
    unreal
        .bunches
        .iter()
        .enumerate()
        .map(|(bunch_index, bunch)| {
            let prefix_bits = proof
                .package_map_exports
                .iter()
                .find(|item| item.bunch_index == bunch_index)
                .map_or(0, |item| item.prefix.bit_length);
            let data_bit_length = bunch.data_bit_length - prefix_bits;
            Ok(LogicalBunch {
                bunch_index,
                channel_index: bunch.channel_index,
                open: bunch.open,
                partial: bunch.partial,
                partial_initial: bunch.partial_initial,
                partial_final: bunch.partial_final,
                reliable: bunch.reliable,
                reliable_sequence_raw: bunch.reliable_sequence_raw,
                data_bit_offset: bunch.data_bit_offset + prefix_bits,
                data_bit_length,
                data: extract_lsb_bits(&bunch.data, prefix_bits, data_bit_length)?,
            })
        })
        .collect()
}

fn append_batch_semantics(
    frame: u64,
    direction: &'static str,
    ue_wire_offset: usize,
    bunches: &[LogicalBunch],
    decoder: &mut D0Decoder,
    record: &mut PacketRecord,
    report: &mut ReportAccumulator,
) -> Result<(), CompatibilityPacketError> {
    for bunch in bunches {
        if direction != "server_to_client"
            || bunch.channel_index != BATCH_CHANNEL_INDEX
            || bunch.open
            || bunch.partial
        {
            continue;
        }
        let actor = decoder
            .decode_actor_message(&bunch.data, bunch.data_bit_length)
            .map_err(|source| CompatibilityPacketError::Batch { frame, source })?;
        if actor.summary.consumed_bits != bunch.data_bit_length {
            return Err(contract(
                frame,
                codev_obf::s("970f0c470e1d5deeb64e1947122156a0b1071c04082150a0b6011657132341a0bc1a0b0411264becb04e08451f224be1b1"),
            ));
        }
        if actor.properties.is_empty() {
            return Err(contract(frame, codev_obf::s("5ac767e0cab8ddd17b8672e0d684d69f70c760a3cc8484cf6ac963e6d09fcdda6b")));
        }
        let batch_properties = actor
            .properties
            .iter()
            .filter(|property| matches!(property.value, A0Value::BatchData(_)))
            .count();
        if batch_properties > 1 {
            return Err(contract(
                frame,
                codev_obf::s("970f0c470e1d5deeb64e1947122156a0bd0f0b040b3b48f4bc1e1441460c45f4b6063c45122f04f0a7010841143a4de5a6"),
            ));
        }
        let primary = actor
            .properties
            .iter()
            .find(|property| matches!(property.value, A0Value::BatchData(_)))
            .unwrap_or(&actor.properties[0]);
        let wire_data_offset = ue_wire_offset + bunch.data_bit_offset;
        replace_batch_unknown(
            record,
            wire_data_offset,
            bunch.data_bit_length,
            &bunch.data,
            &actor,
        )?;
        let descriptions = actor.properties.iter().map(property_description).collect();
        record.layers.push(PacketLayer::BatchActor(Layer {
            name: "codev_batch_sync_actor",
            fields: BatchActorFields {
                bunch_index: bunch.bunch_index,
                channel_index: BATCH_CHANNEL_INDEX,
                has_rep_layout: actor.summary.has_rep_layout,
                is_actor: actor.summary.is_actor,
                content_payload_bit_offset: actor.summary.content_payload_bit_offset,
                content_payload_bit_length: actor.summary.content_payload_bit_length,
                checksum_present: actor.summary.checksum_present,
                property_handle: primary.handle,
                property_count: actor.properties.len(),
                properties: descriptions,
                property_handle_bit_offset: primary.handle_bit_offset,
                property_handle_bit_length: primary.handle_bit_length,
                property_payload_bit_offset: primary.payload_bit_offset,
                property_payload_bit_length: primary.payload_bit_length,
                property_terminator: 0,
                property_terminator_bit_offset: actor.summary.property_terminator_bit_offset,
            },
            raw_hex: hex(&bunch.data),
            consumed_bits: actor.summary.consumed_bits,
            validation: BatchActorValidation {
                structure: "passed",
                exact_consumption: true,
                wire_bit_offset: wire_data_offset,
                property_payload_wire_bit_offset: wire_data_offset + primary.payload_bit_offset,
                reader: "CodeV 0x103AAA568 / 0x103AA6E60",
            },
        }));
        let batch_value = match primary.value {
            A0Value::BatchData(value) => Some(value),
            A0Value::RawTwoBits { .. } => None,
            _ => None,
        };
        let update_records = batch_value.map(|_| {
            actor
                .updates
                .iter()
                .map(|update| batch_update_record(update, wire_data_offset))
                .collect::<Vec<_>>()
        });
        let semantic_status = if batch_value.is_some() {
            "batch_movement_decoded"
        } else {
            "property_payload_unresolved"
        };
        record
            .messages
            .push(PacketMessage::Batch(BatchActorMessage {
                message_type: "codev_batch_sync_actor",
                bunch_index: bunch.bunch_index,
                channel_index: BATCH_CHANNEL_INDEX,
                wire_bit_offset: wire_data_offset,
                data_bit_length: bunch.data_bit_length,
                property_handle: primary.handle,
                property_count: actor.properties.len(),
                property_handles: actor
                    .properties
                    .iter()
                    .map(|property| property.handle)
                    .collect(),
                property_payload_bit_offset: primary.payload_bit_offset,
                property_payload_wire_bit_offset: wire_data_offset + primary.payload_bit_offset,
                property_payload_bit_length: primary.payload_bit_length,
                property_terminator: 0,
                bit_exact: true,
                semantic_status,
                character_count: batch_value.map(|value| value.character_count),
                present_slots: batch_value.map(|value| value.present_slots().collect()),
                update_count: update_records.as_ref().map(Vec::len),
                updates: update_records,
                identity_binding: batch_value.map(|_| "batch_slot_tracks_only_unresolved"),
            }));
        if let Some(batch_value) = batch_value {
            let present_slots = batch_value.present_slots().collect::<Vec<_>>();
            record.layers.push(PacketLayer::BatchProperty(Layer {
                name: "codev_batch_sync_property",
                fields: BatchPropertyFields {
                    property_handle: primary.handle,
                    character_count: batch_value.character_count,
                    present_slots,
                    update_count: actor.updates.len(),
                    identity_binding: "unresolved_batch_slot_N",
                },
                raw_hex: hex(&extract_lsb_bits(
                    &bunch.data,
                    primary.payload_bit_offset,
                    primary.payload_bit_length,
                )?),
                consumed_bits: primary.payload_bit_length,
                validation: BatchPropertyValidation {
                    structure: "passed",
                    exact_consumption: true,
                    wire_bit_offset: wire_data_offset + primary.payload_bit_offset,
                    reader: "CodeV 0x103AAA568",
                },
            }));
            let validation = record.validation.batch_sync.get_or_insert(BatchValidation {
                decoded_actor_messages: 0,
                character_updates: 0,
                exact_consumption: true,
            });
            validation.decoded_actor_messages += 1;
            validation.character_updates += actor.updates.len() as u64;
            report.batch_property_count += 1;
        }
        report.batch_actor_count += 1;
    }
    Ok(())
}

fn replace_batch_unknown(
    record: &mut PacketRecord,
    wire_data_offset: usize,
    data_bit_length: usize,
    data: &[u8],
    actor: &ActorMessage,
) -> Result<(), CompatibilityPacketError> {
    let matches = record
        .unknown_spans
        .iter()
        .enumerate()
        .filter(|(_, span)| {
            span.layer == "unreal_channel_payload"
                && span.bit_offset == wire_data_offset
                && span.bit_length == data_bit_length
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(contract(
            record.packet_index,
            codev_obf::f1("1665f85811e2a1393724fc5a00ddb7363024e15a0dd2b0323024f74659c4b63c3a6bfb5559c2a8363a77", matches.len()),
        ));
    }
    record.unknown_spans.remove(matches[0]);
    if let Some(unresolved) = actor
        .properties
        .iter()
        .find(|property| matches!(property.value, A0Value::RawTwoBits { .. }))
    {
        record.unknown_spans.push(UnknownSpan {
            layer: "codev_batch_sync_property_payload_unresolved",
            bit_offset: wire_data_offset + unresolved.payload_bit_offset,
            bit_length: unresolved.payload_bit_length,
            raw_hex: hex(&extract_lsb_bits(
                data,
                unresolved.payload_bit_offset,
                unresolved.payload_bit_length,
            )?),
            reason: format!(
                "channel 32 property handle {} is exact uint2 but its gameplay semantics are unresolved",
                unresolved.handle
            ),
        });
    }
    Ok(())
}

fn property_description(property: &A0Property) -> BatchPropertyDescription {
    BatchPropertyDescription {
        property_handle: property.handle,
        property_handle_bit_offset: property.handle_bit_offset,
        property_handle_bit_length: property.handle_bit_length,
        property_payload_bit_offset: property.payload_bit_offset,
        property_payload_bit_length: property.payload_bit_length,
        two_bit_value: match property.value {
            A0Value::RawTwoBits { raw } => Some(raw),
            A0Value::BatchData(_) => None,
            _ => None,
        },
        is_batch_data: matches!(property.value, A0Value::BatchData(_)),
    }
}

fn batch_update_record(update: &D0Update, wire_data_offset: usize) -> BatchUpdateRecord {
    BatchUpdateRecord {
        batch_slot: update.slot,
        track_id: format!("batch_slot_{}", update.slot),
        identity_binding: "unresolved",
        state_index: update.state_index,
        change_mask: update.change_mask,
        use_baseline: update.use_baseline,
        source_baseline: update.source_baseline,
        store_baseline: update.store_baseline,
        destination_baseline: update.destination_baseline,
        bit_offset: update.bit_offset,
        wire_bit_offset: wire_data_offset + update.bit_offset,
        bit_length: update.bit_length,
        position_changed: update.movement.is_some(),
        position: unit_vector(update.state.position),
        state: compatibility_state(update.state),
        movement: update
            .movement
            .map(|movement| compatibility_movement(movement, wire_data_offset)),
        extra_state: update.extra_state,
    }
}

fn unit_vector(value: codev_protocol::Vec3) -> UnitVector {
    UnitVector {
        x: value.x,
        y: value.y,
        z: value.z,
        unit: "Unreal_world_unit",
    }
}

fn compatibility_state(value: MovementState) -> CompatibilityState {
    CompatibilityState {
        position: value.position.as_array(),
        velocity: value.velocity.as_array(),
        acceleration: value.acceleration.as_array(),
        rotation_degrees: value.rotation_degrees.as_array(),
        movement_flags: value.movement_flags,
        has_movement_mode: value.has_movement_mode,
        movement_mode: value.movement_mode,
        delta_counter: value.delta_counter,
        minimal_word: value.minimal_word,
        extra_state: value.extra_state,
    }
}

fn compatibility_movement(value: MovementUpdate, wire_data_offset: usize) -> CompatibilityMovement {
    CompatibilityMovement {
        kind: match value.kind {
            MovementKind::Full => "full",
            MovementKind::Minimal => "minimal",
        },
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_offset + value.bit_offset,
        bit_length: value.bit_length,
        position: compatibility_vector(value.position, wire_data_offset),
        velocity: compatibility_vector(value.velocity, wire_data_offset),
        acceleration: value
            .acceleration
            .map(|field| compatibility_vector(field, wire_data_offset)),
        rotation: value
            .rotation
            .map(|field| compatibility_rotator(field, wire_data_offset)),
    }
}

fn compatibility_vector(value: VectorField, wire_data_offset: usize) -> CompatibilityVector {
    CompatibilityVector {
        x: value.value.x,
        y: value.value.y,
        z: value.value.z,
        unit: "Unreal_world_unit",
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_offset + value.bit_offset,
        bit_length: value.bit_length,
        quantization_decimals: value.quantization_decimals,
        absolute_xy: value.absolute_xy,
        xy_width: value.xy_width,
        z_width: value.z_width,
    }
}

fn compatibility_rotator(value: RotatorField, wire_data_offset: usize) -> CompatibilityRotator {
    CompatibilityRotator {
        degrees: value.value_degrees.as_array(),
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_offset + value.bit_offset,
        bit_length: value.bit_length,
    }
}

fn package_bindings(
    exports: &[codev_stream::NetGuidExport],
    bunch_index: usize,
    channel_index: u32,
) -> Vec<PackageMapBinding> {
    let mut bindings = Vec::new();
    for export in exports {
        collect_binding(export, bunch_index, channel_index, &mut bindings);
    }
    bindings
}

fn collect_binding(
    export: &codev_stream::NetGuidExport,
    bunch_index: usize,
    channel_index: u32,
    bindings: &mut Vec<PackageMapBinding>,
) {
    if let (Some(flags), Some(path)) = (export.flags, export.path.as_ref()) {
        bindings.push(PackageMapBinding {
            netguid: export.netguid,
            outer_netguid: export.outer.as_deref().map(|outer| outer.netguid),
            path: path.value.clone(),
            network_checksum: export.network_checksum,
            flags,
            bunch_index,
            channel_index,
        });
    }
    if let Some(outer) = export.outer.as_deref() {
        collect_binding(outer, bunch_index, channel_index, bindings);
    }
}

fn channel_name(name: &SerializedName) -> ChannelName {
    match name {
        SerializedName::HardCoded {
            comparison_index,
            bit_offset,
            bit_length,
        } => ChannelName {
            hard_coded: true,
            comparison_index: Some(*comparison_index),
            number: 0,
            string_value: None,
            string_encoding: None,
            string_raw_hex: None,
            raw_bit_offset: *bit_offset,
            raw_bit_length: *bit_length,
        },
        SerializedName::StringBacked {
            value,
            number,
            bit_offset,
            bit_length,
        } => ChannelName {
            hard_coded: false,
            comparison_index: None,
            number: *number,
            string_value: Some(value.value.clone()),
            string_encoding: Some(match value.encoding {
                FStringEncoding::Utf8 => "utf-8",
                FStringEncoding::Utf16Le => "utf-16-le",
            }),
            string_raw_hex: Some(hex(&value.raw)),
            raw_bit_offset: *bit_offset,
            raw_bit_length: *bit_length,
        },
    }
}

fn exact_coverage(
    payload_bits: usize,
    record: &PacketRecord,
) -> Result<bool, CompatibilityPacketError> {
    // Reconstruct the known partition from typed layers. Batch actor ranges
    // replace their former channel-payload unknown span and exclude only the
    // explicit handle-5 unknown range.
    let mut intervals = record
        .unknown_spans
        .iter()
        .map(|span| (span.bit_offset, span.bit_offset + span.bit_length))
        .collect::<Vec<_>>();
    let base = if record.direction == "client_to_server" {
        80
    } else {
        0
    };
    if base != 0 {
        intervals.push((0, base));
    }
    for layer in &record.layers {
        match layer {
            PacketLayer::PacketHandler(value) => intervals.push((
                value.validation.wire_bit_offset,
                value.validation.wire_bit_offset + value.consumed_bits,
            )),
            PacketLayer::Notify(value) => intervals.push((
                value.validation.wire_bit_offset,
                value.validation.wire_bit_offset + value.consumed_bits,
            )),
            PacketLayer::PacketInfo(value) => intervals.push((
                value.validation.wire_bit_offset,
                value.validation.wire_bit_offset + value.consumed_bits,
            )),
            PacketLayer::Bunch(value) => intervals.push((
                value.validation.wire_bit_offset,
                value.validation.wire_bit_offset + value.consumed_bits,
            )),
            PacketLayer::PackageMap(value) => intervals.push((
                value.validation.wire_bit_offset,
                value.validation.wire_bit_offset + value.consumed_bits,
            )),
            PacketLayer::BatchActor(value) => {
                let start = value.validation.wire_bit_offset;
                let end = start + value.consumed_bits;
                let unknown = record.unknown_spans.iter().find(|span| {
                    span.layer == "codev_batch_sync_property_payload_unresolved"
                        && span.bit_offset >= start
                        && span.bit_offset + span.bit_length <= end
                });
                if let Some(unknown) = unknown {
                    if start < unknown.bit_offset {
                        intervals.push((start, unknown.bit_offset));
                    }
                    let unknown_end = unknown.bit_offset + unknown.bit_length;
                    if unknown_end < end {
                        intervals.push((unknown_end, end));
                    }
                } else {
                    intervals.push((start, end));
                }
            }
            PacketLayer::ClientOuter(_) | PacketLayer::SgNet(_) | PacketLayer::BatchProperty(_) => {
            }
        }
    }
    // Both nested and outer archive terminals, and any byte padding after the
    // outer marker, are independently known structural bits.
    let handler = record
        .layers
        .iter()
        .find_map(|layer| match layer {
            PacketLayer::PacketHandler(value) => Some(value),
            _ => None,
        })
        .ok_or_else(|| contract(record.packet_index, codev_obf::s("a6c74242de5219209bcf525ad2483661a5ca5d54c51c1261b2cb43")))?;
    let outer_terminal = base + handler.fields.archive_bit_length;
    intervals.push((outer_terminal, payload_bits));
    if let Some(unreal) = record.layers.iter().find_map(|layer| match layer {
        PacketLayer::Notify(value) => Some(value.validation.wire_bit_offset),
        _ => None,
    }) {
        // The UE terminal is immediately before the PacketHandler outer
        // terminal because the handler payload includes the nested archive.
        intervals.push((outer_terminal - 1, outer_terminal));
        let _ = unreal;
    }
    intervals.sort_unstable();
    let mut cursor = 0;
    for (start, end) in intervals {
        if start != cursor || end < start {
            return Ok(false);
        }
        cursor = end;
    }
    Ok(cursor == payload_bits)
}

fn connection_phase(value: u16) -> &'static str {
    match value {
        0x8841 => "observed_initial_connection_id_ciphertext",
        0xaf57 => "observed_later_connection_id_ciphertext",
        _ => "unknown",
    }
}

fn integrity_status(value: IntegrityStatus) -> &'static str {
    match value {
        IntegrityStatus::Valid => "valid",
        IntegrityStatus::Invalid => "invalid",
        IntegrityStatus::OffloadSeed => "offload_seed",
        IntegrityStatus::Disabled => "disabled",
        IntegrityStatus::NotApplicable => "not_applicable",
        IntegrityStatus::NotValidated => "not_validated",
    }
}

fn timestamp_seconds(timestamp_ns: u64) -> f64 {
    (timestamp_ns / 1_000_000_000) as f64 + (timestamp_ns % 1_000_000_000) as f64 / 1_000_000_000.0
}

fn contract(frame: u64, detail: impl Into<String>) -> CompatibilityPacketError {
    CompatibilityPacketError::Contract {
        frame,
        detail: detail.into(),
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_stream::{discover_primary_udp_flow, recover_enter_game_session_from_classic_pcap};
    use std::fs::File;
    use std::io::{BufReader, Read};

    #[test]
    fn python_line_formatter_matches_json_dumps_separators() {
        #[derive(Serialize)]
        struct Row<'a> {
            a: [u8; 2],
            b: &'a str,
        }
        let mut output = Vec::new();
        write_python_json_line(&mut output, &Row { a: [1, 2], b: "x" }).unwrap();
        assert_eq!(output, b"{\"a\": [1, 2], \"b\": \"x\"}\n");
    }

    #[test]
    fn packet_pair_install_restores_both_previous_files_on_second_rename_failure() {
        let output = std::env::temp_dir().join(format!(
            "codev-packet-rollback-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&output).unwrap();
        fs::write(output.join("packets.jsonl"), b"old packets\n").unwrap();
        fs::write(output.join("unresolved.jsonl"), b"old unresolved\n").unwrap();
        let pair = AtomicArtifactPair::new(&output);
        fs::write(&pair.packet_temp, b"new packets\n").unwrap();
        fs::write(&pair.unresolved_temp, b"new unresolved\n").unwrap();
        fs::remove_file(&pair.unresolved_temp).unwrap();
        assert!(pair.commit(&output).is_err());
        assert_eq!(
            fs::read(output.join("packets.jsonl")).unwrap(),
            b"old packets\n"
        );
        assert_eq!(
            fs::read(output.join("unresolved.jsonl")).unwrap(),
            b"old unresolved\n"
        );
        fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn private_full_capture_matches_v2_packet_and_unresolved_bytes() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        let oracle = root.join("work/oracle-v2-full-20260815-session");
        if !pcap.is_file() || !oracle.join("packets.jsonl").is_file() {
            return;
        }
        let recovered = recover_enter_game_session_from_classic_pcap(&pcap).unwrap();
        let cipher =
            C0Cipher::from_packet_key(&recovered.session.packet_key, recovered.session.g0_id);
        let mut discovery = S0PcapSource::open(&pcap).unwrap();
        let flow = discover_primary_udp_flow(&mut discovery).unwrap();
        let output =
            std::env::temp_dir().join(format!("codev-packets-v2-{:032x}", rand::random::<u128>()));
        fs::create_dir(&output).unwrap();
        let report = write_compatibility_packet_artifacts(&pcap, &cipher, flow, &output).unwrap();
        assert_eq!(report.packet_count, 12_414);
        assert_eq!(report.unresolved_span_count, 15_319);
        assert_eq!(report.bunch_count, 20_360);
        assert_eq!(report.partial_payloads_completed, 512);
        assert_eq!(report.partial_fragment_count, 1_047);
        assert_eq!(report.partial_duplicate_fragments, 0);
        assert_eq!(
            report.partial_fragments_per_payload,
            BTreeMap::from([("2".into(), 495), ("3".into(), 15), ("6".into(), 2)])
        );
        assert_eq!(report.partial_total_reassembled_bits, 480_283);
        assert_eq!(
            report.flag_one_raw_size_distribution,
            BTreeMap::from([("1".into(), 3), ("3".into(), 1)])
        );
        assert_eq!(report.client_watermark_counter.count, 6_845);
        assert_eq!(report.client_watermark_counter.first, Some(874_695_872));
        assert_eq!(report.client_watermark_counter.last, Some(874_702_716));
        assert!(report.client_watermark_counter.gaps.is_empty());
        assert_eq!(report.client_watermark_crc32c_tested, 6_845);
        assert_eq!(report.client_watermark_crc32c_validated, 6_845);
        assert!(report.client_to_server.duplicate_packet_ids.is_empty());
        assert!(report.server_to_client.duplicate_packet_ids.is_empty());
        assert_eq!(report.client_to_server.network_integrity["valid"], 6_845);
        assert_eq!(
            report.client_to_server.network_integrity["udp:offload_seed"],
            6_845
        );
        assert_eq!(report.server_to_client.network_integrity["valid"], 5_569);
        assert_eq!(
            report.server_to_client.network_integrity["udp:valid"],
            5_569
        );
        assert_eq!(
            report.client_watermark_counter_low14_relation.matches,
            6_843
        );
        assert_eq!(report.ack_recent_peer_match.client_to_server.matched, 6_841);
        assert_eq!(report.ack_recent_peer_match.server_to_client.matched, 5_566);
        assert_eq!(report.batch_actor_count, 4_444);
        assert_eq!(report.batch_property_count, 4_442);
        assert_eq!(
            report.packets_sha256,
            "5c42e45834fa21c47f7b4150c7cf145b82afbb289e15d70b1556910cca9a95a5"
        );
        assert_eq!(
            report.unresolved_sha256,
            "370111029a7592ce11ccf37b0990465896077a72aa00a749d21db85db5fa0954"
        );
        assert!(files_equal(
            &output.join("packets.jsonl"),
            &oracle.join("packets.jsonl")
        ));
        assert!(files_equal(
            &output.join("unresolved.jsonl"),
            &oracle.join("unresolved.jsonl")
        ));
        fs::remove_dir_all(output).unwrap();
    }

    fn files_equal(left: &Path, right: &Path) -> bool {
        let mut left = BufReader::with_capacity(1024 * 1024, File::open(left).unwrap());
        let mut right = BufReader::with_capacity(1024 * 1024, File::open(right).unwrap());
        let mut left_buffer = [0_u8; 64 * 1024];
        let mut right_buffer = [0_u8; 64 * 1024];
        loop {
            let left_count = left.read(&mut left_buffer).unwrap();
            let right_count = right.read(&mut right_buffer).unwrap();
            if left_count != right_count || left_buffer[..left_count] != right_buffer[..right_count]
            {
                return false;
            }
            if left_count == 0 {
                return true;
            }
        }
    }
}
