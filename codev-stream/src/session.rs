//! Strict SGNet -> PacketHandler -> Unreal -> dynamic BatchSync channel decoder.
//!
//! This module deliberately implements only the wire shape proven for CodeV
//! 1.24.0.2911.  PacketHandler pass-through packets are decoded incrementally;
//! Oodle packets are counted and stopped at the compression boundary.  They
//! are never treated as Unreal plaintext.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::path::{Path, PathBuf};

use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use codev_protocol::{A0Property, A0Summary, D0Decoder, D0Update, DecodeError, DecodeScratch};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::session_acl::enforce_private_permissions;
use crate::{
    CampAssignment, Direction, Endpoint, IpAddress, PacketError, PacketSource,
    PartialBunchAssembler, PartialError, PartialFragment, PartialKey, ReorderError, ReorderOutput,
    RoundCampClassifier, S0PcapSource, SequenceReorderBuffer, SourceError, TransportKind,
    TransportPacket, parse_transport,
};

pub const SUPPORTED_BUILD: &str = "1.24.0.2911";
pub const SGNET_CLIENT_PREFIX_BYTES: usize = 10;
pub const SGNET_CHACHA_COUNTER: u64 = 1;
pub const UNREAL_MAX_PACKET_BYTES: u32 = 1024;
pub const UNREAL_PACKET_SEQUENCE_MODULUS: u64 = 0x4000;
pub const UNREAL_RELIABLE_SEQUENCE_MODULUS: u64 = 1024;

const CHANNEL_CLOSE_REASON_COUNT: u32 = 15;
const HARD_CODED_NAME_MAX: u32 = 702;
const PACKET_INFO_MODULUS: u32 = 1024;
const MAX_BATCH_CHANNEL_CANDIDATES: usize = 512;
/// 诊断普查记录上限，避免长对局把内存吃光。
const MAX_CENSUS_RECORDS: usize = 400_000;
const MAX_PENDING_GAP_RECORDS: usize = 64;
const MAX_NETGUID_EXPORTS: u32 = 2048;
const MAX_NETGUID_OUTER_DEPTH: usize = 16;

/// Derived SGNet material.  Raw PacketKey/GameId values are not retained.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct C0Cipher {
    key: [u8; 32],
    nonce: [u8; 12],
}

impl C0Cipher {
    pub fn from_packet_key(packet_key: &str, g0_id: u64) -> Self {
        let key_seed = encryption_key_seed(packet_key);
        let nonce_seed = (g0_id as u32).wrapping_add(23_u32.wrapping_mul((g0_id >> 32) as u32));
        Self {
            key: derive_bytes::<32>(key_seed),
            nonce: derive_bytes::<12>(nonce_seed),
        }
    }

    fn crypt_copy_in_place(&self, bytes: &mut [u8]) {
        let mut cipher = ChaCha20::new((&self.key).into(), (&self.nonce).into());
        cipher.seek(SGNET_CHACHA_COUNTER * 64);
        cipher.apply_keystream(bytes);
    }

    pub fn crypt_client_datagram(&self, wire: &[u8]) -> Result<Vec<u8>, SessionError> {
        if wire.len() < SGNET_CLIENT_PREFIX_BYTES {
            return Err(SessionError::ClientDatagramTooShort(wire.len()));
        }
        let mut logical = wire.to_vec();
        self.crypt_copy_in_place(&mut logical[8..10]);
        self.crypt_copy_in_place(&mut logical[10..]);
        Ok(logical)
    }

    pub fn crypt_server_datagram(&self, wire: &[u8]) -> Vec<u8> {
        let mut logical = wire.to_vec();
        self.crypt_copy_in_place(&mut logical);
        logical
    }
}

/// Private, cold-path session loader.  It accepts the recovered schema and
/// common PacketKey/GameId spellings without serializing the values again.
pub struct PrivateSession {
    pub build: String,
    cipher: Option<C0Cipher>,
}

impl PrivateSession {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SessionError> {
        let path = path.as_ref();
        let file = open_private_session_file(path)?;
        let mut document: PrivateSessionDocument = serde_json::from_reader(file)?;
        let build = document
            .build
            .as_deref()
            .ok_or(SessionError::MissingBuild)?;
        if !build_matches(build) {
            document.session.packet_key.zeroize();
            return Err(SessionError::UnsupportedBuild(build.to_owned()));
        }
        let mut g0_id = document.session.g0_id.parse_and_zeroize()?;
        let cipher = C0Cipher::from_packet_key(&document.session.packet_key, g0_id);
        document.session.packet_key.zeroize();
        g0_id.zeroize();
        Ok(Self {
            build: document
                .build
                .take()
                .expect("the build was validated immediately above"),
            cipher: Some(cipher),
        })
    }

    pub fn into_cipher(mut self) -> C0Cipher {
        self.cipher
            .take()
            .expect("a loaded private session always owns derived cipher material")
    }
}

/// Open a private session file and validate the access controls on the exact
/// file handle that will be read.
///
/// On POSIX this preserves the existing rule that group/other permission bits
/// must be clear. On Windows the owner and every DACL entry are checked against
/// the current process user, inherited/unprotected ACLs are rejected, and the
/// current user must have explicit read rights.
pub fn open_private_session_file(path: impl AsRef<Path>) -> Result<File, SessionError> {
    let file = File::open(path)?;
    enforce_private_permissions(&file)?;
    Ok(file)
}

#[derive(Deserialize)]
struct PrivateSessionDocument {
    #[serde(default)]
    build: Option<String>,
    session: PrivateSessionFields,
}

struct PrivateSessionFields {
    packet_key: String,
    g0_id: GameIdValue,
}

impl<'de> Deserialize<'de> for PrivateSessionFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let packet_key = take_aliased_string(&mut map, &codev_conceal::session_key_aliases())
            .ok_or_else(|| de::Error::custom("missing session key"))?;
        let g0_id = take_aliased_value(
            &mut map,
            &[
                codev_conceal::game_id_snake(),
                codev_conceal::game_id_camel(),
                codev_conceal::g0_id(),
                codev_conceal::game_id_upper(),
            ],
        )
        .ok_or_else(|| de::Error::custom("missing game id"))?;
        let g0_id = serde_json::from_value(g0_id).map_err(de::Error::custom)?;
        Ok(Self { packet_key, g0_id })
    }
}

fn take_aliased_value(
    map: &mut serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<serde_json::Value> {
    names.iter().find_map(|name| map.remove(*name))
}

fn take_aliased_string(
    map: &mut serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    take_aliased_value(map, names).and_then(|value| match value {
        serde_json::Value::String(text) => Some(text),
        _ => None,
    })
}

impl Drop for PrivateSessionFields {
    fn drop(&mut self) {
        self.packet_key.zeroize();
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GameIdValue {
    Integer(u64),
    Text(String),
}

impl Drop for GameIdValue {
    fn drop(&mut self) {
        match self {
            Self::Integer(value) => value.zeroize(),
            Self::Text(value) => value.zeroize(),
        }
    }
}

impl GameIdValue {
    fn parse_and_zeroize(&mut self) -> Result<u64, SessionError> {
        match self {
            Self::Integer(value) => Ok(*value),
            Self::Text(value) => {
                let trimmed = value.trim();
                let parsed = if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16).map_err(|_| SessionError::InvalidGameId)
                } else {
                    trimmed.parse().map_err(|_| SessionError::InvalidGameId)
                };
                value.zeroize();
                parsed
            }
        }
    }
}

fn build_matches(value: &str) -> bool {
    matches!(value.trim(), "1.24.0.2911" | "1.24.0 (2911)")
}

fn encryption_key_seed(value: &str) -> u32 {
    let mut crc = 0_u32;
    for mut unit in value.encode_utf16() {
        if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
            unit -= 0x20;
        }
        for byte in [unit as u8, (unit >> 8) as u8] {
            crc = crc_table_entry((crc as u8) ^ byte) ^ (crc >> 8);
        }
    }
    crc
}

fn crc_table_entry(index: u8) -> u32 {
    let mut value = u32::from(index) << 24;
    for _ in 0..8 {
        value = (value << 1)
            ^ if value & 0x8000_0000 != 0 {
                0x04c1_1db7
            } else {
                0
            };
    }
    value
}

fn park_miller_step(seed: u32) -> u32 {
    let signed = seed as i32;
    let quotient = signed / 127_773;
    let remainder = signed - quotient * 127_773;
    let candidate = 16_807_i32
        .wrapping_mul(remainder)
        .wrapping_sub(2_836_i32.wrapping_mul(quotient));
    if candidate > 0 {
        candidate as u32
    } else {
        candidate.wrapping_add(0x7fff_ffff) as u32
    }
}

fn derive_bytes<const N: usize>(seed: u32) -> [u8; N] {
    let mut state = seed;
    let mut output = [0_u8; N];
    for byte in &mut output {
        state = park_miller_step(state);
        *byte = (state ^ (state >> 8) ^ (state >> 16) ^ (state >> 24)) as u8;
    }
    output
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UdpFlowKey {
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
}

impl UdpFlowKey {
    pub fn new(left: Endpoint, right: Endpoint) -> Self {
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

    pub fn contains(self, source: Endpoint, destination: Endpoint) -> bool {
        Self::new(source, destination) == self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedUdpFlow {
    pub key: UdpFlowKey,
    pub client: Endpoint,
    pub server: Endpoint,
    pub packet_count: u64,
    pub payload_bytes: u64,
}

impl SelectedUdpFlow {
    /// Construct an explicit flow selector.  Packet/byte counts are populated
    /// from the PCAP during validation before decoding begins.
    pub fn for_endpoints(client: Endpoint, server: Endpoint) -> Self {
        Self {
            key: UdpFlowKey::new(client, server),
            client,
            server,
            packet_count: 0,
            payload_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Default)]
struct FlowCount {
    packets: u64,
    payload_bytes: u64,
}

pub fn discover_primary_udp_flow<S: PacketSource>(
    source: &mut S,
) -> Result<SelectedUdpFlow, SessionError> {
    let flows = collect_udp_flows(source)?;
    select_udp_flow(flows, None)
}

fn collect_udp_flows<S: PacketSource>(
    source: &mut S,
) -> Result<HashMap<UdpFlowKey, FlowCount>, SessionError> {
    let mut flows: HashMap<UdpFlowKey, FlowCount> = HashMap::new();
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if transport.kind != TransportKind::Udp {
            continue;
        }
        let key = UdpFlowKey::new(transport.source, transport.destination);
        let count = flows.entry(key).or_default();
        count.packets += 1;
        count.payload_bytes = count
            .payload_bytes
            .saturating_add(transport.payload.len() as u64);
    }
    Ok(flows)
}

fn select_udp_flow(
    flows: HashMap<UdpFlowKey, FlowCount>,
    requested: Option<SelectedUdpFlow>,
) -> Result<SelectedUdpFlow, SessionError> {
    let (key, client, server, count) = if let Some(requested) = requested {
        if requested.client == requested.server
            || UdpFlowKey::new(requested.client, requested.server) != requested.key
        {
            return Err(SessionError::InvalidSelectedUdpFlow);
        }
        let count = flows
            .get(&requested.key)
            .copied()
            .ok_or(SessionError::SelectedUdpFlowNotFound)?;
        (requested.key, requested.client, requested.server, count)
    } else {
        let (key, count) = flows
            .into_iter()
            .min_by(|(left_key, left), (right_key, right)| {
                right
                    .packets
                    .cmp(&left.packets)
                    .then_with(|| right.payload_bytes.cmp(&left.payload_bytes))
                    .then_with(|| flow_cmp(left_key, right_key))
            })
            .ok_or(SessionError::NoUdpFlow)?;
        let (client, server) = infer_client_server(key);
        (key, client, server, count)
    };
    Ok(SelectedUdpFlow {
        key,
        client,
        server,
        packet_count: count.packets,
        payload_bytes: count.payload_bytes,
    })
}

fn infer_client_server(flow: UdpFlowKey) -> (Endpoint, Endpoint) {
    let left_private = is_private(flow.endpoint_a.ip);
    let right_private = is_private(flow.endpoint_b.ip);
    if left_private != right_private {
        if left_private {
            (flow.endpoint_a, flow.endpoint_b)
        } else {
            (flow.endpoint_b, flow.endpoint_a)
        }
    } else if flow.endpoint_a.port > flow.endpoint_b.port {
        (flow.endpoint_a, flow.endpoint_b)
    } else {
        (flow.endpoint_b, flow.endpoint_a)
    }
}

fn is_private(address: IpAddress) -> bool {
    match address {
        IpAddress::V4(bytes) => std::net::Ipv4Addr::from(bytes).is_private(),
        IpAddress::V6(bytes) => std::net::Ipv6Addr::from(bytes).is_unique_local(),
    }
}

fn flow_cmp(left: &UdpFlowKey, right: &UdpFlowKey) -> Ordering {
    endpoint_cmp(&left.endpoint_a, &right.endpoint_a)
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipelineStats {
    pub datagrams: u64,
    pub sgnet_decrypted: u64,
    pub sgnet_wire_reencode_exact: u64,
    pub packet_handler_envelopes_exact: u64,
    pub packet_handler_pass_through: u64,
    pub oodle_compressed: u64,
    pub unreal_packets: u64,
    pub unreal_packets_exact: u64,
    pub bunches: u64,
    pub package_map_export_prefixes_exact: u64,
    pub netguid_records: u64,
    pub duplicate_packets: u64,
    pub stale_packets: u64,
    pub sequence_gaps: u64,
    pub capture_gaps: u64,
    pub dropped_gap_records: u64,
    pub partial_fragments: u64,
    pub partial_payloads_completed: u64,
    pub actor_messages: u64,
    pub batch_properties: u64,
    pub raw_two_bit_properties: u64,
    pub character_updates: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PipelineGapReason {
    Sequence,
    CaptureDrop,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PipelineGap {
    pub reason: PipelineGapReason,
    pub direction: Option<Direction>,
    pub first_missing: Option<u64>,
    pub last_missing: Option<u64>,
    pub resumed_at: Option<u64>,
    pub detected_ns: u64,
}

#[derive(Clone, Debug)]
pub struct A0Payload {
    pub direction: Direction,
    pub capture_index: u64,
    pub timestamp_ns: u64,
    pub packet_sequence: u64,
    pub channel_index: u32,
    pub channel_generation: u64,
    pub source_capture_indices: Vec<u64>,
    /// Zero-based bunch index inside the source Unreal packet. Reassembled
    /// partial payloads have no single compatible bunch index.
    pub bunch_index: Option<usize>,
    /// Bit offset of actor data in the SGNet UDP payload used by the legacy
    /// compatibility artifacts. It is absent for reassembled partial data.
    pub wire_data_bit_offset: Option<usize>,
    pub data: Vec<u8>,
    pub bit_length: usize,
    pub summary: A0Summary,
    pub properties: Vec<A0Property>,
    pub updates: Vec<D0Update>,
    /// Fail-closed camp groups bound from proven player-character actor
    /// spawns. Camp 1 is the local five-person group; camp 2 is the remote
    /// five-person group. Unclassified origin/proxy/ability slots are absent.
    pub camp_assignments: Vec<CampAssignment>,
    /// 本机自己那个角色的出生点（本包内第一个 open 的玩家角色）。`None` 表示还没看到 open。
    pub local_anchor_spawn: Option<[f64; 3]>,
}

#[derive(Clone, Debug, Default)]
struct ChannelState {
    generation: u64,
    lifecycle_observed: bool,
    open: bool,
    open_signature: Option<OpenSignature>,
    reliable_reference: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OpenSignature {
    reliable_sequence_raw: u16,
    close: bool,
    partial: bool,
    partial_initial: bool,
    partial_final: bool,
    package_map_export_prefix_parsed: bool,
    netguid_record_count: u32,
    data_bit_length: usize,
    wire_data_sha256: [u8; 32],
}

impl OpenSignature {
    fn from_bunch(bunch: &UnrealBunch) -> Option<Self> {
        Some(Self {
            reliable_sequence_raw: bunch.reliable_sequence_raw?,
            close: bunch.close,
            partial: bunch.partial,
            partial_initial: bunch.partial_initial,
            partial_final: bunch.partial_final,
            package_map_export_prefix_parsed: bunch.package_map_export_prefix_parsed,
            netguid_record_count: bunch.netguid_record_count,
            data_bit_length: bunch.data_bit_length,
            wire_data_sha256: bunch.wire_data_sha256,
        })
    }
}

#[derive(Clone, Debug)]
struct UnrealBunch {
    channel_index: u32,
    open: bool,
    close: bool,
    reliable_sequence_raw: Option<u16>,
    partial: bool,
    partial_initial: bool,
    partial_final: bool,
    package_map_export_prefix_parsed: bool,
    netguid_record_count: u32,
    wire_data_sha256: [u8; 32],
    data_bit_offset: usize,
    data: Vec<u8>,
    data_bit_length: usize,
}

#[derive(Clone, Debug)]
struct UnrealDatagram {
    direction: Direction,
    capture_index: u64,
    timestamp_ns: u64,
    ue_wire_bit_offset: usize,
    bunches: Vec<UnrealBunch>,
}

#[derive(Clone, Debug)]
struct PartialMetadata {
    direction: Direction,
    capture_index: u64,
    timestamp_ns: u64,
    packet_sequence: u64,
    channel_index: u32,
    channel_generation: u64,
    open: bool,
    close: bool,
    source_capture_indices: Vec<u64>,
}

pub struct P0Pipeline {
    cipher: C0Cipher,
    client: Endpoint,
    server: Endpoint,
    client_reorder: SequenceReorderBuffer<UnrealDatagram>,
    server_reorder: SequenceReorderBuffer<UnrealDatagram>,
    partials: PartialBunchAssembler,
    partial_metadata: HashMap<PartialKey, PartialMetadata>,
    channels: HashMap<(Direction, u32), ChannelState>,
    batch_channel: Option<PartialKey>,
    batch_candidates: HashMap<PartialKey, D0Decoder>,
    batch: D0Decoder,
    camp_classifier: RoundCampClassifier,
    channel_census: BTreeMap<u32, ChannelCensus>,
    census_mode: bool,
    census_decoder: D0Decoder,
    census_scratch: DecodeScratch,
    handle_census: BTreeMap<u32, HandleCensusState>,
    census_records: Vec<CensusRecord>,
    census_scanned_messages: u64,
    census_decode_failures: u64,
    player_character_class_guids: HashSet<u32>,
    /// 第一个 open 的玩家角色（客户端本地 pawn 一定最先创建，netguid 最小）的出生点。
    /// 用来把"自己"钉到具体槽位：出生点和坐标流里某一槽的首次位置完全一致。
    local_anchor_spawn: Option<[f64; 3]>,
    scratch: DecodeScratch,
    stats: PipelineStats,
    gaps: VecDeque<PipelineGap>,
    last_timestamp_ns: u64,
}

impl P0Pipeline {
    /// Start a selected-flow decoder from a build-validated private session.
    pub fn from_private_session(
        session: PrivateSession,
        client: Endpoint,
        server: Endpoint,
    ) -> Self {
        Self::new(session.into_cipher(), client, server)
    }

    /// Start a selected-flow decoder from already-derived material.
    ///
    /// Callers using this low-level constructor are responsible for proving
    /// that the capture is build [`SUPPORTED_BUILD`].  Normal file-backed
    /// callers should prefer [`Self::from_private_session`].
    pub fn new(cipher: C0Cipher, client: Endpoint, server: Endpoint) -> Self {
        Self {
            cipher,
            client,
            server,
            client_reorder: SequenceReorderBuffer::default(),
            server_reorder: SequenceReorderBuffer::default(),
            partials: PartialBunchAssembler::default(),
            partial_metadata: HashMap::new(),
            channels: HashMap::new(),
            batch_channel: None,
            batch_candidates: HashMap::new(),
            batch: D0Decoder::new(),
            camp_classifier: RoundCampClassifier::default(),
            channel_census: BTreeMap::new(),
            census_mode: false,
            census_decoder: D0Decoder::new(),
            census_scratch: DecodeScratch::with_capacity(4, 16),
            handle_census: BTreeMap::new(),
            census_records: Vec::new(),
            census_scanned_messages: 0,
            census_decode_failures: 0,
            player_character_class_guids: HashSet::new(),
            local_anchor_spawn: None,
            scratch: DecodeScratch::with_capacity(2, 16),
            stats: PipelineStats::default(),
            gaps: VecDeque::with_capacity(MAX_PENDING_GAP_RECORDS),
            last_timestamp_ns: 0,
        }
    }

    pub const fn client(&self) -> Endpoint {
        self.client
    }

    pub const fn server(&self) -> Endpoint {
        self.server
    }

    pub const fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// The server-to-client Unreal channel generation proven to carry
    /// BatchData for this live session. Channel indices are allocated at
    /// runtime and are not stable between matches.
    pub const fn batch_channel(&self) -> Option<(u32, u64)> {
        match self.batch_channel {
            Some(key) => Some((key.channel_index, key.channel_generation)),
            None => None,
        }
    }

    pub const fn latest_timestamp_ns(&self) -> Option<u64> {
        if self.stats.datagrams == 0 {
            None
        } else {
            Some(self.last_timestamp_ns)
        }
    }

    /// Drain sequence gaps not yet consumed by the event sink.  The internal
    /// queue is capped at 64 records; any overwritten records are reflected
    /// in [`PipelineStats::dropped_gap_records`].
    pub fn drain_gaps(&mut self) -> Vec<PipelineGap> {
        self.gaps.drain(..).collect()
    }

    /// Mark a libpcap/Npcap drop counter increase or equivalent capture loss.
    ///
    /// Both packet reorder buffers are reset, so any buffered but unreleased
    /// datagrams are deliberately discarded and the next valid datagram in
    /// each direction establishes a fresh sequence reference.  Active partial
    /// chains and per-channel reliable references are cleared.  Channel
    /// generations are retained, while all BatchSync position/baseline
    /// validity is marked discontinuous until independently recoverable wire
    /// updates arrive.
    pub fn mark_capture_gap(&mut self, detected_ns: u64) {
        self.client_reorder.reset();
        self.server_reorder.reset();
        self.partials.invalidate_all();
        self.partial_metadata.clear();
        for state in self.channels.values_mut() {
            state.reliable_reference = None;
        }
        self.batch.mark_gap();
        self.batch_candidates.clear();
        self.stats.capture_gaps += 1;
        self.record_gap(PipelineGap {
            reason: PipelineGapReason::CaptureDrop,
            direction: None,
            first_missing: None,
            last_missing: None,
            resumed_at: None,
            detected_ns,
        });
    }

    pub fn push_transport(
        &mut self,
        transport: &TransportPacket<'_>,
    ) -> Result<Vec<A0Payload>, SessionError> {
        if transport.kind != TransportKind::Udp {
            return Ok(Vec::new());
        }
        let direction = if transport.source == self.client && transport.destination == self.server {
            Direction::ClientToServer
        } else if transport.source == self.server && transport.destination == self.client {
            Direction::ServerToClient
        } else {
            return Ok(Vec::new());
        };
        self.push_datagram(
            direction,
            transport.capture_index,
            transport.timestamp_ns,
            transport.payload,
        )
    }

    pub fn push_datagram(
        &mut self,
        direction: Direction,
        capture_index: u64,
        timestamp_ns: u64,
        wire: &[u8],
    ) -> Result<Vec<A0Payload>, SessionError> {
        self.stats.datagrams += 1;
        self.last_timestamp_ns = self.last_timestamp_ns.max(timestamp_ns);
        let logical = match direction {
            Direction::ClientToServer => self.cipher.crypt_client_datagram(wire)?,
            Direction::ServerToClient => self.cipher.crypt_server_datagram(wire),
        };
        self.stats.sgnet_decrypted += 1;
        let rebuilt = match direction {
            Direction::ClientToServer => self.cipher.crypt_client_datagram(&logical)?,
            Direction::ServerToClient => self.cipher.crypt_server_datagram(&logical),
        };
        if rebuilt != wire {
            return Err(SessionError::SgNetWireRoundTripMismatch);
        }
        self.stats.sgnet_wire_reencode_exact += 1;
        let inner = match direction {
            Direction::ClientToServer => &logical[SGNET_CLIENT_PREFIX_BYTES..],
            Direction::ServerToClient => &logical,
        };
        let wire_proof = crate::wire::prove_packet_handler_wire(inner)?;
        for package in &wire_proof.package_map_exports {
            for export in &package.prefix.exports {
                collect_player_character_class_guids(
                    export,
                    &mut self.player_character_class_guids,
                );
            }
        }
        let handler = parse_packet_handler(inner)?;
        self.stats.packet_handler_envelopes_exact += 1;
        let (ue_payload, handler_payload_bit_offset) = match handler {
            PacketHandlerPayload::PassThrough {
                payload,
                payload_bit_offset,
            } => {
                if !wire_proof.handler.pass_through() {
                    return Err(SessionError::WireParserDisagreement("P0 flag"));
                }
                self.stats.packet_handler_pass_through += 1;
                (payload, payload_bit_offset)
            }
            PacketHandlerPayload::Oodle { .. } => {
                if wire_proof.handler.pass_through() {
                    return Err(SessionError::WireParserDisagreement("P0 flag"));
                }
                self.stats.oodle_compressed += 1;
                self.invalidate_direction(direction);
                return Ok(Vec::new());
            }
        };
        let (packet_raw, bunches) = parse_unreal_packet(&ue_payload)?;
        let proof_ue_payload = crate::wire::packet_handler_payload(&wire_proof.handler)?;
        if proof_ue_payload != ue_payload {
            return Err(SessionError::WireParserDisagreement("P0 payload"));
        }
        let proof_unreal = wire_proof
            .unreal
            .as_ref()
            .ok_or(SessionError::WireParserDisagreement("P0 flag"))?;
        if proof_unreal.notify.packet_raw != packet_raw
            || proof_unreal.bunches.len() != bunches.len()
        {
            return Err(SessionError::WireParserDisagreement("U0 packet"));
        }
        let proven_export_prefixes = wire_proof.package_map_export_prefixes;
        let proven_netguid_records = wire_proof.netguid_records;
        let legacy_export_prefixes = bunches
            .iter()
            .filter(|bunch| bunch.package_map_export_prefix_parsed)
            .count() as u64;
        let legacy_netguid_records = bunches
            .iter()
            .map(|bunch| u64::from(bunch.netguid_record_count))
            .sum::<u64>();
        if proven_export_prefixes != legacy_export_prefixes
            || proven_netguid_records != legacy_netguid_records
        {
            return Err(SessionError::WireParserDisagreement("PackageMap export"));
        }
        self.stats.unreal_packets += 1;
        self.stats.unreal_packets_exact += 1;
        self.stats.bunches += bunches.len() as u64;
        self.stats.package_map_export_prefixes_exact += proven_export_prefixes;
        self.stats.netguid_records += proven_netguid_records;
        let fingerprint = fingerprint64(inner);
        let datagram = UnrealDatagram {
            direction,
            capture_index,
            timestamp_ns,
            ue_wire_bit_offset: match direction {
                Direction::ClientToServer => SGNET_CLIENT_PREFIX_BYTES * 8,
                Direction::ServerToClient => 0,
            } + handler_payload_bit_offset,
            bunches,
        };
        let output = match direction {
            Direction::ClientToServer => {
                self.client_reorder
                    .push(packet_raw, timestamp_ns, fingerprint, datagram)?
            }
            Direction::ServerToClient => {
                self.server_reorder
                    .push(packet_raw, timestamp_ns, fingerprint, datagram)?
            }
        };
        self.process_reorder_output(direction, timestamp_ns, output)
    }

    /// Release any sequence gap whose 50 ms deadline has expired.  Live
    /// callers should invoke this from their capture-loop timer even when no
    /// new datagram arrives.
    ///
    /// 空闲时不必 100Hz 调用本方法：先问 [`Self::next_reorder_deadline_ns`]，
    /// 没有期限就可以低频等待。
    pub fn next_reorder_deadline_ns(&self) -> Option<u64> {
        match (
            self.client_reorder.next_deadline_ns(),
            self.server_reorder.next_deadline_ns(),
        ) {
            (Some(client), Some(server)) => Some(client.min(server)),
            (Some(client), None) | (None, Some(client)) => Some(client),
            (None, None) => None,
        }
    }

    pub fn poll_timeout(&mut self, now_ns: u64) -> Result<Vec<A0Payload>, SessionError> {
        let client = self.client_reorder.poll_timeout(now_ns);
        let server = self.server_reorder.poll_timeout(now_ns);
        let mut actors = self.process_reorder_output(Direction::ClientToServer, now_ns, client)?;
        actors.extend(self.process_reorder_output(Direction::ServerToClient, now_ns, server)?);
        Ok(actors)
    }

    /// 打开宽容句柄普查（诊断用；会放松未知属性句柄的 fail-closed 行为）。
    pub fn enable_handle_census(&mut self) {
        self.census_mode = true;
        self.census_decoder.set_tolerant(true);
    }

    /// 逐条普查记录（诊断用）。
    pub fn census_records(&self) -> &[CensusRecord] {
        &self.census_records
    }

    /// 按出现次数降序返回未支持句柄统计。
    pub fn handle_census(&self) -> Vec<HandleCensus> {
        let mut entries: Vec<HandleCensus> = self
            .handle_census
            .iter()
            .map(|(handle, state)| HandleCensus {
                handle: *handle,
                occurrences: state.occurrences,
                channels_seen: state.channels.len() as u64,
                min_remaining_bits: state.min_remaining_bits,
                max_remaining_bits: state.max_remaining_bits,
                top_samples: {
                    let mut entries: Vec<((u8, u64), u64)> =
                        state.samples.iter().map(|(k, v)| (*k, *v)).collect();
                    entries.sort_by(|a, b| b.1.cmp(&a.1));
                    entries
                        .into_iter()
                        .take(8)
                        .map(|((width, value), count)| HandleSample {
                            value,
                            width,
                            count,
                        })
                        .collect()
                },
            })
            .collect();
        entries.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
        entries
    }

    /// 按 bunch 数降序返回通道普查结果。
    pub fn channel_census(&self) -> Vec<ChannelCensus> {
        let mut entries: Vec<ChannelCensus> = self
            .channel_census
            .iter()
            .map(|(channel_index, census)| ChannelCensus {
                channel_index: *channel_index,
                ..*census
            })
            .collect();
        entries.sort_by(|a, b| b.bunches.cmp(&a.bunches));
        entries
    }

    pub fn finish(&mut self) -> Result<Vec<A0Payload>, SessionError> {
        let mut actors = Vec::new();
        for direction in [Direction::ClientToServer, Direction::ServerToClient] {
            loop {
                let output = match direction {
                    Direction::ClientToServer => self.client_reorder.poll_timeout(u64::MAX),
                    Direction::ServerToClient => self.server_reorder.poll_timeout(u64::MAX),
                };
                let progressed = output.gap.is_some() || !output.released.is_empty();
                actors.extend(self.process_reorder_output(
                    direction,
                    self.last_timestamp_ns,
                    output,
                )?);
                if !progressed {
                    break;
                }
            }
        }
        if !self.partial_metadata.is_empty() {
            return Err(SessionError::UnterminatedPartialChains(
                self.partial_metadata.len(),
            ));
        }
        Ok(actors)
    }

    fn process_reorder_output(
        &mut self,
        direction: Direction,
        detected_ns: u64,
        output: ReorderOutput<UnrealDatagram>,
    ) -> Result<Vec<A0Payload>, SessionError> {
        if output.duplicate {
            self.stats.duplicate_packets += 1;
        }
        if output.stale {
            self.stats.stale_packets += 1;
        }
        if let Some(gap) = output.gap {
            self.stats.sequence_gaps += 1;
            self.record_gap(PipelineGap {
                reason: PipelineGapReason::Sequence,
                direction: Some(direction),
                first_missing: Some(gap.first_missing),
                last_missing: Some(gap.last_missing),
                resumed_at: Some(gap.resumed_at),
                detected_ns,
            });
            self.invalidate_direction(direction);
        }
        let mut actors = Vec::new();
        for sequenced in output.released {
            let packet_sequence = sequenced.unwrapped_sequence;
            debug_assert_eq!(sequenced.value.direction, direction);
            for (bunch_index, bunch) in sequenced.value.bunches.into_iter().enumerate() {
                self.process_bunch(
                    direction,
                    sequenced.value.capture_index,
                    sequenced.value.timestamp_ns,
                    packet_sequence,
                    bunch_index,
                    sequenced.value.ue_wire_bit_offset,
                    bunch,
                    &mut actors,
                )?;
            }
        }
        Ok(actors)
    }

    fn record_gap(&mut self, gap: PipelineGap) {
        if self.gaps.len() == MAX_PENDING_GAP_RECORDS {
            self.gaps.pop_front();
            self.stats.dropped_gap_records += 1;
        }
        self.gaps.push_back(gap);
    }

    #[allow(clippy::too_many_arguments)]
    fn process_bunch(
        &mut self,
        direction: Direction,
        capture_index: u64,
        timestamp_ns: u64,
        packet_sequence: u64,
        bunch_index: usize,
        ue_wire_bit_offset: usize,
        bunch: UnrealBunch,
        actors: &mut Vec<A0Payload>,
    ) -> Result<(), SessionError> {
        self.channel_census
            .entry(bunch.channel_index)
            .or_default()
            .bunches += 1;
        if bunch.open {
            if !self.open_channel(direction, bunch.channel_index, &bunch)? && !bunch.partial {
                self.channel_census
                    .entry(bunch.channel_index)
                    .or_default()
                    .dropped_unrecognized_open += 1;
                // Unreal may retransmit a reliable channel-open bunch in a
                // later packet with the same ChSequence. Its payload was
                // already applied to this generation. A retransmitted partial
                // open must still be reassembled with its following fragments
                // so they are consumed as one duplicate open message.
                return Ok(());
            }
        } else if self
            .channels
            .get(&(direction, bunch.channel_index))
            .is_some_and(|state| state.lifecycle_observed && !state.open)
        {
            self.channel_census
                .entry(bunch.channel_index)
                .or_default()
                .dropped_closed_channel_traffic += 1;
            // Once a close has been observed, traffic without a new open can
            // only belong to the closed generation (for example a delayed
            // reliable retransmission). Capture-start traffic remains
            // compatible because an unseen channel has no observed lifecycle.
            return Ok(());
        }
        let channel_generation = self
            .channels
            .entry((direction, bunch.channel_index))
            .or_default()
            .generation;
        let key = PartialKey {
            direction,
            channel_index: bunch.channel_index,
            channel_generation,
        };
        if bunch.partial {
            self.channel_census
                .entry(bunch.channel_index)
                .or_default()
                .pending_partial_fragments += 1;
            self.stats.partial_fragments += 1;
            let reliable_sequence =
                self.unwrap_reliable(direction, bunch.channel_index, bunch.reliable_sequence_raw);
            if bunch.partial_initial {
                // An exact reliable retransmission of the initial fragment is
                // ignored by the assembler. Keep the original capture/time
                // metadata instead of overwriting it with the duplicate.
                self.partial_metadata
                    .entry(key)
                    .or_insert_with(|| PartialMetadata {
                        direction,
                        capture_index,
                        timestamp_ns,
                        packet_sequence,
                        channel_index: bunch.channel_index,
                        channel_generation,
                        open: bunch.open,
                        close: bunch.close,
                        source_capture_indices: vec![capture_index],
                    });
            } else if let Some(metadata) = self.partial_metadata.get_mut(&key) {
                metadata.source_capture_indices.push(capture_index);
                metadata.close |= bunch.close;
            }
            let completed = self.partials.feed(PartialFragment {
                key,
                reliable_sequence,
                initial: bunch.partial_initial,
                final_fragment: bunch.partial_final,
                data: &bunch.data,
                bit_length: bunch.data_bit_length,
            });
            let completed = match completed {
                Ok(value) => value,
                // A PCAP may begin in the middle of a large Unreal bunch.
                // Drop that orphan continuation and keep decoding later
                // complete bunches; reliable gaps and malformed chains still
                // remain hard errors below.
                Err(PartialError::Orphan(_)) => {
                    self.partial_metadata.remove(&key);
                    return Ok(());
                }
                // 分析模式：抓包从半途开始时的"旧链没有 final"直接丢弃，继续解后面。
                Err(PartialError::OverlappingInitial(_)) if crate::partial::tolerate_overlapping_initial() => {
                    self.partial_metadata.remove(&key);
                    return Ok(());
                }
                Err(error) => {
                    self.partial_metadata.remove(&key);
                    return Err(error.into());
                }
            };
            if let Some(completed) = completed {
                self.stats.partial_payloads_completed += 1;
                let metadata = self
                    .partial_metadata
                    .remove(&key)
                    .ok_or(SessionError::MissingPartialMetadata(bunch.channel_index))?;
                self.process_complete_message(
                    metadata.direction,
                    metadata.capture_index,
                    metadata.timestamp_ns,
                    metadata.packet_sequence,
                    metadata.channel_index,
                    metadata.channel_generation,
                    metadata.open,
                    metadata.source_capture_indices,
                    None,
                    None,
                    completed.data,
                    completed.bit_length,
                    actors,
                )?;
                if metadata.close {
                    self.close_channel(direction, bunch.channel_index);
                }
            }
        } else {
            self.process_complete_message(
                direction,
                capture_index,
                timestamp_ns,
                packet_sequence,
                bunch.channel_index,
                channel_generation,
                bunch.open,
                vec![capture_index],
                Some(bunch_index),
                Some(ue_wire_bit_offset + bunch.data_bit_offset),
                bunch.data,
                bunch.data_bit_length,
                actors,
            )?;
            if bunch.close {
                self.close_channel(direction, bunch.channel_index);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn process_complete_message(
        &mut self,
        direction: Direction,
        capture_index: u64,
        timestamp_ns: u64,
        packet_sequence: u64,
        channel_index: u32,
        channel_generation: u64,
        open: bool,
        source_capture_indices: Vec<u64>,
        bunch_index: Option<usize>,
        wire_data_bit_offset: Option<usize>,
        data: Vec<u8>,
        bit_length: usize,
        actors: &mut Vec<A0Payload>,
    ) -> Result<(), SessionError> {
        if channel_generation > 0
            && self
                .channels
                .get(&(direction, channel_index))
                .is_some_and(|state| state.generation != channel_generation)
        {
            return Err(SessionError::StaleChannelGeneration(channel_generation));
        }
        if direction != Direction::ServerToClient {
            self.channel_census
                .entry(channel_index)
                .or_default()
                .dropped_not_server_to_client += 1;
            return Ok(());
        }
        if self.census_mode && !open {
            self.census_scanned_messages += 1;
            let mut scratch = std::mem::replace(
                &mut self.census_scratch,
                DecodeScratch::with_capacity(4, 16),
            );
            let outcome =
                self.census_decoder
                    .decode_actor_message_into(&data, bit_length, &mut scratch);
            match outcome {
                Ok(_) => {
                    for unknown in &scratch.unknown_handles {
                        if self.census_records.len() < MAX_CENSUS_RECORDS {
                            self.census_records.push(CensusRecord {
                                timestamp_ns,
                                channel_index,
                                handle: unknown.handle,
                                bit_offset: unknown.bit_offset,
                                remaining_bits: unknown.remaining_bits,
                                sample_bits: unknown.sample_bits,
                                sample_width: unknown.sample_width,
                                raw_window: unknown.raw_window,
                                raw_window_len: unknown.raw_window_len,
                            });
                        }
                        let state = self.handle_census.entry(unknown.handle).or_default();
                        state.occurrences += 1;
                        state.channels.insert(channel_index);
                        if unknown.sample_width > 0 {
                            *state
                                .samples
                                .entry((unknown.sample_width, unknown.sample_bits))
                                .or_default() += 1;
                        }
                        let bits = unknown.remaining_bits;
                        if state.occurrences == 1 {
                            state.min_remaining_bits = bits;
                            state.max_remaining_bits = bits;
                        } else {
                            state.min_remaining_bits = state.min_remaining_bits.min(bits);
                            state.max_remaining_bits = state.max_remaining_bits.max(bits);
                        }
                    }
                }
                Err(_) => self.census_decode_failures += 1,
            }
            self.census_scratch = scratch;
        }
        if open {
            self.channel_census
                .entry(channel_index)
                .or_default()
                .observed_channel_open += 1;
            if let Some((actor_guid, [x, y, z])) =
                parse_player_character_spawn(&data, bit_length, &self.player_character_class_guids)
            {
                if std::env::var_os("CODEV_PC_OPEN_HEX").is_some() {
                    let bytes = data.len().min(160);
                    eprintln!(
                        "[pc-open-hex] ch={channel_index} guid={actor_guid} bits={bit_length} hex={}",
                        data[..bytes]
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    );
                }
                if std::env::var_os("CODEV_CHAN_OPEN").is_some() {
                    eprintln!(
                        "[chan-open] ch={channel_index} capture={capture_index} actor_guid={actor_guid} pos=({x:.1},{y:.1},{z:.1}) PC"
                    );
                }
                self.camp_classifier
                    .observe_player_spawn(actor_guid, capture_index, x, y, z);
                if self.local_anchor_spawn.is_none() {
                    self.local_anchor_spawn = Some([x, y, z]);
                }
            } else if std::env::var_os("CODEV_CHAN_OPEN").is_some() {
                let actor_guid = codev_protocol::Lsb0Reader::new(&data, bit_length)
                    .ok()
                    .and_then(|mut reader| reader.serialize_int_packed().ok())
                    .unwrap_or(0);
                eprintln!(
                    "[chan-open] ch={channel_index} capture={capture_index} actor_guid={actor_guid} PC=no"
                );
            }
            return Ok(());
        }
        let key = PartialKey {
            direction,
            channel_index,
            channel_generation,
        };
        let summary = match self.batch_channel {
            Some(selected) if selected != key => {
                self.channel_census
                    .entry(channel_index)
                    .or_default()
                    .dropped_after_coordinate_channel_pinned += 1;
                return Ok(());
            }
            Some(_) => {
                self.batch
                    .decode_actor_message_into(&data, bit_length, &mut self.scratch)?
            }
            None => {
                if !self.batch_candidates.contains_key(&key)
                    && self.batch_candidates.len() >= MAX_BATCH_CHANNEL_CANDIDATES
                {
                    return Ok(());
                }
                let candidate = self
                    .batch_candidates
                    .entry(key)
                    .or_insert_with(D0Decoder::new);
                let summary =
                    match candidate.decode_actor_message_into(&data, bit_length, &mut self.scratch)
                    {
                        Ok(summary) => summary,
                        Err(_) => {
                            self.channel_census
                                .entry(channel_index)
                                .or_default()
                                .dropped_actor_decode_failed += 1;
                            return Ok(());
                        }
                    };
                // A raw handle-5 actor message is legal on many unrelated
                // channels. A completely validated handle-17 BatchData
                // property is the bounded, fail-closed proof that this is the
                // session's coordinate channel.
                if summary.batch_property_count == 0 {
                    self.channel_census
                        .entry(channel_index)
                        .or_default()
                        .dropped_without_batch_property += 1;
                    return Ok(());
                }
                self.batch = self
                    .batch_candidates
                    .remove(&key)
                    .expect("the decoded candidate was inserted above");
                self.batch_candidates.clear();
                self.batch_channel = Some(key);
                summary
            }
        };
        self.stats.actor_messages += 1;
        if let Some(path) = std::env::var_os("CODEV_RAW_DUMP")
            && self.census_scanned_messages < 4000
        {
            use std::io::Write;
            let bytes = data.len().min(512);
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
            {
                let _ = writeln!(
                    file,
                    "{},{},{},{}",
                    capture_index,
                    channel_index,
                    bit_length,
                    data[..bytes]
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
            }
        }
        {
            let entry = self.channel_census.entry(channel_index).or_default();
            entry.decoded_actor_messages += 1;
            entry.decoded_character_updates += self.scratch.updates.len() as u64;
        }
        self.stats.batch_properties += u64::from(summary.batch_property_count);
        self.stats.raw_two_bit_properties += u64::from(summary.raw_two_bit_property_count);
        self.stats.character_updates += self.scratch.updates.len() as u64;
        self.camp_classifier
            .observe(capture_index, &self.scratch.updates);
        actors.push(A0Payload {
            direction,
            capture_index,
            timestamp_ns,
            packet_sequence,
            channel_index,
            channel_generation,
            source_capture_indices,
            bunch_index,
            wire_data_bit_offset,
            data,
            bit_length,
            summary,
            properties: self.scratch.properties.clone(),
            updates: self.scratch.updates.clone(),
            camp_assignments: self.camp_classifier.assignments(),
            local_anchor_spawn: self.local_anchor_spawn,
        });
        Ok(())
    }

    /// Start a new observed channel generation. Returns `false` only for an
    /// exact reliable retransmission of the active generation's open bunch.
    fn open_channel(
        &mut self,
        direction: Direction,
        channel_index: u32,
        bunch: &UnrealBunch,
    ) -> Result<bool, SessionError> {
        let signature = OpenSignature::from_bunch(bunch);
        let old_key;
        {
            let state = self.channels.entry((direction, channel_index)).or_default();
            if state.lifecycle_observed && state.open {
                if signature.is_some() && state.open_signature == signature {
                    return Ok(false);
                }
                return Err(SessionError::OverlappingChannelOpen(channel_index));
            }
            old_key = PartialKey {
                direction,
                channel_index,
                channel_generation: state.generation,
            };
            state.generation = state.generation.saturating_add(1);
            state.lifecycle_observed = true;
            state.open = true;
            state.open_signature = signature;
            state.reliable_reference = bunch.reliable_sequence_raw.map(u64::from);
        }
        self.partials.invalidate(old_key);
        self.partial_metadata.remove(&old_key);
        self.batch_candidates.remove(&old_key);
        if self.batch_channel == Some(old_key) {
            self.batch_channel = None;
            self.batch.reset();
            self.camp_classifier.reset_slots();
        }
        Ok(true)
    }

    fn close_channel(&mut self, direction: Direction, channel_index: u32) {
        let state = self.channels.entry((direction, channel_index)).or_default();
        let key = PartialKey {
            direction,
            channel_index,
            channel_generation: state.generation,
        };
        self.partials.invalidate(key);
        self.partial_metadata.remove(&key);
        self.batch_candidates.remove(&key);
        state.lifecycle_observed = true;
        state.open = false;
        state.open_signature = None;
        state.reliable_reference = None;
        if self.batch_channel == Some(key) {
            self.batch_channel = None;
            self.batch.reset();
            self.camp_classifier.reset_slots();
        }
    }

    fn unwrap_reliable(
        &mut self,
        direction: Direction,
        channel_index: u32,
        raw: Option<u16>,
    ) -> Option<u16> {
        let raw = u64::from(raw?);
        let state = self.channels.entry((direction, channel_index)).or_default();
        let reference = state.reliable_reference.unwrap_or(raw);
        let candidate = unwrap_near(raw, reference, UNREAL_RELIABLE_SEQUENCE_MODULUS);
        state.reliable_reference = Some(reference.max(candidate));
        Some(candidate as u16)
    }

    fn invalidate_direction(&mut self, direction: Direction) {
        let keys: Vec<_> = self
            .partial_metadata
            .keys()
            .copied()
            .filter(|key| key.direction == direction)
            .collect();
        for key in keys {
            self.partials.invalidate(key);
            self.partial_metadata.remove(&key);
        }
        if direction == Direction::ServerToClient {
            self.batch.mark_gap();
            self.batch_candidates.clear();
        }
    }
}

#[derive(Clone, Debug)]
pub struct PipelineReport {
    pub pcap: PathBuf,
    pub flow: SelectedUdpFlow,
    pub stats: PipelineStats,
    /// 每个 Unreal channel 的收包与丢弃统计。用来回答"某个字段是不是
    /// 因为通道被判为非坐标通道而被整条丢弃"，而不是被解出来再筛掉。
    pub channel_census: Vec<ChannelCensus>,
    /// 宽容普查模式下扫到的未支持属性句柄统计（默认模式为空）。
    pub handle_census: Vec<HandleCensus>,
    /// 宽容普查模式下的逐条样本记录（默认模式为空）。
    pub census_records: Vec<CensusRecord>,
    /// 普查实际尝试解析的消息条数。
    pub census_scanned_messages: u64,
    /// 普查中连"开始解析"都失败的消息条数。
    pub census_decode_failures: u64,
}

/// 宽容普查模式下，每个"当前解码器不认识的属性句柄"的统计。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleCensus {
    pub handle: u32,
    /// 该句柄出现的消息条数。
    pub occurrences: u64,
    /// 见过该句柄的通道数。
    pub channels_seen: u64,
    pub min_remaining_bits: usize,
    pub max_remaining_bits: usize,
    /// 该句柄后面紧随位的高频取值（最多 8 个），用来判断数值形态：
    /// 例如血量会落在 0-150 且随受伤下降，枚举类则会集中在少数几个值。
    pub top_samples: Vec<HandleSample>,
}

/// 宽容普查模式下逐条记录的未支持句柄样本，用于时间序列分析。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CensusRecord {
    pub timestamp_ns: u64,
    pub channel_index: u32,
    pub handle: u32,
    pub bit_offset: usize,
    pub remaining_bits: usize,
    pub sample_bits: u64,
    pub sample_width: u8,
    pub raw_window: [u8; 8],
    pub raw_window_len: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleSample {
    pub value: u64,
    pub width: u8,
    pub count: u64,
}

#[derive(Default)]
struct HandleCensusState {
    occurrences: u64,
    min_remaining_bits: usize,
    max_remaining_bits: usize,
    channels: std::collections::BTreeSet<u32>,
    samples: std::collections::HashMap<(u8, u64), u64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelCensus {
    pub channel_index: u32,
    pub bunches: u64,
    /// 坐标通道确定后，其它通道的 bunch 直接返回，未做任何解析。
    pub dropped_after_coordinate_channel_pinned: u64,
    /// 打开签名不认识、非分片，直接跳过。
    pub dropped_unrecognized_open: u64,
    /// 按 actor 消息解析失败（例如遇到未支持的属性句柄）。
    pub dropped_actor_decode_failed: u64,
    /// 能解析出来，但没有任何 BatchData 属性，被判为非坐标通道。
    pub dropped_without_batch_property: u64,
    pub decoded_actor_messages: u64,
    pub decoded_character_updates: u64,
    /// 客户端发往服务器的方向，雷达用不到。
    pub dropped_not_server_to_client: u64,
    /// 通道 open 消息（只用于建通道，不含属性数据）。
    pub observed_channel_open: u64,
    /// 分片未收齐，等待后续分片。
    pub pending_partial_fragments: u64,
    /// 通道已关闭后的迟到重传。
    pub dropped_closed_channel_traffic: u64,
}

/// Decode the busiest UDP flow in a classic PCAP using two bounded passes.
/// Actor payloads are delivered immediately and are never hex/JSON encoded.
pub fn decode_classic_pcap_with<F>(
    pcap: impl AsRef<Path>,
    session: impl AsRef<Path>,
    actor_visitor: F,
) -> Result<PipelineReport, SessionError>
where
    F: FnMut(A0Payload) -> Result<(), SessionError>,
{
    let private = PrivateSession::load(session)?;
    decode_classic_pcap_with_cipher(pcap, private.into_cipher(), None, actor_visitor)
}

/// Decode a classic PCAP directly from in-memory SGNet material.
///
/// This is the no-temporary-file bridge for an MNA-derived PacketKey/GameId.
/// The cipher is consumed and zeroized on drop.  `selected_flow=None` chooses
/// the busiest UDP flow deterministically; an explicit flow is validated
/// against the first PCAP pass and its packet/byte counts are recomputed.
/// Actor payloads are streamed to the visitor during the second bounded pass.
/// Callers must have independently proven build [`SUPPORTED_BUILD`].
pub fn decode_classic_pcap_with_cipher<F>(
    pcap: impl AsRef<Path>,
    cipher: C0Cipher,
    selected_flow: Option<SelectedUdpFlow>,
    actor_visitor: F,
) -> Result<PipelineReport, SessionError>
where
    F: FnMut(A0Payload) -> Result<(), SessionError>,
{
    decode_classic_pcap_with_cipher_options(pcap, cipher, selected_flow, actor_visitor, false)
}

/// 与 [`decode_classic_pcap_with_cipher`] 相同，但可打开诊断用的宽容句柄普查。
pub fn decode_classic_pcap_with_cipher_options<F>(
    pcap: impl AsRef<Path>,
    cipher: C0Cipher,
    selected_flow: Option<SelectedUdpFlow>,
    mut actor_visitor: F,
    handle_census: bool,
) -> Result<PipelineReport, SessionError>
where
    F: FnMut(A0Payload) -> Result<(), SessionError>,
{
    let pcap = pcap.as_ref();
    let mut discovery = S0PcapSource::open(pcap)?;
    let flows = collect_udp_flows(&mut discovery)?;
    let flow = select_udp_flow(flows, selected_flow)?;
    let mut pipeline = P0Pipeline::new(cipher, flow.client, flow.server);
    if handle_census {
        pipeline.enable_handle_census();
    }
    let mut source = S0PcapSource::open(pcap)?;
    while let Some(packet) = source.next_packet()? {
        let transport = match parse_transport(&packet) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !flow.key.contains(transport.source, transport.destination) {
            continue;
        }
        for actor in pipeline.push_transport(&transport)? {
            actor_visitor(actor)?;
        }
    }
    for actor in pipeline.finish()? {
        actor_visitor(actor)?;
    }
    Ok(PipelineReport {
        pcap: pcap.to_owned(),
        flow,
        stats: pipeline.stats(),
        channel_census: pipeline.channel_census(),
        handle_census: pipeline.handle_census(),
        census_records: pipeline.census_records().to_vec(),
        census_scanned_messages: pipeline.census_scanned_messages,
        census_decode_failures: pipeline.census_decode_failures,
    })
}

enum PacketHandlerPayload {
    PassThrough {
        payload: Vec<u8>,
        payload_bit_offset: usize,
    },
    Oodle {
        _raw_size: u16,
    },
}

fn parse_packet_handler(data: &[u8]) -> Result<PacketHandlerPayload, SessionError> {
    let archive_bits = archive_bit_length(data)?;
    let mut reader = codev_protocol::Lsb0Reader::new(data, archive_bits)?;
    let compressed = reader.read_bit()?;
    if compressed {
        let raw_size = reader.serialize_int(1024)? + 1;
        return Ok(PacketHandlerPayload::Oodle {
            _raw_size: raw_size as u16,
        });
    }
    let payload_start = reader.position();
    let payload_bits = reader.bits_left();
    if payload_bits == 0 {
        return Err(SessionError::EmptyPacketHandlerPayload);
    }
    let payload = extract_lsb_bits(data, payload_start, payload_bits);
    if bit_at(&payload, payload_bits - 1) != 1 {
        return Err(SessionError::MissingNestedTerminal);
    }
    Ok(PacketHandlerPayload::PassThrough {
        payload,
        payload_bit_offset: payload_start,
    })
}

fn parse_unreal_packet(data: &[u8]) -> Result<(u16, Vec<UnrealBunch>), SessionError> {
    let archive_bits = archive_bit_length(data)?;
    let mut reader = codev_protocol::Lsb0Reader::new(data, archive_bits)?;
    let notify = reader.read_bits(32)?;
    let history_count = (notify & 0x0f) + 1;
    let packet_raw = ((notify >> 18) & 0x3fff) as u16;
    skip_bits(&mut reader, usize::try_from(history_count).unwrap() * 8)?;

    let has_packet_info = reader.read_bit()?;
    if has_packet_info {
        reader.serialize_int(PACKET_INFO_MODULUS)?;
        if reader.read_bit()? {
            reader.read_bits(8)?;
        }
    }

    let mut bunches = Vec::new();
    while reader.bits_left() != 0 {
        bunches.push(parse_unreal_bunch(data, &mut reader)?);
    }
    Ok((packet_raw, bunches))
}

fn parse_unreal_bunch(
    data: &[u8],
    reader: &mut codev_protocol::Lsb0Reader<'_>,
) -> Result<UnrealBunch, SessionError> {
    let channel_index = reader.serialize_int_packed()?;
    let control = reader.read_bit()?;
    let open = control && reader.read_bit()?;
    let close = control && reader.read_bit()?;
    if close {
        reader.serialize_int(CHANNEL_CLOSE_REASON_COUNT)?;
    }
    reader.read_bit()?; // replication paused
    let reliable = reader.read_bit()?;
    let has_package_map_exports = reader.read_bit()?;
    reader.read_bit()?; // must-be-mapped GUIDs
    let partial = reader.read_bit()?;
    let reliable_sequence_raw = reliable
        .then(|| reader.serialize_int(UNREAL_RELIABLE_SEQUENCE_MODULUS as u32))
        .transpose()?
        .map(|value| value as u16);
    let partial_initial = partial && reader.read_bit()?;
    let partial_final = partial && reader.read_bit()?;
    if open || reliable {
        parse_serialized_name(reader)?;
    }
    let data_bits = reader.serialize_int(8 * UNREAL_MAX_PACKET_BYTES)? as usize;
    let data_start = reader.position();
    skip_bits(reader, data_bits)?;
    let raw_data = extract_lsb_bits(data, data_start, data_bits);
    let wire_data_sha256 = Sha256::digest(&raw_data).into();
    let (prefix_bits, netguid_record_count) = if has_package_map_exports {
        parse_package_map_export_prefix(&raw_data, data_bits)?
    } else {
        (0, 0)
    };
    let logical_bits = data_bits - prefix_bits;
    Ok(UnrealBunch {
        channel_index,
        open,
        close,
        reliable_sequence_raw,
        partial,
        partial_initial,
        partial_final,
        package_map_export_prefix_parsed: has_package_map_exports,
        netguid_record_count,
        wire_data_sha256,
        data_bit_offset: data_start + prefix_bits,
        data: extract_lsb_bits(&raw_data, prefix_bits, logical_bits),
        data_bit_length: logical_bits,
    })
}

fn parse_package_map_export_prefix(
    data: &[u8],
    bit_length: usize,
) -> Result<(usize, u32), SessionError> {
    let mut reader = codev_protocol::Lsb0Reader::new(data, bit_length)?;
    if reader.read_bit()? {
        return Err(SessionError::AlternatePackageMapLayout);
    }
    let count = reader.read_bits(32)?;
    if count > MAX_NETGUID_EXPORTS {
        return Err(SessionError::NetGuidExportCount(count));
    }
    let mut records = 0_u32;
    for _ in 0..count {
        parse_netguid_export(&mut reader, 0, &mut records)?;
    }
    Ok((reader.position(), records))
}

fn parse_netguid_export(
    reader: &mut codev_protocol::Lsb0Reader<'_>,
    depth: usize,
    records: &mut u32,
) -> Result<(), SessionError> {
    if depth > MAX_NETGUID_OUTER_DEPTH {
        return Err(SessionError::NetGuidOuterDepth);
    }
    *records = records.saturating_add(1);
    let netguid = reader.serialize_int_packed()?;
    if netguid == 0 {
        return Ok(());
    }
    let flags = reader.read_bits(8)? as u8;
    if flags & 1 != 0 {
        parse_netguid_export(reader, depth + 1, records)?;
        parse_netguid_fstring(reader)?;
        if flags & 4 != 0 {
            reader.read_bits(32)?;
        }
    }
    Ok(())
}

fn parse_netguid_fstring(reader: &mut codev_protocol::Lsb0Reader<'_>) -> Result<(), SessionError> {
    let signed_length = reader.read_bits(32)? as i32;
    if signed_length == i32::MIN {
        return Err(SessionError::NetGuidFStringLength);
    }
    let utf16 = signed_length < 0;
    let units = signed_length.unsigned_abs() as usize;
    let width = if utf16 { 16 } else { 8 };
    if units > reader.bits_left() / width {
        return Err(SessionError::NetGuidFStringLength);
    }
    let mut last = 0_u32;
    for _ in 0..units {
        last = reader.read_bits(width as u8)?;
    }
    if units != 0 && last != 0 {
        return Err(SessionError::NetGuidFStringTerminator);
    }
    Ok(())
}

fn collect_player_character_class_guids(
    export: &crate::wire::NetGuidExport,
    output: &mut HashSet<u32>,
) {
    if export
        .path
        .as_ref()
        .is_some_and(|path| path.value.contains("Default__BP_PlayerCharacter_C"))
    {
        output.insert(export.netguid);
    }
    if let Some(outer) = export.outer.as_deref() {
        collect_player_character_class_guids(outer, output);
    }
}

fn parse_player_character_spawn(
    data: &[u8],
    bit_length: usize,
    player_character_class_guids: &HashSet<u32>,
) -> Option<(u32, [f64; 3])> {
    let mut reader = codev_protocol::Lsb0Reader::new(data, bit_length).ok()?;
    let actor_guid = reader.serialize_int_packed().ok()?;
    if actor_guid == 0 || actor_guid & 1 != 0 {
        return None;
    }
    let class_guid = reader.serialize_int_packed().ok()?;
    reader.serialize_int_packed().ok()?; // level GUID
    if !player_character_class_guids.contains(&class_guid) || !reader.read_bit().ok()? {
        return None;
    }
    let position = if reader.read_bit().ok()? {
        parse_packed_spawn_vector(&mut reader)?
    } else {
        parse_raw_spawn_vector(&mut reader)?
    };
    position
        .iter()
        .all(|coordinate| coordinate.is_finite())
        .then_some((actor_guid, position))
}

fn parse_packed_spawn_vector(reader: &mut codev_protocol::Lsb0Reader<'_>) -> Option<[f64; 3]> {
    let component_bits = reader.serialize_int(24).ok()?.checked_add(2)?;
    let modulus = 1_u32.checked_shl(component_bits)?;
    let bias = f64::from(modulus >> 1);
    Some([
        (f64::from(reader.serialize_int(modulus).ok()?) - bias) / 10.0,
        (f64::from(reader.serialize_int(modulus).ok()?) - bias) / 10.0,
        (f64::from(reader.serialize_int(modulus).ok()?) - bias) / 10.0,
    ])
}

fn parse_raw_spawn_vector(reader: &mut codev_protocol::Lsb0Reader<'_>) -> Option<[f64; 3]> {
    Some([
        f64::from(f32::from_bits(reader.read_bits(32).ok()?)),
        f64::from(f32::from_bits(reader.read_bits(32).ok()?)),
        f64::from(f32::from_bits(reader.read_bits(32).ok()?)),
    ])
}

fn parse_serialized_name(reader: &mut codev_protocol::Lsb0Reader<'_>) -> Result<(), SessionError> {
    if reader.read_bit()? {
        let index = reader.serialize_int_packed()?;
        if index > HARD_CODED_NAME_MAX {
            return Err(SessionError::HardCodedNameOutOfRange(index));
        }
        return Ok(());
    }
    let raw_length = reader.read_bits(32)?;
    let signed_length = raw_length as i32;
    if signed_length == i32::MIN {
        return Err(SessionError::InvalidFStringLength);
    }
    let utf16 = signed_length < 0;
    let units = signed_length.unsigned_abs() as usize;
    let width = if utf16 { 16 } else { 8 };
    if units > reader.bits_left() / width {
        return Err(SessionError::InvalidFStringLength);
    }
    let mut last = 0_u32;
    for _ in 0..units {
        last = reader.read_bits(width as u8)?;
    }
    if units != 0 && last != 0 {
        return Err(SessionError::MissingFStringTerminator);
    }
    reader.read_bits(32)?; // signed FName number
    Ok(())
}

fn archive_bit_length(data: &[u8]) -> Result<usize, SessionError> {
    let Some(&last) = data.last() else {
        return Err(SessionError::MissingTerminalMarker);
    };
    if last == 0 {
        return Err(SessionError::MissingTerminalMarker);
    }
    Ok((data.len() - 1) * 8 + (7 - last.leading_zeros() as usize))
}

fn skip_bits(
    reader: &mut codev_protocol::Lsb0Reader<'_>,
    mut count: usize,
) -> Result<(), DecodeError> {
    while count >= 32 {
        reader.read_bits(32)?;
        count -= 32;
    }
    if count != 0 {
        reader.read_bits(count as u8)?;
    }
    Ok(())
}

fn extract_lsb_bits(data: &[u8], start: usize, bit_length: usize) -> Vec<u8> {
    let mut output = vec![0_u8; bit_length.div_ceil(8)];
    if bit_length == 0 {
        return output;
    }
    if start & 7 == 0 {
        let byte_start = start >> 3;
        let byte_length = output.len();
        output.copy_from_slice(&data[byte_start..byte_start + byte_length]);
    } else {
        for bit in 0..bit_length {
            let value = bit_at(data, start + bit);
            output[bit >> 3] |= value << (bit & 7);
        }
    }
    if bit_length & 7 != 0 {
        let keep = bit_length & 7;
        let last = output.len() - 1;
        output[last] &= (1_u8 << keep) - 1;
    }
    output
}

#[inline]
fn bit_at(data: &[u8], bit: usize) -> u8 {
    (data[bit >> 3] >> (bit & 7)) & 1
}

fn fingerprint64(data: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn unwrap_near(raw: u64, reference: u64, modulus: u64) -> u64 {
    let base = (reference / modulus) * modulus;
    let mut candidate = base + raw;
    let half = modulus / 2;
    if candidate.saturating_add(half) < reference {
        candidate = candidate.saturating_add(modulus);
    } else if candidate > reference.saturating_add(half) && candidate >= modulus {
        candidate -= modulus;
    }
    candidate
}

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("transport packet error: {0}")]
    Packet(#[from] PacketError),
    #[error("protocol bit error: {0}")]
    Protocol(#[from] DecodeError),
    #[error("wire envelope error: {0}")]
    Wire(#[from] crate::wire::WireError),
    #[error("sequence reorder error: {0}")]
    Reorder(#[from] ReorderError),
    #[error("partial bunch error: {0}")]
    Partial(#[from] PartialError),
    #[error("session I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid private session JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("session file permissions 0{0:o} are broader than 0600")]
    InsecureSessionPermissions(u32),
    #[error("private session Windows ACL is unsafe: {0}")]
    InsecureWindowsSessionAcl(&'static str),
    #[error("private session has an invalid GameId")]
    InvalidGameId,
    #[error("private session does not identify a protocol build")]
    MissingBuild,
    #[error("session build {0:?} is unsupported; expected {SUPPORTED_BUILD}")]
    UnsupportedBuild(String),
    #[error("capture contains no UDP flow")]
    NoUdpFlow,
    #[error("selected UDP flow endpoints and canonical key disagree")]
    InvalidSelectedUdpFlow,
    #[error("selected UDP flow does not occur in the capture")]
    SelectedUdpFlowNotFound,
    #[error("client S0 datagram is {0} bytes; at least 10 are required")]
    ClientDatagramTooShort(usize),
    #[error("S0 decrypt/encrypt round trip changed wire bytes")]
    SgNetWireRoundTripMismatch,
    #[error("{0} semantic re-encode changed wire bytes")]
    WireRoundTripMismatch(&'static str),
    #[error("independent typed and streaming parsers disagree for {0}")]
    WireParserDisagreement(&'static str),
    #[error("packet lacks its highest-set terminal marker")]
    MissingTerminalMarker,
    #[error("pass-through P0 payload is empty")]
    EmptyPacketHandlerPayload,
    #[error("pass-through P0 payload lacks its nested U0 terminal marker")]
    MissingNestedTerminal,
    #[error("hard-coded FName index {0} exceeds {HARD_CODED_NAME_MAX}")]
    HardCodedNameOutOfRange(u32),
    #[error("serialized FString length exceeds its bunch header")]
    InvalidFStringLength,
    #[error("serialized FString lacks its terminal null")]
    MissingFStringTerminator,
    #[error("alternate PackageMap export layout is unsupported")]
    AlternatePackageMapLayout,
    #[error("PackageMap N0 export count {0} exceeds {MAX_NETGUID_EXPORTS}")]
    NetGuidExportCount(u32),
    #[error("PackageMap N0 outer recursion exceeds {MAX_NETGUID_OUTER_DEPTH} levels")]
    NetGuidOuterDepth,
    #[error("PackageMap N0 FString has an invalid length")]
    NetGuidFStringLength,
    #[error("PackageMap N0 FString lacks its terminal null")]
    NetGuidFStringTerminator,
    #[error("partial completion for channel {0} lost its initial metadata")]
    MissingPartialMetadata(u32),
    #[error("capture ended with {0} unterminated partial bunch chains")]
    UnterminatedPartialChains(usize),
    #[error("message belongs to stale channel generation {0}")]
    StaleChannelGeneration(u64),
    #[error("channel {0} received a nonidentical open while its generation is active")]
    OverlappingChannelOpen(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).unwrap();
                u8::from_str_radix(text, 16).unwrap()
            })
            .collect()
    }

    fn raw_player_spawn(actor_guid: u32, class_guid: u32, position: [f32; 3]) -> (Vec<u8>, usize) {
        let mut writer = codev_protocol::Lsb0Writer::with_capacity(128);
        writer.serialize_int_packed(actor_guid).unwrap();
        writer.serialize_int_packed(class_guid).unwrap();
        writer.serialize_int_packed(2).unwrap();
        writer.write_bit(true);
        writer.write_bit(false);
        for coordinate in position {
            writer.write_bits(coordinate.to_bits(), 32).unwrap();
        }
        let bit_length = writer.position();
        (writer.into_bytes(), bit_length)
    }

    #[test]
    fn parses_only_proven_player_character_actor_spawns() {
        let classes = HashSet::from([100_u32]);
        let (data, bit_length) = raw_player_spawn(52, 100, [5306.0, 530.0, 400.3]);
        let (actor_guid, position) =
            parse_player_character_spawn(&data, bit_length, &classes).unwrap();
        assert_eq!(actor_guid, 52);
        assert_eq!(position[0], 5306.0);
        assert_eq!(position[1], 530.0);
        assert!((position[2] - 400.3).abs() < 0.001);

        let (wrong_class, wrong_bits) = raw_player_spawn(54, 101, [1.0, 2.0, 3.0]);
        assert!(parse_player_character_spawn(&wrong_class, wrong_bits, &classes).is_none());
    }

    fn lifecycle_bunch(
        channel_index: u32,
        open: bool,
        close: bool,
        reliable_sequence_raw: Option<u16>,
        data: &[u8],
    ) -> UnrealBunch {
        UnrealBunch {
            channel_index,
            open,
            close,
            reliable_sequence_raw,
            partial: false,
            partial_initial: false,
            partial_final: false,
            package_map_export_prefix_parsed: false,
            netguid_record_count: 0,
            wire_data_sha256: Sha256::digest(data).into(),
            data_bit_offset: 0,
            data: data.to_vec(),
            data_bit_length: data.len() * 8,
        }
    }

    fn test_pipeline() -> P0Pipeline {
        P0Pipeline::new(
            C0Cipher {
                key: [0; 32],
                nonce: [0; 12],
            },
            Endpoint {
                ip: IpAddress::V4([10, 0, 0, 1]),
                port: 50_000,
            },
            Endpoint {
                ip: IpAddress::V4([1, 1, 1, 1]),
                port: 10_000,
            },
        )
    }

    #[test]
    fn discovers_runtime_batch_channel_from_validated_batchdata() {
        let mut pipeline = test_pipeline();
        let mut actors = Vec::new();

        // Handle 5 alone is common and must not select an unrelated channel.
        pipeline
            .process_complete_message(
                Direction::ServerToClient,
                1,
                1,
                1,
                32,
                0,
                false,
                vec![1],
                Some(0),
                Some(0),
                decode_hex("9b500800"),
                29,
                &mut actors,
            )
            .unwrap();
        assert_eq!(pipeline.batch_channel(), None);
        assert!(actors.is_empty());

        // The coordinate channel is allocated dynamically for each match.
        pipeline
            .process_complete_message(
                Direction::ServerToClient,
                2,
                2,
                2,
                95,
                0,
                false,
                vec![2],
                Some(0),
                Some(0),
                decode_hex("d708104900c20901c2b50e017765ac01005040000800"),
                172,
                &mut actors,
            )
            .unwrap();
        assert_eq!(pipeline.batch_channel(), Some((95, 0)));
        assert_eq!(actors.len(), 1);
        assert_eq!(actors[0].channel_index, 95);
        assert_eq!(actors[0].updates.len(), 1);
        assert_eq!(pipeline.stats().batch_properties, 1);
        assert_eq!(pipeline.stats().character_updates, 1);

        // Once proven, actor-shaped traffic on another channel is ignored.
        pipeline
            .process_complete_message(
                Direction::ServerToClient,
                3,
                3,
                3,
                32,
                0,
                false,
                vec![3],
                Some(0),
                Some(0),
                decode_hex("d708104900c20901c2b50e017765ac01005040000800"),
                172,
                &mut actors,
            )
            .unwrap();
        assert_eq!(actors.len(), 1);
        assert_eq!(pipeline.stats().actor_messages, 1);
    }

    fn private_session_fixture(document: &str) -> PathBuf {
        use std::io::Write;
        let path = std::env::temp_dir().join(format!(
            "c0-m-session-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(document.as_bytes()).unwrap();
        path
    }

    #[test]
    fn static_derivation_matches_ida_vectors() {
        assert_eq!(encryption_key_seed("abc"), 0xc05c_9c7b);
        assert_eq!(encryption_key_seed("ABC"), 0xc05c_9c7b);
        assert_eq!(encryption_key_seed("EncryptionKey"), 0x7082_ace5);
        assert_eq!(park_miller_step(1), 16_807);
        assert_eq!(park_miller_step(16_807), 282_475_249);
        assert_eq!(park_miller_step(0x8000_0000), 0x7fff_be58);
        assert_eq!(
            derive_bytes::<12>(1),
            [
                0xe6, 0x0d, 0xa2, 0xa9, 0x40, 0x08, 0x55, 0x44, 0xc9, 0x9a, 0x27, 0x57
            ]
        );
        assert_eq!(derive_bytes::<32>(0), [0x80; 32]);
    }

    #[test]
    fn package_map_prefix_parser_is_bounded_and_fail_closed() {
        assert!(matches!(
            parse_package_map_export_prefix(&[1], 1),
            Err(SessionError::AlternatePackageMapLayout)
        ));
        assert_eq!(
            parse_package_map_export_prefix(&[0; 5], 33).unwrap(),
            (33, 0)
        );
        assert!(parse_package_map_export_prefix(&[0], 1).is_err());
    }

    #[test]
    fn chacha_client_copy_boundaries_restart_counter_one() {
        let cipher = C0Cipher {
            key: std::array::from_fn(|index| index as u8),
            nonce: std::array::from_fn(|index| index as u8),
        };
        let mut packet = Vec::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
        packet.extend(0_u8..=129);
        let encrypted = cipher.crypt_client_datagram(&packet).unwrap();
        assert_eq!(&encrypted[..8], &packet[..8]);
        assert_eq!(cipher.crypt_client_datagram(&encrypted).unwrap(), packet);
    }

    #[test]
    fn bit_extraction_preserves_non_aligned_tail() {
        assert_eq!(
            extract_lsb_bits(&[0b1010_1100, 0b0000_0011], 3, 7),
            [0b0111_0101]
        );
    }

    #[test]
    fn reliable_sequence_unwrap_accepts_1023_to_zero_partial_chain() {
        let client = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 1]),
            port: 50_000,
        };
        let server = Endpoint {
            ip: IpAddress::V4([1, 1, 1, 1]),
            port: 10_000,
        };
        let mut pipeline = P0Pipeline::new(
            C0Cipher {
                key: [0; 32],
                nonce: [0; 12],
            },
            client,
            server,
        );
        assert_eq!(
            pipeline.unwrap_reliable(Direction::ServerToClient, 7, Some(1023)),
            Some(1023)
        );
        assert_eq!(
            pipeline.unwrap_reliable(Direction::ServerToClient, 7, Some(0)),
            Some(1024)
        );
    }

    #[test]
    fn reliable_open_retransmission_does_not_advance_channel_generation() {
        let mut pipeline = test_pipeline();
        let open = lifecycle_bunch(9, true, false, Some(77), &[0x45, 0x23]);
        let mut actors = Vec::new();

        pipeline
            .process_bunch(
                Direction::ServerToClient,
                1,
                1,
                1,
                0,
                0,
                open.clone(),
                &mut actors,
            )
            .unwrap();
        pipeline
            .process_bunch(Direction::ServerToClient, 2, 2, 2, 0, 0, open, &mut actors)
            .unwrap();

        let state = &pipeline.channels[&(Direction::ServerToClient, 9)];
        assert_eq!(state.generation, 1);
        assert!(state.open);
        assert_eq!(state.reliable_reference, Some(77));
        assert!(actors.is_empty());
    }

    #[test]
    fn partial_open_retransmission_consumes_its_duplicate_continuation() {
        let mut pipeline = test_pipeline();
        let mut open = lifecycle_bunch(9, true, false, Some(77), &[0x45]);
        open.partial = true;
        open.partial_initial = true;
        let mut continuation = lifecycle_bunch(9, false, false, Some(78), &[0x23]);
        continuation.partial = true;
        continuation.partial_final = true;
        let mut actors = Vec::new();

        for (capture_index, bunch) in [open.clone(), continuation.clone(), open, continuation]
            .into_iter()
            .enumerate()
        {
            pipeline
                .process_bunch(
                    Direction::ServerToClient,
                    capture_index as u64,
                    capture_index as u64,
                    capture_index as u64,
                    0,
                    0,
                    bunch,
                    &mut actors,
                )
                .unwrap();
        }

        assert_eq!(
            pipeline.channels[&(Direction::ServerToClient, 9)].generation,
            1
        );
        assert_eq!(pipeline.stats().partial_payloads_completed, 2);
        assert!(pipeline.partial_metadata.is_empty());
        assert!(actors.is_empty());
    }

    #[test]
    fn in_flight_partial_retransmission_does_not_abort_the_chain() {
        let mut pipeline = test_pipeline();
        let mut initial = lifecycle_bunch(9, true, false, Some(77), &[0x45]);
        initial.partial = true;
        initial.partial_initial = true;
        let mut final_fragment = lifecycle_bunch(9, false, false, Some(78), &[0x23]);
        final_fragment.partial = true;
        final_fragment.partial_final = true;
        let mut actors = Vec::new();

        pipeline
            .process_bunch(
                Direction::ServerToClient,
                1,
                1,
                1,
                0,
                0,
                initial.clone(),
                &mut actors,
            )
            .unwrap();
        // Same ChSequence + same bits while the chain is open: UDP retransmission,
        // not an overlapping channel or reliable gap.
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                2,
                2,
                2,
                0,
                0,
                initial,
                &mut actors,
            )
            .unwrap();
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                3,
                3,
                3,
                0,
                0,
                final_fragment,
                &mut actors,
            )
            .unwrap();

        assert_eq!(pipeline.stats().partial_payloads_completed, 1);
        assert!(pipeline.partial_metadata.is_empty());
    }

    #[test]
    fn nonidentical_open_on_active_channel_fails_closed() {
        let mut pipeline = test_pipeline();
        let mut actors = Vec::new();
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                1,
                1,
                1,
                0,
                0,
                lifecycle_bunch(9, true, false, Some(77), &[1]),
                &mut actors,
            )
            .unwrap();

        assert!(matches!(
            pipeline.process_bunch(
                Direction::ServerToClient,
                2,
                2,
                2,
                0,
                0,
                lifecycle_bunch(9, true, false, Some(77), &[2]),
                &mut actors,
            ),
            Err(SessionError::OverlappingChannelOpen(9))
        ));
        assert_eq!(
            pipeline.channels[&(Direction::ServerToClient, 9)].generation,
            1
        );
    }

    #[test]
    fn data_after_close_is_ignored_until_reopen() {
        let mut pipeline = test_pipeline();
        let mut actors = Vec::new();
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                1,
                1,
                1,
                0,
                0,
                lifecycle_bunch(9, true, false, Some(10), &[1]),
                &mut actors,
            )
            .unwrap();
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                2,
                2,
                2,
                0,
                0,
                lifecycle_bunch(9, false, true, Some(11), &[]),
                &mut actors,
            )
            .unwrap();

        let mut stale = lifecycle_bunch(9, false, false, Some(12), &[1]);
        stale.partial = true;
        stale.partial_initial = false;
        stale.partial_final = true;
        pipeline
            .process_bunch(Direction::ServerToClient, 3, 3, 3, 0, 0, stale, &mut actors)
            .unwrap();

        let state = &pipeline.channels[&(Direction::ServerToClient, 9)];
        assert_eq!(state.generation, 1);
        assert!(!state.open);
        assert_eq!(pipeline.stats().partial_fragments, 0);
        assert!(actors.is_empty());
    }

    #[test]
    fn reopen_starts_a_fresh_generation_and_resets_partial_state() {
        let mut pipeline = test_pipeline();
        let mut actors = Vec::new();
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                1,
                1,
                1,
                0,
                0,
                lifecycle_bunch(9, true, false, Some(20), &[1]),
                &mut actors,
            )
            .unwrap();
        let mut partial = lifecycle_bunch(9, false, false, Some(21), &[1]);
        partial.partial = true;
        partial.partial_initial = true;
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                2,
                2,
                2,
                0,
                0,
                partial,
                &mut actors,
            )
            .unwrap();
        assert_eq!(pipeline.partial_metadata.len(), 1);
        pipeline
            .process_bunch(
                Direction::ServerToClient,
                3,
                3,
                3,
                0,
                0,
                lifecycle_bunch(9, false, true, Some(22), &[]),
                &mut actors,
            )
            .unwrap();
        assert!(pipeline.partial_metadata.is_empty());

        pipeline
            .process_bunch(
                Direction::ServerToClient,
                4,
                4,
                4,
                0,
                0,
                lifecycle_bunch(9, true, false, Some(700), &[2]),
                &mut actors,
            )
            .unwrap();
        let state = &pipeline.channels[&(Direction::ServerToClient, 9)];
        assert_eq!(state.generation, 2);
        assert!(state.open);
        assert_eq!(state.reliable_reference, Some(700));
    }

    #[test]
    fn oodle_flag_stops_at_the_compression_boundary() {
        let boundary = parse_packet_handler(&[0x01, 0x08]).unwrap();
        assert!(matches!(
            boundary,
            PacketHandlerPayload::Oodle { _raw_size: 1 }
        ));
    }

    #[test]
    fn private_session_requires_supported_build_and_accepts_wire_field_aliases() {
        let missing =
            private_session_fixture(r#"{"session":{"PacketKey":"test-key","GameId":"0x31"}}"#);
        assert!(matches!(
            PrivateSession::load(&missing),
            Err(SessionError::MissingBuild)
        ));
        std::fs::remove_file(missing).unwrap();

        let unknown = private_session_fixture(
            r#"{"build":"9.9.9.9","session":{"PacketKey":"test-key","GameId":"0x31"}}"#,
        );
        assert!(matches!(
            PrivateSession::load(&unknown),
            Err(SessionError::UnsupportedBuild(_))
        ));
        std::fs::remove_file(unknown).unwrap();

        let supported = private_session_fixture(
            r#"{"build":"1.24.0 (2911)","session":{"PacketKey":"test-key","GameId":"0x31"}}"#,
        );
        let session = PrivateSession::load(&supported).unwrap();
        assert_eq!(session.build, "1.24.0 (2911)");
        std::fs::remove_file(supported).unwrap();
    }

    #[test]
    fn gap_records_are_directional_drainable_and_bounded() {
        let client = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 1]),
            port: 50_000,
        };
        let server = Endpoint {
            ip: IpAddress::V4([1, 1, 1, 1]),
            port: 10_000,
        };
        let mut pipeline = P0Pipeline::new(
            C0Cipher {
                key: [0; 32],
                nonce: [0; 12],
            },
            client,
            server,
        );
        for index in 0..=MAX_PENDING_GAP_RECORDS {
            pipeline
                .process_reorder_output(
                    Direction::ServerToClient,
                    1_000 + index as u64,
                    ReorderOutput {
                        gap: Some(crate::SequenceGap {
                            first_missing: index as u64,
                            last_missing: index as u64 + 1,
                            resumed_at: index as u64 + 2,
                        }),
                        ..ReorderOutput::default()
                    },
                )
                .unwrap();
        }
        assert_eq!(pipeline.stats().sequence_gaps, 65);
        assert_eq!(pipeline.stats().dropped_gap_records, 1);
        let gaps = pipeline.drain_gaps();
        assert_eq!(gaps.len(), MAX_PENDING_GAP_RECORDS);
        assert_eq!(
            gaps[0],
            PipelineGap {
                reason: PipelineGapReason::Sequence,
                direction: Some(Direction::ServerToClient),
                first_missing: Some(1),
                last_missing: Some(2),
                resumed_at: Some(3),
                detected_ns: 1_001,
            }
        );
        assert!(pipeline.drain_gaps().is_empty());
    }

    /// 守卫：reorder 的释放死线必须能从 pipeline 问出来。
    /// 之前 proxy 侧是靠一个 100Hz 定时任务"顺手"释放的，那个任务其实调的是空函数；
    /// 改成按死线唤醒之后，这条链路是唯一的释放保证。
    #[test]
    fn pipeline_reports_reorder_deadline_and_clears_it_after_release() {
        let client = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 1]),
            port: 50_000,
        };
        let server = Endpoint {
            ip: IpAddress::V4([1, 1, 1, 1]),
            port: 10_000,
        };
        let mut pipeline = P0Pipeline::new(
            C0Cipher {
                key: [0; 32],
                nonce: [0; 12],
            },
            client,
            server,
        );
        let packet = |capture_index| UnrealDatagram {
            direction: Direction::ClientToServer,
            capture_index,
            timestamp_ns: capture_index,
            ue_wire_bit_offset: 1,
            bunches: Vec::new(),
        };
        // 顺序流：没有缺口 → 不给期限，调用方可以低频等待。
        assert_eq!(pipeline.next_reorder_deadline_ns(), None);
        pipeline.client_reorder.push(10, 0, 10, packet(10)).unwrap();
        assert_eq!(pipeline.next_reorder_deadline_ns(), None);

        // 缺 11 而 12 先到 → 期限 = 缺口起点 + 50ms 释放窗口。
        assert!(
            pipeline
                .client_reorder
                .push(12, 1_000, 12, packet(12))
                .unwrap()
                .released
                .is_empty()
        );
        assert_eq!(
            pipeline.next_reorder_deadline_ns(),
            Some(1_000 + crate::DEFAULT_REORDER_TIMEOUT_NS)
        );

        // 死线到点 poll 一次 → 缺口释放，期限随即撤销（不会反复醒）。
        let deadline = pipeline.next_reorder_deadline_ns().unwrap();
        let released = pipeline.client_reorder.poll_timeout(deadline).released;
        assert_eq!(
            released
                .iter()
                .map(|item| item.value.capture_index)
                .collect::<Vec<_>>(),
            [12]
        );
        assert_eq!(pipeline.next_reorder_deadline_ns(), None);
    }

    #[test]
    fn capture_gap_discards_reorder_and_partial_state_and_restarts_sequence_reference() {
        let client = Endpoint {
            ip: IpAddress::V4([10, 0, 0, 1]),
            port: 50_000,
        };
        let server = Endpoint {
            ip: IpAddress::V4([1, 1, 1, 1]),
            port: 10_000,
        };
        let mut pipeline = P0Pipeline::new(
            C0Cipher {
                key: [0; 32],
                nonce: [0; 12],
            },
            client,
            server,
        );
        let packet = |capture_index| UnrealDatagram {
            direction: Direction::ClientToServer,
            capture_index,
            timestamp_ns: capture_index,
            ue_wire_bit_offset: 1,
            bunches: Vec::new(),
        };
        assert_eq!(
            pipeline
                .client_reorder
                .push(10, 10, 10, packet(10))
                .unwrap()
                .released
                .len(),
            1
        );
        assert!(
            pipeline
                .client_reorder
                .push(12, 12, 12, packet(12))
                .unwrap()
                .released
                .is_empty()
        );
        let partial_key = PartialKey {
            direction: Direction::ServerToClient,
            channel_index: 9,
            channel_generation: 3,
        };
        pipeline
            .partials
            .feed(PartialFragment {
                key: partial_key,
                reliable_sequence: Some(4),
                initial: true,
                final_fragment: false,
                data: &[1],
                bit_length: 1,
            })
            .unwrap();
        pipeline.partial_metadata.insert(
            partial_key,
            PartialMetadata {
                direction: Direction::ServerToClient,
                capture_index: 20,
                timestamp_ns: 20,
                packet_sequence: 20,
                channel_index: 9,
                channel_generation: 3,
                open: false,
                close: false,
                source_capture_indices: vec![20],
            },
        );
        pipeline.channels.insert(
            (Direction::ServerToClient, 9),
            ChannelState {
                generation: 3,
                lifecycle_observed: true,
                open: true,
                open_signature: None,
                reliable_reference: Some(4),
            },
        );

        pipeline.mark_capture_gap(99);
        assert_eq!(pipeline.stats().capture_gaps, 1);
        assert_eq!(pipeline.client_reorder.expected(), None);
        assert_eq!(pipeline.server_reorder.expected(), None);
        assert!(pipeline.partial_metadata.is_empty());
        assert_eq!(
            pipeline.channels[&(Direction::ServerToClient, 9)].generation,
            3
        );
        assert_eq!(
            pipeline.channels[&(Direction::ServerToClient, 9)].reliable_reference,
            None
        );
        assert!(matches!(
            pipeline.partials.feed(PartialFragment {
                key: partial_key,
                reliable_sequence: Some(5),
                initial: false,
                final_fragment: true,
                data: &[1],
                bit_length: 1,
            }),
            Err(PartialError::Orphan(9))
        ));
        let validity = pipeline.batch.slot_validity(0).unwrap();
        assert_eq!(
            validity.continuity,
            codev_protocol::SlotContinuity::Discontinuous
        );
        let restarted = pipeline
            .client_reorder
            .push(500, 100, 500, packet(100))
            .unwrap();
        assert_eq!(restarted.released[0].unwrapped_sequence, 500);
        assert_eq!(
            pipeline.drain_gaps(),
            vec![PipelineGap {
                reason: PipelineGapReason::CaptureDrop,
                direction: None,
                first_missing: None,
                last_missing: None,
                resumed_at: None,
                detected_ns: 99,
            }]
        );
    }
}
