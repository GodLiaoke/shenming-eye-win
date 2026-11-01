//! Explicit, streaming Rust compatibility-artifact development sink.
//!
//! This module owns the complete eleven-artifact compatibility sink, including
//! streaming JSONL, typed network/session evidence, match/summary documents and
//! the rendered report. The Python implementation remains an explicit oracle,
//! not a production dependency of the default decode path.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{self, File};
use std::io::{self, BufWriter, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use codev_protocol::{MovementKind, MovementState, MovementUpdate, RotatorField, VectorField};
use codev_stream::{
    A0Payload, C0Cipher, Endpoint, IpAddress, PacketSource, S0PcapSource, SelectedUdpFlow,
    decode_classic_pcap_with_cipher, parse_transport, recover_enter_game_session_from_classic_pcap,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::compat_auxiliary::{
    AuxiliaryVoiceEvent, CompatibilityAuxiliaryError, VoiceRoomInfo, scan_auxiliary_capture,
};
use crate::compat_batch::BatchSummaryAccumulator;
use crate::compat_documents::{
    CompatibilityDocumentError, CompatibilityDocumentInputs, FixtureClassification,
    build_compatibility_documents,
};
use crate::compat_gate::{RecoveryGateError, build_recovery_gate};
use crate::compat_netguid::{NetGuidArtifactError, build_netguid_artifact};
use crate::compat_network::{CompatibilityNetworkError, build_compatibility_network_artifacts};
use crate::compat_packets::{
    CompatibilityPacketError, CompatibilityPacketReport, write_compatibility_packet_artifacts,
};
use crate::compat_report::render_full_session_report;
use crate::compat_session::{CompatibilitySessionError, load_compatibility_enter_session};
use crate::record::{create_private_directory, open_private};

const KNOWN_UDP_SHA256: &str = "d94d7950a79c25d67caed0d1064274fa9eb5cdc60f05063676c5229fb749e3a5";
const KNOWN_FULL_SHA256: &str = "82c779ed1212d600794683226c15c7d7751fc06a1632163be7566adbbc49e2e7";
const FIELD_DICTIONARY_XOR: u8 = 0xA7;

/// S2：运行时注入的字段字典（来自云端、按会话密钥加密后下发）。
///
/// 没注入时**行为与改动前完全一致**（回退到编译期内嵌的那份），
/// 所以这条改动是安全的：不接云端也能照常跑。
/// 用 `RwLock<Option<..>>` 而不是 `OnceLock`：会话密钥每 35 分钟轮换一次，
/// 客户端必须能**替换**成新会话加密的字典。OnceLock 只允许写入一次，
/// 会导致轮换后注入不进去（本地解码继续用旧字典甚至彻底失效）。
static RUNTIME_DICTIONARY: std::sync::RwLock<Option<Vec<u8>>> = std::sync::RwLock::new(None);

/// 注入或替换字段字典明文。返回 `true` 表示已写入（含替换）。
pub fn set_runtime_dictionary(bytes: Vec<u8>) -> bool {
    let mut guard = RUNTIME_DICTIONARY
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = Some(bytes);
    true
}

/// 当前是否已注入运行时字典（供诊断与测试断言）。
pub fn runtime_dictionary_is_set() -> bool {
    RUNTIME_DICTIONARY
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .is_some()
}

/// 清除运行时字典，回退到编译期内嵌的那份。
/// 生产上用于"会话到期且续期失败"时立刻止损；测试上用于隔离全局状态。
pub fn clear_runtime_dictionary() {
    let mut guard = RUNTIME_DICTIONARY
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

/// 取字段字典明文：**优先运行时注入**，否则回退到编译期内嵌（异或解包）。
pub fn embedded_fields_json_bytes() -> Vec<u8> {
    if let Some(injected) = RUNTIME_DICTIONARY
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        return injected.clone();
    }
    const ENC: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fields.bin"));
    ENC.iter().map(|byte| byte ^ FIELD_DICTIONARY_XOR).collect()
}

pub fn embedded_fields_json() -> String {
    String::from_utf8(embedded_fields_json_bytes()).expect("embedded field dictionary is UTF-8")
}
const FIELD_KEYS: [&str; 12] = [
    "field_id",
    "layer",
    "name",
    "direction",
    "bit_offset",
    "bit_width",
    "value_type",
    "byte_order",
    "condition",
    "semantics",
    "confidence",
    "evidence",
];
const IDA_EVIDENCE: [&str; 5] = [
    "IDA 0x103AAA568 BatchDataNetSerialize",
    "IDA 0x103AA6E60 per-character codec",
    "IDA 0x103AA6AF4 full movement codec",
    "IDA 0x103AA6C8C minimal movement codec",
    "IDA 0x10429BBA8 quantized-vector decoder",
];

#[derive(Debug, Error)]
pub enum NativeEventsError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("session pipeline error: {0}")]
    Session(#[from] codev_stream::SessionError),
    #[error("capture source error: {0}")]
    Source(#[from] codev_stream::SourceError),
    #[error("M0 recovery error: {0}")]
    Mna(#[from] codev_stream::W0CaptureError),
    #[error("decoder field schema is invalid: {0}")]
    FieldSchema(String),
    #[error("compatibility network artifact error: {0}")]
    CompatibilityNetwork(#[from] CompatibilityNetworkError),
    #[error("compatibility recovery gate error: {0}")]
    RecoveryGate(#[from] RecoveryGateError),
    #[error("compatibility N0 artifact error: {0}")]
    NetGuid(#[from] NetGuidArtifactError),
    #[error("compatibility packet artifact error: {0}")]
    CompatibilityPackets(#[from] CompatibilityPacketError),
    #[error("compatibility auxiliary capture error: {0}")]
    CompatibilityAuxiliary(#[from] CompatibilityAuxiliaryError),
    #[error("compatibility match/summary document error: {0}")]
    CompatibilityDocuments(#[from] CompatibilityDocumentError),
    #[error("compatibility private session error: {0}")]
    CompatibilitySession(#[from] CompatibilitySessionError),
    #[error("actor {0} is reassembled and has no single legacy wire offset")]
    ReassembledActor(u64),
}

#[derive(Clone, Debug, Serialize)]
pub struct NativeEventsReport {
    pub schema_version: &'static str,
    pub status: &'static str,
    pub artifact: &'static str,
    pub completed_compatibility_artifacts: [&'static str; 11],
    pub pcap_sha256: String,
    pub known_full_fixture: bool,
    pub actor_messages: u64,
    pub batch_properties: u64,
    pub non_batch_properties: u64,
    pub character_updates: u64,
    pub fresh_movement_updates: u64,
    pub carry_forward_updates: u64,
    pub auxiliary_events: u64,
    pub event_count: u64,
    pub packet_artifacts: CompatibilityPacketReport,
    pub validation_passed: bool,
    pub incomplete_compatibility_artifacts: [&'static str; 0],
}

impl NativeEventsReport {
    pub const fn exit_code(&self) -> i32 {
        if self.validation_passed { 0 } else { 2 }
    }
}

struct TemporaryArtifact {
    path: PathBuf,
    committed: bool,
}

impl TemporaryArtifact {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(mut self, destination: &Path) -> io::Result<()> {
        fs::rename(&self.path, destination)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for TemporaryArtifact {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize)]
struct CompatibilityEvent<T> {
    event_type: &'static str,
    timestamp: f64,
    fields: T,
    source_packets: [u64; 1],
    confidence: &'static str,
}

#[derive(Serialize)]
struct VoiceFields<'a> {
    room: &'a VoiceRoomInfo,
}

#[derive(Serialize)]
struct BatchFields {
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
    channel_index: u32,
    bunch_index: usize,
    packet_sequence_raw: u64,
    coordinate_semantics: &'static str,
    coordinate_confidence: &'static str,
    identity_confidence: &'static str,
    ida_evidence: [&'static str; 5],
}

#[derive(Serialize)]
struct UnitVector {
    x: f64,
    y: f64,
    z: f64,
    unit: &'static str,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
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

#[derive(Serialize)]
struct CompatibilityRotator {
    degrees: [f64; 3],
    bit_offset: usize,
    wire_bit_offset: usize,
    bit_length: usize,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum FieldSchemaRoot {
    Fields(Vec<Value>),
    Document(FieldSchemaDocument),
}

#[derive(Deserialize)]
struct FieldSchemaDocument {
    #[serde(default)]
    inherit_builtin_fields: bool,
    #[serde(default)]
    field_specs: Option<Vec<Value>>,
}

pub fn write_native_events(
    pcap: &Path,
    schema: Option<&Path>,
    output: &Path,
) -> Result<NativeEventsReport, NativeEventsError> {
    let schema = schema.map(resolve_schema_file).transpose()?;
    let field_specs = load_field_specs(schema.as_deref())?;
    create_private_directory(output)?;
    let pcap_sha256 = sha256_file(pcap)?;
    let known_full_fixture = pcap_sha256 == KNOWN_FULL_SHA256;
    let (recovered_session, mna_provenance) = if let Some(schema) = schema.as_deref() {
        (load_compatibility_enter_session(schema)?, None)
    } else {
        let recovery = recover_enter_game_session_from_classic_pcap(pcap)?;
        let provenance = recovery.notification.clone();
        (recovery.into_session(), Some(provenance))
    };
    let server = endpoint(&recovered_session.server_ip, recovered_session.server_port);
    let selected_flow = find_selected_flow(pcap, server, recovered_session.server_port)?;
    let auxiliary_capture = scan_auxiliary_capture(pcap, selected_flow)?;
    let mut auxiliary = VecDeque::from(auxiliary_capture.events.clone());
    let auxiliary_events = auxiliary.len() as u64;
    let event_cipher =
        C0Cipher::from_packet_key(&recovered_session.packet_key, recovered_session.g0_id);
    let artifact_cipher = event_cipher.clone();
    let temporary = TemporaryArtifact::new(
        output.join(format!(".events.jsonl.{:032x}.tmp", rand::random::<u128>())),
    );
    let mut writer = BufWriter::with_capacity(1024 * 1024, open_private(&temporary.path, true)?);
    let mut actor_messages = 0_u64;
    let mut batch_properties = 0_u64;
    let mut non_batch_properties = 0_u64;
    let mut character_updates = 0_u64;
    let mut fresh_movement_updates = 0_u64;
    let mut batch_slots = 0_u64;
    let mut last_timestamp_ns = 0_u64;
    let mut batch_summary = BatchSummaryAccumulator::default();

    let decode_result =
        decode_classic_pcap_with_cipher(pcap, event_cipher, Some(selected_flow), |actor| {
            write_actor_events(
                &mut writer,
                &mut auxiliary,
                actor,
                &mut actor_messages,
                &mut batch_properties,
                &mut non_batch_properties,
                &mut character_updates,
                &mut fresh_movement_updates,
                &mut batch_slots,
                &mut last_timestamp_ns,
                &mut batch_summary,
            )
            .map_err(native_to_session_error)
        });
    let pipeline = match decode_result {
        Ok(report) => report,
        Err(error) => {
            drop(writer);
            return Err(error.into());
        }
    };
    let network_artifacts = build_compatibility_network_artifacts(pcap)?;
    let netguid_artifact = build_netguid_artifact(pcap, &artifact_cipher, pipeline.flow)?;
    let recovery_gate = build_recovery_gate(
        pipeline.stats,
        &network_artifacts.facts,
        batch_slots.count_ones(),
    )?;
    let packet_artifacts =
        write_compatibility_packet_artifacts(pcap, &artifact_cipher, pipeline.flow, output)?;
    let batch_summary = batch_summary.finish();
    let canonical_pcap = fs::canonicalize(pcap)?;
    let flow_manifest_value = serde_json::to_value(&network_artifacts.flow_manifest)?;
    let netguid_value = serde_json::to_value(&netguid_artifact)?;
    let recovery_gate_value = serde_json::to_value(&recovery_gate)?;
    let packet_report_value = serde_json::to_value(&packet_artifacts)?;
    let documents = build_compatibility_documents(&CompatibilityDocumentInputs {
        pcap: &canonical_pcap,
        pcap_sha256: &pcap_sha256,
        session: &recovered_session,
        pipeline: pipeline.stats,
        batch_sync: &batch_summary,
        flow_manifest: &flow_manifest_value,
        netguid: &netguid_value,
        recovery_gate: &recovery_gate_value,
        packet_report: &packet_report_value,
        mna_provenance: mna_provenance.as_ref(),
        auxiliary: &auxiliary_capture,
        fixture: FixtureClassification {
            known_udp_fixture: pcap_sha256 == KNOWN_UDP_SHA256,
            known_full_fixture,
        },
    })?;
    let report_markdown = render_full_session_report(
        &documents.summary_document,
        &documents.match_document,
        &recovery_gate_value,
    );
    while let Some(event) = auxiliary.pop_front() {
        write_auxiliary(&mut writer, &event)?;
    }
    writer.flush()?;
    drop(writer);
    temporary.commit(&output.join("events.jsonl"))?;
    write_json_atomic(output, "fields.json", &field_specs)?;
    write_json_atomic(
        output,
        "flow_manifest.json",
        &network_artifacts.flow_manifest,
    )?;
    write_json_atomic(output, "tcp_streams.json", &network_artifacts.tcp_streams)?;
    write_json_atomic(output, "recovery_gate.json", &recovery_gate)?;
    write_json_atomic(output, "netguid.json", &netguid_artifact)?;
    write_json_atomic(output, "match.json", &documents.match_document)?;
    write_json_atomic(output, "summary.json", &documents.summary_document)?;
    write_text_atomic(output, "report.md", &report_markdown)?;

    let carry_forward_updates = character_updates - fresh_movement_updates;
    let validation_passed = pipeline.stats.actor_messages == actor_messages
        && pipeline.stats.character_updates == character_updates
        && batch_summary.actor_messages == actor_messages
        && batch_summary.bit_exact_actor_messages == actor_messages
        && batch_summary.batch_properties == batch_properties
        && batch_summary.non_batch_properties == non_batch_properties
        && batch_summary.character_updates == character_updates
        && packet_artifacts.packet_count == pipeline.stats.datagrams
        && packet_artifacts.packet_handler_reencode_exact == pipeline.stats.datagrams
        && packet_artifacts.sgnet_wire_reencode_exact == pipeline.stats.datagrams
        && packet_artifacts.unreal_reencode_exact == pipeline.stats.unreal_packets
        && packet_artifacts.bunch_count == pipeline.stats.bunches
        && packet_artifacts.package_map_reencode_exact
            == pipeline.stats.package_map_export_prefixes_exact
        && packet_artifacts.partial_payloads_completed == pipeline.stats.partial_payloads_completed
        && packet_artifacts.batch_actor_count == actor_messages
        && packet_artifacts.batch_property_count == batch_properties
        && packet_artifacts.exact_bit_coverage == packet_artifacts.packet_count
        && compatibility_baseline_checks_pass(&documents.summary_document)
        && (!known_full_fixture
            || (actor_messages == 4_444
                && batch_properties == 4_442
                && non_batch_properties == 9
                && character_updates == 17_031
                && fresh_movement_updates == 16_953
                && carry_forward_updates == 78
                && auxiliary_events == 3
                && packet_artifacts.unresolved_span_count == 15_319
                && packet_artifacts.packets_sha256
                    == "5c42e45834fa21c47f7b4150c7cf145b82afbb289e15d70b1556910cca9a95a5"
                && packet_artifacts.unresolved_sha256
                    == "370111029a7592ce11ccf37b0990465896077a72aa00a749d21db85db5fa0954"));
    let report = NativeEventsReport {
        schema_version: "codev.rust-compatibility-decode/v1",
        status: "complete",
        artifact: "events.jsonl",
        completed_compatibility_artifacts: [
            "events.jsonl",
            "fields.json",
            "flow_manifest.json",
            "tcp_streams.json",
            "recovery_gate.json",
            "netguid.json",
            "packets.jsonl",
            "unresolved.jsonl",
            "match.json",
            "summary.json",
            "report.md",
        ],
        pcap_sha256,
        known_full_fixture,
        actor_messages,
        batch_properties,
        non_batch_properties,
        character_updates,
        fresh_movement_updates,
        carry_forward_updates,
        auxiliary_events,
        event_count: character_updates + auxiliary_events,
        packet_artifacts,
        validation_passed,
        incomplete_compatibility_artifacts: [],
    };
    Ok(report)
}

fn resolve_schema_file(path: &Path) -> Result<PathBuf, NativeEventsError> {
    if !path.is_dir() {
        return Ok(path.to_owned());
    }
    for name in ["decoder-schema.json", "fields.json"] {
        let candidate = path.join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(NativeEventsError::FieldSchema(format!(
        "schema directory {} contains neither decoder-schema.json nor fields.json",
        path.display()
    )))
}

fn load_field_specs(schema: Option<&Path>) -> Result<Vec<Value>, NativeEventsError> {
    let Some(schema) = schema else {
        return builtin_field_specs();
    };
    let root: FieldSchemaRoot = serde_json::from_reader(File::open(schema)?)?;
    match root {
        FieldSchemaRoot::Fields(fields) => validate_field_specs(fields),
        FieldSchemaRoot::Document(document) if document.inherit_builtin_fields => {
            if document
                .field_specs
                .is_some_and(|fields| !fields.is_empty())
            {
                return Err(NativeEventsError::FieldSchema(
                    "a schema inheriting built-in fields must omit field_specs or use an empty array"
                        .into(),
                ));
            }
            builtin_field_specs()
        }
        FieldSchemaRoot::Document(document) => {
            validate_field_specs(document.field_specs.ok_or_else(|| {
                NativeEventsError::FieldSchema("field_specs must be a JSON array".into())
            })?)
        }
    }
}

fn builtin_field_specs() -> Result<Vec<Value>, NativeEventsError> {
    let fields: Vec<Value> = serde_json::from_str(&embedded_fields_json()).map_err(|error| {
        NativeEventsError::FieldSchema(format!(
            "embedded 1.24.0.2911 field dictionary cannot be decoded: {error}"
        ))
    })?;
    validate_field_specs(fields)
}

fn validate_field_specs(fields: Vec<Value>) -> Result<Vec<Value>, NativeEventsError> {
    let mut identifiers = BTreeSet::new();
    for (index, field) in fields.iter().enumerate() {
        let object = field.as_object().ok_or_else(|| {
            NativeEventsError::FieldSchema(format!("field_specs[{index}] is not an object"))
        })?;
        let missing: Vec<_> = FIELD_KEYS
            .iter()
            .copied()
            .filter(|key| !object.contains_key(*key))
            .collect();
        if !missing.is_empty() {
            return Err(NativeEventsError::FieldSchema(format!(
                "field_specs[{index}] is missing {missing:?}"
            )));
        }
        let extra: Vec<_> = object
            .keys()
            .filter(|key| !FIELD_KEYS.contains(&key.as_str()))
            .collect();
        if !extra.is_empty() {
            return Err(NativeEventsError::FieldSchema(format!(
                "field_specs[{index}] has unsupported keys {extra:?}"
            )));
        }
        let field_id = object["field_id"]
            .as_str()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                NativeEventsError::FieldSchema(format!(
                    "field_specs[{index}].field_id must be a non-empty string"
                ))
            })?;
        if !identifiers.insert(field_id.to_owned()) {
            return Err(NativeEventsError::FieldSchema(format!(
                "duplicate field_id {field_id:?}"
            )));
        }
        let confidence = object["confidence"].as_str();
        if !matches!(
            confidence,
            Some("proven" | "high" | "medium" | "low" | "unknown")
        ) {
            return Err(NativeEventsError::FieldSchema(format!(
                "field_specs[{index}].confidence is invalid"
            )));
        }
        validate_optional_unsigned(object, index, "bit_offset", 0)?;
        validate_optional_unsigned(object, index, "bit_width", 1)?;
    }
    Ok(fields)
}

fn validate_optional_unsigned(
    object: &serde_json::Map<String, Value>,
    index: usize,
    name: &str,
    minimum: u64,
) -> Result<(), NativeEventsError> {
    let value = &object[name];
    if !value.is_null() && value.as_u64().is_none_or(|value| value < minimum) {
        return Err(NativeEventsError::FieldSchema(format!(
            "field_specs[{index}].{name} is invalid"
        )));
    }
    Ok(())
}

fn native_to_session_error(error: NativeEventsError) -> codev_stream::SessionError {
    match error {
        NativeEventsError::Io(error) => codev_stream::SessionError::Io(error),
        NativeEventsError::Json(error) => codev_stream::SessionError::Json(error),
        NativeEventsError::Session(error) => error,
        NativeEventsError::Source(error) => codev_stream::SessionError::Source(error),
        other => codev_stream::SessionError::Io(io::Error::other(other.to_string())),
    }
}

#[allow(clippy::too_many_arguments)]
fn write_actor_events(
    writer: &mut BufWriter<File>,
    auxiliary: &mut VecDeque<AuxiliaryVoiceEvent>,
    actor: A0Payload,
    actor_messages: &mut u64,
    batch_properties: &mut u64,
    non_batch_properties: &mut u64,
    character_updates: &mut u64,
    fresh_movement_updates: &mut u64,
    batch_slots: &mut u64,
    last_timestamp_ns: &mut u64,
    batch_summary: &mut BatchSummaryAccumulator,
) -> Result<(), NativeEventsError> {
    if actor.timestamp_ns < *last_timestamp_ns {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "actor timestamps are not monotonic",
        )
        .into());
    }
    while auxiliary
        .front()
        .is_some_and(|event| event.timestamp_ns <= actor.timestamp_ns)
    {
        write_auxiliary(writer, &auxiliary.pop_front().unwrap())?;
    }
    *last_timestamp_ns = actor.timestamp_ns;
    *actor_messages += 1;
    *batch_properties += u64::from(actor.summary.batch_property_count);
    *non_batch_properties += u64::from(actor.summary.raw_two_bit_property_count);
    batch_summary.observe_actor(&actor);
    let bunch_index = actor
        .bunch_index
        .ok_or(NativeEventsError::ReassembledActor(actor.capture_index))?;
    let wire_data_bit_offset = actor
        .wire_data_bit_offset
        .ok_or(NativeEventsError::ReassembledActor(actor.capture_index))?;
    for update in &actor.updates {
        *batch_slots |= 1_u64 << update.slot;
        let event = batch_event(&actor, update, bunch_index, wire_data_bit_offset);
        serde_json::to_writer(&mut *writer, &event)?;
        writer.write_all(b"\n")?;
        *character_updates += 1;
        *fresh_movement_updates += u64::from(update.fresh_movement());
    }
    Ok(())
}

fn batch_event(
    actor: &A0Payload,
    update: &codev_protocol::D0Update,
    bunch_index: usize,
    wire_data_bit_offset: usize,
) -> CompatibilityEvent<BatchFields> {
    CompatibilityEvent {
        event_type: "batch_character_state_update",
        timestamp: timestamp_seconds(actor.timestamp_ns),
        fields: BatchFields {
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
            wire_bit_offset: wire_data_bit_offset + update.bit_offset,
            bit_length: update.bit_length,
            position_changed: update.fresh_movement(),
            position: unit_vector(update.state.position),
            state: compatibility_state(update.state),
            movement: update
                .movement
                .map(|movement| compatibility_movement(movement, wire_data_bit_offset)),
            extra_state: update.extra_state,
            channel_index: actor.channel_index,
            bunch_index,
            packet_sequence_raw: actor.packet_sequence & 0x3fff,
            coordinate_semantics: "actor_world_location_at_0.1_unreal_world_unit",
            coordinate_confidence: "proven",
            identity_confidence: "unknown",
            ida_evidence: IDA_EVIDENCE,
        },
        source_packets: [actor.capture_index + 1],
        confidence: "proven",
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

fn compatibility_movement(
    value: MovementUpdate,
    wire_data_bit_offset: usize,
) -> CompatibilityMovement {
    CompatibilityMovement {
        kind: match value.kind {
            MovementKind::Full => "full",
            MovementKind::Minimal => "minimal",
        },
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_bit_offset + value.bit_offset,
        bit_length: value.bit_length,
        position: compatibility_vector(value.position, wire_data_bit_offset),
        velocity: compatibility_vector(value.velocity, wire_data_bit_offset),
        acceleration: value
            .acceleration
            .map(|field| compatibility_vector(field, wire_data_bit_offset)),
        rotation: value
            .rotation
            .map(|field| compatibility_rotator(field, wire_data_bit_offset)),
    }
}

fn compatibility_vector(value: VectorField, wire_data_bit_offset: usize) -> CompatibilityVector {
    CompatibilityVector {
        x: value.value.x,
        y: value.value.y,
        z: value.value.z,
        unit: "Unreal_world_unit",
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_bit_offset + value.bit_offset,
        bit_length: value.bit_length,
        quantization_decimals: value.quantization_decimals,
        absolute_xy: value.absolute_xy,
        xy_width: value.xy_width,
        z_width: value.z_width,
    }
}

fn compatibility_rotator(value: RotatorField, wire_data_bit_offset: usize) -> CompatibilityRotator {
    CompatibilityRotator {
        degrees: value.value_degrees.as_array(),
        bit_offset: value.bit_offset,
        wire_bit_offset: wire_data_bit_offset + value.bit_offset,
        bit_length: value.bit_length,
    }
}

fn write_auxiliary(
    writer: &mut BufWriter<File>,
    event: &AuxiliaryVoiceEvent,
) -> Result<(), NativeEventsError> {
    serde_json::to_writer(
        &mut *writer,
        &CompatibilityEvent {
            event_type: "voice_room_info",
            timestamp: timestamp_seconds(event.timestamp_ns),
            fields: VoiceFields { room: &event.room },
            source_packets: [event.source_packet],
            confidence: "proven",
        },
    )?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub(crate) fn endpoint(address: &str, port: u16) -> Option<Endpoint> {
    let ip = address.parse::<IpAddr>().ok()?;
    Some(Endpoint {
        ip: match ip {
            IpAddr::V4(value) => IpAddress::V4(value.octets()),
            IpAddr::V6(value) => IpAddress::V6(value.octets()),
        },
        port,
    })
}

pub(crate) fn find_selected_flow(
    pcap: &Path,
    advertised_server: Option<Endpoint>,
    server_port: u16,
) -> Result<SelectedUdpFlow, NativeEventsError> {
    let mut source = S0PcapSource::open(pcap)?;
    let mut candidates = HashMap::<(Endpoint, Endpoint), u64>::new();
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        let candidate = if advertised_server == Some(transport.destination)
            || (advertised_server.is_none() && transport.destination.port == server_port)
        {
            Some((transport.source, transport.destination))
        } else if advertised_server == Some(transport.source)
            || (advertised_server.is_none() && transport.source.port == server_port)
        {
            Some((transport.destination, transport.source))
        } else {
            None
        };
        if let Some(candidate) = candidate {
            *candidates.entry(candidate).or_default() += 1;
        }
    }
    let maximum = candidates.values().copied().max().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "authenticated UDP endpoint is absent from capture",
        )
    })?;
    let mut winners = candidates
        .into_iter()
        .filter(|(_, count)| *count == maximum)
        .map(|(flow, _)| flow);
    let (client, server) = winners.next().expect("maximum came from one candidate");
    if winners.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "authenticated UDP port has equally-sized competing tuples",
        )
        .into());
    }
    Ok(SelectedUdpFlow::for_endpoints(client, server))
}

pub(crate) fn sha256_file(path: &Path) -> io::Result<String> {
    let mut input = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn timestamp_seconds(timestamp_ns: u64) -> f64 {
    (timestamp_ns / 1_000_000_000) as f64 + (timestamp_ns % 1_000_000_000) as f64 / 1_000_000_000.0
}

fn compatibility_baseline_checks_pass(summary: &Value) -> bool {
    summary
        .get("baseline_checks")
        .and_then(Value::as_object)
        .is_some_and(|checks| {
            checks.iter().all(|(name, value)| {
                if matches!(name.as_str(), "known_udp_fixture" | "known_full_fixture") {
                    return value.is_boolean();
                }
                value.as_bool() == Some(true)
                    || value.get("status").and_then(Value::as_str) == Some("not_applicable")
            })
        })
}

fn write_json_atomic<T: Serialize>(
    output: &Path,
    name: &str,
    value: &T,
) -> Result<(), NativeEventsError> {
    let temporary =
        TemporaryArtifact::new(output.join(format!(".{name}.{:032x}.tmp", rand::random::<u128>())));
    let mut writer = BufWriter::new(open_private(&temporary.path, true)?);
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    drop(writer);
    temporary.commit(&output.join(name))?;
    Ok(())
}

fn write_text_atomic(output: &Path, name: &str, value: &str) -> Result<(), NativeEventsError> {
    let temporary =
        TemporaryArtifact::new(output.join(format!(".{name}.{:032x}.tmp", rand::random::<u128>())));
    let mut writer = BufWriter::new(open_private(&temporary.path, true)?);
    writer.write_all(value.as_bytes())?;
    writer.flush()?;
    drop(writer);
    temporary.commit(&output.join(name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    use codev_protocol::{D0Decoder, DecodeScratch};
    use codev_stream::Direction;

    #[test]
    fn timestamp_conversion_matches_python_integer_true_division() {
        assert_eq!(
            timestamp_seconds(1_785_975_843_847_207_000),
            1_785_975_843.847_207
        );
    }

    #[test]
    fn embedded_field_dictionary_is_version_pinned_and_strictly_valid() {
        assert_eq!(
            format!("{:x}", Sha256::digest(embedded_fields_json_bytes())),
            "217018bf7a167ab7d65ca9c019c088ae3783521071fc5196e20683997ed91a32"
        );
        let fields = builtin_field_specs().unwrap();
        assert_eq!(fields.len(), 146);
        assert_eq!(
            fields.first().unwrap()["field_id"],
            "codev.outer.client.watermark_crc32c_raw"
        );
        assert_eq!(
            fields.last().unwrap()["field_id"],
            "codev.batch_sync.batch.extra_state"
        );
        assert!(
            fields
                .iter()
                .any(|field| { field["field_id"] == "codev.batch_sync.actor.handle_5_value" })
        );
        assert!(
            fields
                .iter()
                .any(|field| { field["field_id"] == "codev.batch_sync.actor.property_terminator" })
        );
    }

    #[test]
    fn field_validation_matches_python_schema_boundaries() {
        let valid = builtin_field_specs().unwrap().remove(0);
        assert!(validate_field_specs(vec![valid.clone()]).is_ok());

        let mut duplicate = valid.clone();
        duplicate["name"] = Value::String("other_name".into());
        let error = validate_field_specs(vec![valid.clone(), duplicate]).unwrap_err();
        assert!(error.to_string().contains("duplicate field_id"));

        let mut extra = valid.clone();
        extra["not_in_contract"] = Value::Bool(true);
        let error = validate_field_specs(vec![extra]).unwrap_err();
        assert!(error.to_string().contains("unsupported keys"));

        let mut zero_width = valid;
        zero_width["bit_width"] = Value::from(0);
        let error = validate_field_specs(vec![zero_width]).unwrap_err();
        assert!(error.to_string().contains("bit_width is invalid"));
    }

    #[test]
    fn real_native_sink_writes_all_private_atomic_compatibility_artifacts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        let session = root.join("work/session-20260806/session.json");
        if !pcap.is_file() || !session.is_file() {
            return;
        }
        let output = std::env::temp_dir().join(format!(
            "codev-native-field-artifact-test-{:032x}",
            rand::random::<u128>()
        ));
        let report = write_native_events(&pcap, Some(&session), &output).unwrap();
        assert!(report.validation_passed);
        assert_eq!(
            report.completed_compatibility_artifacts,
            [
                "events.jsonl",
                "fields.json",
                "flow_manifest.json",
                "tcp_streams.json",
                "recovery_gate.json",
                "netguid.json",
                "packets.jsonl",
                "unresolved.jsonl",
                "match.json",
                "summary.json",
                "report.md"
            ]
        );
        for completed in report.completed_compatibility_artifacts {
            assert!(
                !report
                    .incomplete_compatibility_artifacts
                    .contains(&completed)
            );
        }
        let actual: Vec<Value> =
            serde_json::from_reader(File::open(output.join("fields.json")).unwrap()).unwrap();
        assert_eq!(actual, builtin_field_specs().unwrap());
        let gate_oracle = root.join("analysis/v2/recovery-gate-1.24.0.2911.json");
        if gate_oracle.is_file() {
            let actual = std::fs::read(output.join("recovery_gate.json")).unwrap();
            let expected = std::fs::read(gate_oracle).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                format!("{:x}", Sha256::digest(&actual)),
                "d20b65648eb9ca6ea378a5509f55776c9e3c4b242ca62fbcff0a6a8d5dbe9bed"
            );
        }
        let netguid_oracle = root.join("work/oracle-v2-full-20260815-session/netguid.json");
        if netguid_oracle.is_file() {
            assert_eq!(
                std::fs::read(output.join("netguid.json")).unwrap(),
                std::fs::read(netguid_oracle).unwrap()
            );
        }
        assert!(std::fs::read_dir(&output).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".tmp")
        }));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for artifact in report.completed_compatibility_artifacts {
                assert_eq!(
                    output
                        .join(artifact)
                        .metadata()
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
        std::fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn first_real_batch_event_matches_legacy_field_and_type_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let messages = root.join("work/session-20260806/unreal-messages.jsonl");
        let legacy = root.join("output-20260806-formal/events.jsonl");
        if !messages.is_file() || !legacy.is_file() {
            return;
        }

        let mut decoder = D0Decoder::new();
        let mut scratch = DecodeScratch::with_capacity(2, 16);
        let mut bytes = Vec::new();
        let mut selected = None;
        for line in BufReader::new(File::open(messages).unwrap()).lines() {
            let row: Value = serde_json::from_str(&line.unwrap()).unwrap();
            if row["channel_index"] != 32 || row["open"] == true {
                continue;
            }
            decode_hex(row["data_hex"].as_str().unwrap(), &mut bytes);
            let summary = decoder
                .decode_actor_message_into(
                    &bytes,
                    row["data_bit_length"].as_u64().unwrap() as usize,
                    &mut scratch,
                )
                .unwrap();
            if scratch.updates.is_empty() {
                continue;
            }
            selected = Some(A0Payload {
                direction: Direction::ServerToClient,
                capture_index: row["pcap_frame"].as_u64().unwrap() - 1,
                timestamp_ns: row["timestamp_ns"].as_u64().unwrap(),
                packet_sequence: row["packet_sequence"].as_u64().unwrap(),
                channel_index: 32,
                channel_generation: 1,
                source_capture_indices: vec![row["pcap_frame"].as_u64().unwrap() - 1],
                bunch_index: Some(row["bunch_index"].as_u64().unwrap() as usize),
                // Independently retained wire metadata from the historical
                // bit-exact packet artifact; the update begins at 3339.
                wire_data_bit_offset: Some(3_298),
                data: bytes.clone(),
                bit_length: row["data_bit_length"].as_u64().unwrap() as usize,
                summary,
                properties: scratch.properties.clone(),
                updates: scratch.updates.clone(),
                camp_assignments: Vec::new(),
                local_anchor_spawn: None,
            });
            break;
        }
        let actor = selected.expect("private fixture contains a first coordinate update");
        let actual = serde_json::to_value(batch_event(
            &actor,
            &actor.updates[0],
            actor.bunch_index.unwrap(),
            actor.wire_data_bit_offset.unwrap(),
        ))
        .unwrap();
        let expected = BufReader::new(File::open(legacy).unwrap())
            .lines()
            .map(|line| serde_json::from_str::<Value>(&line.unwrap()).unwrap())
            .find(|event| event["event_type"] == "batch_character_state_update")
            .unwrap();
        assert_eq!(actual, expected);
    }

    fn decode_hex(value: &str, output: &mut Vec<u8>) {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid hex"),
            }
        }
        output.clear();
        output.extend(
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| nibble(pair[0]) << 4 | nibble(pair[1])),
        );
    }
}
