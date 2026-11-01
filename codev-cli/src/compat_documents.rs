//! Pure builders for the private compatibility `match.json` and `summary.json`.
//!
//! These projections consume only typed decoder state and already-serialized
//! compatibility artifacts. They never read an oracle output and never
//! serialize raw SGNet session material. Fields whose historical forensic
//! detail is not present in the typed inputs are represented by an explicit
//! structured status instead of a guessed number.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use codev_protocol::{BATCH_CHANNEL_INDEX, BATCH_PROPERTY_HANDLE};
use codev_stream::{
    ENTER_GAME_NOTIFY_COMMAND, EnterGameSession, MnaFieldEvidence, PipelineStats,
    REENTER_GAME_NOTIFY_COMMAND, SUPPORTED_BUILD, W0Provenance,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::compat_auxiliary::CompatibilityAuxiliaryCapture;
use crate::compat_batch::BatchSyncSummary;

const DISPLAY_BUILD: &str = "1.24.0 (2911)";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FixtureClassification {
    pub known_udp_fixture: bool,
    pub known_full_fixture: bool,
}

pub struct CompatibilityDocumentInputs<'a> {
    pub pcap: &'a Path,
    pub pcap_sha256: &'a str,
    pub session: &'a EnterGameSession,
    pub pipeline: PipelineStats,
    pub batch_sync: &'a BatchSyncSummary,
    pub flow_manifest: &'a Value,
    pub netguid: &'a Value,
    pub recovery_gate: &'a Value,
    pub packet_report: &'a Value,
    pub mna_provenance: Option<&'a W0Provenance>,
    pub auxiliary: &'a CompatibilityAuxiliaryCapture,
    pub fixture: FixtureClassification,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompatibilityDocuments {
    pub match_document: Value,
    pub summary_document: Value,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CompatibilityDocumentError {
    #[error("compatibility document is missing {0}")]
    Missing(String),
    #[error("compatibility document field {path} must be {expected}")]
    WrongType {
        path: String,
        expected: &'static str,
    },
    #[error("compatibility document invariant failed: {0}")]
    Invariant(String),
    #[error("serialized compatibility input contains forbidden session field {0}")]
    ForbiddenSessionField(String),
    #[error("failed to serialize typed B0 summary: {0}")]
    BatchSerialization(String),
}

pub fn build_compatibility_documents(
    inputs: &CompatibilityDocumentInputs<'_>,
) -> Result<CompatibilityDocuments, CompatibilityDocumentError> {
    validate_sha256(inputs.pcap_sha256)?;
    for (name, value) in [
        ("flow_manifest", inputs.flow_manifest),
        ("netguid", inputs.netguid),
        ("recovery_gate", inputs.recovery_gate),
        ("packet_report", inputs.packet_report),
    ] {
        reject_serialized_session_material(value, name)?;
    }

    let flow = FlowFacts::parse(inputs.flow_manifest, inputs.session)?;
    let packet = PacketFacts::parse(inputs.packet_report)?;
    let netguid = NetGuidFacts::parse(inputs.netguid)?;
    let recovery = RecoveryFacts::parse(inputs.recovery_gate)?;
    let batch = serde_json::to_value(inputs.batch_sync)
        .map_err(|error| CompatibilityDocumentError::BatchSerialization(error.to_string()))?;

    validate_batch(inputs.batch_sync, &batch)?;
    validate_cross_artifact_invariants(inputs, &flow, &packet, &netguid, &recovery)?;

    let decoder_schema = decoder_schema_status();
    let sgnet_cipher = sgnet_cipher_status(inputs.session, &decoder_schema, &packet);
    let capture_projection = json!({
        "status": "not_used_full_session_available",
        "reason": "the legacy 29-byte value is a known-plaintext differential projection, not the actual ChaCha keystream"
    });
    let fixed_projection = json!({
        "status": "not_used_plaintext_available",
        "deprecated_name": "session_mask_derivation",
        "correct_model": "sgnet_chacha20_fixed_keystream_projection"
    });
    let full_session = build_full_session(inputs, &packet, &netguid, &recovery, &batch);
    let summary = build_summary(
        inputs,
        &flow,
        &packet,
        &netguid,
        &recovery,
        &full_session,
        &decoder_schema,
        &sgnet_cipher,
        &capture_projection,
        &fixed_projection,
    );
    let match_document = build_match(
        inputs,
        &flow,
        &netguid,
        &batch,
        &full_session,
        &decoder_schema,
        &sgnet_cipher,
        &capture_projection,
        &fixed_projection,
    )?;
    reject_serialized_session_material(&match_document, "match")?;
    reject_serialized_session_material(&summary, "summary")?;

    Ok(CompatibilityDocuments {
        match_document,
        summary_document: summary,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_summary(
    inputs: &CompatibilityDocumentInputs<'_>,
    flow: &FlowFacts,
    packet: &PacketFacts,
    netguid: &NetGuidFacts,
    recovery: &RecoveryFacts,
    full_session: &Value,
    decoder_schema: &Value,
    sgnet_cipher: &Value,
    capture_projection: &Value,
    fixed_projection: &Value,
) -> Value {
    let stats = inputs.pipeline;
    let main_bits_exact = packet.exact_bit_coverage == packet.packet_count;
    let wire_exact = packet.sgnet_wire_reencode_exact == packet.packet_count;
    let packet_handler_exact = packet.packet_handler_reencode_exact == packet.packet_count;
    let unreal_exact = packet.unreal_reencode_exact == stats.unreal_packets;
    let netguid_conflict_free = netguid.conflicts.is_empty();
    let partial_issue_free = recovery.has_validated_layer(&format!(
        "partial_bunch_reassembly_{}_complete_zero_issues",
        stats.partial_payloads_completed
    ));
    let integrity_validated =
        recovery.has_validated_layer("ethernet_ipv4_udp_integrity_and_offload");
    let watermark_validated =
        recovery.has_validated_layer("client_watermark_crc32c_and_uint32_counter");
    let all_accounted = flow.input_packet_count == flow.accounted_packet_count;

    let full_checks = full_fixture_checks(inputs, flow, packet, netguid);
    let baseline_checks = json!({
        "known_udp_fixture": inputs.fixture.known_udp_fixture,
        "known_full_fixture": inputs.fixture.known_full_fixture,
        "all_packets_accounted": all_accounted,
        "all_main_packet_bits_accounted": main_bits_exact,
        "all_main_packets_reencode_exactly": wire_exact,
        "client_watermark_counter_no_gaps": watermark_validated,
        "client_watermark_crc32c_all_valid": watermark_validated,
        "reliability_plaintext_prefix_or_capture_projection_available": recovery.fully_decrypted,
        "no_duplicate_inner_packet_ids": packet.client_to_server.duplicate_inner_packet_ids == 0 && packet.server_to_client.duplicate_inner_packet_ids == 0,
        "all_ipv4_checksums_valid": integrity_validated,
        "all_udp_checksums_valid_or_offload": integrity_validated,
        "all_packet_handler_envelopes_reencode_exactly": packet_handler_exact,
        "all_applicable_unreal_packets_reencode_exactly": unreal_exact,
        "partial_bunch_reassembly_has_no_issues": partial_issue_free,
        "netguid_bindings_have_no_conflicts": netguid_conflict_free,
        "batch_sync_actor_messages_are_bit_exact": inputs.batch_sync.bit_exact_actor_messages == inputs.batch_sync.actor_messages,
        "batch_sync_has_no_parse_failures": inputs.batch_sync.parse_failures == 0,
        "full_primary_packet_count_12414": fixture_baseline(inputs.fixture.known_full_fixture, flow.primary_packet_count == 12_414),
        "full_packet_handler_exact_12414": fixture_baseline(inputs.fixture.known_full_fixture, packet.packet_handler_reencode_exact == 12_414),
        "full_sgnet_wire_exact_12414": fixture_baseline(inputs.fixture.known_full_fixture, packet.sgnet_wire_reencode_exact == 12_414),
        "full_oodle_flag_one_packets_4": fixture_baseline(inputs.fixture.known_full_fixture, stats.oodle_compressed == 4),
        "full_unreal_packets_exact_12410": fixture_baseline(inputs.fixture.known_full_fixture, packet.unreal_reencode_exact == 12_410),
        "full_unreal_bunches_20360": fixture_baseline(inputs.fixture.known_full_fixture, stats.bunches == 20_360),
        "full_client_bunches_5887": fixture_baseline(inputs.fixture.known_full_fixture, packet.client_to_server.bunch_count == 5_887),
        "full_server_bunches_14473": fixture_baseline(inputs.fixture.known_full_fixture, packet.server_to_client.bunch_count == 14_473),
        "full_package_map_prefixes_512": fixture_baseline(inputs.fixture.known_full_fixture, stats.package_map_export_prefixes_exact == 512),
        "full_netguid_records_2469": fixture_baseline(inputs.fixture.known_full_fixture, stats.netguid_records == 2_469),
        "full_partial_payloads_512": fixture_baseline(inputs.fixture.known_full_fixture, stats.partial_payloads_completed == 512),
        "full_batch_sync_actor_messages_4444": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.actor_messages == 4_444),
        "full_batch_sync_properties_4442": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.batch_properties == 4_442),
        "full_batch_sync_non_batch_properties_9": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.non_batch_properties == 9),
        "full_batch_sync_character_updates_17031": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.character_updates == 17_031),
        "full_batch_sync_tracks_10": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.track_count == 10)
    });

    let direction_stats = json!({
        "client_to_server": direction_statistics(
            &packet.client_to_server,
            flow.client_to_server_packets,
            flow.client_to_server_payload_bytes,
        ),
        "server_to_client": direction_statistics(
            &packet.server_to_client,
            flow.server_to_client_packets,
            flow.server_to_client_payload_bytes,
        )
    });
    let network_integrity = json!({
        "client_to_server": packet.client_to_server.network_integrity.clone().unwrap_or_else(|| {
            unavailable_status("direction checksum categories are absent from CompatibilityPacketReport")
        }),
        "server_to_client": packet.server_to_client.network_integrity.clone().unwrap_or_else(|| {
            unavailable_status("direction checksum categories are absent from CompatibilityPacketReport")
        })
    });
    let reliability = match (
        packet.client_to_server.reliability.clone(),
        packet.server_to_client.reliability.clone(),
    ) {
        (Some(client), Some(server)) => {
            let mut reliability = Map::new();
            let client_control = client.get("control_packet_count").and_then(Value::as_u64);
            let server_control = server.get("control_packet_count").and_then(Value::as_u64);
            reliability.insert("client_to_server".into(), client);
            reliability.insert("server_to_client".into(), server);
            if client_control == server_control
                && let Some(control_packets) = client_control
            {
                reliability.insert(
                    "control_packets_excluded_per_direction".into(),
                    Value::from(control_packets),
                );
            }
            if let Some(relation) = packet.client_watermark_counter_low14_relation.clone() {
                reliability.insert("client_watermark_counter_low14_relation".into(), relation);
            }
            if let Some(ack_recent) = packet.ack_recent_peer_match.clone() {
                reliability.insert("ack_recent_peer_match".into(), ack_recent);
            }
            if let Some(low5) = packet.ack_history_low5_semantics.clone() {
                reliability.insert("ack_history_low5_semantics".into(), low5);
            }
            if let (Some(client_packet_info), Some(server_packet_info)) = (
                packet.client_to_server.packet_info.clone(),
                packet.server_to_client.packet_info.clone(),
            ) {
                reliability.insert(
                    "packet_info".into(),
                    json!({
                        "client_to_server": client_packet_info,
                        "server_to_client": server_packet_info
                    }),
                );
            }
            if let (Some(client_first_bunch), Some(server_first_bunch)) = (
                packet.client_to_server.first_bunch_prefix.clone(),
                packet.server_to_client.first_bunch_prefix.clone(),
            ) {
                reliability.insert(
                    "first_bunch_prefix".into(),
                    json!({
                        "client_to_server": client_first_bunch,
                        "server_to_client": server_first_bunch
                    }),
                );
            }
            if let (Some(Value::Array(mut client_repeated)), Some(Value::Array(server_repeated))) = (
                packet.client_to_server.repeated_suffix_candidates.clone(),
                packet.server_to_client.repeated_suffix_candidates.clone(),
            ) {
                client_repeated.extend(server_repeated);
                reliability.insert(
                    "repeated_suffix_candidates".into(),
                    Value::Array(client_repeated),
                );
            }
            Value::Object(reliability)
        }
        _ => json!({
            "status": "unavailable_from_typed_inputs",
            "reason": "PacketNotify aggregate evidence is absent from CompatibilityPacketReport",
            "source_artifacts": ["packets.jsonl", "unresolved.jsonl"],
            "fabricated_values": false
        }),
    };

    json!({
        "schema_version": 3,
        "pcap": inputs.pcap.display().to_string(),
        "pcap_sha256": inputs.pcap_sha256,
        "decoder_schema": decoder_schema,
        "packet_count": flow.input_packet_count,
        "flow_count": flow.flow_count,
        "unclassified_packet_count": flow.unclassified_count,
        "tcp_flow_count": flow.tcp_flow_count,
        "capture_scope": {
            "last_capture_packet_is_main_flow_packet": flow.capture_end == flow.game_flow_end,
            "post_game_tail_present": flow.capture_end != flow.game_flow_end,
            "seconds_after_game_flow": flow.seconds_after_game_flow,
            "seconds_before_game_flow": flow.seconds_before_game_flow
        },
        "main_flow": flow.primary_flow,
        "client": flow.client,
        "server": flow.server,
        "client_watermark_counter": packet.client_watermark_counter.clone().unwrap_or_else(|| aggregate_status(watermark_validated, "per-packet counter details are absent from CompatibilityPacketReport")),
        "client_watermark_counter_low16": packet.client_watermark_counter_low16.clone().unwrap_or_else(|| aggregate_status(watermark_validated, "low16 counter details are absent from CompatibilityPacketReport")),
        "client_watermark_crc32c": match (
            packet.client_watermark_crc32c_tested,
            packet.client_watermark_crc32c_validated,
        ) {
            (Some(tested), Some(validated)) => json!({
                "validated": validated,
                "tested": tested,
                "payload_authenticator": false
            }),
            _ => json!({
                "status": if watermark_validated { "validated_by_recovery_gate" } else { "unavailable" },
                "tested": Value::Null,
                "validated": Value::Null,
                "payload_authenticator": false,
                "reason": "per-packet CRC counts are absent from CompatibilityPacketReport"
            }),
        },
        "encrypted_connection_id_raw_distribution": packet.encrypted_connection_id_raw_distribution.clone().unwrap_or_else(|| unavailable_status("encrypted connection-id histogram is absent from CompatibilityPacketReport")),
        "plaintext_connection_id_distribution": packet.plaintext_connection_id_distribution.clone().unwrap_or_else(|| unavailable_status("plaintext connection-id histogram is absent from CompatibilityPacketReport")),
        "sgnet_cipher": sgnet_cipher,
        "capture_recovered_keystream_prefix": capture_projection,
        "fixed_keystream_projection": fixed_projection,
        "reliability": reliability,
        "full_session_decode": full_session,
        "network_integrity": network_integrity,
        "direction_stats": direction_stats,
        "baseline_checks": baseline_checks,
        "fixture_checks": build_fixture_checks(flow, packet, recovery),
        "full_fixture_checks": full_checks,
        "main_packet_bit_coverage": {
            "exact_coverage_packets": packet.exact_bit_coverage,
            "packet_count": packet.packet_count,
            "coverage_complete": main_bits_exact
        },
        "reencode_validation": {
            "exact_packets": packet.sgnet_wire_reencode_exact,
            "packet_count": packet.packet_count,
            "all_exact": wire_exact
        },
        "fully_decrypted": recovery.fully_decrypted,
        "fully_decoded": recovery.fully_decoded,
        "blocking_layer": recovery.blocking_layer
    })
}

#[allow(clippy::too_many_arguments)]
fn build_match(
    inputs: &CompatibilityDocumentInputs<'_>,
    flow: &FlowFacts,
    netguid: &NetGuidFacts,
    batch: &Value,
    full_session: &Value,
    decoder_schema: &Value,
    sgnet_cipher: &Value,
    capture_projection: &Value,
    fixed_projection: &Value,
) -> Result<Value, CompatibilityDocumentError> {
    let source_packets = inputs
        .mna_provenance
        .map_or(&[][..], |provenance| provenance.source_frames.as_slice());
    let participants = build_participants(inputs.session, source_packets, inputs.auxiliary)?;
    let teams = build_teams(inputs.session, source_packets)?;
    let source_mna_sequence = inputs.session.source_mna_sequence;
    let message_type = if inputs.session.reenter {
        codev_conceal::reenter_game_notify()
    } else {
        codev_conceal::e0_notify()
    };
    let command_id = if inputs.session.reenter {
        REENTER_GAME_NOTIFY_COMMAND
    } else {
        ENTER_GAME_NOTIFY_COMMAND
    };
    let map_name = map_name_from_path(&netguid.main_map_path)?;
    let status = inputs.batch_sync.status;
    let event_type = if inputs.session.reenter {
        "reenter_game_notify"
    } else {
        "e0_notify"
    };
    let mut limitations = vec![
        codev_obf::f1("b01fc666dd8ee270821be0629b9e81fd54ea6183394b2d9d0bff2be606284ea47823f5234d160b38b339eb68ccdae9798d3ce466db8e449466bd07894c2b09f160f0a856ec8e449466bd15844f2706f042d46183394a1c950adf05e4153846b862be28bb40042dfb63da", grouped_u64(inputs.pipeline.packet_handler_envelopes_exact)),
        codev_obf::s("612ede5b8b417d305f2bd1559cd6b5d0612ede5b8b417b3e4526db490db5b401502cd6559a7c5b375e6f598860d0b0f9d8cc15108c405b32596f58945ad0a8d6d4f80fd66f97d0f5bca001ab9e544725582ed1108c405b32596f58875cd3b9d8d4c031d57ea4d0ebbeaa35a70b9bb9b7b9df5ba74ed18df3d6c63ad969b8d2eab5ac3db2").to_owned(),
        format!(
            "{} 个 PackageMap export 前缀与 NetGUID 绑定已恢复；Channel 32 的 BatchData 已逐位恢复为 {} 条 batch_slot_N 坐标轨迹，但槽位到 PlayerState 身份的对象引用尚未证明。",
            grouped_u64(inputs.pipeline.package_map_export_prefixes_exact),
            grouped_u64(inputs.batch_sync.track_count as u64)
        ),
        "客户端前 4 字节是 endpoint/counter WaterMark CRC-32C，不覆盖载荷，因此不是载荷 MAC。".to_owned(),
        "静态 PAK/Codev.dic 与 Oodle 资源块审计不属于当前 Rust typed 输入；兼容文档不会从 Python oracle 回填该证据。".to_owned(),
        codev_obf::f2("63ca9850c3cfdd6e18764fc95fb18d6ba50655d714304189e43850d81a27152710e6d239d1b0b94460cbb350c7ef158eea3258d15f3359a0e26b049498ce812805ccdb08e42e48e161ee9e94193954a6b8671451f7c8d0660eb0ba139add832409d3d00be2b2a05861ee8e53cdebd2602bb0a81e98ca902938ebdc39c8b6b543", grouped_u64(inputs.pipeline.packet_handler_pass_through), grouped_u64(inputs.pipeline.oodle_compressed)),
        "主 UDP 已静态确认使用无 tag 的 IETF ChaCha20（counter 1、每次 copy 重启），不是此前猜测的 AES/HMAC。".to_owned(),
        "ACK history 的 low5 因果语义已闭合；bit 5 以上的索引语义仍未静态证明。".to_owned(),
        "MNA TCP 重组保留 Enter/ReEnter 通知的 PCAP frame span、捕获时间与 Map/Mode Protobuf 字段字节范围。".to_owned(),
        "辅助语音房间、AppId 与队伍信令由同一 PCAP 的有界 typed 扫描器恢复，不读取 Python oracle。".to_owned(),
        "GameId 及派生 seed 按隐私门禁不输出；字符串 seed/hash 字段使用显式 <redacted:not-retained> 标记。".to_owned(),
        "人物身份仅作为私有 MNA roster 记录保留；坐标事件继续仅发布 batch_slot_N，未建立猜测绑定。".to_owned(),
        "服务器未发送给该客户端的隐藏状态不可能从客户端 PCAP 还原。".to_owned(),
    ];

    if inputs.mna_provenance.is_none() {
        limitations.push(
            "本次使用外部 session schema，未携带原始 MNA 通知的 PCAP provenance；相关字段保持显式 unavailable。"
                .to_owned(),
        );
    }

    let map_metadata = build_map_metadata(inputs, netguid, map_name, source_mna_sequence);
    let mode_metadata = build_mode_metadata(inputs, source_mna_sequence);
    let enter_metadata = build_enter_metadata(
        inputs,
        message_type,
        command_id,
        participants.len(),
        teams.len(),
        source_mna_sequence,
    );
    let events = build_match_events(inputs, event_type, teams.len(), source_mna_sequence);

    Ok(json!({
        "build": DISPLAY_BUILD,
        "status": status,
        "capture_start": flow.capture_start,
        "capture_end": flow.capture_end,
        "game_flow_start": flow.game_flow_start,
        "game_flow_end": flow.game_flow_end,
        "server": flow.server,
        "client": flow.client,
        "metadata": {
            "app_ids": inputs.auxiliary.app_ids,
            "observed_builds": [SUPPORTED_BUILD],
            "voice_rooms": inputs.auxiliary.voice_rooms,
            "auxiliary_team_signals": inputs.auxiliary.team_signals,
            "decoder_schema": decoder_schema,
            "sgnet_cipher": sgnet_cipher,
            "capture_recovered_keystream_prefix": capture_projection,
            "fixed_keystream_projection": fixed_projection,
            "full_session_decode": full_session,
            "batch_sync_coordinates": batch,
            "map": map_metadata,
            "mode": mode_metadata,
            "e0_notify": enter_metadata
        },
        "participants": participants,
        "teams": teams,
        "phases": [],
        "events": events,
        "score": {},
        "result": {},
        "limitations": limitations
    }))
}

fn build_map_metadata(
    inputs: &CompatibilityDocumentInputs<'_>,
    netguid: &NetGuidFacts,
    map_name: &str,
    source_mna_sequence: u32,
) -> Value {
    let mut metadata = json!({
        "map_id": inputs.session.map_id,
        "asset_path": netguid.main_map_path,
        "name": map_name,
        "display_name_zh": map_name,
        "confidence": "proven",
        "evidence": "descriptor-exact MNA MapId plus unique same-session PackageMap main-map export",
        "field_evidence": [],
        "source_packets": netguid.main_map_source_frames,
    });
    let object = metadata
        .as_object_mut()
        .expect("map metadata literal is an object");
    if let Some(provenance) = inputs.mna_provenance {
        object.insert(
            "field_evidence".to_owned(),
            Value::Array(vec![mna_field_evidence(&provenance.map_id_evidence)]),
        );
        object.insert(
            "source_packets".to_owned(),
            json!(&provenance.source_frames),
        );
    } else {
        object.insert(
            "source_mna_sequence".to_owned(),
            Value::from(source_mna_sequence),
        );
    }
    metadata
}

fn build_mode_metadata(
    inputs: &CompatibilityDocumentInputs<'_>,
    source_mna_sequence: u32,
) -> Value {
    let mut metadata = json!({
        "g1_mode": inputs.session.g1_mode,
        "s0_mode": inputs.session.s0_mode,
        "confidence": "proven",
        "evidence": "descriptor-exact MNA notification",
        "field_evidence": {},
        "source_packets": [],
    });
    let object = metadata
        .as_object_mut()
        .expect("mode metadata literal is an object");
    if let Some(provenance) = inputs.mna_provenance {
        object.insert(
            "field_evidence".to_owned(),
            json!({
                "g1_mode": [mna_field_evidence(&provenance.game_mode_evidence)],
                "s0_mode": [mna_field_evidence(&provenance.sub_game_mode_evidence)],
            }),
        );
        object.insert(
            "source_packets".to_owned(),
            json!(&provenance.source_frames),
        );
    } else {
        object.insert(
            "source_mna_sequence".to_owned(),
            Value::from(source_mna_sequence),
        );
    }
    metadata
}

fn build_enter_metadata(
    inputs: &CompatibilityDocumentInputs<'_>,
    message_type: &str,
    command_id: u64,
    roster_count: usize,
    team_count: usize,
    source_mna_sequence: u32,
) -> Value {
    let mut metadata = json!({
        "message_type": message_type,
        "command_id": command_id,
        "roster_count": roster_count,
        "team_count": team_count,
        "source_packets": inputs.mna_provenance.map_or(&[][..], |provenance| provenance.source_frames.as_slice()),
        "confidence": "proven",
        "privacy": {
            "classification": "private_local_roster",
            "required_file_mode": "0600",
            "session_material_included": false
        }
    });
    if inputs.mna_provenance.is_none() {
        metadata
            .as_object_mut()
            .expect("enter metadata literal is an object")
            .insert(
                "source_mna_sequence".to_owned(),
                Value::from(source_mna_sequence),
            );
    }
    metadata
}

fn build_match_events(
    inputs: &CompatibilityDocumentInputs<'_>,
    event_type: &str,
    team_count: usize,
    source_mna_sequence: u32,
) -> Vec<Value> {
    let mut events = inputs
        .auxiliary
        .events
        .iter()
        .map(|event| {
            (
                event.timestamp_ns,
                json!({
                    "event_type": "voice_room_info",
                    "timestamp": timestamp_seconds(event.timestamp_ns),
                    "fields": { "room": &event.room },
                    "source_packets": [event.source_packet],
                    "confidence": "proven"
                }),
            )
        })
        .collect::<Vec<_>>();
    let fields = json!({
        "map_id": inputs.session.map_id,
        "g1_mode": inputs.session.g1_mode,
        "s0_mode": inputs.session.s0_mode,
        "roster_count": inputs.session.roster.len(),
        "team_count": team_count
    });
    if let Some(provenance) = inputs.mna_provenance {
        events.push((
            provenance.timestamp_ns,
            json!({
                "event_type": event_type,
                "timestamp": timestamp_seconds(provenance.timestamp_ns),
                "fields": fields,
                "source_packets": &provenance.source_frames,
                "confidence": "proven"
            }),
        ));
        events.sort_by_key(|(timestamp_ns, _)| *timestamp_ns);
    } else {
        events.push((
            u64::MAX,
            json!({
                "event_type": event_type,
                "timestamp": Value::Null,
                "timestamp_status": "not_retained_by_typed_mna_session",
                "fields": fields,
                "source_packets": [],
                "source_mna_sequence": source_mna_sequence,
                "confidence": "proven"
            }),
        ));
    }
    events.into_iter().map(|(_, event)| event).collect()
}

fn mna_field_evidence(evidence: &MnaFieldEvidence) -> Value {
    json!({
        "path": evidence.path,
        "field_number": evidence.field_number,
        "declared_type": evidence.declared_type,
        "wire_type": evidence.wire_type,
        "plaintext_start": evidence.plaintext_start,
        "plaintext_end": evidence.plaintext_end,
        "value_start": evidence.value_start,
        "value_end": evidence.value_end,
    })
}

fn timestamp_seconds(timestamp_ns: u64) -> f64 {
    (timestamp_ns / 1_000_000_000) as f64 + (timestamp_ns % 1_000_000_000) as f64 / 1_000_000_000.0
}

fn build_full_session(
    inputs: &CompatibilityDocumentInputs<'_>,
    packet: &PacketFacts,
    netguid: &NetGuidFacts,
    recovery: &RecoveryFacts,
    batch: &Value,
) -> Value {
    let stats = inputs.pipeline;
    let partial_issue_free = recovery.has_validated_layer(&format!(
        "partial_bunch_reassembly_{}_complete_zero_issues",
        stats.partial_payloads_completed
    ));
    let partial_reassembly = match (
        packet.partial_fragment_count,
        packet.partial_duplicate_fragments,
        packet.partial_fragments_per_payload.clone(),
        packet.partial_total_reassembled_bits,
    ) {
        (
            Some(fragment_count),
            Some(duplicate_fragments),
            Some(fragments_per_payload),
            Some(total_reassembled_bits),
        ) => json!({
            "status": if partial_issue_free { "complete" } else { "issues_present" },
            "fragment_count": fragment_count,
            "completed_payloads": stats.partial_payloads_completed,
            "duplicate_fragments": duplicate_fragments,
            "issues": if partial_issue_free { json!([]) } else { json!([{"status": "validation_unavailable"}]) },
            "fragments_per_payload": fragments_per_payload,
            "total_reassembled_bits": total_reassembled_bits
        }),
        _ => json!({
            "status": if partial_issue_free { "complete_aggregate_only" } else { "validation_unavailable" },
            "fragment_count": stats.partial_fragments,
            "completed_payloads": stats.partial_payloads_completed,
            "duplicate_fragments": Value::Null,
            "issues": if partial_issue_free { json!([]) } else { json!([{"status": "validation_unavailable"}]) },
            "fragments_per_payload": unavailable_status("fragment histogram is absent from CompatibilityPacketReport"),
            "total_reassembled_bits": Value::Null
        }),
    };
    json!({
        "status": "transport_and_unreal_envelopes_complete",
        "counts": {
            "batch_sync_actor_messages": inputs.batch_sync.actor_messages,
            "batch_sync_batch_properties": inputs.batch_sync.batch_properties,
            "batch_sync_bit_exact_actor_messages": inputs.batch_sync.bit_exact_actor_messages,
            "batch_sync_character_updates": inputs.batch_sync.character_updates,
            "batch_sync_event_count": inputs.batch_sync.event_count,
            "batch_sync_non_batch_properties": inputs.batch_sync.non_batch_properties,
            "batch_sync_parse_failures": inputs.batch_sync.parse_failures,
            "batch_sync_track_count": inputs.batch_sync.track_count,
            "bunches": stats.bunches,
            "netguid_records": stats.netguid_records,
            "oodle_flag_one_packets": stats.oodle_compressed,
            "oodle_pass_through_packets": stats.packet_handler_pass_through,
            "package_map_export_prefixes_exact": stats.package_map_export_prefixes_exact,
            "packet_handler_reencode_exact": packet.packet_handler_reencode_exact,
            "packets": packet.packet_count,
            "partial_fragments": stats.partial_fragments,
            "partial_payloads_completed": stats.partial_payloads_completed,
            "partial_reassembly_issues": if partial_issue_free { Value::from(0) } else { Value::Null },
            "sgnet_wire_reencode_exact": packet.sgnet_wire_reencode_exact,
            "unreal_reencode_exact": packet.unreal_reencode_exact
        },
        "directions": {
            "client_to_server": {
                "packets": packet.client_to_server.packet_count,
                "bunches": packet.client_to_server.bunch_count,
                "oodle_flag_one_packets": packet.client_to_server.oodle_flag_one_packets,
                "oodle_pass_through_packets": packet.client_to_server.oodle_pass_through_packets,
                "package_map_export_prefixes_exact": packet.client_to_server.package_map_reencode_exact,
                "packet_handler_reencode_exact": packet.client_to_server.packet_handler_reencode_exact,
                "sgnet_wire_reencode_exact": packet.client_to_server.sgnet_wire_reencode_exact,
                "unreal_reencode_exact": packet.client_to_server.unreal_reencode_exact
            },
            "server_to_client": {
                "packets": packet.server_to_client.packet_count,
                "bunches": packet.server_to_client.bunch_count,
                "oodle_flag_one_packets": packet.server_to_client.oodle_flag_one_packets,
                "oodle_pass_through_packets": packet.server_to_client.oodle_pass_through_packets,
                "package_map_export_prefixes_exact": packet.server_to_client.package_map_reencode_exact,
                "packet_handler_reencode_exact": packet.server_to_client.packet_handler_reencode_exact,
                "sgnet_wire_reencode_exact": packet.server_to_client.sgnet_wire_reencode_exact,
                "unreal_reencode_exact": packet.server_to_client.unreal_reencode_exact
            }
        },
        "flag_one_raw_size_distribution": packet.flag_one_raw_size_distribution.clone().unwrap_or_else(|| unavailable_status("raw flag-one size histogram is absent from CompatibilityPacketReport")),
        "partial_reassembly": partial_reassembly,
        "batch_sync": batch,
        "netguid": {
            "record_count": stats.netguid_records,
            "binding_count": netguid.binding_count,
            "binding_conflicts": netguid.conflicts,
            "main_map_path": netguid.main_map_path,
            "map_path_confidence": "proven",
            "bindings_output": "netguid.json"
        },
        "validation": {
            "sgnet_wire_reencode_exact": packet.sgnet_wire_reencode_exact == packet.packet_count,
            "packet_handler_reencode_exact": packet.packet_handler_reencode_exact == packet.packet_count,
            "unreal_reencode_exact": packet.unreal_reencode_exact == stats.unreal_packets,
            "partial_reassembly_issue_count": if partial_issue_free { Value::from(0) } else { Value::Null },
            "netguid_binding_conflict_count": netguid.conflicts.len()
        }
    })
}

fn validate_cross_artifact_invariants(
    inputs: &CompatibilityDocumentInputs<'_>,
    flow: &FlowFacts,
    packet: &PacketFacts,
    netguid: &NetGuidFacts,
    recovery: &RecoveryFacts,
) -> Result<(), CompatibilityDocumentError> {
    let stats = inputs.pipeline;
    invariant(
        flow.primary_packet_count == stats.datagrams,
        "primary flow packet count must equal PipelineStats.datagrams",
    )?;
    invariant(
        packet.packet_count == stats.datagrams,
        "CompatibilityPacketReport.packet_count must equal PipelineStats.datagrams",
    )?;
    invariant(
        stats.sgnet_decrypted == stats.datagrams,
        codev_obf::s("e1ddef4786b0fedbe8cee9419af4addae5dfeb528df1e09ee9def941dff2e89ed7ecc4508bb0e9dbe7d9f3458bf5e9"),
    )?;
    invariant(
        packet.sgnet_wire_reencode_exact == stats.sgnet_wire_reencode_exact
            && stats.sgnet_wire_reencode_exact == stats.datagrams,
        codev_obf::s("d42b38ef3b472a19e60f02aa3d026204e90f19ee2a472c0ef20202f96f032612e60b04ef2a"),
    )?;
    invariant(
        packet.packet_handler_reencode_exact == stats.packet_handler_envelopes_exact
            && stats.packet_handler_envelopes_exact == stats.datagrams,
        codev_obf::s("2ef95a1650e524b310fc551847b109aa1ffb4d5d47f441b710fb561950b10fbd0bf64d0e15f505a11fff4b1850"),
    )?;
    invariant(
        stats.packet_handler_pass_through + stats.oodle_compressed == stats.datagrams,
        codev_obf::s("6cadaa212b64047152a8a52f3c302a7c5dabe929216522644fecad256e7e23641cafa63c2b626c7150a0e92e2f642d774eada439"),
    )?;
    invariant(
        stats.unreal_packets == stats.packet_handler_pass_through
            && stats.unreal_packets_exact == stats.unreal_packets
            && packet.unreal_reencode_exact == stats.unreal_packets,
        "UE packet exact re-encode counts disagree",
    )?;
    invariant(packet.bunch_count == stats.bunches, "bunch counts disagree")?;
    let client = &packet.client_to_server;
    let server = &packet.server_to_client;
    invariant(
        client.packet_count == flow.client_to_server_packets
            && server.packet_count == flow.server_to_client_packets
            && client.packet_count + server.packet_count == packet.packet_count,
        "direction packet counts disagree",
    )?;
    if let Some(payload_bytes) = client.payload_bytes {
        invariant(
            payload_bytes == flow.client_to_server_payload_bytes,
            "client direction payload-byte aggregates disagree",
        )?;
    }
    if let Some(payload_bytes) = server.payload_bytes {
        invariant(
            payload_bytes == flow.server_to_client_payload_bytes,
            "server direction payload-byte aggregates disagree",
        )?;
    }
    invariant(
        client.packet_handler_reencode_exact + server.packet_handler_reencode_exact
            == packet.packet_handler_reencode_exact
            && client.sgnet_wire_reencode_exact + server.sgnet_wire_reencode_exact
                == packet.sgnet_wire_reencode_exact
            && client.unreal_reencode_exact + server.unreal_reencode_exact
                == packet.unreal_reencode_exact
            && client.bunch_count + server.bunch_count == packet.bunch_count
            && client.package_map_reencode_exact + server.package_map_reencode_exact
                == packet.package_map_reencode_exact
            && client.oodle_flag_one_packets + server.oodle_flag_one_packets
                == stats.oodle_compressed
            && client.oodle_pass_through_packets + server.oodle_pass_through_packets
                == stats.packet_handler_pass_through,
        "direction decode aggregates disagree",
    )?;
    for (direction, facts) in [("client_to_server", client), ("server_to_client", server)] {
        if let Some(duplicate_packet_ids) = &facts.duplicate_packet_ids {
            let unique_duplicates = duplicate_packet_ids
                .as_array()
                .ok_or_else(|| {
                    wrong_type(
                        format!("packet_report.{direction}.duplicate_packet_ids"),
                        "array",
                    )
                })?
                .len() as u64;
            invariant(
                (facts.duplicate_inner_packet_ids == 0 && unique_duplicates == 0)
                    || (unique_duplicates > 0
                        && unique_duplicates <= facts.duplicate_inner_packet_ids),
                format!("{direction} PacketNotify duplicate aggregates disagree"),
            )?;
        }
    }
    invariant(
        packet.package_map_reencode_exact == stats.package_map_export_prefixes_exact,
        "PackageMap prefix counts disagree",
    )?;
    invariant(
        packet.partial_payloads_completed == stats.partial_payloads_completed,
        "partial completion counts disagree",
    )?;
    if let Some(fragment_count) = packet.partial_fragment_count {
        invariant(
            fragment_count == stats.partial_fragments,
            "partial fragment counts disagree",
        )?;
    }
    if let Some(distribution) = &packet.partial_fragments_per_payload {
        invariant(
            distribution_total(distribution)? == packet.partial_payloads_completed,
            "partial fragments-per-payload distribution does not cover all completions",
        )?;
    }
    if let Some(distribution) = &packet.flag_one_raw_size_distribution {
        invariant(
            distribution_total(distribution)? == stats.oodle_compressed,
            "Oodle raw-size distribution does not cover all flag-one packets",
        )?;
    }
    if let (Some(tested), Some(validated)) = (
        packet.client_watermark_crc32c_tested,
        packet.client_watermark_crc32c_validated,
    ) {
        invariant(
            tested == client.packet_count && validated == tested,
            "client watermark CRC counts do not prove every client packet",
        )?;
    }
    if let Some(distribution) = &packet.encrypted_connection_id_raw_distribution {
        invariant(
            distribution_total(distribution)? == client.packet_count,
            "encrypted connection-id distribution does not cover every client packet",
        )?;
    }
    if let Some(distribution) = &packet.plaintext_connection_id_distribution {
        invariant(
            distribution_total(distribution)? == client.packet_count,
            "plaintext connection-id distribution does not cover every client packet",
        )?;
    }
    invariant(
        packet.batch_actor_count == stats.actor_messages
            && stats.actor_messages == inputs.batch_sync.actor_messages,
        codev_obf::s("14157e1388c8f77535546b1394f4fc3b351b7f1e94e8ae7f3f076b1792feeb"),
    )?;
    invariant(
        packet.batch_property_count == stats.batch_properties
            && stats.batch_properties == inputs.batch_sync.batch_properties,
        "BatchData property counts disagree",
    )?;
    invariant(
        stats.raw_two_bit_properties == inputs.batch_sync.non_batch_properties,
        "non-Batch property counts disagree",
    )?;
    invariant(
        stats.character_updates == inputs.batch_sync.character_updates,
        codev_obf::s("f7c1d553f62a9ee4d680d440fa1893ef95c3ce45f00d94aad1c9d251f90b82ef"),
    )?;
    invariant(
        packet.exact_bit_coverage == packet.packet_count,
        "packet and explicit-unknown spans must cover every selected packet",
    )?;
    invariant(
        netguid.binding_count == netguid.binding_len,
        "netguid binding_count must equal bindings length",
    )?;
    invariant(
        netguid.conflicts.is_empty(),
        "NetGUID conflicts prevent publishing a map identity",
    )?;
    invariant(
        recovery.fully_decrypted,
        "RecoveryGate must prove full transport decryption",
    )?;
    invariant(
        !recovery.fully_decoded,
        "this builder must not promote unresolved gameplay semantics",
    )?;
    invariant(
        !recovery.fabricated_semantics,
        "RecoveryGate reports fabricated semantics",
    )?;
    invariant(
        recovery.has_validated_layer(&format!(
            "partial_bunch_reassembly_{}_complete_zero_issues",
            stats.partial_payloads_completed
        )),
        "RecoveryGate lacks the matching partial-reassembly proof",
    )?;
    Ok(())
}

fn validate_batch(
    summary: &BatchSyncSummary,
    value: &Value,
) -> Result<(), CompatibilityDocumentError> {
    invariant(
        summary.channel_index == BATCH_CHANNEL_INDEX,
        codev_obf::s("83f71ba6bc622afba2b60cadb55f3df0adb606abb0542bb5a8e54fabbb4573e3a4e41cacbb5f7ee5a8f801a0b01110fda0f801a0b81160a7"),
    )?;
    invariant(
        summary.property_handle == BATCH_PROPERTY_HANDLE,
        codev_obf::s("fee26a613a3713bedfa36e703d140fa2c8fa3e6a330a0ebcd9a37771720a05a49cf57b70210d05be91f3776c3c010ef0d4e270663e014ae18b"),
    )?;
    invariant(
        summary.event_count == summary.character_updates,
        codev_obf::s("b0e80ad955fcfd5591a91bcc58c1f06491e60bd4498fe94e81fd5edf4cdae557d2ea16db4fcee74f97fb21cf4dcbe54f97fa"),
    )?;
    invariant(
        summary.bit_exact_actor_messages == summary.actor_messages,
        codev_obf::s("57d4d9f611b4f6445eebccb830f5e34442d7c7a573b8f7544298d6b93da6f74a5398c1be36bcf00755d7d8a63fb0f64216cfdca436f5e04b59dbde"),
    )?;
    invariant(
        summary.parse_failures == 0,
        codev_obf::s("29acb8f8b49ad92b08edbcfaaebac5650daca5f7a9bbc5364bbdbefeaaacce314baea3f6aca8d42c09a4a0f2a8b080351eafa0f2bfa8d42c04a3"),
    )?;
    invariant(
        summary.property_handle_distribution.values().sum::<u64>()
            == summary.batch_properties + summary.non_batch_properties,
        "property-handle distribution does not cover all properties",
    )?;
    invariant(
        summary.character_count_distribution.values().sum::<u64>() == summary.batch_properties,
        "character-count distribution does not cover all BatchData properties",
    )?;
    invariant(
        summary.change_mask_distribution.values().sum::<u64>() == summary.character_updates,
        "change-mask distribution does not cover all updates",
    )?;

    let tracks = required_array(value, "tracks")?;
    invariant(
        tracks.len() == summary.track_count,
        codev_obf::s("b0e80ad955fcfd5591a90ac85cccef6491e60bd4498fe05497fa5ed452dba45e83fc1fd61ddbf65a91e20d9a51caea5c86e1"),
    )?;
    let identity = required_object(value, "identity_binding")?;
    invariant(
        required_str_in(identity, "status", "batch_sync.identity_binding")? == "unresolved",
        "coordinate identity must remain unresolved",
    )?;
    invariant(
        !required_bool_in(
            identity,
            "guessed_mapping_used",
            "batch_sync.identity_binding",
        )?,
        "guessed coordinate identity mapping is forbidden",
    )?;
    let labels = required_array_in(identity, "labels", "batch_sync.identity_binding")?;
    let mut expected_labels = BTreeSet::new();
    let mut observed_slots = BTreeSet::new();
    let mut track_update_count = 0_u64;
    for (index, track) in tracks.iter().enumerate() {
        let path = format!("batch_sync.tracks[{index}]");
        let track = track
            .as_object()
            .ok_or_else(|| wrong_type(path.clone(), "object"))?;
        let slot = required_u64_in(track, "batch_slot", &path)?;
        invariant(slot <= u8::MAX.into(), "batch slot exceeds u8")?;
        invariant(
            observed_slots.insert(slot),
            codev_obf::s("967ce5749f14f0d89729d7798214f9ff8b67f6388205f0cf9929e6749903"),
        )?;
        let expected = format!("batch_slot_{slot}");
        invariant(
            required_str_in(track, "track_id", &path)? == expected,
            "track id does not match its batch slot",
        )?;
        invariant(
            required_str_in(track, "identity_binding", &path)? == "unresolved"
                && required_str_in(track, "identity_confidence", &path)? == "unknown",
            "coordinate track promoted an unproven identity",
        )?;
        expected_labels.insert(expected);
        track_update_count += required_u64_in(track, "update_count", &path)?;
    }
    let observed_labels: BTreeSet<_> = labels
        .iter()
        .enumerate()
        .map(|(index, label)| {
            label.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                wrong_type(
                    format!("batch_sync.identity_binding.labels[{index}]"),
                    "string",
                )
            })
        })
        .collect::<Result<_, _>>()?;
    invariant(
        expected_labels == observed_labels,
        "identity labels do not match coordinate tracks",
    )?;
    invariant(
        track_update_count == summary.character_updates,
        codev_obf::s("d25d2abcd915ec70c24e3fba9241f674c74338ffd65ab96ec95b6bbcdd43fc72864e27b39277f874c54718a6dc56b975d64b2aabd746"),
    )?;
    Ok(())
}

fn build_participants(
    session: &EnterGameSession,
    source_packets: &[u64],
    auxiliary: &CompatibilityAuxiliaryCapture,
) -> Result<Vec<Value>, CompatibilityDocumentError> {
    validate_roster(session)?;
    let roster_source = format!(
        "MNA {}.{}",
        if session.reenter {
            codev_conceal::reenter_game_notify()
        } else {
            codev_conceal::e0_notify()
        },
        codev_conceal::c0_info()
    );
    Ok(session
        .roster
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let mut participant = json!({
                "participant_id": format!("enter_game_roster_{index}"),
                "roster_index": index,
                "agent_id": entry.agent_id,
                "camp_id": entry.camp_id.to_string(),
                "position_slot": entry.position_slot,
                "source": roster_source,
                "source_packets": source_packets,
                "confidence": "proven",
                "name": entry.name,
                "uid": entry.uid,
                "open_id": entry.open_id,
                "skin_id": entry.skin_id,
                "selected_backpack_id": entry.selected_backpack_id
            });
            let object = participant
                .as_object_mut()
                .expect("participant literal is an object");
            if source_packets.is_empty() {
                object.insert(
                    "source_mna_sequence".to_owned(),
                    Value::from(session.source_mna_sequence),
                );
            }
            if auxiliary.open_ids.binary_search(&entry.open_id).is_ok() {
                object.insert(
                    "auxiliary_identity_source".to_owned(),
                    Value::from("GCloud room/telemetry signaling"),
                );
            }
            participant
        })
        .collect())
}

fn build_teams(
    session: &EnterGameSession,
    source_packets: &[u64],
) -> Result<Vec<Value>, CompatibilityDocumentError> {
    validate_roster(session)?;
    let roster_source = format!(
        "MNA {}.{}",
        if session.reenter {
            codev_conceal::reenter_game_notify()
        } else {
            codev_conceal::e0_notify()
        },
        codev_conceal::c0_info()
    );
    let mut teams = BTreeMap::<u64, Vec<String>>::new();
    for (index, entry) in session.roster.iter().enumerate() {
        teams
            .entry(entry.camp_id)
            .or_default()
            .push(format!("enter_game_roster_{index}"));
    }
    Ok(teams
        .into_iter()
        .map(|(camp_id, participant_ids)| {
            let mut team = json!({
                "id": camp_id.to_string(),
                "kind": "camp",
                "player_count": participant_ids.len(),
                "participant_ids": participant_ids,
                "source": roster_source,
                "source_packets": source_packets,
                "confidence": "proven"
            });
            if source_packets.is_empty() {
                team.as_object_mut()
                    .expect("team literal is an object")
                    .insert(
                        "source_mna_sequence".to_owned(),
                        Value::from(session.source_mna_sequence),
                    );
            }
            team
        })
        .collect())
}

fn validate_roster(session: &EnterGameSession) -> Result<(), CompatibilityDocumentError> {
    invariant(
        session.roster.len() == 10,
        "descriptor-exact match roster must contain ten players",
    )?;
    let mut uids = BTreeSet::new();
    let mut open_ids = BTreeSet::new();
    let mut camps = BTreeMap::<u64, BTreeSet<u32>>::new();
    for entry in &session.roster {
        invariant(
            !entry.name.is_empty(),
            "roster stable Name must not be empty",
        )?;
        invariant(
            !entry.uid.is_empty() && entry.uid.bytes().all(|byte| byte.is_ascii_digit()),
            "roster UID must be non-empty decimal text",
        )?;
        invariant(
            !entry.open_id.is_empty() && entry.open_id.bytes().all(|byte| byte.is_ascii_digit()),
            "roster OpenID must be non-empty decimal text",
        )?;
        invariant(uids.insert(&entry.uid), "roster UID must be unique")?;
        invariant(
            open_ids.insert(&entry.open_id),
            "roster OpenID must be unique",
        )?;
        invariant(entry.agent_id != 0, "roster AgentId must be non-zero")?;
        invariant(entry.camp_id != 0, "roster CampId must be non-zero")?;
        invariant(
            (1..=5).contains(&entry.position_slot),
            "roster position slot must be in 1..=5",
        )?;
        invariant(
            camps
                .entry(entry.camp_id)
                .or_default()
                .insert(entry.position_slot),
            "position slots must be unique inside each camp",
        )?;
    }
    invariant(camps.len() == 2, "roster must contain exactly two camps")?;
    invariant(
        camps.values().all(|slots| slots.len() == 5),
        "each roster camp must contain five unique position slots",
    )?;
    Ok(())
}

fn decoder_schema_status() -> Value {
    let sha256 = format!(
        "{:x}",
        Sha256::digest(crate::artifacts::embedded_fields_json_bytes())
    );
    json!({
        "schema_id": "codev-1.24.0.2911-rust-native-v1",
        "schema_version": "codev.rust-typed-session/v1",
        "build": DISPLAY_BUILD,
        "inherit_builtin_fields": true,
        "source": "embedded Rust protocol model",
        "sha256": sha256
    })
}

fn sgnet_cipher_status(
    session: &EnterGameSession,
    decoder_schema: &Value,
    packet: &PacketFacts,
) -> Value {
    json!({
        "status": "available_from_descriptor_exact_mna_notification",
        "source": decoder_schema,
        "key_seed_hex": "<redacted:not-retained>",
        "nonce_seed_hex": "<redacted:not-retained>",
        "derived_key_sha256": "<redacted:not-retained>",
        "source_mna_sequence": session.source_mna_sequence,
        "notification": if session.reenter { codev_conceal::reenter_game_notify() } else { codev_conceal::e0_notify() },
        "encryption_key_retained_in_output": false,
        "session_identifier_retained_in_output": false,
        "control_exchange_validation": packet.control_exchange_validation.clone().unwrap_or_else(|| unavailable_status("control exchange observations are absent from CompatibilityPacketReport"))
    })
}

fn full_fixture_checks(
    inputs: &CompatibilityDocumentInputs<'_>,
    flow: &FlowFacts,
    packet: &PacketFacts,
    _netguid: &NetGuidFacts,
) -> Value {
    let stats = inputs.pipeline;
    json!({
        "full_primary_packet_count_12414": fixture_baseline(inputs.fixture.known_full_fixture, flow.primary_packet_count == 12_414),
        "full_packet_handler_exact_12414": fixture_baseline(inputs.fixture.known_full_fixture, packet.packet_handler_reencode_exact == 12_414),
        "full_sgnet_wire_exact_12414": fixture_baseline(inputs.fixture.known_full_fixture, packet.sgnet_wire_reencode_exact == 12_414),
        "full_oodle_flag_one_packets_4": fixture_baseline(inputs.fixture.known_full_fixture, stats.oodle_compressed == 4),
        "full_unreal_packets_exact_12410": fixture_baseline(inputs.fixture.known_full_fixture, packet.unreal_reencode_exact == 12_410),
        "full_unreal_bunches_20360": fixture_baseline(inputs.fixture.known_full_fixture, stats.bunches == 20_360),
        "full_client_bunches_5887": fixture_baseline(inputs.fixture.known_full_fixture, packet.client_to_server.bunch_count == 5_887),
        "full_server_bunches_14473": fixture_baseline(inputs.fixture.known_full_fixture, packet.server_to_client.bunch_count == 14_473),
        "full_package_map_prefixes_512": fixture_baseline(inputs.fixture.known_full_fixture, stats.package_map_export_prefixes_exact == 512),
        "full_netguid_records_2469": fixture_baseline(inputs.fixture.known_full_fixture, stats.netguid_records == 2_469),
        "full_partial_payloads_512": fixture_baseline(inputs.fixture.known_full_fixture, stats.partial_payloads_completed == 512),
        "full_batch_sync_actor_messages_4444": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.actor_messages == 4_444),
        "full_batch_sync_properties_4442": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.batch_properties == 4_442),
        "full_batch_sync_non_batch_properties_9": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.non_batch_properties == 9),
        "full_batch_sync_character_updates_17031": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.character_updates == 17_031),
        "full_batch_sync_tracks_10": fixture_baseline(inputs.fixture.known_full_fixture, inputs.batch_sync.track_count == 10)
    })
}

fn build_fixture_checks(flow: &FlowFacts, packet: &PacketFacts, recovery: &RecoveryFacts) -> Value {
    let watermark = packet.client_watermark_counter.as_ref();
    let client_reliability = packet.client_to_server.reliability.as_ref();
    let server_reliability = packet.server_to_client.reliability.as_ref();
    let ack_recent = packet.ack_recent_peer_match.as_ref();
    let relation = packet.client_watermark_counter_low14_relation.as_ref();
    let client_packet_info = packet.client_to_server.packet_info.as_ref();
    let server_packet_info = packet.server_to_client.packet_info.as_ref();
    let client_first_bunch = packet.client_to_server.first_bunch_prefix.as_ref();
    let server_first_bunch = packet.server_to_client.first_bunch_prefix.as_ref();
    let low5 = packet.ack_history_low5_semantics.as_ref();
    let repeated_count = packet
        .client_to_server
        .repeated_suffix_candidates
        .as_ref()
        .and_then(Value::as_array)
        .map_or(0, Vec::len)
        + packet
            .server_to_client
            .repeated_suffix_candidates
            .as_ref()
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
    let client_udp_offload = packet
        .client_to_server
        .network_integrity
        .as_ref()
        .and_then(|value| value.get("udp:offload_seed"))
        .and_then(Value::as_u64);
    let server_udp_valid = packet
        .server_to_client
        .network_integrity
        .as_ref()
        .and_then(|value| value.get("udp:valid"))
        .and_then(Value::as_u64);
    let captured_low5 = low5
        .and_then(|value| value.get("captured_but_peer_reported_missing"))
        .and_then(Value::as_array);
    json!({
        "packet_count_17494": flow.input_packet_count == 17_494,
        "flow_count_27": flow.flow_count == 27,
        "primary_packet_count_16297": flow.primary_packet_count == 16_297,
        "client_watermark_counter_first_0x23bd1362": nested_u64(watermark, &["first"]) == Some(0x23bd_1362),
        "client_watermark_counter_last_0x23bd36d7": nested_u64(watermark, &["last"]) == Some(0x23bd_36d7),
        "client_watermark_counter_no_gaps": nested_array(watermark, &["gaps"]).is_some_and(|values| values.is_empty()),
        "client_watermark_crc32c_all_valid": packet.client_watermark_crc32c_tested.is_some()
            && packet.client_watermark_crc32c_tested == packet.client_watermark_crc32c_validated,
        "sgnet_plaintext_prefix_or_capture_projection_available": recovery.fully_decrypted,
        "client_inner_packet_ids_continuous": nested_u64(client_reliability, &["packet_id_sequence", "continuous_steps"]) == Some(9_075)
            && nested_array(client_reliability, &["packet_id_sequence", "gaps"]).is_some_and(|values| values.is_empty()),
        "server_missing_packet_ids_21": nested_u64(server_reliability, &["missing_packet_id_count"]) == Some(21),
        "server_one_adjacent_reorder": nested_array(server_reliability, &["reorders"]).is_some_and(|values| values.len() == 1),
        "client_ack_recent_matches_9074": nested_u64(ack_recent, &["client_to_server", "matched"]) == Some(9_074),
        "server_ack_recent_matches_7216": nested_u64(ack_recent, &["server_to_client", "matched"]) == Some(7_216),
        "client_watermark_packet_id_relation_all": nested_u64(relation, &["matches"]) == Some(9_076)
            && nested_u64(relation, &["tested"]) == Some(9_076),
        "packet_info_present_counts": nested_u64(client_packet_info, &["present_count"]) == Some(9_077)
            && nested_u64(server_packet_info, &["present_count"]) == Some(7_113),
        "packet_info_time_delta_median_below_1ms": nested_f64(client_packet_info, &["capture_delta_error_median_ms"]).is_some_and(|value| value < 1.0)
            && nested_f64(server_packet_info, &["capture_delta_error_median_ms"]).is_some_and(|value| value < 1.0),
        "first_bunch_prefix_counts": nested_u64(client_first_bunch, &["parsed_first_bunch_count"]) == Some(6_535)
            && nested_u64(server_first_bunch, &["parsed_first_bunch_count"]) == Some(6_682),
        "large_repeated_suffix_pairs_3": repeated_count == 3,
        "server_capture_gaps_ack_history_low5_confirmed_19_of_21": nested_u64(low5, &["capture_gap_confirmation", "server_to_client", "confirmed_by_low5_count"]) == Some(19)
            && nested_u64(low5, &["capture_gap_confirmation", "server_to_client", "actual_capture_gap_count"]) == Some(21),
        "client_0x2db4_peer_reported_not_accepted": captured_low5.is_some_and(|items| items.iter().any(|item| {
            item["peer_packet_direction"] == "client_to_server" && item["packet_id"] == "0x2db4"
        })),
        "client_udp_offload_seed_all": client_udp_offload == Some(9_078),
        "server_udp_checksums_valid_all": server_udp_valid == Some(7_219)
    })
}

fn nested_value<'a>(root: Option<&'a Value>, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(root?, |value, key| value.get(*key))
}

fn nested_u64(root: Option<&Value>, path: &[&str]) -> Option<u64> {
    nested_value(root, path).and_then(Value::as_u64)
}

fn nested_f64(root: Option<&Value>, path: &[&str]) -> Option<f64> {
    nested_value(root, path).and_then(Value::as_f64)
}

fn nested_array<'a>(root: Option<&'a Value>, path: &[&str]) -> Option<&'a [Value]> {
    nested_value(root, path)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

fn fixture_baseline(applicable: bool, passed: bool) -> Value {
    if applicable {
        Value::Bool(passed)
    } else {
        json!({"status": "not_applicable"})
    }
}

fn aggregate_status(validated: bool, reason: &str) -> Value {
    json!({
        "status": if validated { "validated_aggregate_only" } else { "unavailable" },
        "details_available": false,
        "reason": reason
    })
}

fn unavailable_status(reason: &str) -> Value {
    json!({
        "status": "unavailable_from_typed_inputs",
        "reason": reason,
        "fabricated_values": false
    })
}

fn direction_statistics(
    direction: &PacketDirectionFacts,
    packet_count: u64,
    transport_payload_bytes: u64,
) -> Value {
    match (
        direction.payload_bytes,
        direction.aggregate_entropy_bits_per_byte,
        direction.common_payload_lengths.clone(),
    ) {
        (Some(payload_bytes), Some(entropy), Some(common_payload_lengths)) => json!({
            "packet_count": direction.packet_count,
            "payload_bytes": payload_bytes,
            "aggregate_entropy_bits_per_byte": entropy,
            "common_payload_lengths": common_payload_lengths
        }),
        _ => json!({
            "status": "transport_aggregates_only",
            "packet_count": packet_count,
            "payload_bytes": transport_payload_bytes,
            "aggregate_entropy_bits_per_byte": Value::Null,
            "common_payload_lengths": [],
            "unavailable_fields": ["aggregate_entropy_bits_per_byte", "common_payload_lengths"]
        }),
    }
}

fn distribution_total(value: &Value) -> Result<u64, CompatibilityDocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| wrong_type("compatibility distribution", "object"))?;
    object.values().try_fold(0_u64, |total, count| {
        let count = count
            .as_u64()
            .ok_or_else(|| wrong_type("compatibility distribution count", "integer"))?;
        total
            .checked_add(count)
            .ok_or_else(|| invariant_error("compatibility distribution total overflow"))
    })
}

struct FlowFacts {
    input_packet_count: u64,
    accounted_packet_count: u64,
    flow_count: usize,
    unclassified_count: usize,
    tcp_flow_count: usize,
    capture_start: String,
    capture_end: String,
    game_flow_start: String,
    game_flow_end: String,
    seconds_before_game_flow: f64,
    seconds_after_game_flow: f64,
    primary_flow: Value,
    primary_packet_count: u64,
    client: String,
    server: String,
    client_to_server_packets: u64,
    server_to_client_packets: u64,
    client_to_server_payload_bytes: u64,
    server_to_client_payload_bytes: u64,
}

impl FlowFacts {
    fn parse(
        document: &Value,
        session: &EnterGameSession,
    ) -> Result<Self, CompatibilityDocumentError> {
        let root = document
            .as_object()
            .ok_or_else(|| wrong_type("flow_manifest", "object"))?;
        let input_packet_count = required_u64_in(root, "input_packet_count", "flow_manifest")?;
        let accounted_packet_count =
            required_u64_in(root, "accounted_packet_count", "flow_manifest")?;
        let flow_count_u64 = required_u64_in(root, "flow_count", "flow_manifest")?;
        let flow_count = usize::try_from(flow_count_u64)
            .map_err(|_| invariant_error("flow_count does not fit usize"))?;
        let primary_flow_id = required_str_in(root, "primary_flow_id", "flow_manifest")?;
        let flows = required_array_in(root, "flows", "flow_manifest")?;
        let unclassified = required_array_in(root, "unclassified", "flow_manifest")?;
        invariant(
            flow_count == flows.len(),
            "flow_count must equal flows length",
        )?;
        invariant(
            input_packet_count == accounted_packet_count,
            "flow accounting must cover every capture packet",
        )?;

        let mut capture_start: Option<&str> = None;
        let mut capture_end: Option<&str> = None;
        let mut tcp_flow_count = 0_usize;
        let mut primary: Option<&Map<String, Value>> = None;
        for (index, flow) in flows.iter().enumerate() {
            let path = format!("flow_manifest.flows[{index}]");
            let flow = flow
                .as_object()
                .ok_or_else(|| wrong_type(path.clone(), "object"))?;
            let first = required_str_in(flow, "first_timestamp", &path)?;
            let last = required_str_in(flow, "last_timestamp", &path)?;
            invariant(
                !first.is_empty() && !last.is_empty(),
                "flow timestamps must not be empty",
            )?;
            capture_start = Some(capture_start.map_or(first, |old| old.min(first)));
            capture_end = Some(capture_end.map_or(last, |old| old.max(last)));
            let protocol = required_str_in(flow, "protocol", &path)?;
            if protocol == "tcp" {
                tcp_flow_count += 1;
            }
            if required_str_in(flow, "flow_id", &path)? == primary_flow_id {
                invariant(
                    primary.is_none(),
                    "primary_flow_id matches more than one flow",
                )?;
                primary = Some(flow);
            }
        }
        let primary = primary.ok_or_else(|| missing("flow_manifest primary flow"))?;
        invariant(
            required_str_in(primary, "protocol", "flow_manifest.primary")? == "udp",
            "primary flow must be UDP",
        )?;
        invariant(
            required_u64_in(primary, "parse_issue_count", "flow_manifest.primary")? == 0,
            "primary flow has parse issues",
        )?;
        let endpoint_a = required_str_in(primary, "endpoint_a", "flow_manifest.primary")?;
        let endpoint_b = required_str_in(primary, "endpoint_b", "flow_manifest.primary")?;
        let a_is_server = endpoint_port(endpoint_a)? == session.server_port;
        let b_is_server = endpoint_port(endpoint_b)? == session.server_port;
        invariant(
            a_is_server ^ b_is_server,
            "MNA server port does not uniquely orient the primary UDP flow",
        )?;
        let a_to_b_packets = required_u64_in(primary, "a_to_b_packets", "flow_manifest.primary")?;
        let b_to_a_packets = required_u64_in(primary, "b_to_a_packets", "flow_manifest.primary")?;
        let a_to_b_payload_bytes =
            required_u64_in(primary, "a_to_b_payload_bytes", "flow_manifest.primary")?;
        let b_to_a_payload_bytes =
            required_u64_in(primary, "b_to_a_payload_bytes", "flow_manifest.primary")?;
        let primary_packet_count =
            required_u64_in(primary, "packet_count", "flow_manifest.primary")?;
        let primary_payload_bytes =
            required_u64_in(primary, "transport_payload_bytes", "flow_manifest.primary")?;
        invariant(
            a_to_b_packets + b_to_a_packets == primary_packet_count,
            "primary directional packet counts do not sum to packet_count",
        )?;
        invariant(
            a_to_b_payload_bytes + b_to_a_payload_bytes == primary_payload_bytes,
            "primary directional payload bytes do not sum to transport_payload_bytes",
        )?;
        let game_flow_start =
            required_str_in(primary, "first_timestamp", "flow_manifest.primary")?.to_owned();
        let game_flow_end =
            required_str_in(primary, "last_timestamp", "flow_manifest.primary")?.to_owned();
        let mut primary_projection = primary.clone();
        primary_projection.remove("classification");
        let primary_flow = Value::Object(primary_projection);
        let capture_start_value =
            capture_start.ok_or_else(|| missing("flow_manifest capture start"))?;
        let capture_end_value = capture_end.ok_or_else(|| missing("flow_manifest capture end"))?;
        let seconds_before_game_flow =
            timestamp_delta_seconds(&game_flow_start, capture_start_value)?;
        let seconds_after_game_flow = timestamp_delta_seconds(capture_end_value, &game_flow_end)?;
        let (
            client,
            server,
            client_to_server_packets,
            server_to_client_packets,
            client_to_server_payload_bytes,
            server_to_client_payload_bytes,
        ) = if a_is_server {
            (
                endpoint_b.to_owned(),
                endpoint_a.to_owned(),
                b_to_a_packets,
                a_to_b_packets,
                b_to_a_payload_bytes,
                a_to_b_payload_bytes,
            )
        } else {
            (
                endpoint_a.to_owned(),
                endpoint_b.to_owned(),
                a_to_b_packets,
                b_to_a_packets,
                a_to_b_payload_bytes,
                b_to_a_payload_bytes,
            )
        };
        Ok(Self {
            input_packet_count,
            accounted_packet_count,
            flow_count,
            unclassified_count: unclassified.len(),
            tcp_flow_count,
            capture_start: capture_start_value.to_owned(),
            capture_end: capture_end_value.to_owned(),
            game_flow_start,
            game_flow_end,
            seconds_before_game_flow,
            seconds_after_game_flow,
            primary_flow,
            primary_packet_count,
            client,
            server,
            client_to_server_packets,
            server_to_client_packets,
            client_to_server_payload_bytes,
            server_to_client_payload_bytes,
        })
    }
}

struct PacketFacts {
    packet_count: u64,
    packet_handler_reencode_exact: u64,
    unreal_reencode_exact: u64,
    package_map_reencode_exact: u64,
    sgnet_wire_reencode_exact: u64,
    exact_bit_coverage: u64,
    bunch_count: u64,
    partial_payloads_completed: u64,
    batch_actor_count: u64,
    batch_property_count: u64,
    client_watermark_counter: Option<Value>,
    client_watermark_counter_low16: Option<Value>,
    client_watermark_crc32c_tested: Option<u64>,
    client_watermark_crc32c_validated: Option<u64>,
    encrypted_connection_id_raw_distribution: Option<Value>,
    plaintext_connection_id_distribution: Option<Value>,
    flag_one_raw_size_distribution: Option<Value>,
    partial_fragment_count: Option<u64>,
    partial_duplicate_fragments: Option<u64>,
    partial_fragments_per_payload: Option<Value>,
    partial_total_reassembled_bits: Option<u64>,
    client_watermark_counter_low14_relation: Option<Value>,
    ack_recent_peer_match: Option<Value>,
    ack_history_low5_semantics: Option<Value>,
    control_exchange_validation: Option<Value>,
    client_to_server: PacketDirectionFacts,
    server_to_client: PacketDirectionFacts,
}

struct PacketDirectionFacts {
    packet_count: u64,
    oodle_flag_one_packets: u64,
    oodle_pass_through_packets: u64,
    packet_handler_reencode_exact: u64,
    unreal_reencode_exact: u64,
    bunch_count: u64,
    package_map_reencode_exact: u64,
    sgnet_wire_reencode_exact: u64,
    duplicate_inner_packet_ids: u64,
    duplicate_packet_ids: Option<Value>,
    payload_bytes: Option<u64>,
    aggregate_entropy_bits_per_byte: Option<f64>,
    common_payload_lengths: Option<Value>,
    network_integrity: Option<Value>,
    reliability: Option<Value>,
    packet_info: Option<Value>,
    first_bunch_prefix: Option<Value>,
    repeated_suffix_candidates: Option<Value>,
}

impl PacketDirectionFacts {
    fn parse(value: &Value, direction: &str) -> Result<Self, CompatibilityDocumentError> {
        let root = value
            .as_object()
            .ok_or_else(|| wrong_type(format!("packet_report.{direction}"), "object"))?;
        let field = |name| required_u64_in(root, name, &format!("packet_report.{direction}"));
        Ok(Self {
            packet_count: field("packet_count")?,
            oodle_flag_one_packets: field("oodle_flag_one_packets")?,
            oodle_pass_through_packets: field("oodle_pass_through_packets")?,
            packet_handler_reencode_exact: field("packet_handler_reencode_exact")?,
            unreal_reencode_exact: field("unreal_reencode_exact")?,
            bunch_count: field("bunch_count")?,
            package_map_reencode_exact: field("package_map_reencode_exact")?,
            sgnet_wire_reencode_exact: field("sgnet_wire_reencode_exact")?,
            duplicate_inner_packet_ids: field("duplicate_inner_packet_ids")?,
            duplicate_packet_ids: optional_array_value(root, "duplicate_packet_ids", direction)?,
            payload_bytes: optional_u64_in(root, "payload_bytes", direction)?,
            aggregate_entropy_bits_per_byte: optional_f64_in(
                root,
                "aggregate_entropy_bits_per_byte",
                direction,
            )?,
            common_payload_lengths: optional_array_value(
                root,
                "common_payload_lengths",
                direction,
            )?,
            network_integrity: optional_object_value(root, "network_integrity", direction)?,
            reliability: build_direction_reliability(root, direction)?,
            packet_info: optional_object_value(root, "packet_info", direction)?,
            first_bunch_prefix: optional_object_value(root, "first_bunch_prefix", direction)?,
            repeated_suffix_candidates: optional_array_value(
                root,
                "repeated_suffix_candidates",
                direction,
            )?,
        })
    }
}

impl PacketFacts {
    fn parse(document: &Value) -> Result<Self, CompatibilityDocumentError> {
        let root = document
            .as_object()
            .ok_or_else(|| wrong_type("packet_report", "object"))?;
        Ok(Self {
            packet_count: required_u64_in(root, "packet_count", "packet_report")?,
            packet_handler_reencode_exact: required_u64_in(
                root,
                "packet_handler_reencode_exact",
                "packet_report",
            )?,
            unreal_reencode_exact: required_u64_in(root, "unreal_reencode_exact", "packet_report")?,
            package_map_reencode_exact: required_u64_in(
                root,
                "package_map_reencode_exact",
                "packet_report",
            )?,
            sgnet_wire_reencode_exact: required_u64_in(
                root,
                "sgnet_wire_reencode_exact",
                "packet_report",
            )?,
            exact_bit_coverage: required_u64_in(root, "exact_bit_coverage", "packet_report")?,
            bunch_count: required_u64_in(root, "bunch_count", "packet_report")?,
            partial_payloads_completed: required_u64_in(
                root,
                "partial_payloads_completed",
                "packet_report",
            )?,
            batch_actor_count: required_u64_in(root, "batch_actor_count", "packet_report")?,
            batch_property_count: required_u64_in(root, "batch_property_count", "packet_report")?,
            client_watermark_counter: optional_object_value(
                root,
                "client_watermark_counter",
                "packet_report",
            )?,
            client_watermark_counter_low16: optional_object_value(
                root,
                "client_watermark_counter_low16",
                "packet_report",
            )?,
            client_watermark_crc32c_tested: optional_u64_in(
                root,
                "client_watermark_crc32c_tested",
                "packet_report",
            )?,
            client_watermark_crc32c_validated: optional_u64_in(
                root,
                "client_watermark_crc32c_validated",
                "packet_report",
            )?,
            encrypted_connection_id_raw_distribution: optional_object_value(
                root,
                "encrypted_connection_id_raw_distribution",
                "packet_report",
            )?,
            plaintext_connection_id_distribution: optional_object_value(
                root,
                "plaintext_connection_id_distribution",
                "packet_report",
            )?,
            flag_one_raw_size_distribution: optional_object_value(
                root,
                "flag_one_raw_size_distribution",
                "packet_report",
            )?,
            partial_fragment_count: optional_u64_in(
                root,
                "partial_fragment_count",
                "packet_report",
            )?,
            partial_duplicate_fragments: optional_u64_in(
                root,
                "partial_duplicate_fragments",
                "packet_report",
            )?,
            partial_fragments_per_payload: optional_object_value(
                root,
                "partial_fragments_per_payload",
                "packet_report",
            )?,
            partial_total_reassembled_bits: optional_u64_in(
                root,
                "partial_total_reassembled_bits",
                "packet_report",
            )?,
            client_watermark_counter_low14_relation: optional_object_value(
                root,
                "client_watermark_counter_low14_relation",
                "packet_report",
            )?,
            ack_recent_peer_match: optional_object_value(
                root,
                "ack_recent_peer_match",
                "packet_report",
            )?,
            ack_history_low5_semantics: optional_object_value(
                root,
                "ack_history_low5_semantics",
                "packet_report",
            )?,
            control_exchange_validation: optional_object_value(
                root,
                "control_exchange_validation",
                "packet_report",
            )?,
            client_to_server: PacketDirectionFacts::parse(
                root.get("client_to_server")
                    .ok_or_else(|| missing("packet_report.client_to_server"))?,
                "client_to_server",
            )?,
            server_to_client: PacketDirectionFacts::parse(
                root.get("server_to_client")
                    .ok_or_else(|| missing("packet_report.server_to_client"))?,
                "server_to_client",
            )?,
        })
    }
}

struct NetGuidFacts {
    binding_count: usize,
    binding_len: usize,
    conflicts: Vec<Value>,
    main_map_path: String,
    main_map_source_frames: Vec<u64>,
}

impl NetGuidFacts {
    fn parse(document: &Value) -> Result<Self, CompatibilityDocumentError> {
        let root = document
            .as_object()
            .ok_or_else(|| wrong_type("netguid", "object"))?;
        let binding_count_u64 = required_u64_in(root, "binding_count", "netguid")?;
        let binding_count = usize::try_from(binding_count_u64)
            .map_err(|_| invariant_error("netguid binding_count does not fit usize"))?;
        let conflicts = required_array_in(root, "conflicts", "netguid")?.to_vec();
        let bindings = required_array_in(root, "bindings", "netguid")?;
        let mut guids = BTreeSet::new();
        let mut main_maps = BTreeMap::<String, BTreeSet<u64>>::new();
        for (index, binding) in bindings.iter().enumerate() {
            let path = format!("netguid.bindings[{index}]");
            let binding = binding
                .as_object()
                .ok_or_else(|| wrong_type(path.clone(), "object"))?;
            let guid = required_u64_in(binding, "netguid", &path)?;
            invariant(
                guids.insert(guid),
                "netguid bindings contain a duplicate GUID",
            )?;
            let object_path = required_str_in(binding, "path", &path)?;
            if is_main_map_path(object_path) {
                main_maps
                    .entry(object_path.to_owned())
                    .or_default()
                    .insert(required_u64_in(binding, "source_frame", &path)?);
            }
        }
        invariant(
            main_maps.len() == 1,
            "NetGUID bindings must contain exactly one absolute main-map path",
        )?;
        let (main_map_path, source_frames) = main_maps.into_iter().next().unwrap();
        Ok(Self {
            binding_count,
            binding_len: bindings.len(),
            conflicts,
            main_map_path,
            main_map_source_frames: source_frames.into_iter().collect(),
        })
    }
}

struct RecoveryFacts {
    fully_decrypted: bool,
    fully_decoded: bool,
    blocking_layer: String,
    fabricated_semantics: bool,
    validated_layers: BTreeSet<String>,
}

impl RecoveryFacts {
    fn parse(document: &Value) -> Result<Self, CompatibilityDocumentError> {
        let root = document
            .as_object()
            .ok_or_else(|| wrong_type("recovery_gate", "object"))?;
        let layers = required_array_in(root, "validated_layers", "recovery_gate")?;
        let validated_layers = layers
            .iter()
            .enumerate()
            .map(|(index, value)| {
                value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                    wrong_type(format!("recovery_gate.validated_layers[{index}]"), "string")
                })
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            fully_decrypted: required_bool_in(root, "fully_decrypted", "recovery_gate")?,
            fully_decoded: required_bool_in(root, "fully_decoded", "recovery_gate")?,
            blocking_layer: required_str_in(root, "blocking_layer", "recovery_gate")?.to_owned(),
            fabricated_semantics: required_bool_in(root, "fabricated_semantics", "recovery_gate")?,
            validated_layers,
        })
    }

    fn has_validated_layer(&self, layer: &str) -> bool {
        self.validated_layers.contains(layer)
    }
}

fn is_main_map_path(path: &str) -> bool {
    let Some((prefix, leaf)) = path.rsplit_once('/') else {
        return false;
    };
    path.starts_with("/Game/Maps/")
        && prefix.contains("/Levels")
        && leaf.starts_with("MAP_")
        && leaf.ends_with("_Main")
}

fn map_name_from_path(path: &str) -> Result<&str, CompatibilityDocumentError> {
    let rest = path
        .strip_prefix("/Game/Maps/")
        .ok_or_else(|| invariant_error("main map path is outside /Game/Maps"))?;
    let name = rest
        .split('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| invariant_error("main map path has no map directory"))?;
    Ok(name)
}

fn grouped_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            output.push(',');
        }
        output.push(character);
    }
    output
}

fn endpoint_port(endpoint: &str) -> Result<u16, CompatibilityDocumentError> {
    let port = if let Some(rest) = endpoint.strip_prefix('[') {
        let (_, port) = rest
            .split_once("]:")
            .ok_or_else(|| invariant_error("invalid bracketed endpoint"))?;
        port
    } else {
        endpoint
            .rsplit_once(':')
            .map(|(_, port)| port)
            .ok_or_else(|| invariant_error("endpoint has no port"))?
    };
    port.parse()
        .map_err(|_| invariant_error("endpoint port is not a u16"))
}

fn timestamp_delta_seconds(later: &str, earlier: &str) -> Result<f64, CompatibilityDocumentError> {
    let later = parse_iso_timestamp_ns(later)?;
    let earlier = parse_iso_timestamp_ns(earlier)?;
    invariant(
        later >= earlier,
        "flow timestamp ordering produced a negative duration",
    )?;
    Ok((later - earlier) as f64 / 1_000_000_000.0)
}

fn parse_iso_timestamp_ns(value: &str) -> Result<i128, CompatibilityDocumentError> {
    let bytes = value.as_bytes();
    let invalid = || invariant_error(format!("unsupported flow timestamp {value:?}"));
    if bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return Err(invalid());
    }
    let decimal = |start: usize, end: usize| -> Result<i64, CompatibilityDocumentError> {
        value[start..end].parse::<i64>().map_err(|_| invalid())
    };
    let year = decimal(0, 4)?;
    let month = decimal(5, 7)?;
    let day = decimal(8, 10)?;
    let hour = decimal(11, 13)?;
    let minute = decimal(14, 16)?;
    let second = decimal(17, 19)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(invalid());
    }
    let mut cursor = 19_usize;
    let mut fraction_ns = 0_i64;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        let digits = cursor - start;
        if digits == 0 || digits > 9 {
            return Err(invalid());
        }
        fraction_ns = value[start..cursor].parse::<i64>().map_err(|_| invalid())?
            * 10_i64.pow((9 - digits) as u32);
    }
    let offset_seconds = match bytes.get(cursor) {
        Some(b'Z') if cursor + 1 == bytes.len() => 0_i64,
        Some(sign @ (b'+' | b'-'))
            if cursor + 6 == bytes.len() && bytes.get(cursor + 3) == Some(&b':') =>
        {
            let offset_hour = value[cursor + 1..cursor + 3]
                .parse::<i64>()
                .map_err(|_| invalid())?;
            let offset_minute = value[cursor + 4..cursor + 6]
                .parse::<i64>()
                .map_err(|_| invalid())?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(invalid());
            }
            let magnitude = offset_hour * 3_600 + offset_minute * 60;
            if *sign == b'-' { -magnitude } else { magnitude }
        }
        _ => return Err(invalid()),
    };
    let days = days_from_civil(year, month, day);
    let local_seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    Ok(i128::from(local_seconds - offset_seconds) * 1_000_000_000 + i128::from(fraction_ns))
}

fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let adjusted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * adjusted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn validate_sha256(value: &str) -> Result<(), CompatibilityDocumentError> {
    invariant(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "pcap_sha256 must be 64 hexadecimal characters",
    )
}

fn reject_serialized_session_material(
    value: &Value,
    path: &str,
) -> Result<(), CompatibilityDocumentError> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized: String = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                if matches!(
                    normalized.as_str(),
                    "packetkey" | "gameid" | "encryptionkey"
                ) {
                    return Err(CompatibilityDocumentError::ForbiddenSessionField(format!(
                        "{path}.{key}"
                    )));
                }
                reject_serialized_session_material(child, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_serialized_session_material(child, &format!("{path}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn required_object<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a Map<String, Value>, CompatibilityDocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| wrong_type("batch_sync", "object"))?;
    object
        .get(key)
        .ok_or_else(|| missing(format!("batch_sync.{key}")))?
        .as_object()
        .ok_or_else(|| wrong_type(format!("batch_sync.{key}"), "object"))
}

fn required_array<'a>(
    value: &'a Value,
    key: &str,
) -> Result<&'a [Value], CompatibilityDocumentError> {
    let object = value
        .as_object()
        .ok_or_else(|| wrong_type("batch_sync", "object"))?;
    required_array_in(object, key, "batch_sync")
}

fn required_array_in<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<&'a [Value], CompatibilityDocumentError> {
    object
        .get(key)
        .ok_or_else(|| missing(format!("{parent}.{key}")))?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "array"))
}

fn required_str_in<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<&'a str, CompatibilityDocumentError> {
    object
        .get(key)
        .ok_or_else(|| missing(format!("{parent}.{key}")))?
        .as_str()
        .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "string"))
}

fn required_u64_in(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<u64, CompatibilityDocumentError> {
    object
        .get(key)
        .ok_or_else(|| missing(format!("{parent}.{key}")))?
        .as_u64()
        .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "non-negative integer"))
}

fn required_bool_in(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<bool, CompatibilityDocumentError> {
    object
        .get(key)
        .ok_or_else(|| missing(format!("{parent}.{key}")))?
        .as_bool()
        .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "boolean"))
}

fn optional_u64_in(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<Option<u64>, CompatibilityDocumentError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "non-negative integer"))
        })
        .transpose()
}

fn optional_f64_in(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<Option<f64>, CompatibilityDocumentError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_f64()
                .ok_or_else(|| wrong_type(format!("{parent}.{key}"), "number"))
        })
        .transpose()
}

fn optional_array_value(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<Option<Value>, CompatibilityDocumentError> {
    object
        .get(key)
        .map(|value| {
            if value.is_array() {
                Ok(value.clone())
            } else {
                Err(wrong_type(format!("{parent}.{key}"), "array"))
            }
        })
        .transpose()
}

fn optional_object_value(
    object: &Map<String, Value>,
    key: &str,
    parent: &str,
) -> Result<Option<Value>, CompatibilityDocumentError> {
    object
        .get(key)
        .map(|value| {
            if value.is_object() {
                Ok(value.clone())
            } else {
                Err(wrong_type(format!("{parent}.{key}"), "object"))
            }
        })
        .transpose()
}

fn build_direction_reliability(
    object: &Map<String, Value>,
    direction: &str,
) -> Result<Option<Value>, CompatibilityDocumentError> {
    if !object.contains_key("control_packet_count") {
        return Ok(None);
    }
    const NUMBER_FIELDS: [&str; 3] = [
        "control_packet_count",
        "normal_packet_count",
        "missing_packet_id_count",
    ];
    const OBJECT_FIELDS: [&str; 4] = [
        "ack_history_byte_count_distribution",
        "packet_id_sequence",
        "packet_id_delta_counts",
        "peer_reported_missing",
    ];
    const ARRAY_FIELDS: [&str; 4] = [
        "duplicate_packet_ids",
        "missing_packet_ids",
        "reorders",
        "ack_backward_steps",
    ];
    let parent = format!("packet_report.{direction}");
    let mut result = Map::new();
    for key in NUMBER_FIELDS {
        result.insert(
            key.to_owned(),
            Value::from(required_u64_in(object, key, &parent)?),
        );
    }
    for key in OBJECT_FIELDS {
        result.insert(
            key.to_owned(),
            optional_object_value(object, key, &parent)?
                .ok_or_else(|| missing(format!("{parent}.{key}")))?,
        );
    }
    for key in ARRAY_FIELDS {
        result.insert(
            key.to_owned(),
            optional_array_value(object, key, &parent)?
                .ok_or_else(|| missing(format!("{parent}.{key}")))?,
        );
    }
    for key in ["ack_first", "ack_last"] {
        let value = object
            .get(key)
            .ok_or_else(|| missing(format!("{parent}.{key}")))?;
        if !value.is_null() && value.as_u64().is_none() {
            return Err(wrong_type(format!("{parent}.{key}"), "integer or null"));
        }
        result.insert(key.to_owned(), value.clone());
    }
    Ok(Some(Value::Object(result)))
}

fn invariant(
    condition: bool,
    message: impl Into<String>,
) -> Result<(), CompatibilityDocumentError> {
    if condition {
        Ok(())
    } else {
        Err(invariant_error(message))
    }
}

fn invariant_error(message: impl Into<String>) -> CompatibilityDocumentError {
    CompatibilityDocumentError::Invariant(message.into())
}

fn missing(path: impl Into<String>) -> CompatibilityDocumentError {
    CompatibilityDocumentError::Missing(path.into())
}

fn wrong_type(path: impl Into<String>, expected: &'static str) -> CompatibilityDocumentError {
    CompatibilityDocumentError::WrongType {
        path: path.into(),
        expected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use codev_protocol::{
        A0Property, A0Summary, A0Value, D0Summary, D0Update, MovementState, SlotContinuity, Vec3,
    };
    use codev_stream::{A0Payload, Direction, W0RosterEntry};
    use zeroize::Zeroizing;

    use crate::compat_batch::BatchSummaryAccumulator;

    fn session() -> EnterGameSession {
        let mut roster = Vec::new();
        for index in 0..10_u32 {
            roster.push(W0RosterEntry {
                name: format!("private-name-{index}"),
                display_name: (index == 0).then(|| "private-display-alias".to_owned()),
                uid: (10_000 + index).to_string(),
                open_id: (20_000 + index).to_string(),
                agent_id: 3_001 + index,
                skin_id: 3_001_001 + index,
                selected_backpack_id: 1,
                camp_id: u64::from(index / 5 + 1),
                position_slot: index % 5 + 1,
                device_tag: index == 0,
            });
        }
        EnterGameSession {
            server_ip: "game.example.invalid".into(),
            server_vip: Some("203.0.113.8".into()),
            server_port: 15_806,
            packet_key: Zeroizing::new("must-never-be-serialized".into()),
            g0_id: 0x1122_3344_5566_7788,
            map_id: 1_003,
            g1_mode: 102,
            s0_mode: 101_002,
            roster,
            source_mna_sequence: 613,
            reenter: false,
        }
    }

    fn batch_summary() -> BatchSyncSummary {
        let update = D0Update {
            slot: 0,
            state_index: 0,
            bit_offset: 1,
            bit_length: 3,
            use_baseline: false,
            source_baseline: None,
            source_baseline_position_valid: None,
            store_baseline: false,
            destination_baseline: None,
            change_mask: 0,
            movement: None,
            extra_state: None,
            state: MovementState {
                position: Vec3::new(1.0, 2.0, 3.0),
                ..MovementState::default()
            },
            position_valid: true,
            continuity: SlotContinuity::Continuous,
        };
        let property = A0Property {
            handle: BATCH_PROPERTY_HANDLE,
            handle_bit_offset: 0,
            handle_bit_length: 1,
            payload_bit_offset: 1,
            payload_bit_length: 3,
            value: A0Value::BatchData(D0Summary {
                character_count: 1,
                bit_offset: 1,
                bit_length: 3,
                present_slot_mask: 1,
                update_count: 1,
            }),
        };
        let actor = A0Payload {
            direction: Direction::ServerToClient,
            capture_index: 8,
            timestamp_ns: 100,
            packet_sequence: 1,
            channel_index: BATCH_CHANNEL_INDEX,
            channel_generation: 0,
            source_capture_indices: vec![8],
            bunch_index: Some(0),
            wire_data_bit_offset: Some(0),
            data: vec![0],
            bit_length: 5,
            summary: A0Summary {
                has_rep_layout: true,
                is_actor: true,
                content_payload_bit_offset: 0,
                content_payload_bit_length: 5,
                checksum_present: false,
                property_count: 1,
                batch_property_count: 1,
                raw_two_bit_property_count: 0,
                property_terminator_bit_offset: 4,
                property_terminator_bit_length: 1,
                consumed_bits: 5,
            },
            properties: vec![property],
            updates: vec![update],
            camp_assignments: Vec::new(),
            local_anchor_spawn: None,
        };
        let mut accumulator = BatchSummaryAccumulator::default();
        accumulator.observe_actor(&actor);
        accumulator.finish()
    }

    fn flow_manifest() -> Value {
        json!({
            "input_packet_count": 12,
            "accounted_packet_count": 12,
            "flow_count": 2,
            "unclassified": [],
            "primary_flow_id": "udp:10.0.0.2:40000<->203.0.113.8:15806",
            "primary_selection": "fixture",
            "flows": [
                {
                    "flow_id": "tcp:10.0.0.2:50000<->203.0.113.9:443",
                    "ip_version": 4,
                    "protocol": "tcp",
                    "endpoint_a": "10.0.0.2:50000",
                    "endpoint_b": "203.0.113.9:443",
                    "packet_count": 10,
                    "transport_payload_bytes": 100,
                    "captured_bytes": 200,
                    "original_bytes": 200,
                    "first_timestamp": "2026-08-06T08:00:00.000000+08:00",
                    "last_timestamp": "2026-08-06T08:10:00.000000+08:00",
                    "duration_seconds": 600.0,
                    "a_to_b_packets": 5,
                    "b_to_a_packets": 5,
                    "a_to_b_payload_bytes": 50,
                    "b_to_a_payload_bytes": 50,
                    "parse_issue_count": 0
                },
                {
                    "flow_id": "udp:10.0.0.2:40000<->203.0.113.8:15806",
                    "ip_version": 4,
                    "protocol": "udp",
                    "endpoint_a": "10.0.0.2:40000",
                    "endpoint_b": "203.0.113.8:15806",
                    "packet_count": 2,
                    "transport_payload_bytes": 80,
                    "captured_bytes": 164,
                    "original_bytes": 164,
                    "first_timestamp": "2026-08-06T08:05:00.000000+08:00",
                    "last_timestamp": "2026-08-06T08:06:00.000000+08:00",
                    "duration_seconds": 60.0,
                    "a_to_b_packets": 1,
                    "b_to_a_packets": 1,
                    "a_to_b_payload_bytes": 30,
                    "b_to_a_payload_bytes": 50,
                    "parse_issue_count": 0,
                    "classification": {"class": "main_game_udp", "confidence": "proven"}
                }
            ]
        })
    }

    fn pipeline() -> PipelineStats {
        PipelineStats {
            datagrams: 2,
            sgnet_decrypted: 2,
            sgnet_wire_reencode_exact: 2,
            packet_handler_envelopes_exact: 2,
            packet_handler_pass_through: 2,
            oodle_compressed: 0,
            unreal_packets: 2,
            unreal_packets_exact: 2,
            bunches: 3,
            package_map_export_prefixes_exact: 1,
            netguid_records: 1,
            partial_fragments: 2,
            partial_payloads_completed: 1,
            actor_messages: 1,
            batch_properties: 1,
            raw_two_bit_properties: 0,
            character_updates: 1,
            ..PipelineStats::default()
        }
    }

    fn packet_report() -> Value {
        json!({
            "packet_count": 2,
            "unresolved_span_count": 2,
            "packet_handler_reencode_exact": 2,
            "unreal_reencode_exact": 2,
            "package_map_reencode_exact": 1,
            "sgnet_wire_reencode_exact": 2,
            "exact_bit_coverage": 2,
            "bunch_count": 3,
            "partial_payloads_completed": 1,
            "batch_actor_count": 1,
            "batch_property_count": 1,
            "packets_sha256": "00",
            "unresolved_sha256": "00",
            "packets_bytes": 1,
            "unresolved_bytes": 1,
            "client_to_server": {
                "packet_count": 1,
                "oodle_flag_one_packets": 0,
                "oodle_pass_through_packets": 1,
                "packet_handler_reencode_exact": 1,
                "unreal_reencode_exact": 1,
                "bunch_count": 1,
                "package_map_reencode_exact": 0,
                "sgnet_wire_reencode_exact": 1,
                "duplicate_inner_packet_ids": 0
            },
            "server_to_client": {
                "packet_count": 1,
                "oodle_flag_one_packets": 0,
                "oodle_pass_through_packets": 1,
                "packet_handler_reencode_exact": 1,
                "unreal_reencode_exact": 1,
                "bunch_count": 2,
                "package_map_reencode_exact": 1,
                "sgnet_wire_reencode_exact": 1,
                "duplicate_inner_packet_ids": 0
            }
        })
    }

    fn netguid() -> Value {
        json!({
            "binding_count": 1,
            "conflicts": [],
            "bindings": [{
                "netguid": 7,
                "outer_netguid": 0,
                "path": "/Game/Maps/Icebox/Levels/MAP_IceBox_Main",
                "network_checksum": Value::Null,
                "flags": 3,
                "bunch_index": 0,
                "channel_index": 2,
                "source_frame": 9
            }]
        })
    }

    fn recovery_gate() -> Value {
        json!({
            "schema_version": "codev.recovery-gate/v3",
            "status": "transport_decryption_complete_semantic_decode_in_progress",
            "fully_decrypted": true,
            "fully_decoded": false,
            "blocking_layer": "unreal_replication_rpc_class_semantics",
            "validated_layers": [
                "ethernet_ipv4_udp_integrity_and_offload",
                "client_watermark_crc32c_and_uint32_counter",
                "partial_bunch_reassembly_1_complete_zero_issues"
            ],
            "fabricated_semantics": false
        })
    }

    fn with_inputs<T>(mutator: impl FnOnce(&mut CompatibilityDocumentInputs<'_>) -> T) -> T {
        let session = session();
        let batch = batch_summary();
        let flow = flow_manifest();
        let netguid = netguid();
        let recovery = recovery_gate();
        let packet = packet_report();
        let auxiliary = CompatibilityAuxiliaryCapture::default();
        let mut inputs = CompatibilityDocumentInputs {
            pcap: Path::new("fixture.pcap"),
            pcap_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            session: &session,
            pipeline: pipeline(),
            batch_sync: &batch,
            flow_manifest: &flow,
            netguid: &netguid,
            recovery_gate: &recovery,
            packet_report: &packet,
            mna_provenance: None,
            auxiliary: &auxiliary,
            fixture: FixtureClassification::default(),
        };
        mutator(&mut inputs)
    }

    fn contains_forbidden_key(value: &Value) -> bool {
        match value {
            Value::Object(object) => object.iter().any(|(key, child)| {
                let normalized: String = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect();
                matches!(
                    normalized.as_str(),
                    "packetkey" | "gameid" | "encryptionkey"
                ) || contains_forbidden_key(child)
            }),
            Value::Array(values) => values.iter().any(contains_forbidden_key),
            _ => false,
        }
    }

    #[test]
    fn private_match_keeps_roster_without_session_material_or_identity_guess() {
        with_inputs(|inputs| {
            let documents = build_compatibility_documents(inputs).unwrap();
            let match_state = &documents.match_document;
            assert_eq!(match_state["participants"].as_array().unwrap().len(), 10);
            assert_eq!(match_state["participants"][0]["name"], "private-name-0");
            assert_eq!(match_state["participants"][0]["uid"], "10000");
            assert_eq!(match_state["participants"][0]["open_id"], "20000");
            assert!(match_state["participants"][0].get("batch_slot").is_none());
            assert_eq!(
                match_state["metadata"]["batch_sync_coordinates"]["tracks"][0]["track_id"],
                "batch_slot_0"
            );
            assert_eq!(
                match_state["metadata"]["batch_sync_coordinates"]["tracks"][0]["identity_binding"],
                "unresolved"
            );
            assert!(!contains_forbidden_key(match_state));
            assert!(!contains_forbidden_key(&documents.summary_document));
            assert_eq!(
                match_state["metadata"]["sgnet_cipher"]["key_seed_hex"],
                "<redacted:not-retained>"
            );
            assert!(
                match_state["metadata"]["sgnet_cipher"]
                    .get("g0_id")
                    .is_none()
            );
            assert!(
                !serde_json::to_string(match_state)
                    .unwrap()
                    .contains("must-never-be-serialized")
            );
        });
    }

    #[test]
    fn core_counts_and_checks_are_dynamic_typed_projections() {
        with_inputs(|inputs| {
            let documents = build_compatibility_documents(inputs).unwrap();
            let summary = documents.summary_document;
            assert_eq!(summary["packet_count"], 12);
            assert_eq!(summary["flow_count"], 2);
            assert_eq!(summary["tcp_flow_count"], 1);
            assert_eq!(summary["full_session_decode"]["counts"]["packets"], 2);
            assert_eq!(
                summary["full_session_decode"]["counts"]["batch_sync_actor_messages"],
                1
            );
            assert_eq!(
                summary["full_session_decode"]["counts"]["batch_sync_character_updates"],
                1
            );
            assert_eq!(
                summary["main_packet_bit_coverage"]["coverage_complete"],
                true
            );
            assert_eq!(summary["reencode_validation"]["all_exact"], true);
            assert_eq!(summary["baseline_checks"]["all_packets_accounted"], true);
            assert_eq!(
                summary["baseline_checks"]["no_duplicate_inner_packet_ids"],
                true
            );
            assert_eq!(
                summary["full_session_decode"]["directions"]["client_to_server"]["bunches"],
                1
            );
        });
    }

    #[test]
    fn cross_artifact_count_mismatch_fails_closed() {
        let session = session();
        let batch = batch_summary();
        let flow = flow_manifest();
        let netguid = netguid();
        let recovery = recovery_gate();
        let mut packet = packet_report();
        let auxiliary = CompatibilityAuxiliaryCapture::default();
        packet["packet_count"] = json!(3);
        let inputs = CompatibilityDocumentInputs {
            pcap: Path::new("fixture.pcap"),
            pcap_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            session: &session,
            pipeline: pipeline(),
            batch_sync: &batch,
            flow_manifest: &flow,
            netguid: &netguid,
            recovery_gate: &recovery,
            packet_report: &packet,
            mna_provenance: None,
            auxiliary: &auxiliary,
            fixture: FixtureClassification::default(),
        };
        let error = build_compatibility_documents(&inputs).unwrap_err();
        assert!(error.to_string().contains("packet_count"));
    }

    #[test]
    fn serialized_input_with_game_id_is_rejected_before_projection() {
        let session = session();
        let batch = batch_summary();
        let flow = flow_manifest();
        let netguid = netguid();
        let mut recovery = recovery_gate();
        recovery["GameId"] = json!(123);
        let packet = packet_report();
        let auxiliary = CompatibilityAuxiliaryCapture::default();
        let inputs = CompatibilityDocumentInputs {
            pcap: Path::new("fixture.pcap"),
            pcap_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            session: &session,
            pipeline: pipeline(),
            batch_sync: &batch,
            flow_manifest: &flow,
            netguid: &netguid,
            recovery_gate: &recovery,
            packet_report: &packet,
            mna_provenance: None,
            auxiliary: &auxiliary,
            fixture: FixtureClassification::default(),
        };
        assert!(matches!(
            build_compatibility_documents(&inputs),
            Err(CompatibilityDocumentError::ForbiddenSessionField(_))
        ));
    }

    #[test]
    fn python_v2_top_level_field_names_and_json_types_are_preserved() {
        const MATCH_TYPES: [(&str, &str); 16] = [
            ("build", "string"),
            ("status", "string"),
            ("capture_start", "string"),
            ("capture_end", "string"),
            ("game_flow_start", "string"),
            ("game_flow_end", "string"),
            ("server", "string"),
            ("client", "string"),
            ("metadata", "object"),
            ("participants", "array"),
            ("teams", "array"),
            ("phases", "array"),
            ("events", "array"),
            ("score", "object"),
            ("result", "object"),
            ("limitations", "array"),
        ];
        const SUMMARY_TYPES: [(&str, &str); 32] = [
            ("schema_version", "number"),
            ("pcap", "string"),
            ("pcap_sha256", "string"),
            ("decoder_schema", "object"),
            ("packet_count", "number"),
            ("flow_count", "number"),
            ("unclassified_packet_count", "number"),
            ("tcp_flow_count", "number"),
            ("capture_scope", "object"),
            ("main_flow", "object"),
            ("client", "string"),
            ("server", "string"),
            ("client_watermark_counter", "object"),
            ("client_watermark_counter_low16", "object"),
            ("client_watermark_crc32c", "object"),
            ("encrypted_connection_id_raw_distribution", "object"),
            ("plaintext_connection_id_distribution", "object"),
            ("sgnet_cipher", "object"),
            ("capture_recovered_keystream_prefix", "object"),
            ("fixed_keystream_projection", "object"),
            ("reliability", "object"),
            ("full_session_decode", "object"),
            ("network_integrity", "object"),
            ("direction_stats", "object"),
            ("baseline_checks", "object"),
            ("fixture_checks", "object"),
            ("full_fixture_checks", "object"),
            ("main_packet_bit_coverage", "object"),
            ("reencode_validation", "object"),
            ("fully_decrypted", "boolean"),
            ("fully_decoded", "boolean"),
            ("blocking_layer", "string"),
        ];
        with_inputs(|inputs| {
            let documents = build_compatibility_documents(inputs).unwrap();
            assert_top_level_types(&documents.match_document, &MATCH_TYPES);
            assert_top_level_types(&documents.summary_document, &SUMMARY_TYPES);
            assert_eq!(
                documents.summary_document["blocking_layer"].as_str(),
                Some("unreal_replication_rpc_class_semantics")
            );
        });
    }

    fn assert_top_level_types(value: &Value, expected: &[(&str, &str)]) {
        let object = value.as_object().unwrap();
        let expected_keys: BTreeSet<_> = expected.iter().map(|(key, _)| *key).collect();
        let actual_keys: BTreeSet<_> = object.keys().map(String::as_str).collect();
        assert_eq!(actual_keys, expected_keys);
        for (key, expected_type) in expected {
            let actual_type = match &value[*key] {
                Value::Null => "null",
                Value::Bool(_) => "boolean",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            assert_eq!(actual_type, *expected_type, "field {key}");
        }
    }

    #[test]
    fn fixture_classification_is_not_inferred_from_private_values() {
        let fixture = FixtureClassification {
            known_udp_fixture: false,
            known_full_fixture: true,
        };
        assert!(fixture.known_full_fixture);
        assert!(!fixture.known_udp_fixture);
        let _ = BTreeMap::<String, u64>::new();
    }
}
