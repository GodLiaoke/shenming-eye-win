//! Evidence-derived compatibility `recovery_gate.json`.

use codev_stream::PipelineStats;
use serde::Serialize;
use thiserror::Error;

use crate::compat_network::CompatibilityCaptureFacts;

#[derive(Debug, Error)]
pub enum RecoveryGateError {
    #[error("recovery gate proof is incomplete: {0}")]
    Incomplete(&'static str),
}

#[derive(Debug, Serialize)]
pub struct RecoveryGate {
    schema_version: &'static str,
    status: &'static str,
    fully_decrypted: bool,
    fully_decoded: bool,
    blocking_layer: &'static str,
    runtime_extraction_allowed: bool,
    same_session_tcp_present: bool,
    validated_layers: Vec<String>,
    unvalidated_layers: [&'static str; 4],
    required_inputs: Vec<&'static str>,
    required_static_work: [&'static str; 2],
    static_findings: &'static str,
    packet_notify_audit: &'static str,
    pak_oodle_findings: &'static str,
    pak_index_audit: &'static str,
    pak_config_audit: &'static str,
    oodle_boundary_probe_historical_ciphertext_experiment: &'static str,
    sgnet_cipher_audit: &'static str,
    sgnet_session_material_audit: &'static str,
    sgnet_visible_id_seed_exclusion: &'static str,
    keystream_extension_audit: &'static str,
    lua_control_plane_audit: &'static str,
    lua_key_material_audit: &'static str,
    lua_travel_dataflow_audit: &'static str,
    protobuf_control_plane_audit: &'static str,
    hard_boundary: String,
    fabricated_semantics: bool,
}

pub fn build_recovery_gate(
    stats: PipelineStats,
    capture: &CompatibilityCaptureFacts,
    track_count: u32,
) -> Result<RecoveryGate, RecoveryGateError> {
    require(capture.all_packets_accounted, "flow accounting")?;
    require(
        capture.primary_packet_count == stats.datagrams,
        "primary flow/pipeline packet count",
    )?;
    require(
        capture.primary_ipv4_checksums_valid == capture.primary_packet_count,
        "IPv4 header checksums",
    )?;
    require(
        capture.primary_udp_checksums_valid_or_offload == capture.primary_packet_count,
        "UDP checksums/offload seeds",
    )?;
    require(
        capture.client_watermark_tested != 0
            && capture.client_watermark_validated == capture.client_watermark_tested
            && capture.client_watermark_counter_continuous,
        "client WaterMark CRC/counter sequence",
    )?;
    require(
        stats.sgnet_decrypted == stats.datagrams
            && stats.sgnet_wire_reencode_exact == stats.datagrams,
        codev_obf::s_static("d42b38ef3b472b04e41e0ffa3b482a0fe41e0ffa3b473808f50956f820122105a71804e33f"),
    )?;
    require(
        stats.packet_handler_envelopes_exact == stats.datagrams
            && stats.packet_handler_pass_through + stats.oodle_compressed == stats.datagrams,
        codev_obf::s_static("0615691b85efc67a3810661592bbeb752011661f90feae7839026f0281fceb"),
    )?;
    require(
        stats.unreal_packets == stats.packet_handler_pass_through
            && stats.unreal_packets_exact == stats.unreal_packets,
        "Unreal packet archive coverage",
    )?;
    require(
        stats.sequence_gaps == 0 && stats.capture_gaps == 0 && stats.dropped_gap_records == 0,
        "lossless sequence and partial continuity",
    )?;
    require(
        stats.actor_messages != 0 && stats.character_updates != 0 && track_count != 0,
        codev_obf::s_static("6f9e82e46ca70ef74edf95e86b8613f0439e82e2249101f0499a98e461"),
    )?;

    let mut required_inputs = Vec::new();
    if capture.tcp_flow_count == 0 {
        required_inputs.push("过滤前、同一局、覆盖登录/匹配的原始全量 PCAP");
    }
    if capture.capture_end_ns <= capture.primary_last_ns {
        required_inputs.push(
            "若需验证赛后结果页控制链，补充主对局流结束后的抓包尾部；当前输入在最后一个主流包处终止",
        );
    }

    let mut validated_layers = vec![
        "classic_pcap_container".into(),
        "ethernet_ipv4_udp_integrity_and_offload".into(),
        "bidirectional_flow_accounting".into(),
        "client_watermark_crc32c_and_uint32_counter".into(),
        "sgnet_ietf_chacha20_session_decryption".into(),
        format!(
            "packet_handler_oodle_envelope_{}_exact",
            stats.packet_handler_envelopes_exact
        ),
        format!(
            "unreal_packet_notify_packet_info_and_all_bunch_headers_{}_exact",
            stats.unreal_packets_exact
        ),
        format!(
            "package_map_netguid_export_prefixes_{}_exact",
            stats.package_map_export_prefixes_exact
        ),
        format!(
            "partial_bunch_reassembly_{}_complete_zero_issues",
            stats.partial_payloads_completed
        ),
        format!(
            "batch_sync_channel_32_actor_messages_{}_exact",
            stats.actor_messages
        ),
        format!(
            "batch_sync_coordinates_{}_updates_{}_unbound_tracks",
            stats.character_updates, track_count
        ),
        "lossless_unknown_span_and_exact_reencode".into(),
    ];
    if capture.voice_room_count != 0 {
        validated_layers.push("gcloud_cleartext_room_metadata".into());
    }
    validated_layers.extend([
        "static_packet_handler_and_oodle_header_format".into(),
        "pak_v14_main_path_directory_indexes_with_embedded_sha1".into(),
        "codev_dictionary_entry_location_and_stored_payload_sha1".into(),
        "embedded_arm64_oodle_asset_and_network_decoder_adapter".into(),
        "historical_ciphertext_direct_tail_oodle_probe_retained_not_promoted".into(),
        "static_lua_packetkey_to_native_encryptionkey_exact_dataflow".into(),
        "authenticated_lobby_protobuf_field_numbers_and_bkdr_command_ids".into(),
        "pcap_direct_enter_game_wire_pattern_exclusion".into(),
    ]);
    let hard_boundary = format!(
        "SGNet 会话材料已由同局 HTTPS 明文控制链确定，{} 个主 UDP 包完成解密和逐包重加密；\
PacketHandler、{} 个 UE 包、{} 个 bunch、{} 个 PackageMap export 以及 {} 条 partial 链均已位精确验证。\
Channel 32 的 {} 条 actor 消息已精确耗尽并恢复 {} 条 batch_slot_N 状态更新；\
槽位到玩家身份的绑定仍未证明。当前边界还包括版本化 replication/RPC 类字段语义；\
服务器未向客户端发送的隐藏状态仍不可恢复。",
        grouped(stats.datagrams),
        grouped(stats.unreal_packets),
        grouped(stats.bunches),
        grouped(stats.package_map_export_prefixes_exact),
        grouped(stats.partial_payloads_completed),
        grouped(stats.actor_messages),
        grouped(stats.character_updates),
    );

    Ok(RecoveryGate {
        schema_version: "codev.recovery-gate/v3",
        status: "transport_decryption_complete_semantic_decode_in_progress",
        fully_decrypted: true,
        fully_decoded: false,
        blocking_layer: "unreal_replication_rpc_class_semantics",
        runtime_extraction_allowed: false,
        same_session_tcp_present: capture.tcp_flow_count != 0,
        validated_layers,
        unvalidated_layers: [
            "ack_history_bits_beyond_low5_index_mapping",
            "unreal_replication_and_rpc_class_field_semantics",
            "batch_slot_to_playerstate_identity_binding",
            "semantic_match_events_and_result",
        ],
        required_inputs,
        required_static_work: [
            "将已恢复的 Actor content block、RepLayout 与 LuaRepObj ClassNetCache 字段索引映射为比分、击杀和回合事件",
            "证明 batch_slot_N 到 PlayerCharacter/PlayerState 的 replicated object reference；在此之前不得把坐标轨迹绑定到玩家身份",
        ],
        static_findings: "analysis/idalib-codev-final2/findings.json",
        packet_notify_audit: "analysis/packet-notify-audit.json",
        pak_oodle_findings: "analysis/pak-oodle.json",
        pak_index_audit: "analysis/pak-footer-audit.json",
        pak_config_audit: "analysis/pak-config-audit.json",
        oodle_boundary_probe_historical_ciphertext_experiment: "analysis/oodle-boundary-probe.json",
        sgnet_cipher_audit: "analysis/sgnet-inbound-wrapper-audit.json",
        sgnet_session_material_audit: "analysis/sgnet-key-material-pcap-audit.json",
        sgnet_visible_id_seed_exclusion: "analysis/sgnet-visible-id-seed-exclusion.json",
        keystream_extension_audit: "analysis/keystream-extension-audit.json",
        lua_control_plane_audit: "analysis/lua-control-plane-audit.json",
        lua_key_material_audit: "analysis/lua-key-material-audit.json",
        lua_travel_dataflow_audit: "analysis/lua-travel-dataflow-audit.json",
        protobuf_control_plane_audit: "analysis/protobuf-control-plane-audit.json",
        hard_boundary,
        fabricated_semantics: false,
    })
}

fn require(condition: bool, name: &'static str) -> Result<(), RecoveryGateError> {
    if condition {
        Ok(())
    } else {
        Err(RecoveryGateError::Incomplete(name))
    }
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut output = String::with_capacity(digits.len() + digits.len() / 3);
    let first = digits.len() % 3;
    if first != 0 {
        output.push_str(&digits[..first]);
    }
    for chunk in digits.as_bytes()[first..].chunks(3) {
        if !output.is_empty() {
            output.push(',');
        }
        output.push_str(std::str::from_utf8(chunk).expect("decimal digits are UTF-8"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousands_grouping_matches_chinese_gate_text() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(512), "512");
        assert_eq!(grouped(4_444), "4,444");
        assert_eq!(grouped(17_031), "17,031");
    }
}
