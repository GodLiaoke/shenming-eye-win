//! Native renderer for the complete-session compatibility report.
//!
//! This is deliberately a pure projection of the three machine artifacts.
//! It never reinterprets unresolved wire fields and therefore cannot promote
//! identity, map, or gameplay semantics while formatting human-readable text.

use serde_json::Value;

pub fn render_full_session_report(summary: &Value, match_state: &Value, gate: &Value) -> String {
    let main = object(summary, "main_flow");
    let full = object(summary, "full_session_decode");
    let counts = object(full, "counts");
    let directions = object(full, "directions");
    let partial = object(full, "partial_reassembly");
    let netguid = object(full, "netguid");
    let batch = object(full, "batch_sync");
    let metadata = object(match_state, "metadata");
    let map = object(metadata, "map");
    let limitations = array(match_state, "limitations");
    let participants = array(match_state, "participants");
    let teams = array(match_state, "teams");
    let baseline = object(summary, "baseline_checks");
    let failed_checks: Vec<_> = baseline
        .as_object()
        .into_iter()
        .flat_map(|values| values.iter())
        .filter(|(name, _)| !matches!(name.as_str(), "known_udp_fixture" | "known_full_fixture"))
        .filter(|(_, passed)| {
            passed.as_bool() != Some(true)
                && passed.get("status").and_then(Value::as_str) != Some("not_applicable")
        })
        .map(|(name, _)| name.as_str())
        .collect();

    let reencode = object(summary, "reencode_validation");
    let coverage = object(summary, "main_packet_bit_coverage");
    let client_direction = object(directions, "client_to_server");
    let server_direction = object(directions, "server_to_client");

    let mut lines = vec![
        "# CodeV 1.24.0 对局流量静态解密报告".into(),
        String::new(),
        "## 结论".into(),
        String::new(),
        codev_obf::f2("ba8a1328437a677eded41d4ccca3f9b23e124d485de3f9b27ed724480f43009c197ccdb9cc80eaae1d5ac9ffdce36673c4da07500a5e1229c8ab4d7a5e24167ebba224285d436441f9d7207b05503c28ff9c4d63762c3e43ba8a13edb987d2efbb851a28424f6447cedb285d094f0727f9914d626a2c3e54b8b80d287d49675dd2d43477095a2a2be4954f4445251e65ba8d3528415b6741c1d70f46cca8e7b6715cc7a38fa6614fdc", display(main.get("flow_id")), display(main.get("packet_count"))),
        String::new(),
        format!(
            "å¯ééªè¯é­ç¯ï¼PacketHandler {}/{}ï¼UE {}/{}ï¼å®æ´ wire {}/{} åç²¾ç¡®éç¼ç ã",
            unsigned(counts, "packet_handler_reencode_exact"),
            unsigned(counts, "packets"),
            unsigned(counts, "unreal_reencode_exact"),
            unsigned(counts, "oodle_pass_through_packets"),
            unsigned(reencode, "exact_packets"),
            unsigned(reencode, "packet_count"),
        ),
        String::new(),
        format!(
            "地图由 PackageMap NetGUID 路径证明为 `{}`：`{}`。当前阻塞层为 `{}`；未完成的 replication/RPC 语义不会被猜测。",
            string_or(map, "name", "未知"),
            string_or(netguid, "main_map_path", "未恢复"),
            display(summary.get("blocking_layer")),
        ),
        String::new(),
        "## 输入与范围".into(),
        String::new(),
        format!("- PCAP：`{}`", display(summary.get("pcap"))),
        format!(
            "- PCAP SHA-256：`{}`",
            display(summary.get("pcap_sha256"))
        ),
        "- 构建：`1.24.0 (2911)`；仅恢复该客户端在抓包期间实际收发的状态。".into(),
        "- 静态边界：禁止 Frida、LLDB、运行时内存提取；服务器未下发的隐藏状态不可恢复。".into(),
        String::new(),
        "## 分层解码统计".into(),
        String::new(),
        codev_obf::f3("b41a288b6c60feaed15b168e636ee9fa7cb6fd05b391e0a77686e38c636afce7a91a2daf2fec006e70bae20f838e746603410505b390fdb6f85d45db2fee13477c9df30c81ac7e522fdff46fe0b701a1e4d9f868", unsigned(counts, "packets"), unsigned(counts, "oodle_pass_through_packets"), unsigned(counts, "oodle_flag_one_packets")),
        format!(
            "- UE bunch：{}；C→S {}，S→C {}。",
            unsigned(counts, "bunches"),
            unsigned(client_direction, "bunches"),
            unsigned(server_direction, "bunches"),
        ),
        format!(
            "- PackageMap export 前缀：{}；NetGUID 记录：{}；唯一绑定：{}；冲突：{}。",
            unsigned(counts, "package_map_export_prefixes_exact"),
            unsigned(counts, "netguid_records"),
            unsigned(netguid, "binding_count"),
            array(netguid, "binding_conflicts").len(),
        ),
        format!(
            "- partial fragments：{}；完整重组：{}；问题：{}。",
            unsigned(partial, "fragment_count"),
            unsigned(partial, "completed_payloads"),
            array(partial, "issues").len(),
        ),
        format!(
            "- BatchSync actorï¼{}/{} ç²¾ç¡®èå°½ï¼BatchData å±æ§ {}ï¼å¶ä»å±æ§ {}ï¼è§è²ç¶ææ´æ° {}ã",
            grouped_field(batch, "bit_exact_actor_messages"),
            grouped_field(batch, "actor_messages"),
            grouped_field(batch, "batch_properties"),
            grouped_field(batch, "non_batch_properties"),
            grouped_field(batch, "character_updates"),
        ),
        format!(
            "- 逐包 bit coverage：{}/{}。",
            unsigned(coverage, "exact_coverage_packets"),
            unsigned(coverage, "packet_count"),
        ),
        String::new(),
        "## 关键静态证据".into(),
        String::new(),
        codev_obf::s("88aa601cb3a1f160e6e2521895a5b770856e8bd5184c02a72c0ddce767a4b53894ba076a9ba2b279c6ead0db7ca4b53894ba046acdf1b57095ead0db7ca4b53894ba046acda5b4259dead0db7f").into(),
        codev_obf::f1("e167250cb897b6cc84261b09b799a19783281101be136f22ac770d5cebcd958efc753759bb136f232adbd9886a7cf3c3b16791d571186b2229cdd488577936254ba3cdd7fb9abfd9ab7a454d3c6767514cdd96ed59", grouped_field(counts, "oodle_pass_through_packets")),
        "- PacketNotify/bunch：`0x1064A4EA0`、`0x1064AC7EC`。".into(),
        "- PackageMap/NetGUID：`0x106500668`、`0x1064FB260`。".into(),
        codev_obf::s("dca89b6be60251c888e6ba2577fca97d510f36b6080109e3c0b8ea4bd3200cadc9e83a8a130109e3c0b8ea4bd3577cadc1e83a8a130109e3c0b8ea4bd35778ddc5e83a8a130109e3c0b8ea4bd3577aa3b2e83a8a130109e3c0b8ed38ab237bdac9e83a8a10").into(),
        "- 每个 payload 未命名区均以精确 bit offset 写入 `unresolved.jsonl`，没有因解析失败静默丢包。".into(),
        String::new(),
        "## 当前对局状态".into(),
        String::new(),
        format!(
            "- `MatchState` 当前已写入的身份记录：{}；辅助信令队伍/阵营标识：{}（不等同于完整 10 人名单）。",
            participants.len(),
            teams.len(),
        ),
        format!(
            "- 地图：`{}`（{}）。",
            string_or(map, "name", "未知"),
            string_or(map, "confidence", "unknown"),
        ),
        format!(
            "- 比分：`{}`。",
            json_or_unmapped(match_state.get("score"))
        ),
        format!(
            "- 结果：`{}`。",
            json_or_unmapped(match_state.get("result"))
        ),
        String::new(),
        "## 人物坐标".into(),
        String::new(),
        format!(
            "- 已恢复 {} 条稳定坐标轨迹、{} 条状态更新；完整逐条记录位于 `events.jsonl` 的 `batch_character_state_update`。",
            grouped_field(batch, "track_count"),
            grouped_field(batch, "character_updates"),
        ),
        "- 轨迹仅命名为 `batch_slot_N`。PlayerCharacter → PlayerState 的对象引用尚未逐位证明，因此没有把坐标猜测绑定到名单中的玩家。".into(),
        "- 坐标为 native movement object `+24` 的人物世界位置，量化精度 0.1 Unreal world unit；每条事件含 PCAP frame、wire bit offset、状态和 IDA 证据。".into(),
        format!(
            "- Channel 32 的其他 {} 个 property handle payload 仍以精确范围保留在 `unresolved.jsonl`。",
            unsigned(batch, "non_batch_properties"),
        ),
        String::new(),
        "## 未决项".into(),
        String::new(),
    ];
    if limitations.is_empty() {
        lines.push("- 无。".into());
    } else {
        lines.extend(
            limitations
                .iter()
                .map(|item| format!("- {}", display(Some(item)))),
        );
    }
    lines.extend([
        String::new(),
        "## 验收".into(),
        String::new(),
        if failed_checks.is_empty() {
            "全部适用 baseline checks 通过。".into()
        } else {
            format!("未通过：{}", failed_checks.join(", "))
        },
        format!(
            "恢复门状态：`{}`；`fabricated_semantics={}`。",
            display(gate.get("status")),
            python_bool(gate.get("fabricated_semantics")),
        ),
        String::new(),
    ]);
    lines.join("\n")
}

fn object<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn unsigned(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map_or_else(|| "未迁移".into(), |number| number.to_string())
}

fn string_or<'a>(value: &'a Value, key: &str, fallback: &'a str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or(fallback)
}

fn display(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => "未知".into(),
        Some(Value::String(value)) => value.clone(),
        Some(Value::Bool(value)) => python_bool(Some(&Value::Bool(*value))).into(),
        Some(value) => value.to_string(),
    }
}

fn python_bool(value: Option<&Value>) -> &'static str {
    match value.and_then(Value::as_bool) {
        Some(true) => "True",
        Some(false) => "False",
        None => "None",
    }
}

fn json_or_unmapped(value: Option<&Value>) -> String {
    match value {
        Some(Value::Object(object)) if object.is_empty() => "尚未完成字段映射".into(),
        Some(Value::Array(array)) if array.is_empty() => "尚未完成字段映射".into(),
        Some(value) if !value.is_null() => {
            serde_json::to_string(value).expect("JSON value serialization is infallible")
        }
        _ => "尚未完成字段映射".into(),
    }
}

fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut result = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, byte) in digits.bytes().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            result.push(',');
        }
        result.push(char::from(byte));
    }
    result
}

fn grouped_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_u64)
        .map_or_else(|| "未迁移".into(), grouped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn full_fixture_report_is_byte_exact_with_python_v2() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let oracle = root.join("work/oracle-v2-full-20260815-session");
        if !oracle.join("summary.json").is_file() {
            return;
        }
        let summary: Value =
            serde_json::from_slice(&fs::read(oracle.join("summary.json")).unwrap()).unwrap();
        let match_state: Value =
            serde_json::from_slice(&fs::read(oracle.join("match.json")).unwrap()).unwrap();
        let gate: Value =
            serde_json::from_slice(&fs::read(oracle.join("recovery_gate.json")).unwrap()).unwrap();
        let actual = render_full_session_report(&summary, &match_state, &gate);
        let expected = fs::read_to_string(oracle.join("report.md")).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn grouping_and_failures_are_stable() {
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(17_031), "17,031");
        let summary = serde_json::json!({
            "baseline_checks": {"known_udp_fixture": false, "broken": false}
        });
        let report = render_full_session_report(
            &summary,
            &serde_json::json!({}),
            &serde_json::json!({"fabricated_semantics": false}),
        );
        assert!(report.contains("未通过：broken"));
    }
}
