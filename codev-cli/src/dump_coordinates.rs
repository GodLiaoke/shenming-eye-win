//! Diagnostic coordinate dump for map calibration.
//!
//! `codev-net decode` is a fail-closed evidence sink: after a full decode it
//! still refuses to publish anything unless every recovery-gate proof holds
//! (WaterMark counter continuity, lossless sequence continuity, ...). A capture
//! that is lossy, or that starts after the session already began, therefore
//! yields no coordinates at all — even though every actor message decoded.
//!
//! This module exposes the decoded per-slot world coordinates directly, with
//! the gate deliberately bypassed and the bypass recorded in the output meta.
//! It is a calibration aid, not an evidence artifact: nothing it writes is a
//! substitute for `decode`'s compatibility documents.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use codev_stream::{
    C0Cipher, decode_classic_pcap_with_cipher_options,
    recover_enter_game_session_from_classic_pcap,
    recover_enter_game_session_from_classic_pcap_open_ended,
};
use serde::Serialize;

use crate::artifacts::{NativeEventsError, endpoint, find_selected_flow};
use crate::compat_netguid::build_netguid_artifact;

#[derive(Serialize)]
pub struct CoordinateRecord {
    pub timestamp_ns: u64,
    pub capture_index: u64,
    pub packet_sequence: u64,
    pub channel_index: u32,
    pub slot: u8,
    pub track_id: String,
    pub x: f64,
    pub y: f64,
    pub z: f64,
    pub yaw_degrees: f64,
    pub pitch_degrees: f64,
    /// BatchData 里那个 2 bit 的 state_index（诊断用：看它是否携带玩家序号）。
    pub state_index: u8,
    /// change_mask & 4 时的 8 bit extra_state（诊断用：看它是否携带阵营/存活标志）。
    pub extra_state: Option<u8>,
    /// 本次更新来自哪条基线（诊断用）。
    pub source_baseline: Option<u8>,
    pub fresh_movement: bool,
    pub continuity: String,
}

#[derive(Serialize)]
pub struct DumpSummary {
    pub schema_version: &'static str,
    pub artifact: &'static str,
    pub pcap: String,
    pub pcap_sha256: String,
    pub build_id: &'static str,
    pub map_id: u32,
    pub g1_mode: u32,
    pub s0_mode: u32,
    pub map_object_path: Option<String>,
    pub coordinate_records: u64,
    pub slots: Vec<u8>,
    pub coordinate_min: Option<[f64; 3]>,
    pub coordinate_max: Option<[f64; 3]>,
    pub pipeline_datagrams: u64,
    pub pipeline_actor_messages: u64,
    pub pipeline_character_updates: u64,
    pub sequence_gaps: u64,
    /// 控制面 roster 里的英雄/阵营/位次。刻意不含昵称、Uid、OpenId：
    /// 公开产物不暴露玩家身份，只保留可用于画面标注的英雄与阵营。
    pub roster: Vec<DumpRosterEntry>,
    /// 解码过程中证明的 slot → 阵营 绑定。
    pub camp_slots: Vec<DumpCampSlot>,
    /// 每个 Unreal channel 的收包与丢弃统计：用来判断某个字段是不是
    /// 因为所在通道被整条丢弃而拿不到（而不是被解出来后又筛掉）。
    pub channel_census: Vec<codev_stream::ChannelCensus>,
    /// 宽容句柄普查结果（仅在 --handle-census 下非空）：当前解码器不认识的
    /// 属性句柄及其出现次数、载荷规模，用于定位血量/持械等未解字段。
    pub handle_census: Vec<codev_stream::HandleCensus>,
    /// 逐条普查样本落盘路径（--handle-census 时才会写）。
    pub census_records_path: Option<String>,
    /// 普查实际尝试解析的服务端消息条数。
    pub census_scanned_messages: u64,
    /// 普查中连"开始解析"都失败的消息条数。
    pub census_decode_failures: u64,
    /// Always `true`: this dump intentionally skips the recovery gate.
    pub evidence_gate_bypassed: bool,
    /// 贴槽结果：自己落在哪个槽、本机五人槽位、每条 roster 记录绑到的槽位。
    pub roster_binding: Option<DumpRosterBinding>,
}

fn build_roster_binding(
    roster: &[codev_stream::W0RosterEntry],
    local_state_counts: &std::collections::BTreeMap<u8, u64>,
    first_positions: &std::collections::BTreeMap<u8, (f64, f64)>,
    anchor_spawn: Option<[f64; 3]>,
) -> Option<DumpRosterBinding> {
    let local_slots = codev_stream::pick_local_team_slots(local_state_counts);
    if roster.len() != 10 || local_slots.len() != 5 {
        return None;
    }
    // 自己：出生点和坐标流里某个槽位的首次位置完全一致（x/y，容差 5）。
    let self_slot = anchor_spawn.and_then(|spawn| {
        first_positions
            .iter()
            .filter(|(slot, (x, y))| {
                local_slots.contains(slot)
                    && (x - spawn[0]).abs() <= 5.0
                    && (y - spawn[1]).abs() <= 5.0
            })
            .map(|(slot, _)| *slot)
            .min()
    });
    let mut player_slots: Vec<u8> = local_slots.clone();
    for slot in first_positions.keys() {
        if !player_slots.contains(slot) {
            player_slots.push(*slot);
        }
    }
    player_slots.sort_unstable();
    player_slots.truncate(10);
    let seats: Vec<codev_stream::RosterSeat> = roster
        .iter()
        .map(|entry| codev_stream::RosterSeat {
            camp_id: entry.camp_id,
            agent_id: entry.agent_id,
            position_slot: entry.position_slot,
            device_tag: entry.device_tag,
            self_key: Some(codev_session::identity_hash(&entry.uid)),
        })
        .collect();
    let plan =
        codev_stream::assign_roster_slots(&seats, &local_slots, &player_slots, self_slot, None);
    Some(DumpRosterBinding {
        self_slot,
        local_slots,
        player_slots,
        seats: roster
            .iter()
            .enumerate()
            .map(|(index, entry)| DumpRosterSeat {
                position_index: index,
                agent_id: entry.agent_id,
                camp_id: entry.camp_id,
                position_slot: entry.position_slot,
                device_tag: entry.device_tag,
                slot: plan.slots.get(index).copied().flatten(),
                is_local_camp: plan.local_camp_id == Some(entry.camp_id),
            })
            .collect(),
    })
}

#[derive(Serialize, Clone)]
pub struct DumpRosterBinding {
    pub self_slot: Option<u8>,
    pub local_slots: Vec<u8>,
    pub player_slots: Vec<u8>,
    pub seats: Vec<DumpRosterSeat>,
}

#[derive(Serialize, Clone)]
pub struct DumpRosterSeat {
    pub position_index: usize,
    pub agent_id: u32,
    pub camp_id: u64,
    pub position_slot: u32,
    pub device_tag: bool,
    pub slot: Option<u8>,
    pub is_local_camp: bool,
}

#[derive(Serialize)]
pub struct DumpRosterEntry {
    pub position_index: usize,
    pub agent_id: u32,
    pub camp_id: u64,
    pub position_slot: u32,
}

#[derive(Serialize)]
pub struct DumpCampSlot {
    pub slot: u8,
    pub camp_id: u32,
}

pub fn dump_coordinates(
    pcap: &Path,
    output: &Path,
    handle_census: bool,
) -> Result<DumpSummary, NativeEventsError> {
    // 分析入口：抓包可能从一局中间开始，允许丢弃"永远等不到 final"的旧 partial 链。
    codev_stream::set_tolerate_overlapping_initial(true);

    let census_path = output.with_extension("census.jsonl");
    // 诊断dump不要求抓包在会话结束时收尾：录到一半、没抓到 FIN 的包同样可用。
    // 采集包常常把几片滚动抓包拼在一起，里面可能同时存在多局的 M0 流；
    // 诊断路径取最新那一局（严格校验路径不变，仍会拒绝歧义包）。
    let recovery = recover_enter_game_session_from_classic_pcap(pcap)
        .or_else(|_| recover_enter_game_session_from_classic_pcap_open_ended(pcap))
        .or_else(|_| codev_stream::recover_latest_enter_game_session_from_classic_pcap(pcap))?;
    let session = recovery.session.clone();
    let server = endpoint(&session.server_ip, session.server_port);
    let selected_flow = find_selected_flow(pcap, server, session.server_port)?;
    let cipher = C0Cipher::from_packet_key(&session.packet_key, session.g0_id);

    let file = File::create(output)?;
    let mut writer = BufWriter::with_capacity(1024 * 1024, file);
    let mut records = 0_u64;
    let mut slots = BTreeSet::<u8>::new();
    let mut minimum = [f64::INFINITY; 3];
    let mut maximum = [f64::NEG_INFINITY; 3];
    let mut camp_by_slot = std::collections::BTreeMap::<u8, u32>::new();
    let mut local_state_counts = std::collections::BTreeMap::<u8, u64>::new();
    let mut first_positions = std::collections::BTreeMap::<u8, (f64, f64)>::new();
    let mut anchor_spawn: Option<[f64; 3]> = None;

    let report = decode_classic_pcap_with_cipher_options(
        pcap,
        cipher.clone(),
        Some(selected_flow),
        |actor| {
            if anchor_spawn.is_none() {
                anchor_spawn = actor.local_anchor_spawn;
            }
            for assignment in &actor.camp_assignments {
                camp_by_slot.insert(assignment.slot, assignment.camp_id);
            }
            for update in &actor.updates {
                if update.state_index == 0 {
                    *local_state_counts.entry(update.slot).or_insert(0) += 1;
                }
                if !update.position_valid {
                    continue;
                }
                let state = update.state;
                first_positions
                    .entry(update.slot)
                    .or_insert((state.position.x, state.position.y));
                let record = CoordinateRecord {
                    timestamp_ns: actor.timestamp_ns,
                    capture_index: actor.capture_index,
                    packet_sequence: actor.packet_sequence,
                    channel_index: actor.channel_index,
                    slot: update.slot,
                    track_id: format!("batch_slot_{}", update.slot),
                    x: state.position.x,
                    y: state.position.y,
                    z: state.position.z,
                    yaw_degrees: state.rotation_degrees.z,
                    pitch_degrees: state.rotation_degrees.x,
                    state_index: update.state_index,
                    extra_state: update.extra_state,
                    source_baseline: update.source_baseline,
                    fresh_movement: update.movement.is_some(),
                    continuity: format!("{:?}", update.continuity),
                };
                serde_json::to_writer(&mut writer, &record)?;
                writer.write_all(b"\n")?;
                records += 1;
                slots.insert(update.slot);
                for (index, value) in [state.position.x, state.position.y, state.position.z]
                    .into_iter()
                    .enumerate()
                {
                    minimum[index] = minimum[index].min(value);
                    maximum[index] = maximum[index].max(value);
                }
            }
            Ok(())
        },
        handle_census,
    )?;
    writer.flush()?;
    drop(writer);

    let binding = build_roster_binding(
        &session.roster,
        &local_state_counts,
        &first_positions,
        anchor_spawn,
    );

    let map_object_path = build_netguid_artifact(pcap, &cipher, selected_flow)
        .ok()
        .and_then(|artifact| {
            artifact
                .bindings
                .iter()
                .map(|binding| binding.path.clone())
                .find(|path| path.starts_with("/Game/Maps/"))
        });

    if handle_census && !report.census_records.is_empty() {
        let mut file = File::create(&census_path)?;
        {
            let mut writer = BufWriter::with_capacity(1024 * 1024, &mut file);
            for record in &report.census_records {
                serde_json::to_writer(&mut writer, record)?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
    }

    let summary = DumpSummary {
        schema_version: "codev.diagnostic-coordinate-dump/v1",
        artifact: "coordinates.jsonl",
        pcap: pcap.display().to_string(),
        pcap_sha256: crate::artifacts::sha256_file(pcap)?,
        build_id: crate::SUPPORTED_BUILD,
        map_id: session.map_id,
        g1_mode: session.g1_mode,
        s0_mode: session.s0_mode,
        map_object_path,
        coordinate_records: records,
        slots: slots.into_iter().collect(),
        coordinate_min: (records > 0).then_some(minimum),
        coordinate_max: (records > 0).then_some(maximum),
        pipeline_datagrams: report.stats.datagrams,
        pipeline_actor_messages: report.stats.actor_messages,
        pipeline_character_updates: report.stats.character_updates,
        sequence_gaps: report.stats.sequence_gaps,
        roster: session
            .roster
            .iter()
            .enumerate()
            .map(|(index, entry)| DumpRosterEntry {
                position_index: index,
                agent_id: entry.agent_id,
                camp_id: entry.camp_id,
                position_slot: entry.position_slot,
            })
            .collect(),
        camp_slots: camp_by_slot
            .iter()
            .map(|(slot, camp_id)| DumpCampSlot {
                slot: *slot,
                camp_id: *camp_id,
            })
            .collect(),
        roster_binding: binding,
        channel_census: report.channel_census.clone(),
        handle_census: report.handle_census.clone(),
        census_records_path: (handle_census && !report.census_records.is_empty())
            .then(|| census_path.display().to_string()),
        census_scanned_messages: report.census_scanned_messages,
        census_decode_failures: report.census_decode_failures,
        evidence_gate_bypassed: true,
    };
    Ok(summary)
}

pub fn write_meta(path: &Path, summary: &DumpSummary) -> Result<(), NativeEventsError> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, summary)?;
    file.write_all(b"\n")?;
    Ok(())
}
