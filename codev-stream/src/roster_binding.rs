//! 把 MNA roster（10 条玩家记录：英雄编号 / 阵营 / 阵营内位次）贴到客户端
//! BatchData 的槽位上。
//!
//! 实测结论（2026-09-30，三局真实抓包交叉验证）：
//!
//! * `BatchData.slot` 是**客户端自己的可见角色数组下标**，跟 MNA roster 的数组顺序
//!   **不是**同一个顺序 —— 早期直接拿 roster 序号当槽位号，就会把队友画成敌人、
//!   把别人的英雄头像贴到自己人身上。
//! * 阵营（队友/敌人）不再需要猜：BatchData 每个槽位带一个 2 bit `state_index`，
//!   **本机五人固定为 0，敌人为 1/2/3**（三局 100% 吻合）。见 `local_state_slots`。
//! * 本机自己的角色：客户端本地 pawn 一定最先创建（netguid 最小、通道最先 open），
//!   它的出生点和坐标流里某一槽的首次位置完全一致 → 可以精确指认"我在几号槽"。
//!
//! 阵营内部的"哪个人在哪个槽"没有单独字段，用最小改动匹配（roster 顺序≈槽位顺序，
//! 再被阵营约束修正）逼近；本机自己那一格永远由上面的出生点锚点钉死。

/// 一条 roster 记录里参与贴槽的字段。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RosterSeat {
    pub camp_id: u64,
    pub agent_id: u32,
    pub position_slot: u32,
    /// 是否带客户端设备字段（真人玩家带，机器人不带）。
    pub device_tag: bool,
    /// 本机身份的哈希（uid 的 FNV-1a）。真人局里多个真人都带设备字段时，靠它区分哪条是我。
    pub self_key: Option<u64>,
}

/// 挑出"哪条 roster 记录是我"：先按身份哈希认，退化成"唯一带设备字段的那条"。
pub fn self_seat_index(roster: &[RosterSeat], self_key: Option<u64>) -> Option<usize> {
    if let Some(key) = self_key
        && let Some(index) = roster.iter().position(|seat| seat.self_key == Some(key))
    {
        return Some(index);
    }
    let mut device = roster
        .iter()
        .enumerate()
        .filter(|(_, seat)| seat.device_tag);
    match (device.next(), device.next()) {
        (Some((index, _)), None) => Some(index),
        _ => None,
    }
}

/// 从一帧 BatchData 里取出"本机阵营"的槽位（`state_index == 0`）。
pub fn local_state_slots<I>(updates: I) -> Vec<u8>
where
    I: IntoIterator<Item = (u8, u8)>,
{
    let mut slots: Vec<u8> = updates
        .into_iter()
        .filter(|(_, state_index)| *state_index == 0)
        .map(|(slot, _)| slot)
        .collect();
    slots.sort_unstable();
    slots.dedup();
    slots
}

/// 按"被判为本机（`state_index == 0`）的次数"挑出本机五人。
///
/// 不能只看"出现过 0 就算本机"：偶发的能力体/投影物 actor 也会短暂带上 0
/// （实测 Bind 那局槽 11 有 7 次 0、808 次 1）。按次数取前 5 个才稳。
pub fn pick_local_team_slots(counts: &std::collections::BTreeMap<u8, u64>) -> Vec<u8> {
    let mut scored: Vec<(u64, u8)> = counts
        .iter()
        .filter(|(_, count)| **count > 0)
        .map(|(slot, count)| (*count, *slot))
        .collect();
    scored.sort_unstable_by(|left, right| right.0.cmp(&left.0).then(left.1.cmp(&right.1)));
    scored.truncate(5);
    let mut slots: Vec<u8> = scored.into_iter().map(|(_, slot)| slot).collect();
    slots.sort_unstable();
    slots
}

/// 把 roster 贴到槽位上：`result[i]` 是第 `i` 条 roster 记录所在槽位。
///
/// * `local_slots`  —— 本机五人的槽位（升序，来自 `state_index == 0`）。
/// * `player_slots` —— 全部玩家槽位（升序，通常是 0..=9；非玩家 actor 不算）。
/// * `anchor_slot`  —— 本机自己所在槽位（出生点锚点解出来的），可缺省。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterPlan {
    /// 第 `i` 条 roster 记录所在槽位；`None` 表示没能判定。
    pub slots: Vec<Option<u8>>,
    /// roster 里属于本机队的 `camp_id`（不是 1/2 的固定含义，是原始值）。
    pub local_camp_id: Option<u64>,
}

/// 在同一局内把名单映射锁定，避免一次瞬时的槽位候选变化把头像贴到别的玩家。
/// 只有同一个完整计划连续观察到两次才提交；提交后本局不再接受后续候选，
/// 直到调用方在新的 channel generation 上 `reset`。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RosterPlanStabilizer {
    committed: Option<RosterPlan>,
    pending: Option<RosterPlan>,
    pending_hits: u8,
}

impl RosterPlanStabilizer {
    pub fn observe(&mut self, candidate: &RosterPlan) -> Option<&RosterPlan> {
        if candidate.slots.is_empty() || candidate.slots.iter().all(Option::is_none) {
            return self.committed.as_ref();
        }
        if self.committed.is_some() {
            return self.committed.as_ref();
        }
        if self.pending.as_ref() == Some(candidate) {
            self.pending_hits = self.pending_hits.saturating_add(1);
        } else {
            self.pending = Some(candidate.clone());
            self.pending_hits = 1;
        }
        if self.pending_hits >= 2 {
            self.committed = self.pending.take();
            self.pending_hits = 0;
        }
        self.committed.as_ref()
    }

    pub fn reset(&mut self) {
        self.committed = None;
        self.pending = None;
        self.pending_hits = 0;
    }

    pub fn committed(&self) -> Option<&RosterPlan> {
        self.committed.as_ref()
    }
}

pub fn assign_roster_slots(
    roster: &[RosterSeat],
    local_slots: &[u8],
    player_slots: &[u8],
    anchor_slot: Option<u8>,
    self_key: Option<u64>,
) -> RosterPlan {
    let mut result = vec![None; roster.len()];
    if roster.is_empty() || local_slots.len() != 5 || player_slots.len() < roster.len() {
        return RosterPlan {
            slots: result,
            local_camp_id: None,
        };
    }

    let mut camps: Vec<u64> = Vec::new();
    for seat in roster {
        if !camps.contains(&seat.camp_id) {
            camps.push(seat.camp_id);
        }
    }
    if camps.len() != 2 {
        return RosterPlan {
            slots: result,
            local_camp_id: None,
        };
    }
    let indices_of = |camp: u64| -> Vec<usize> {
        roster
            .iter()
            .enumerate()
            .filter(|(_, seat)| seat.camp_id == camp)
            .map(|(index, _)| index)
            .collect()
    };

    // 哪个阵营是本机队：用"roster 顺序 ≈ 槽位顺序"的最小改动代价判定，
    // 同时用真人设备字段兜底（本机那条一定带设备字段）。
    let score = |camp: u64| -> (u64, bool) {
        let indices = indices_of(camp);
        let cost = monotone_cost(&indices, local_slots);
        let has_device = indices.iter().any(|index| roster[*index].device_tag);
        (cost, !has_device)
    };
    let local_camp = if score(camps[0]) <= score(camps[1]) {
        camps[0]
    } else {
        camps[1]
    };
    let remote_camp = if local_camp == camps[0] {
        camps[1]
    } else {
        camps[0]
    };

    let remote_slots: Vec<u8> = player_slots
        .iter()
        .copied()
        .filter(|slot| !local_slots.contains(slot))
        .collect();

    // 本机自己：先用出生点锚点钉死，再对剩下的人做最小改动匹配。
    let mut local_indices = indices_of(local_camp);
    let mut local_targets = local_slots.to_vec();
    if let Some(anchor) = anchor_slot
        && local_slots.contains(&anchor)
    {
        let self_index =
            self_seat_index(roster, self_key).filter(|index| local_indices.contains(index));
        if let Some(self_index) = self_index {
            result[self_index] = Some(anchor);
            local_indices.retain(|index| *index != self_index);
            local_targets.retain(|slot| *slot != anchor);
        }
    }
    pair_monotone(&local_indices, &local_targets, &mut result);
    pair_monotone(&indices_of(remote_camp), &remote_slots, &mut result);
    RosterPlan {
        slots: result,
        local_camp_id: Some(local_camp),
    }
}

fn pair_monotone(indices: &[usize], slots: &[u8], result: &mut [Option<u8>]) {
    if indices.len() != slots.len() {
        return;
    }
    let plan = monotone_plan(indices, slots);
    for (index, slot) in indices.iter().zip(plan) {
        result[*index] = Some(slot);
    }
}

/// 两条升序序列做一一配对，使 Σ|index - slot| 最小（单调、不交叉）。
fn monotone_cost(indices: &[usize], slots: &[u8]) -> u64 {
    monotone_dp(indices, slots).0
}

fn monotone_plan(indices: &[usize], slots: &[u8]) -> Vec<u8> {
    monotone_dp(indices, slots).1
}

/// 返回 (最小总代价, 配对方案)。
fn monotone_dp(indices: &[usize], slots: &[u8]) -> (u64, Vec<u8>) {
    let n = indices.len();
    let m = slots.len();
    if n == 0 || n != m {
        return (0, Vec::new());
    }
    // dp[i][j] = 前 i 条记录贴到前 j 个槽位的最小代价
    let mut dp = vec![vec![u64::MAX; m + 1]; n + 1];
    let mut choice = vec![vec![false; m + 1]; n + 1];
    for j in 0..=m {
        dp[0][j] = 0;
    }
    for i in 1..=n {
        for j in i..=m {
            if m - j < n - i {
                continue;
            }
            let skip = dp[i][j - 1];
            let take = if dp[i - 1][j - 1] == u64::MAX {
                u64::MAX
            } else {
                dp[i - 1][j - 1] + distance(indices[i - 1], slots[j - 1])
            };
            if take <= skip {
                dp[i][j] = take;
                choice[i][j] = true;
            } else {
                dp[i][j] = skip;
            }
        }
    }
    let mut plan = vec![0_u8; n];
    let mut i = n;
    let mut j = m;
    while i > 0 && j > 0 {
        if choice[i][j] {
            plan[i - 1] = slots[j - 1];
            i -= 1;
            j -= 1;
        } else {
            j -= 1;
        }
    }
    (dp[n][m], plan)
}

fn distance(index: usize, slot: u8) -> u64 {
    let a = index as i64;
    let b = i64::from(slot);
    u64::try_from((a - b).abs()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seat(camp_id: u64, agent_id: u32, position_slot: u32, device_tag: bool) -> RosterSeat {
        RosterSeat {
            camp_id,
            agent_id,
            position_slot,
            device_tag,
            self_key: device_tag.then(|| codev_session_hash(1992896779448)),
        }
    }

    fn codev_session_hash(value: u64) -> u64 {
        let mut hash = 0xcbf2_9ce4_8422_2325_u64;
        for byte in value.to_string().as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        hash
    }

    fn player_slots() -> Vec<u8> {
        (0..=9).collect()
    }

    /// 2026-09-30 07:56 抓包（Bind）：本机 3002，阵营 1，自己落在槽 9。
    #[test]
    fn bind_capture_binds_local_five_and_self() {
        let roster = vec![
            seat(1, 3008, 2, false),
            seat(1, 3010, 1, false),
            seat(2, 3005, 2, false),
            seat(1, 3002, 5, true),
            seat(2, 3013, 3, false),
            seat(2, 3020, 1, false),
            seat(2, 3011, 5, false),
            seat(2, 3014, 4, false),
            seat(1, 3006, 4, false),
            seat(1, 3007, 3, false),
        ];
        let local = [0_u8, 1, 7, 8, 9];
        let result = assign_roster_slots(&roster, &local, &player_slots(), Some(9), None).slots;
        assert_eq!(result[0], Some(0));
        assert_eq!(result[1], Some(1));
        assert_eq!(result[3], Some(9)); // 自己
        assert_eq!(result[8], Some(7));
        assert_eq!(result[9], Some(8));
        for (index, slot) in result.iter().enumerate() {
            let slot = slot.expect("every seat is bound");
            let roster_camp = roster[index].camp_id;
            let slot_is_local = local.contains(&slot);
            assert_eq!(
                roster_camp == 1,
                slot_is_local,
                "seat {index} camp {roster_camp} landed on slot {slot}"
            );
        }
    }

    /// 天枢云阙那局（Plummet）：本机 3002，阵营 1，自己落在槽 9。
    #[test]
    fn tianshu_capture_binds_local_five_and_self() {
        let roster = vec![
            seat(2, 3001, 4, false),
            seat(1, 3017, 3, false),
            seat(2, 3016, 5, false),
            seat(2, 3004, 2, false),
            seat(1, 3026, 2, false),
            seat(1, 3001, 5, false),
            seat(1, 3002, 1, true),
            seat(1, 3013, 4, false),
            seat(2, 3024, 1, false),
            seat(2, 3008, 3, false),
        ];
        let local = [1_u8, 4, 5, 6, 9];
        let result = assign_roster_slots(&roster, &local, &player_slots(), Some(9), None).slots;
        assert_eq!(result[6], Some(9)); // 自己
        assert_eq!(result[1], Some(1));
        assert_eq!(result[4], Some(4));
        assert_eq!(result[5], Some(5));
        assert_eq!(result[7], Some(6));
        for (index, slot) in result.iter().enumerate() {
            let slot = slot.expect("every seat is bound");
            assert_eq!(roster[index].camp_id == 1, local.contains(&slot));
        }
    }

    /// 9/4 那局（Haven）：本机 3005 在阵营 2 —— 本机阵营不是固定 1，必须按锚点判。
    #[test]
    fn haven_capture_binds_local_five_from_camp_two() {
        let roster = vec![
            seat(1, 3022, 2, false),
            seat(1, 3012, 3, false),
            seat(2, 3022, 4, false),
            seat(2, 3014, 1, false),
            seat(1, 3019, 4, false),
            seat(2, 3005, 3, true),
            seat(1, 3023, 1, false),
            seat(2, 3024, 2, false),
            seat(1, 3005, 5, false),
            seat(2, 3004, 5, false),
        ];
        let local = [2_u8, 3, 6, 8, 9];
        let result = assign_roster_slots(&roster, &local, &player_slots(), Some(9), None).slots;
        assert_eq!(result[5], Some(9)); // 自己
        assert_eq!(result[2], Some(2));
        assert_eq!(result[3], Some(3));
        assert_eq!(result[7], Some(6));
        assert_eq!(result[9], Some(8));
        for (index, slot) in result.iter().enumerate() {
            let slot = slot.expect("every seat is bound");
            assert_eq!(roster[index].camp_id == 2, local.contains(&slot));
        }
    }

    #[test]
    fn state_index_zero_marks_the_local_five() {
        let updates = [(0_u8, 0_u8), (1, 0), (2, 2), (3, 1), (7, 0), (8, 0), (9, 0)];
        assert_eq!(local_state_slots(updates), vec![0, 1, 7, 8, 9]);
    }

    #[test]
    fn roster_plan_is_not_published_until_seen_twice_and_then_stays_locked() {
        let mut stabilizer = RosterPlanStabilizer::default();
        let first = RosterPlan {
            slots: vec![Some(1_u8), Some(2), Some(3)],
            local_camp_id: Some(1),
        };
        assert!(stabilizer.observe(&first).is_none());
        assert_eq!(stabilizer.observe(&first), Some(&first));

        let transient = RosterPlan {
            slots: vec![Some(8_u8), Some(7), Some(6)],
            local_camp_id: Some(2),
        };
        assert_eq!(stabilizer.observe(&transient), Some(&first));
    }
}
