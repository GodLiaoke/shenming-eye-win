use codev_protocol::D0Update;

pub const LOCAL_CAMP_ID: u32 = 1;
pub const REMOTE_CAMP_ID: u32 = 2;

const PLAYER_COUNT: usize = 10;
const CAMP_SIZE: usize = 5;
const MIN_CAMP_SEPARATION_CM: f64 = 5_000.0;
const MAX_CLUSTER_RADIUS_RATIO: f64 = 0.50;
const SPAWN_MATCH_TOLERANCE_CM: f64 = 5.0;

#[derive(Clone, Copy, Debug, PartialEq)]
struct InitialPosition {
    capture_index: u64,
    x: f64,
    y: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct PlayerSpawn {
    actor_guid: u32,
    capture_index: u64,
    position: InitialPosition,
}

/// Fail-closed camp classification based on proven player-character spawns.
///
/// The ten real `BP_PlayerCharacter` actor opens form two five-person spawn
/// groups. BatchData slots are not assumed to use actor GUID or MNA roster
/// order. Instead, their first independently valid coordinates are matched to
/// those actor spawns. The five-slot spawn group observed in BatchData is the
/// local side; the other five of the first ten real BatchData candidates are
/// the remote side. Later ability/decoy slots deliberately remain unresolved.
#[derive(Clone, Debug)]
pub struct RoundCampClassifier {
    initial: [Option<InitialPosition>; 64],
    excluded_origin_slots: [bool; 64],
    camps: [Option<u32>; 64],
    player_spawns: Vec<PlayerSpawn>,
}

impl Default for RoundCampClassifier {
    fn default() -> Self {
        Self {
            initial: [None; 64],
            excluded_origin_slots: [false; 64],
            camps: [None; 64],
            player_spawns: Vec::with_capacity(PLAYER_COUNT),
        }
    }
}

impl RoundCampClassifier {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Reset only BatchData slot state when its dynamic actor channel is
    /// rebound. Proven player actor opens belong to the same round and remain
    /// valid across that channel lifecycle.
    pub fn reset_slots(&mut self) {
        self.initial = [None; 64];
        self.excluded_origin_slots = [false; 64];
        self.camps = [None; 64];
    }

    pub fn observe_player_spawn(
        &mut self,
        actor_guid: u32,
        capture_index: u64,
        x: f64,
        y: f64,
        z: f64,
    ) {
        if self.player_spawns.len() >= PLAYER_COUNT
            || self
                .player_spawns
                .iter()
                .any(|spawn| spawn.actor_guid == actor_guid)
            || !x.is_finite()
            || !y.is_finite()
            || !z.is_finite()
        {
            return;
        }
        self.player_spawns.push(PlayerSpawn {
            actor_guid,
            capture_index,
            position: InitialPosition {
                capture_index,
                x,
                y,
            },
        });
        self.try_commit();
    }

    pub fn observe(&mut self, capture_index: u64, updates: &[D0Update]) {
        for update in updates.iter().filter(|update| update.position_valid) {
            let slot = usize::from(update.slot);
            if self.initial[slot].is_some() || self.excluded_origin_slots[slot] {
                continue;
            }
            let position = update.state.position;
            if !position.x.is_finite() || !position.y.is_finite() || !position.z.is_finite() {
                continue;
            }
            if position.x.abs() + position.y.abs() + position.z.abs() < 1.0 {
                self.excluded_origin_slots[slot] = true;
                continue;
            }
            self.initial[slot] = Some(InitialPosition {
                capture_index,
                x: position.x,
                y: position.y,
            });
        }
        self.try_commit();
    }

    pub fn camp(&self, slot: u8) -> Option<u32> {
        self.camps.get(usize::from(slot)).copied().flatten()
    }

    pub fn assignments(&self) -> Vec<CampAssignment> {
        self.camps
            .iter()
            .enumerate()
            .filter_map(|(slot, camp_id)| {
                Some(CampAssignment {
                    slot: u8::try_from(slot).ok()?,
                    camp_id: (*camp_id)?,
                })
            })
            .collect()
    }

    fn try_commit(&mut self) {
        if self.camps.iter().any(Option::is_some) || self.player_spawns.len() != PLAYER_COUNT {
            return;
        }
        let mut candidates: Vec<(usize, InitialPosition)> = self
            .initial
            .iter()
            .enumerate()
            .filter_map(|(slot, position)| position.map(|position| (slot, position)))
            .collect();
        candidates.sort_unstable_by_key(|(_, position)| position.capture_index);
        if candidates.len() < PLAYER_COUNT {
            return;
        }
        candidates.truncate(PLAYER_COUNT);

        let Some([left, right]) = balanced_spawn_groups(&self.player_spawns) else {
            return;
        };
        let left_matches = exact_spawn_matches(&left, &self.player_spawns, &candidates);
        let right_matches = exact_spawn_matches(&right, &self.player_spawns, &candidates);
        let left_complete = left_matches.len() == CAMP_SIZE;
        let right_complete = right_matches.len() == CAMP_SIZE;
        if !left_complete && !right_complete {
            return;
        }

        let local_matches = match (left_complete, right_complete) {
            (true, false) => left_matches,
            (false, true) => right_matches,
            (true, true) => {
                let left_capture = median_capture(&left, &self.player_spawns);
                let right_capture = median_capture(&right, &self.player_spawns);
                if left_capture <= right_capture {
                    left_matches
                } else {
                    right_matches
                }
            }
            (false, false) => unreachable!(),
        };

        for (slot, _) in candidates {
            self.camps[slot] = Some(if local_matches.contains(&slot) {
                LOCAL_CAMP_ID
            } else {
                REMOTE_CAMP_ID
            });
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampAssignment {
    pub slot: u8,
    pub camp_id: u32,
}

fn balanced_spawn_groups(spawns: &[PlayerSpawn]) -> Option<[[usize; CAMP_SIZE]; 2]> {
    if spawns.len() != PLAYER_COUNT {
        return None;
    }
    let mut best = None::<(f64, [usize; CAMP_SIZE], [usize; CAMP_SIZE])>;
    for mask in 0_u16..(1_u16 << PLAYER_COUNT) {
        if mask & 1 == 0 || mask.count_ones() as usize != CAMP_SIZE {
            continue;
        }
        let mut left = [0_usize; CAMP_SIZE];
        let mut right = [0_usize; CAMP_SIZE];
        let mut left_index = 0;
        let mut right_index = 0;
        for index in 0..PLAYER_COUNT {
            if mask & (1 << index) != 0 {
                left[left_index] = index;
                left_index += 1;
            } else {
                right[right_index] = index;
                right_index += 1;
            }
        }
        let left_centroid = centroid(&left, spawns);
        let right_centroid = centroid(&right, spawns);
        let separation = centroid_distance(left_centroid, right_centroid);
        if separation < MIN_CAMP_SEPARATION_CM {
            continue;
        }
        let maximum_radius = separation * MAX_CLUSTER_RADIUS_RATIO;
        if left.iter().any(|index| {
            point_distance_squared(spawns[*index].position, left_centroid)
                > maximum_radius * maximum_radius
        }) || right.iter().any(|index| {
            point_distance_squared(spawns[*index].position, right_centroid)
                > maximum_radius * maximum_radius
        }) {
            continue;
        }
        let score = within_group_score(&left, spawns, left_centroid)
            + within_group_score(&right, spawns, right_centroid);
        if best.as_ref().is_none_or(|current| score < current.0) {
            best = Some((score, left, right));
        }
    }
    best.map(|(_, left, right)| [left, right])
}

fn exact_spawn_matches(
    group: &[usize; CAMP_SIZE],
    spawns: &[PlayerSpawn],
    candidates: &[(usize, InitialPosition)],
) -> Vec<usize> {
    let mut matched_slots = Vec::with_capacity(CAMP_SIZE);
    for spawn_index in group {
        let spawn = spawns[*spawn_index].position;
        let closest = candidates
            .iter()
            .filter(|(slot, _)| !matched_slots.contains(slot))
            .filter_map(|(slot, position)| {
                let distance = distance_squared(spawn, *position);
                (distance <= SPAWN_MATCH_TOLERANCE_CM * SPAWN_MATCH_TOLERANCE_CM)
                    .then_some((distance, *slot))
            })
            .min_by(|left, right| left.0.total_cmp(&right.0));
        if let Some((_, slot)) = closest {
            matched_slots.push(slot);
        }
    }
    matched_slots
}

fn centroid(group: &[usize; CAMP_SIZE], spawns: &[PlayerSpawn]) -> [f64; 2] {
    let [x, y] = group.iter().fold([0.0, 0.0], |mut sum, index| {
        sum[0] += spawns[*index].position.x;
        sum[1] += spawns[*index].position.y;
        sum
    });
    [x / CAMP_SIZE as f64, y / CAMP_SIZE as f64]
}

fn within_group_score(group: &[usize; CAMP_SIZE], spawns: &[PlayerSpawn], center: [f64; 2]) -> f64 {
    group
        .iter()
        .map(|index| point_distance_squared(spawns[*index].position, center))
        .sum()
}

fn median_capture(group: &[usize; CAMP_SIZE], spawns: &[PlayerSpawn]) -> u64 {
    let mut captures = group.map(|index| spawns[index].capture_index);
    captures.sort_unstable();
    captures[CAMP_SIZE / 2]
}

fn distance_squared(left: InitialPosition, right: InitialPosition) -> f64 {
    let dx = left.x - right.x;
    let dy = left.y - right.y;
    dx * dx + dy * dy
}

fn point_distance_squared(point: InitialPosition, center: [f64; 2]) -> f64 {
    let dx = point.x - center[0];
    let dy = point.y - center[1];
    dx * dx + dy * dy
}

fn centroid_distance(left: [f64; 2], right: [f64; 2]) -> f64 {
    let dx = left[0] - right[0];
    let dy = left[1] - right[1];
    (dx * dx + dy * dy).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_protocol::{MovementState, SlotContinuity, Vec3};

    fn update(slot: u8, x: f64, y: f64, z: f64) -> D0Update {
        D0Update {
            slot,
            state_index: 0,
            bit_offset: 0,
            bit_length: 0,
            use_baseline: false,
            source_baseline: None,
            source_baseline_position_valid: None,
            store_baseline: false,
            destination_baseline: None,
            change_mask: 0,
            movement: None,
            extra_state: None,
            state: MovementState {
                position: Vec3::new(x, y, z),
                ..MovementState::default()
            },
            position_valid: true,
            continuity: SlotContinuity::Continuous,
        }
    }

    fn spawn(classifier: &mut RoundCampClassifier, actor: u32, capture: u64, xyz: [f64; 3]) {
        classifier.observe_player_spawn(actor, capture, xyz[0], xyz[1], xyz[2]);
    }

    #[test]
    fn bind_fixture_binds_five_local_five_remote_and_ignores_origin_proxy() {
        let mut classifier = RoundCampClassifier::default();
        let local = [
            [800.0, 550.0, -89.3],
            [987.4, 275.6, -89.1],
            [1164.7, 199.1, -79.1],
            [1000.0, -300.0, -79.8],
            [1231.7, 837.0, -75.0],
        ];
        let remote = [
            [14900.0, -1488.5, 200.3],
            [13306.0, -80.4, 200.3],
            [12954.8, 2758.0, 500.3],
            [15100.0, -942.4, 200.3],
            [12517.3, 3730.8, 480.3],
        ];
        for (index, position) in local.into_iter().chain(remote).enumerate() {
            spawn(
                &mut classifier,
                2 + index as u32 * 2,
                index as u64,
                position,
            );
        }
        classifier.observe(
            2_000,
            &[
                update(1, 800.0, 550.0, -89.3),
                update(4, 987.4, 275.6, -89.1),
                update(5, 1164.7, 199.1, -79.1),
                update(6, 1000.0, -300.0, -79.8),
                update(8, 1231.7, 837.0, -75.0),
                update(2, 0.0, 0.0, 0.0),
                update(0, 12000.0, -1000.0, 200.3),
                update(3, 12010.0, -900.0, 200.3),
                update(7, 12020.0, -800.0, 200.3),
                update(9, 12030.0, -700.0, 200.3),
                update(10, 12040.0, -600.0, 200.3),
            ],
        );
        for slot in [1, 4, 5, 6, 8] {
            assert_eq!(classifier.camp(slot), Some(LOCAL_CAMP_ID));
        }
        for slot in [0, 3, 7, 9, 10] {
            assert_eq!(classifier.camp(slot), Some(REMOTE_CAMP_ID));
        }
        assert_eq!(classifier.camp(2), None);
    }

    #[test]
    fn ascent_fog_of_war_fixture_binds_exact_local_spawns_and_leaves_late_slots_unknown() {
        let mut classifier = RoundCampClassifier::default();
        let spawns = [
            [-5501.4, 813.8, 300.3],
            [-5501.4, 250.8, 300.3],
            [-5321.4, -11.2, 300.3],
            [-5581.4, 534.8, 300.3],
            [-5321.4, 1058.6, 300.3],
            [5306.0, -570.0, 400.3],
            [5416.0, -320.0, 400.3],
            [5306.0, 530.0, 400.3],
            [5499.2, -20.0, 400.3],
            [5416.0, 280.0, 400.3],
        ];
        for (index, position) in spawns.into_iter().enumerate() {
            spawn(
                &mut classifier,
                2 + index as u32 * 2,
                index as u64,
                position,
            );
        }
        classifier.observe(
            10_000,
            &[
                update(0, 195.1, -4066.4, 300.3),
                update(1, -5501.4, 250.8, 300.3),
                update(2, -5321.4, 1058.6, 300.3),
                update(3, -454.6, -4218.9, 300.3),
                update(4, -5321.4, -11.2, 300.3),
                update(5, -5581.4, 534.8, 300.3),
                update(6, 1462.9, 5553.4, 313.8),
                update(7, 2158.0, -5002.9, 480.3),
                update(8, 1056.1, 2963.6, 200.3),
                update(9, -5501.4, 813.8, 300.3),
            ],
        );
        classifier.observe(
            20_000,
            &[
                update(10, 1314.5, 3172.1, 126.2),
                update(11, 1540.0, 4425.8, 412.2),
                update(12, -1078.7, 3547.3, 176.3),
            ],
        );
        for slot in [1, 2, 4, 5, 9] {
            assert_eq!(classifier.camp(slot), Some(LOCAL_CAMP_ID));
        }
        for slot in [0, 3, 6, 7, 8] {
            assert_eq!(classifier.camp(slot), Some(REMOTE_CAMP_ID));
        }
        for slot in [10, 11, 12] {
            assert_eq!(classifier.camp(slot), None);
        }
    }

    #[test]
    fn batch_positions_without_proven_player_spawns_remain_unresolved() {
        let mut classifier = RoundCampClassifier::default();
        let updates = (0..10)
            .map(|slot| update(slot, f64::from(slot) * 100.0, 100.0, 10.0))
            .collect::<Vec<_>>();
        classifier.observe(1, &updates);
        assert!(classifier.assignments().is_empty());
    }
}
