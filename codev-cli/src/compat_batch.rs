//! Typed, allocation-bounded BatchSync compatibility summary.
//!
//! The event sink streams JSONL directly, while this accumulator retains only
//! ten compact track summaries and fixed-size distributions.  It deliberately
//! never stores individual updates or guessed identity bindings.

use std::collections::BTreeMap;

use codev_protocol::{
    A0Property, A0Value, BATCH_CHANNEL_INDEX, BATCH_PROPERTY_HANDLE, D0Update, Vec3,
};
use codev_stream::A0Payload;
use serde::Serialize;

const IDA_EVIDENCE: [&str; 5] = [
    "IDA 0x103AAA568 BatchDataNetSerialize",
    "IDA 0x103AA6E60 per-character codec",
    "IDA 0x103AA6AF4 full movement codec",
    "IDA 0x103AA6C8C minimal movement codec",
    "IDA 0x10429BBA8 quantized-vector decoder",
];

#[derive(Clone, Debug, Default)]
pub struct BatchSummaryAccumulator {
    actor_messages: u64,
    bit_exact_actor_messages: u64,
    batch_properties: u64,
    non_batch_properties: u64,
    character_updates: u64,
    property_handles: BTreeMap<u32, u64>,
    character_counts: BTreeMap<u8, u64>,
    change_masks: BTreeMap<u8, u64>,
    tracks: BTreeMap<u8, TrackAccumulator>,
}

impl BatchSummaryAccumulator {
    pub fn observe_actor(&mut self, actor: &A0Payload) {
        self.actor_messages += 1;
        self.bit_exact_actor_messages += u64::from(actor.summary.consumed_bits == actor.bit_length);
        for property in &actor.properties {
            self.observe_property(property);
        }
        for update in &actor.updates {
            self.observe_update(actor.capture_index + 1, actor.timestamp_ns, update);
        }
    }

    fn observe_property(&mut self, property: &A0Property) {
        *self.property_handles.entry(property.handle).or_default() += 1;
        match property.value {
            A0Value::BatchData(summary) => {
                self.batch_properties += 1;
                *self
                    .character_counts
                    .entry(summary.character_count)
                    .or_default() += 1;
            }
            A0Value::RawTwoBits { .. } => self.non_batch_properties += 1,
            _ => self.non_batch_properties += 1,
        }
    }

    fn observe_update(&mut self, source_frame: u64, timestamp_ns: u64, update: &D0Update) {
        self.character_updates += 1;
        *self.change_masks.entry(update.change_mask).or_default() += 1;
        self.tracks
            .entry(update.slot)
            .or_insert_with(|| TrackAccumulator::new(update.slot))
            .observe(source_frame, timestamp_ns, update);
    }

    pub fn finish(self) -> BatchSyncSummary {
        let labels = self
            .tracks
            .keys()
            .map(|slot| format!("batch_slot_{slot}"))
            .collect();
        BatchSyncSummary {
            status: "coordinates_decoded_batch_slot_identity_unresolved",
            channel_index: BATCH_CHANNEL_INDEX,
            property_handle: BATCH_PROPERTY_HANDLE,
            actor_messages: self.actor_messages,
            bit_exact_actor_messages: self.bit_exact_actor_messages,
            batch_properties: self.batch_properties,
            non_batch_properties: self.non_batch_properties,
            character_updates: self.character_updates,
            event_count: self.character_updates,
            parse_failures: 0,
            property_handle_distribution: numeric_keys(self.property_handles),
            character_count_distribution: numeric_keys(self.character_counts),
            change_mask_distribution: numeric_keys(self.change_masks),
            track_count: self.tracks.len(),
            tracks: self
                .tracks
                .into_values()
                .map(TrackAccumulator::finish)
                .collect(),
            identity_binding: IdentityBinding {
                status: "unresolved",
                labels,
                reason: "PlayerCharacter to PlayerState object-reference binding has not yet been proven bit-for-bit",
                guessed_mapping_used: false,
            },
            ida_evidence: IDA_EVIDENCE,
        }
    }
}

fn numeric_keys<K: ToString + Ord>(values: BTreeMap<K, u64>) -> BTreeMap<String, u64> {
    values
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

#[derive(Clone, Debug)]
struct TrackAccumulator {
    slot: u8,
    update_count: u64,
    movement_update_count: u64,
    first_frame: u64,
    first_timestamp_ns: u64,
    last_frame: u64,
    last_timestamp_ns: u64,
    minimum: Vec3,
    maximum: Vec3,
    final_position: Vec3,
}

impl TrackAccumulator {
    fn new(slot: u8) -> Self {
        Self {
            slot,
            update_count: 0,
            movement_update_count: 0,
            first_frame: 0,
            first_timestamp_ns: 0,
            last_frame: 0,
            last_timestamp_ns: 0,
            minimum: Vec3::ZERO,
            maximum: Vec3::ZERO,
            final_position: Vec3::ZERO,
        }
    }

    fn observe(&mut self, source_frame: u64, timestamp_ns: u64, update: &D0Update) {
        let position = update.state.position;
        if self.update_count == 0 {
            self.first_frame = source_frame;
            self.first_timestamp_ns = timestamp_ns;
            self.minimum = position;
            self.maximum = position;
        } else {
            self.minimum.x = self.minimum.x.min(position.x);
            self.minimum.y = self.minimum.y.min(position.y);
            self.minimum.z = self.minimum.z.min(position.z);
            self.maximum.x = self.maximum.x.max(position.x);
            self.maximum.y = self.maximum.y.max(position.y);
            self.maximum.z = self.maximum.z.max(position.z);
        }
        self.update_count += 1;
        self.movement_update_count += u64::from(update.fresh_movement());
        self.last_frame = source_frame;
        self.last_timestamp_ns = timestamp_ns;
        self.final_position = position;
    }

    fn finish(self) -> TrackSummary {
        TrackSummary {
            track_id: format!("batch_slot_{}", self.slot),
            batch_slot: self.slot,
            identity_binding: "unresolved",
            identity_confidence: "unknown",
            update_count: self.update_count,
            movement_update_count: self.movement_update_count,
            first_frame: self.first_frame,
            first_timestamp_ns: self.first_timestamp_ns,
            last_frame: self.last_frame,
            last_timestamp_ns: self.last_timestamp_ns,
            coordinate_range: CoordinateRange {
                x: [self.minimum.x, self.maximum.x],
                y: [self.minimum.y, self.maximum.y],
                z: [self.minimum.z, self.maximum.z],
            },
            final_position: PositionSummary {
                x: self.final_position.x,
                y: self.final_position.y,
                z: self.final_position.z,
                unit: "Unreal_world_unit",
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BatchSyncSummary {
    pub status: &'static str,
    pub channel_index: u32,
    pub property_handle: u32,
    pub actor_messages: u64,
    pub bit_exact_actor_messages: u64,
    pub batch_properties: u64,
    pub non_batch_properties: u64,
    pub character_updates: u64,
    pub event_count: u64,
    pub parse_failures: u64,
    pub property_handle_distribution: BTreeMap<String, u64>,
    pub character_count_distribution: BTreeMap<String, u64>,
    pub change_mask_distribution: BTreeMap<String, u64>,
    pub track_count: usize,
    pub tracks: Vec<TrackSummary>,
    pub identity_binding: IdentityBinding,
    pub ida_evidence: [&'static str; 5],
}

#[derive(Clone, Debug, Serialize)]
pub struct TrackSummary {
    track_id: String,
    batch_slot: u8,
    identity_binding: &'static str,
    identity_confidence: &'static str,
    update_count: u64,
    movement_update_count: u64,
    first_frame: u64,
    first_timestamp_ns: u64,
    last_frame: u64,
    last_timestamp_ns: u64,
    coordinate_range: CoordinateRange,
    final_position: PositionSummary,
}

#[derive(Clone, Debug, Serialize)]
struct CoordinateRange {
    x: [f64; 2],
    y: [f64; 2],
    z: [f64; 2],
}

#[derive(Clone, Debug, Serialize)]
struct PositionSummary {
    x: f64,
    y: f64,
    z: f64,
    unit: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct IdentityBinding {
    status: &'static str,
    labels: Vec<String>,
    reason: &'static str,
    guessed_mapping_used: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_protocol::{MovementState, SlotContinuity};

    fn update(slot: u8, position: Vec3, fresh: bool) -> D0Update {
        D0Update {
            slot,
            state_index: 0,
            bit_offset: 0,
            bit_length: 1,
            use_baseline: false,
            source_baseline: None,
            source_baseline_position_valid: None,
            store_baseline: false,
            destination_baseline: None,
            change_mask: if fresh { 3 } else { 0 },
            movement: fresh.then_some(codev_protocol::MovementUpdate {
                kind: codev_protocol::MovementKind::Minimal,
                bit_offset: 0,
                bit_length: 1,
                state: MovementState {
                    position,
                    ..MovementState::default()
                },
                position: codev_protocol::VectorField {
                    value: position,
                    bit_offset: 0,
                    bit_length: 1,
                    quantization_decimals: 1,
                    absolute_xy: true,
                    xy_width: 1,
                    z_width: 1,
                },
                velocity: codev_protocol::VectorField {
                    value: Vec3::ZERO,
                    bit_offset: 0,
                    bit_length: 0,
                    quantization_decimals: 1,
                    absolute_xy: false,
                    xy_width: 0,
                    z_width: 0,
                },
                acceleration: None,
                rotation: None,
            }),
            extra_state: None,
            state: MovementState {
                position,
                ..MovementState::default()
            },
            position_valid: true,
            continuity: SlotContinuity::Continuous,
        }
    }

    #[test]
    fn track_summary_retains_ranges_and_carry_forward_counts() {
        let mut accumulator = BatchSummaryAccumulator::default();
        accumulator.observe_update(10, 100, &update(7, Vec3::new(3.0, -2.0, 5.0), true));
        accumulator.observe_update(11, 200, &update(7, Vec3::new(-1.0, 4.0, 2.0), false));
        let summary = accumulator.finish();
        let value = serde_json::to_value(summary).unwrap();
        assert_eq!(value["track_count"], 1);
        assert_eq!(value["tracks"][0]["update_count"], 2);
        assert_eq!(value["tracks"][0]["movement_update_count"], 1);
        assert_eq!(
            value["tracks"][0]["coordinate_range"]["x"],
            serde_json::json!([-1.0, 3.0])
        );
        assert_eq!(value["tracks"][0]["final_position"]["y"], 4.0);
        assert_eq!(
            value["identity_binding"]["labels"],
            serde_json::json!(["batch_slot_7"])
        );
    }
}
