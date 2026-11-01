//! Stateful, bit-exact protocol core for CodeV 1.24.0.2911 Channel 32.
//!
//! RepLayout properties are decoded in wire order until their packed-zero
//! terminator. Only the two serializers proven for this build are accepted:
//! opaque two-bit handle 5 and BatchData handle 17. Unknown handles fail
//! closed. Slot/current/baseline mutations are staged and become visible only
//! after the complete actor block, including its terminator, is valid.
//!
//! PlayerState h50 Blackboard decoding lives in the separate
//! `player_state` module and is intentionally not part of this Channel 32
//! handle dispatch; its h51 value remains fail-closed pending static closure.

mod bit;
mod model;
mod player_state;

use std::error::Error;
use std::fmt;

pub use bit::{BitWriteError, Lsb0Reader, Lsb0Writer};
pub use model::*;
pub use player_state::*;

const BATCH_SLOT_COUNT_BITS: u8 = 6;
const VECTOR_WIDTH_TABLE: [u8; 3] = [0, 8, 13];
const ROTATOR_WIDTH_TABLE: [u8; 3] = [4, 8, 10];
const COUNTER_WIDTH_TABLE: [u8; 3] = [4, 6, 16];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    ArchiveOutOfRange {
        start_bit: usize,
        bit_length: usize,
        buffer_bits: usize,
    },
    UnexpectedEof {
        bit_position: usize,
        needed_bits: usize,
        remaining_bits: usize,
    },
    InvalidBitWidth(u8),
    InvalidSerializeIntMaximum(u32),
    PackedIntOverflow {
        bit_position: usize,
    },
    PackedIntUnterminated {
        bit_position: usize,
    },
    NotActorRepLayout {
        has_rep_layout: bool,
        is_actor: bool,
    },
    ContentLengthMismatch {
        declared_bits: usize,
        available_bits: usize,
    },
    ChecksumUnsupported,
    MissingPropertyTerminator {
        bit_position: usize,
        remaining_bits: usize,
    },
    UnknownPropertyHandle {
        handle: u32,
        bit_position: usize,
    },
    TrailingActorBits {
        bit_position: usize,
        remaining_bits: usize,
    },
    PropertyCountOverflow,
    InvalidVectorWidthSelector(u32),
    InvalidDeltaWidthSelector(u32),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArchiveOutOfRange {
                start_bit,
                bit_length,
                buffer_bits,
            } => write!(
                formatter,
                "archive range {start_bit}+{bit_length} exceeds {buffer_bits} buffer bits"
            ),
            Self::UnexpectedEof {
                bit_position,
                needed_bits,
                remaining_bits,
            } => write!(
                formatter,
                "need {needed_bits} bits at {bit_position}, only {remaining_bits} remain"
            ),
            Self::InvalidBitWidth(width) => {
                write!(formatter, "cannot read {width} bits into a u32")
            }
            Self::InvalidSerializeIntMaximum(maximum) => {
                write!(
                    formatter,
                    "SerializeInt maximum must be positive, got {maximum}"
                )
            }
            Self::PackedIntOverflow { bit_position } => {
                write!(formatter, "packed u32 overflows at bit {bit_position}")
            }
            Self::PackedIntUnterminated { bit_position } => {
                write!(
                    formatter,
                    "packed u32 is unterminated at bit {bit_position}"
                )
            }
            Self::NotActorRepLayout {
                has_rep_layout,
                is_actor,
            } => write!(
                formatter,
                "expected actor R0 payload (rep_layout={has_rep_layout}, actor={is_actor})"
            ),
            Self::ContentLengthMismatch {
                declared_bits,
                available_bits,
            } => write!(
                formatter,
                "content block declares {declared_bits} bits with {available_bits} available"
            ),
            Self::ChecksumUnsupported => {
                formatter.write_str("replication checksum payload is not implemented")
            }
            Self::MissingPropertyTerminator {
                bit_position,
                remaining_bits,
            } => write!(
                formatter,
                "R0 property list lacks a packed-zero terminator at {bit_position} ({remaining_bits} bits remain)"
            ),
            Self::UnknownPropertyHandle {
                handle,
                bit_position,
            } => write!(
                formatter,
                "unsupported R0 property handle {handle} at bit {bit_position}"
            ),
            Self::TrailingActorBits {
                bit_position,
                remaining_bits,
            } => write!(
                formatter,
                "R0 terminator at {bit_position} leaves {remaining_bits} trailing bits"
            ),
            Self::PropertyCountOverflow => {
                formatter.write_str("actor has more than 65535 R0 properties")
            }
            Self::InvalidVectorWidthSelector(selector) => {
                write!(formatter, "invalid XY vector width selector {selector}")
            }
            Self::InvalidDeltaWidthSelector(selector) => {
                write!(formatter, "invalid delta width selector {selector}")
            }
        }
    }
}

impl Error for DecodeError {}

#[derive(Clone, Copy, Debug, Default)]
struct SlotState {
    current: MovementState,
    baselines: [MovementState; 2],
    validity: SlotValidity,
}

/// Persistent current/two-baseline state for every possible batch slot.
#[derive(Clone, Debug)]
pub struct D0Decoder {
    slots: [SlotState; MAX_BATCH_SLOTS],
    staged_slots: Vec<(u8, SlotState)>,
    /// 宽容普查模式：遇到未支持的属性句柄不再报错，改为记录后收尾。
    /// 生产路径恒为 false，fail-closed 语义不变。
    tolerant: bool,
}

impl Default for D0Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl D0Decoder {
    pub fn new() -> Self {
        Self {
            slots: [SlotState::default(); MAX_BATCH_SLOTS],
            staged_slots: Vec::with_capacity(10),
            tolerant: false,
        }
    }

    /// 打开宽容普查模式（仅诊断用；生产路径必须保持关闭）。
    pub fn set_tolerant(&mut self, tolerant: bool) {
        self.tolerant = tolerant;
    }

    /// Reset all current values, baselines, validity, and continuity epochs.
    pub fn reset(&mut self) {
        self.slots = [SlotState::default(); MAX_BATCH_SLOTS];
        self.staged_slots.clear();
    }

    /// Reset one slot, returning false for an out-of-range slot number.
    pub fn reset_slot(&mut self, slot: u8) -> bool {
        let Some(state) = self.slots.get_mut(usize::from(slot)) else {
            return false;
        };
        *state = SlotState::default();
        true
    }

    pub fn current_state(&self, slot: u8) -> Option<&MovementState> {
        self.slots
            .get(usize::from(slot))
            .map(|state| &state.current)
    }

    pub fn baseline_state(&self, slot: u8, baseline: u8) -> Option<&MovementState> {
        self.slots
            .get(usize::from(slot))?
            .baselines
            .get(usize::from(baseline))
    }

    pub fn slot_validity(&self, slot: u8) -> Option<SlotValidity> {
        self.slots
            .get(usize::from(slot))
            .map(|state| state.validity)
    }

    /// Invalidate all coordinate/baseline continuity after an input gap.
    pub fn mark_gap(&mut self) {
        self.invalidate_slots(u64::MAX);
    }

    /// Invalidate only selected slots after a scoped discontinuity.
    pub fn invalidate_slots(&mut self, slot_mask: u64) {
        for (slot, state) in self.slots.iter_mut().enumerate() {
            if slot_mask & (1_u64 << slot) == 0 {
                continue;
            }
            state.validity.current_position = false;
            state.validity.baseline_positions = [false; 2];
            state.validity.continuity = SlotContinuity::Discontinuous;
        }
    }

    /// Decode one complete actor block into caller-retained vectors.
    ///
    /// On error both output vectors are cleared and no staged slot/current or
    /// baseline mutation is committed.
    pub fn decode_actor_message_into(
        &mut self,
        data: &[u8],
        bit_length: usize,
        scratch: &mut DecodeScratch,
    ) -> Result<A0Summary, DecodeError> {
        scratch.clear();
        self.staged_slots.clear();
        match self.decode_actor_message_inner(data, bit_length, scratch) {
            Ok(summary) => {
                for (slot, state) in self.staged_slots.drain(..) {
                    self.slots[usize::from(slot)] = state;
                }
                Ok(summary)
            }
            Err(error) => {
                self.staged_slots.clear();
                scratch.clear();
                Err(error)
            }
        }
    }

    pub fn decode_actor_message(
        &mut self,
        data: &[u8],
        bit_length: usize,
    ) -> Result<ActorMessage, DecodeError> {
        let mut scratch = DecodeScratch::with_capacity(2, 10);
        let summary = self.decode_actor_message_into(data, bit_length, &mut scratch)?;
        Ok(ActorMessage {
            summary,
            properties: scratch.properties,
            updates: scratch.updates,
        })
    }

    /// Run a visitor only after the complete actor has validated and committed.
    pub fn decode_actor_message_visit<F>(
        &mut self,
        data: &[u8],
        bit_length: usize,
        scratch: &mut DecodeScratch,
        mut visitor: F,
    ) -> Result<A0Summary, DecodeError>
    where
        F: FnMut(&D0Update),
    {
        let summary = self.decode_actor_message_into(data, bit_length, scratch)?;
        for update in &scratch.updates {
            visitor(update);
        }
        Ok(summary)
    }

    fn decode_actor_message_inner(
        &mut self,
        data: &[u8],
        bit_length: usize,
        scratch: &mut DecodeScratch,
    ) -> Result<A0Summary, DecodeError> {
        let mut reader = Lsb0Reader::new(data, bit_length)?;
        let has_rep_layout = reader.read_bit()?;
        let is_actor = reader.read_bit()?;
        if !has_rep_layout || !is_actor {
            return Err(DecodeError::NotActorRepLayout {
                has_rep_layout,
                is_actor,
            });
        }

        let payload_bits = reader.serialize_int_packed()? as usize;
        let payload_offset = reader.position();
        if payload_bits != reader.bits_left() {
            return Err(DecodeError::ContentLengthMismatch {
                declared_bits: payload_bits,
                available_bits: reader.bits_left(),
            });
        }

        let mut payload = Lsb0Reader::range(data, payload_offset, payload_bits)?;
        let checksum_present = payload.read_bit()?;
        if checksum_present {
            return Err(DecodeError::ChecksumUnsupported);
        }

        let mut batch_property_count = 0_u16;
        let mut raw_two_bit_property_count = 0_u16;
        let (terminator_offset, terminator_length) = loop {
            if payload.bits_left() < 8 {
                return Err(DecodeError::MissingPropertyTerminator {
                    bit_position: payload.absolute_position(),
                    remaining_bits: payload.bits_left(),
                });
            }
            let handle_offset = payload.absolute_position();
            let handle = payload.serialize_int_packed()?;
            let handle_length = payload.absolute_position() - handle_offset;
            if handle == 0 {
                if payload.bits_left() != 0 {
                    return Err(DecodeError::TrailingActorBits {
                        bit_position: handle_offset,
                        remaining_bits: payload.bits_left(),
                    });
                }
                break (handle_offset, handle_length);
            }

            let property_offset = payload.absolute_position();
            let value = match handle {
                RAW_TWO_BIT_PROPERTY_HANDLE => {
                    let raw = payload.read_bits(2)? as u8;
                    raw_two_bit_property_count = raw_two_bit_property_count
                        .checked_add(1)
                        .ok_or(DecodeError::PropertyCountOverflow)?;
                    A0Value::RawTwoBits { raw }
                }
                BATCH_PROPERTY_HANDLE => {
                    let batch =
                        self.decode_batch_data_reader(&mut payload, &mut scratch.updates)?;
                    batch_property_count = batch_property_count
                        .checked_add(1)
                        .ok_or(DecodeError::PropertyCountOverflow)?;
                    A0Value::BatchData(batch)
                }
                _ => {
                    if self.tolerant {
                        let remaining_bits = payload.bits_left();
                        let mut sample_bits: u64 = 0;
                        let mut width: usize = 0;
                        let mut pending = remaining_bits.min(64);
                        let mut shift = 0_u32;
                        while pending > 0 {
                            let take = pending.min(32) as u8;
                            match payload.read_bits(take) {
                                Ok(value) => sample_bits |= u64::from(value) << shift,
                                Err(_) => break,
                            }
                            width += usize::from(take);
                            shift += u32::from(take);
                            pending -= usize::from(take);
                        }
                        let byte_start = handle_offset / 8;
                        let mut raw_window = [0_u8; 8];
                        let available = data.len().saturating_sub(byte_start).min(8);
                        raw_window[..available]
                            .copy_from_slice(&data[byte_start..byte_start + available]);
                        scratch.unknown_handles.push(UnknownHandle {
                            handle,
                            bit_offset: handle_offset,
                            remaining_bits,
                            sample_bits,
                            sample_width: u8::try_from(width).unwrap_or(64),
                            raw_window,
                            raw_window_len: available as u8,
                        });
                        // 不知道这个属性的载荷长度，只能把它当作消息末尾收尾。
                        break (handle_offset, handle_length);
                    }
                    return Err(DecodeError::UnknownPropertyHandle {
                        handle,
                        bit_position: handle_offset,
                    });
                }
            };
            let payload_length = payload.absolute_position() - property_offset;
            scratch.properties.push(A0Property {
                handle,
                handle_bit_offset: handle_offset,
                handle_bit_length: handle_length,
                payload_bit_offset: property_offset,
                payload_bit_length: payload_length,
                value,
            });
        };

        let property_count = u16::try_from(scratch.properties.len())
            .map_err(|_| DecodeError::PropertyCountOverflow)?;
        Ok(A0Summary {
            has_rep_layout,
            is_actor,
            content_payload_bit_offset: payload_offset,
            content_payload_bit_length: payload_bits,
            checksum_present,
            property_count,
            batch_property_count,
            raw_two_bit_property_count,
            property_terminator_bit_offset: terminator_offset,
            property_terminator_bit_length: terminator_length,
            consumed_bits: bit_length,
        })
    }

    fn working_slot(&self, slot: u8) -> SlotState {
        self.staged_slots
            .iter()
            .rev()
            .find_map(|(candidate, state)| (*candidate == slot).then_some(*state))
            .unwrap_or(self.slots[usize::from(slot)])
    }

    fn stage_slot(&mut self, slot: u8, state: SlotState) {
        if let Some((_, existing)) = self
            .staged_slots
            .iter_mut()
            .find(|(candidate, _)| *candidate == slot)
        {
            *existing = state;
        } else {
            self.staged_slots.push((slot, state));
        }
    }

    fn decode_batch_data_reader(
        &mut self,
        reader: &mut Lsb0Reader<'_>,
        updates: &mut Vec<D0Update>,
    ) -> Result<D0Summary, DecodeError> {
        let count_offset = reader.absolute_position();
        let first_update = updates.len();
        let character_count = reader.read_bits(BATCH_SLOT_COUNT_BITS)? as u8;
        updates.reserve(usize::from(character_count));
        let mut present_slot_mask = 0_u64;

        for slot in 0..character_count {
            let present_offset = reader.absolute_position();
            if !reader.read_bit()? {
                continue;
            }
            present_slot_mask |= 1_u64 << slot;
            let state_index = reader.read_bits(2)? as u8;
            let use_baseline = reader.read_bit()?;
            let source_baseline = use_baseline
                .then(|| reader.read_bit())
                .transpose()?
                .map(u8::from);
            let store_baseline = reader.read_bit()?;
            let destination_baseline = store_baseline
                .then(|| reader.read_bit())
                .transpose()?
                .map(u8::from);
            let change_mask = reader.read_bits(3)? as u8;

            let mut slot_state = self.working_slot(slot);
            let source_baseline_position_valid = source_baseline
                .map(|index| slot_state.validity.baseline_positions[usize::from(index)]);
            let baseline = source_baseline
                .map(|index| slot_state.baselines[usize::from(index)])
                .unwrap_or_default();

            let (movement, mut state) = if change_mask & 1 != 0 {
                let (movement, state) =
                    read_full_movement(reader, slot_state.current, baseline, use_baseline)?;
                (Some(movement), state)
            } else if change_mask & 2 != 0 {
                let (movement, state) =
                    read_minimal_movement(reader, slot_state.current, baseline, use_baseline)?;
                (Some(movement), state)
            } else {
                (None, slot_state.current)
            };

            let extra_state = if change_mask & 4 != 0 {
                let value = reader.read_bits(8)? as u8;
                state.extra_state = value;
                Some(value)
            } else {
                None
            };

            let position_valid = match movement {
                Some(value) => {
                    let depends_on_baseline = use_baseline && !value.position.absolute_xy;
                    !depends_on_baseline || source_baseline_position_valid == Some(true)
                }
                None => slot_state.validity.current_position,
            };
            let continuity = if position_valid {
                SlotContinuity::Continuous
            } else if slot_state.validity.continuity == SlotContinuity::Discontinuous
                || source_baseline_position_valid == Some(false)
            {
                SlotContinuity::Discontinuous
            } else {
                SlotContinuity::Unknown
            };

            slot_state.current = state;
            slot_state.validity.current_position = position_valid;
            slot_state.validity.continuity = continuity;
            if let Some(destination) = destination_baseline {
                slot_state.baselines[usize::from(destination)] = state;
                slot_state.validity.baseline_positions[usize::from(destination)] = position_valid;
            }
            self.stage_slot(slot, slot_state);

            updates.push(D0Update {
                slot,
                state_index,
                bit_offset: present_offset,
                bit_length: reader.absolute_position() - present_offset,
                use_baseline,
                source_baseline,
                source_baseline_position_valid,
                store_baseline,
                destination_baseline,
                change_mask,
                movement,
                extra_state,
                state,
                position_valid,
                continuity,
            });
        }

        Ok(D0Summary {
            character_count,
            bit_offset: count_offset,
            bit_length: reader.absolute_position() - count_offset,
            present_slot_mask,
            update_count: (updates.len() - first_update) as u8,
        })
    }
}

#[inline]
fn round_quantized(value: f64, scale: i64) -> i64 {
    (value * scale as f64 + 0.5).floor() as i64
}

#[inline]
fn sign_extend(value: u32, width: u8) -> i32 {
    if width == 0 {
        return 0;
    }
    let shift = 32 - u32::from(width);
    ((value << shift) as i32) >> shift
}

#[inline]
fn selector_width(count: usize) -> u8 {
    (usize::BITS - ((2 * count) | 1).leading_zeros() - 1) as u8
}

fn read_delta(
    reader: &mut Lsb0Reader<'_>,
    baseline: i32,
    table: &[u8; 3],
    total_width: u8,
) -> Result<i32, DecodeError> {
    let selector = reader.read_bits(selector_width(table.len()))?;
    let width = if selector == 0 {
        total_width
    } else {
        *table
            .get(selector as usize - 1)
            .ok_or(DecodeError::InvalidDeltaWidthSelector(selector))?
    };
    let delta = sign_extend(reader.read_bits(width)?, width);
    let mask = (1_u32 << total_width) - 1;
    Ok(sign_extend(
        (baseline as u32).wrapping_add(delta as u32) & mask,
        total_width,
    ))
}

fn read_quantized_vector(
    reader: &mut Lsb0Reader<'_>,
    baseline: Vec3,
    decimals: u8,
) -> Result<VectorField, DecodeError> {
    let start = reader.absolute_position();
    let scale = 10_i64.pow(u32::from(decimals));
    let explicit_maximum = 24 + 3 * u32::from(decimals);

    let absolute_xy = reader.read_bit()?;
    let xy_width = if absolute_xy {
        reader.serialize_int(explicit_maximum)? as u8
    } else {
        let selector = reader.read_bits(2)?;
        *VECTOR_WIDTH_TABLE
            .get(selector as usize)
            .ok_or(DecodeError::InvalidVectorWidthSelector(selector))?
    };

    let (mut x, mut y) = (0_i64, 0_i64);
    if xy_width != 0 {
        let x_negative = reader.read_bit()?;
        let y_negative = reader.read_bit()?;
        x = i64::from(reader.read_bits(xy_width)?);
        y = i64::from(reader.read_bits(xy_width)?);
        if x_negative {
            x = -x;
        }
        if y_negative {
            y = -y;
        }
    }

    let z_selector = reader.read_bits(2)?;
    let z_width = if let Some(width) = VECTOR_WIDTH_TABLE.get(z_selector as usize) {
        *width
    } else {
        reader.serialize_int(explicit_maximum)? as u8
    };
    let mut z = 0_i64;
    if z_width != 0 {
        let z_negative = reader.read_bit()?;
        z = i64::from(reader.read_bits(z_width)?);
        if z_negative {
            z = -z;
        }
    }

    if !absolute_xy {
        x += round_quantized(baseline.x, scale);
        y += round_quantized(baseline.y, scale);
        z += round_quantized(baseline.z, scale);
    }

    Ok(VectorField {
        value: Vec3::new(
            x as f64 / scale as f64,
            y as f64 / scale as f64,
            z as f64 / scale as f64,
        ),
        bit_offset: start,
        bit_length: reader.absolute_position() - start,
        quantization_decimals: decimals,
        absolute_xy,
        xy_width,
        z_width,
    })
}

#[inline]
fn rotation_units(value_degrees: f64) -> u16 {
    round_quantized(value_degrees * 65_536.0 / 360.0, 1) as u16
}

fn read_compact_rotator(
    reader: &mut Lsb0Reader<'_>,
    baseline: Vec3,
    fallback: Vec3,
    use_baseline: bool,
) -> Result<RotatorField, DecodeError> {
    let start = reader.absolute_position();
    // ⚠️ `zero` 位（以及逐轴的"这一项在不在"位）表示**这个包没带该轴的旋转**，
    // 不是"旋转等于 0°"。以前在 use_baseline=false（绝对编码）时，缺席的轴会保持
    // 数组初值 0 并被当成真值下发 —— 玩家人站着不动，朝向就在"真实值 ↔ 0"之间来回跳，
    // 跟随视角时地图来回晃（实测抓包：静止帧里 0 度出现 3051 次、跳变 121 次）。
    // 缺席一律沿用**该槽位上一帧**的旋转。
    let zero = reader.read_bit()?;
    let baseline_units = if use_baseline {
        [
            rotation_units(baseline.x),
            rotation_units(baseline.y),
            rotation_units(baseline.z),
        ]
    } else {
        [0; 3]
    };
    let fallback_units = [
        rotation_units(fallback.x),
        rotation_units(fallback.y),
        rotation_units(fallback.z),
    ];
    // 绝对编码下，整包缺席 = 本帧没有旋转更新 → 沿用上一帧
    let mut values = if use_baseline {
        [0_u16; 3]
    } else {
        fallback_units
    };

    if !zero {
        if reader.read_bit()? {
            values[0] = reader.read_bits(16)? as u16;
        } else if !use_baseline {
            values[0] = fallback_units[0];
        }
        if reader.read_bit()? {
            values[1] = reader.read_bits(16)? as u16;
        } else if !use_baseline {
            values[1] = fallback_units[1];
        }
        values[2] = read_delta(
            reader,
            i32::from(baseline_units[2]),
            &ROTATOR_WIDTH_TABLE,
            16,
        )? as u16;
    }
    if use_baseline {
        values[0] = values[0].wrapping_add(baseline_units[0]);
        values[1] = values[1].wrapping_add(baseline_units[1]);
    }

    Ok(RotatorField {
        value_degrees: Vec3::new(
            f64::from(values[0]) * 360.0 / 65_536.0,
            f64::from(values[1]) * 360.0 / 65_536.0,
            f64::from(values[2]) * 360.0 / 65_536.0,
        ),
        bit_offset: start,
        bit_length: reader.absolute_position() - start,
    })
}

fn read_full_movement(
    reader: &mut Lsb0Reader<'_>,
    current: MovementState,
    baseline: MovementState,
    use_baseline: bool,
) -> Result<(MovementUpdate, MovementState), DecodeError> {
    let start = reader.absolute_position();
    let flags = reader.read_bits(2)? as u8;
    let has_mode = reader.read_bit()?;
    let movement_mode = if has_mode {
        reader.read_bits(13)? as u16
    } else {
        current.movement_mode
    };

    let position = read_quantized_vector(reader, baseline.position, 1)?;
    let rotation = read_compact_rotator(
        reader,
        baseline.rotation_degrees,
        current.rotation_degrees,
        use_baseline,
    )?;
    let velocity = read_quantized_vector(reader, baseline.velocity, 1)?;
    let acceleration = if flags & 2 != 0 {
        Some(read_quantized_vector(reader, baseline.acceleration, 1)?)
    } else {
        None
    };
    let counter = read_delta(
        reader,
        if use_baseline {
            baseline.delta_counter
        } else {
            0
        },
        &COUNTER_WIDTH_TABLE,
        24,
    )?;

    let mut state = current;
    state.position = position.value;
    state.velocity = velocity.value;
    if let Some(value) = acceleration {
        state.acceleration = value.value;
    }
    state.rotation_degrees = rotation.value_degrees;
    state.movement_flags = flags;
    state.has_movement_mode = has_mode;
    state.movement_mode = movement_mode;
    state.delta_counter = counter;

    Ok((
        MovementUpdate {
            kind: MovementKind::Full,
            bit_offset: start,
            bit_length: reader.absolute_position() - start,
            state,
            position,
            velocity,
            acceleration,
            rotation: Some(rotation),
        },
        state,
    ))
}

fn read_minimal_movement(
    reader: &mut Lsb0Reader<'_>,
    current: MovementState,
    baseline: MovementState,
    _use_baseline: bool,
) -> Result<(MovementUpdate, MovementState), DecodeError> {
    let start = reader.absolute_position();
    let position = read_quantized_vector(reader, baseline.position, 1)?;
    let yaw_present = reader.read_bit()?;
    // ⚠️ 最小移动包里朝向是**可选**的。以前"没带朝向"直接当 0° 并且覆盖掉上一帧，
    // 于是站着不动时（这类包最多）上报朝向会在"真实值 ↔ 0"之间反复跳：
    // 实测录屏里人不动，yaw 却 120 → 66 → 26 → 103 乱跳 —— 跟随视角时地图就来回晃。
    // 正确做法：没带朝向就沿用这个槽位上一帧的朝向。
    let yaw = if yaw_present {
        f64::from(reader.read_bits(16)?) * 360.0 / 65_536.0
    } else {
        current.rotation_degrees.z
    };
    let minimal_word = reader.read_bits(32)?;
    let velocity = read_quantized_vector(reader, baseline.velocity, 1)?;

    let mut state = current;
    state.position = position.value;
    state.velocity = velocity.value;
    // Full movement stores heading in Z and every downstream consumer reads Z.
    // Writing minimal yaw into Y silently froze heading for the most common packet kind.
    state.rotation_degrees.z = yaw;
    state.minimal_word = minimal_word;

    Ok((
        MovementUpdate {
            kind: MovementKind::Minimal,
            bit_offset: start,
            bit_length: reader.absolute_position() - start,
            state,
            position,
            velocity,
            acceleration: None,
            rotation: None,
        },
        state,
    ))
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

    fn write_lsb_bits(data: &mut [u8], offset: usize, width: usize, value: u32) {
        for index in 0..width {
            let bit = (value >> index) & 1;
            let absolute = offset + index;
            let mask = 1_u8 << (absolute & 7);
            if bit != 0 {
                data[absolute >> 3] |= mask;
            } else {
                data[absolute >> 3] &= !mask;
            }
        }
    }

    #[test]
    fn real_handle_17_message_matches_python_reference() {
        let data = decode_hex("d708104900c20901c2b50e017765ac01005040000800");
        let mut decoder = D0Decoder::new();
        let actor = decoder.decode_actor_message(&data, 172).unwrap();
        assert_eq!(actor.summary.consumed_bits, 172);
        assert_eq!(actor.summary.property_count, 1);
        assert_eq!(actor.summary.batch_property_count, 1);
        let A0Value::BatchData(batch) = actor.properties[0].value else {
            panic!("expected BD0");
        };
        assert_eq!(batch.character_count, 9);
        assert_eq!(batch.present_slots().collect::<Vec<_>>(), vec![8]);
        assert_eq!(batch.bit_length, 137);
        assert_eq!(actor.updates.len(), 1);
        let update = actor.updates[0];
        assert_eq!(update.change_mask, 7);
        assert_eq!(update.movement.unwrap().kind, MovementKind::Full);
        assert_eq!(update.state.position, Vec3::new(-3465.0, -4800.0, 685.4));
        assert_eq!(update.state.rotation_degrees, Vec3::new(0.0, 0.0, 90.0));
        assert_eq!(update.extra_state, Some(128));
        assert!(update.position_valid);
        assert_eq!(update.continuity, SlotContinuity::Continuous);
    }

    #[test]
    fn minimal_movement_without_yaw_keeps_the_previous_heading() {
        // 站着不动时最常见的"最小移动包"里朝向是可选的（yaw_present=false）。
        // 这时必须沿用上一帧朝向 —— 以前会被写成 0°，把真实朝向冲掉，
        // 表现就是跟随视角的地图来回晃（用户录屏实测：人不动，yaw 在 120/66/26/103 之间跳）。
        let mut writer = Lsb0Writer::with_capacity(64);
        writer.write_bit(false); // position.absolute_xy = false
        writer.write_bits(0, 2).unwrap(); // xy selector = 0 → 宽度 0（位置沿用基线）
        writer.write_bits(0, 2).unwrap(); // z  selector = 0 → 宽度 0
        writer.write_bit(false); // ★ yaw_present = false
        writer.write_bits(0xA5A5_1234, 32).unwrap(); // minimal_word
        writer.write_bit(false); // velocity.absolute_xy = false
        writer.write_bits(0, 2).unwrap();
        writer.write_bits(0, 2).unwrap();
        let bytes = writer.into_bytes();

        let mut previous = MovementState::default();
        previous.rotation_degrees = Vec3::new(11.0, 22.0, 123.4);
        previous.position = Vec3::new(-3465.0, -4800.0, 685.4);
        let baseline = previous;

        let mut reader = Lsb0Reader::new(&bytes, 43).expect("reader");
        let (update, state) =
            read_minimal_movement(&mut reader, previous, baseline, false).expect("decode");
        assert_eq!(
            state.rotation_degrees.z, 123.4,
            "没有朝向的包不能把朝向清零（那会让跟随的地图来回晃）"
        );
        assert_eq!(update.state.rotation_degrees, Vec3::new(11.0, 22.0, 123.4));
        assert_eq!(update.kind, MovementKind::Minimal);
    }

    #[test]
    fn minimal_movement_with_yaw_updates_the_heading_component() {
        let mut writer = Lsb0Writer::with_capacity(64);
        writer.write_bit(false);
        writer.write_bits(0, 2).unwrap();
        writer.write_bits(0, 2).unwrap();
        writer.write_bit(true);
        writer.write_bits(16_384, 16).unwrap(); // 90 degrees
        writer.write_bits(0xA5A5_1234, 32).unwrap();
        writer.write_bit(false);
        writer.write_bits(0, 2).unwrap();
        writer.write_bits(0, 2).unwrap();
        let bytes = writer.into_bytes();

        let mut previous = MovementState::default();
        previous.rotation_degrees = Vec3::new(11.0, 22.0, 45.0);
        let mut reader = Lsb0Reader::new(&bytes, 59).expect("reader");
        let (update, state) =
            read_minimal_movement(&mut reader, previous, previous, false).expect("decode");
        assert_eq!(state.rotation_degrees, Vec3::new(11.0, 22.0, 90.0));
        assert_eq!(update.state.rotation_degrees.z, 90.0);
    }

    #[test]
    fn real_handle_5_then_terminator_keeps_opaque_two_bits() {
        let data = decode_hex("9b500800");
        let mut decoder = D0Decoder::new();
        let actor = decoder.decode_actor_message(&data, 29).unwrap();
        assert_eq!(actor.summary.property_count, 1);
        assert_eq!(actor.summary.raw_two_bit_property_count, 1);
        assert_eq!(actor.summary.batch_property_count, 0);
        assert_eq!(actor.properties[0].handle, RAW_TWO_BIT_PROPERTY_HANDLE);
        assert_eq!(actor.properties[0].value, A0Value::RawTwoBits { raw: 1 });
        assert!(actor.updates.is_empty());
    }

    #[test]
    fn real_handle_5_then_17_decodes_both_properties() {
        let data = decode_hex(
            "2f2350484401619400e1ee9844c5ead30000282008a3040827811403569f0600400141182540b8a02ae0aefa3400000a08c22801c2b50e0177d5a701005040104609108e1b4a09ac3e0d0080020200",
        );
        let mut decoder = D0Decoder::new();
        let actor = decoder.decode_actor_message(&data, 631).unwrap();
        assert_eq!(actor.summary.property_count, 2);
        assert_eq!(actor.summary.raw_two_bit_property_count, 1);
        assert_eq!(actor.summary.batch_property_count, 1);
        assert_eq!(
            actor
                .properties
                .iter()
                .map(|property| property.handle)
                .collect::<Vec<_>>(),
            vec![5, 17]
        );
        assert_eq!(actor.properties[0].value, A0Value::RawTwoBits { raw: 1 });
        assert_eq!(
            (
                actor.properties[0].handle_bit_offset,
                actor.properties[0].payload_bit_offset,
                actor.properties[0].payload_bit_length,
            ),
            (19, 27, 2)
        );
        assert_eq!(
            (
                actor.properties[1].handle_bit_offset,
                actor.properties[1].payload_bit_offset,
                actor.properties[1].payload_bit_length,
            ),
            (29, 37, 586)
        );
        assert_eq!(actor.summary.property_terminator_bit_offset, 623);
        let A0Value::BatchData(batch) = actor.properties[1].value else {
            panic!("expected second property to be BD0");
        };
        assert_eq!(batch.character_count, 10);
        assert_eq!(batch.update_count, 5);
        assert_eq!(
            batch.present_slots().collect::<Vec<_>>(),
            vec![5, 6, 7, 8, 9]
        );
        assert_eq!(actor.updates.len(), 5);
    }

    #[test]
    fn unknown_handle_fails_closed() {
        let mut data = decode_hex("9b500800");
        // The packed-zero terminator starts at actor bit 21. Replace it with
        // packed handle 9 (wire byte 18); no serializer is guessed/scanned.
        write_lsb_bits(&mut data, 21, 8, 18);
        let mut decoder = D0Decoder::new();
        assert!(matches!(
            decoder.decode_actor_message(&data, 29),
            Err(DecodeError::UnknownPropertyHandle { handle: 9, .. })
        ));
    }

    #[test]
    fn actor_transaction_rolls_back_after_decoded_batch() {
        let mut data = decode_hex("d708104900c20901c2b50e017765ac01005040000800");
        // Replace the final zero handle with handle 5. BatchData has already
        // parsed and staged slot 8 when the now-missing two-bit body fails.
        write_lsb_bits(&mut data, 164, 8, 10);
        let mut decoder = D0Decoder::new();
        let mut scratch = DecodeScratch::default();
        assert!(
            decoder
                .decode_actor_message_into(&data, 172, &mut scratch)
                .is_err()
        );
        assert!(scratch.properties.is_empty());
        assert!(scratch.updates.is_empty());
        assert_eq!(decoder.current_state(8), Some(&MovementState::default()));
        assert_eq!(decoder.slot_validity(8), Some(SlotValidity::default()));
    }

    #[test]
    fn every_truncation_rejects_without_mutating_state() {
        let data = decode_hex(
            "2f2350484401619400e1ee9844c5ead30000282008a3040827811403569f0600400141182540b8a02ae0aefa3400000a08c22801c2b50e0177d5a701005040104609108e1b4a09ac3e0d0080020200",
        );
        for truncated_bits in 0..631 {
            let mut decoder = D0Decoder::new();
            let mut scratch = DecodeScratch::with_capacity(2, 10);
            assert!(
                decoder
                    .decode_actor_message_into(&data, truncated_bits, &mut scratch)
                    .is_err(),
                "accepted truncation at {truncated_bits} bits"
            );
            assert!(scratch.properties.is_empty());
            assert!(scratch.updates.is_empty());
            for slot in 0..10 {
                assert_eq!(decoder.current_state(slot), Some(&MovementState::default()));
                assert_eq!(decoder.slot_validity(slot), Some(SlotValidity::default()));
            }
        }
    }

    #[test]
    fn gap_invalidates_and_fresh_absolute_position_recovers_slot() {
        let data = decode_hex("d708104900c20901c2b50e017765ac01005040000800");
        let mut decoder = D0Decoder::new();
        decoder.decode_actor_message(&data, 172).unwrap();
        assert!(decoder.slot_validity(8).unwrap().current_position);

        decoder.invalidate_slots(1 << 8);
        assert_eq!(
            decoder.slot_validity(8).unwrap().continuity,
            SlotContinuity::Discontinuous
        );
        let recovered = decoder.decode_actor_message(&data, 172).unwrap();
        assert!(recovered.updates[0].movement.unwrap().position.absolute_xy);
        assert!(recovered.updates[0].position_valid);
        assert_eq!(
            decoder.slot_validity(8).unwrap().continuity,
            SlotContinuity::Continuous
        );
    }

    #[test]
    fn reset_slot_clears_current_baselines_and_validity() {
        let data = decode_hex("d708104900c20901c2b50e017765ac01005040000800");
        let mut decoder = D0Decoder::new();
        decoder.decode_actor_message(&data, 172).unwrap();
        assert!(decoder.reset_slot(8));
        assert_eq!(decoder.current_state(8), Some(&MovementState::default()));
        assert_eq!(decoder.slot_validity(8), Some(SlotValidity::default()));
        assert!(!decoder.reset_slot(64));
    }

    #[test]
    fn public_property_model_round_trips_through_json() {
        let value = A0Value::BatchData(D0Summary {
            character_count: 10,
            bit_offset: 37,
            bit_length: 586,
            present_slot_mask: 0x03e0,
            update_count: 5,
        });
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<A0Value>(&encoded).unwrap(), value);
    }
}
