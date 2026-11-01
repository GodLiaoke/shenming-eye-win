use serde::{Deserialize, Serialize};

pub const BATCH_CHANNEL_INDEX: u32 = 32;
pub const BATCH_PROPERTY_HANDLE: u32 = 17;
pub const RAW_TWO_BIT_PROPERTY_HANDLE: u32 = 5;
pub const MAX_BATCH_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Vec3 {
    pub x: f64,
    pub y: f64,
    pub z: f64,
}

impl Vec3 {
    pub const ZERO: Self = Self {
        x: 0.0,
        y: 0.0,
        z: 0.0,
    };

    pub const fn new(x: f64, y: f64, z: f64) -> Self {
        Self { x, y, z }
    }

    pub const fn as_array(self) -> [f64; 3] {
        [self.x, self.y, self.z]
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct MovementState {
    pub position: Vec3,
    pub velocity: Vec3,
    pub acceleration: Vec3,
    pub rotation_degrees: Vec3,
    pub movement_flags: u8,
    pub has_movement_mode: bool,
    pub movement_mode: u16,
    pub delta_counter: i32,
    pub minimal_word: u32,
    pub extra_state: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MovementKind {
    Full,
    Minimal,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct VectorField {
    pub value: Vec3,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub quantization_decimals: u8,
    pub absolute_xy: bool,
    pub xy_width: u8,
    pub z_width: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct RotatorField {
    pub value_degrees: Vec3,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct MovementUpdate {
    pub kind: MovementKind,
    pub bit_offset: usize,
    pub bit_length: usize,
    /// Slot state after the movement serializer and before any handle-17
    /// `extra_state` byte is applied.
    pub state: MovementState,
    pub position: VectorField,
    pub velocity: VectorField,
    pub acceleration: Option<VectorField>,
    pub rotation: Option<RotatorField>,
}

/// Whether a slot's coordinate can be emitted as a proven continuous value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotContinuity {
    /// No self-contained coordinate has been decoded for this slot yet.
    #[default]
    Unknown,
    /// The current coordinate is independent of any missing/invalid baseline.
    Continuous,
    /// A gap or an invalid baseline makes the current coordinate untrusted.
    Discontinuous,
}

/// Position-specific validity retained independently for current and both
/// wire-selected baselines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotValidity {
    pub current_position: bool,
    pub baseline_positions: [bool; 2],
    pub continuity: SlotContinuity,
}

impl SlotValidity {
    pub const fn baseline_position(self, index: u8) -> Option<bool> {
        if index < 2 {
            Some(self.baseline_positions[index as usize])
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct D0Update {
    pub slot: u8,
    pub state_index: u8,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub use_baseline: bool,
    pub source_baseline: Option<u8>,
    pub source_baseline_position_valid: Option<bool>,
    pub store_baseline: bool,
    pub destination_baseline: Option<u8>,
    pub change_mask: u8,
    pub movement: Option<MovementUpdate>,
    pub extra_state: Option<u8>,
    pub state: MovementState,
    pub position_valid: bool,
    pub continuity: SlotContinuity,
}

impl D0Update {
    pub const fn fresh_movement(&self) -> bool {
        self.movement.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct D0Summary {
    pub character_count: u8,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub present_slot_mask: u64,
    pub update_count: u8,
}

impl D0Summary {
    pub fn present_slots(self) -> impl Iterator<Item = u8> {
        (0..self.character_count).filter(move |slot| self.present_slot_mask & (1 << slot) != 0)
    }
}

/// The two serializers proven for Channel 32 in build 1.24.0.2911.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum A0Value {
    /// Opaque, exactly two-bit payload belonging to handle 5.
    RawTwoBits {
        raw: u8,
    },
    BatchData(D0Summary),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct A0Property {
    pub handle: u32,
    pub handle_bit_offset: usize,
    pub handle_bit_length: usize,
    pub payload_bit_offset: usize,
    pub payload_bit_length: usize,
    pub value: A0Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct A0Summary {
    pub has_rep_layout: bool,
    pub is_actor: bool,
    pub content_payload_bit_offset: usize,
    pub content_payload_bit_length: usize,
    pub checksum_present: bool,
    pub property_count: u16,
    pub batch_property_count: u16,
    pub raw_two_bit_property_count: u16,
    pub property_terminator_bit_offset: usize,
    pub property_terminator_bit_length: usize,
    pub consumed_bits: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct DecodeScratch {
    pub properties: Vec<A0Property>,
    pub updates: Vec<D0Update>,
    /// 宽容普查模式下记录到的未支持属性句柄；严格模式恒为空。
    pub unknown_handles: Vec<UnknownHandle>,
}

/// 一条消息里出现的、当前解码器不认识的 RepLayout 属性句柄。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnknownHandle {
    pub handle: u32,
    pub bit_offset: usize,
    /// 该句柄之后剩余的位数，用来粗略判断该属性的载荷规模。
    pub remaining_bits: usize,
    /// 句柄之后紧随的若干位（最多 64 位，按协议相同的 LSB-first 读取）。
    /// 属性值不一定字节对齐，所以这里保留整段比特，供事后按不同起始位/位宽扫描。
    pub sample_bits: u64,
    /// `sample_bits` 的有效位宽（0-64）。
    pub sample_width: u8,
    /// 该句柄所在字节起点的原始字节窗口，便于事后还原属性编码。
    pub raw_window: [u8; 8],
    pub raw_window_len: u8,
}

impl DecodeScratch {
    pub fn with_capacity(properties: usize, updates: usize) -> Self {
        Self {
            properties: Vec::with_capacity(properties),
            updates: Vec::with_capacity(updates),
            unknown_handles: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.properties.clear();
        self.updates.clear();
        self.unknown_handles.clear();
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ActorMessage {
    pub summary: A0Summary,
    pub properties: Vec<A0Property>,
    pub updates: Vec<D0Update>,
}
