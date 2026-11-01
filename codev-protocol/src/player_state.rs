//! Build-pinned `SGBlackboard.RepProps` decoding for PlayerState opens.
//!
//! This is deliberately a class-specific parser.  It is not part of the
//! Channel 32 `D0Decoder` property dispatch and it is not wired into
//! the production identity graph until the following h51 value and the full
//! Actor transaction are proven.  Values are consumed for bit-accurate
//! alignment only; this module never retains gameplay values such as kills,
//! coins, or shop data.

use crate::{DecodeError, Lsb0Reader};
use std::error::Error;
use std::fmt;

pub const BLACKBOARD_GROUP_COUNT: usize = 47;
pub const BLACKBOARD_H50_HANDLE: u32 = 50;
pub const BLACKBOARD_H51_HANDLE: u32 = 51;

/// The build-pinned SGBlackboard PropIDs, in RepProps group order.
pub const BLACKBOARD_PROP_IDS: [u16; BLACKBOARD_GROUP_COUNT] = [
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 94, 63, 64, 65, 66, 95, 68, 69, 70, 71,
    72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 45, 92, 93,
];

/// Logical serializers selected by the authenticated Blackboard schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlackboardValueKind {
    Bool,
    Int,
    Float,
    IntArray,
}

/// The non-arithmetic, class-specific schema order for the 47 groups.
pub const BLACKBOARD_VALUE_KINDS: [BlackboardValueKind; BLACKBOARD_GROUP_COUNT] = [
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Int,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Float,
    BlackboardValueKind::Int,
    BlackboardValueKind::Float,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Int,
    BlackboardValueKind::Int,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Int,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Int,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
    BlackboardValueKind::IntArray,
    BlackboardValueKind::Bool,
    BlackboardValueKind::Bool,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlayerStateError {
    Decode(DecodeError),
    InvalidHandle {
        field: &'static str,
        expected: u32,
        actual: u32,
        bit_position: usize,
    },
    InvalidCount {
        field: &'static str,
        expected: u16,
        actual: u16,
        bit_position: usize,
    },
    InvalidNestedTerminator {
        group: usize,
        actual: u32,
        bit_position: usize,
    },
    InvalidArrayCount {
        group: usize,
        count: u16,
        bit_position: usize,
    },
    SchemaMismatch {
        group: usize,
        expected_prop_id: u16,
        actual_prop_id: u16,
    },
}

impl fmt::Display for PlayerStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::InvalidHandle {
                field,
                expected,
                actual,
                bit_position,
            } => write!(
                formatter,
                "{field} handle {actual} at bit {bit_position}, expected {expected}"
            ),
            Self::InvalidCount {
                field,
                expected,
                actual,
                bit_position,
            } => write!(
                formatter,
                "{field} count {actual} at bit {bit_position}, expected {expected}"
            ),
            Self::InvalidNestedTerminator {
                group,
                actual,
                bit_position,
            } => write!(
                formatter,
                "RepProps group {group} nested terminator {actual} at bit {bit_position}"
            ),
            Self::InvalidArrayCount {
                group,
                count,
                bit_position,
            } => write!(
                formatter,
                "RepProps group {group} IntArray count {count} at bit {bit_position} exceeds 2048"
            ),
            Self::SchemaMismatch {
                group,
                expected_prop_id,
                actual_prop_id,
            } => write!(
                formatter,
                "RepProps group {group} PropID {actual_prop_id}, expected {expected_prop_id}"
            ),
        }
    }
}

impl Error for PlayerStateError {}

impl From<DecodeError> for PlayerStateError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlackboardGroupSummary {
    pub group_handle: u32,
    pub prop_id: u16,
    pub kind: BlackboardValueKind,
    pub rep_sub_props_count: u16,
    pub rep_sub_prop_handle: u32,
    pub presence: bool,
    pub presence_bit_offset: usize,
    pub value_bit_offset: usize,
    pub value_bit_length: usize,
    pub int_array_count: Option<u16>,
    pub nested_terminator_bit_offset: usize,
    pub next_outer_handle_bit_offset: usize,
    pub next_outer_handle: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerStateH50Summary {
    pub h50_handle: u32,
    pub array_count: u16,
    pub groups: Vec<BlackboardGroupSummary>,
    pub outer_terminator_bit_offset: usize,
    pub next_handle: u32,
    /// Absolute bit offset immediately after packed h51.  The h51 value is
    /// intentionally left for a later, separately proven class parser.
    pub next_value_bit_offset: usize,
    pub consumed_bits: usize,
}

fn expect_handle(
    reader: &mut Lsb0Reader<'_>,
    field: &'static str,
    expected: u32,
) -> Result<u32, PlayerStateError> {
    let bit_position = reader.absolute_position();
    let actual = reader.serialize_int_packed()?;
    if actual != expected {
        return Err(PlayerStateError::InvalidHandle {
            field,
            expected,
            actual,
            bit_position,
        });
    }
    Ok(actual)
}

fn read_expected_count(
    reader: &mut Lsb0Reader<'_>,
    field: &'static str,
    expected: u16,
) -> Result<u16, PlayerStateError> {
    let bit_position = reader.absolute_position();
    let actual = reader.read_bits(16)? as u16;
    if actual != expected {
        return Err(PlayerStateError::InvalidCount {
            field,
            expected,
            actual,
            bit_position,
        });
    }
    Ok(actual)
}

/// Decode h50 `SGBlackboard.RepProps` and the following packed h51 handle.
///
/// `start_bit` must point at the h50 outer property handle. `bit_length` is
/// the available range from that point; it may include the unknown h51 value
/// and any later Actor properties. The function returns immediately after the
/// h51 handle and never interprets trailing bits.
pub fn decode_player_state_h50(
    data: &[u8],
    start_bit: usize,
    bit_length: usize,
) -> Result<PlayerStateH50Summary, PlayerStateError> {
    let mut reader = Lsb0Reader::range(data, start_bit, bit_length)?;
    let h50_start = reader.absolute_position();
    expect_handle(&mut reader, "h50", BLACKBOARD_H50_HANDLE)?;
    let array_count = read_expected_count(&mut reader, "RepProps", BLACKBOARD_GROUP_COUNT as u16)?;
    let mut current_handle = reader.serialize_int_packed()?;
    let mut groups = Vec::with_capacity(BLACKBOARD_GROUP_COUNT);

    for (index, (&prop_id, &kind)) in BLACKBOARD_PROP_IDS
        .iter()
        .zip(BLACKBOARD_VALUE_KINDS.iter())
        .enumerate()
    {
        let group = index + 1;
        if current_handle != group as u32 {
            return Err(PlayerStateError::InvalidHandle {
                field: "RepProps group",
                expected: group as u32,
                actual: current_handle,
                bit_position: reader.absolute_position(),
            });
        }

        // The PropID sequence is a build-pinned class schema. Keeping the
        // lookup explicit prevents accidental index-arithmetic remapping.
        let expected_prop_id = BLACKBOARD_PROP_IDS[index];
        if prop_id != expected_prop_id {
            return Err(PlayerStateError::SchemaMismatch {
                group,
                expected_prop_id,
                actual_prop_id: prop_id,
            });
        }

        let rep_sub_props_count = read_expected_count(&mut reader, "RepSubProps", 1)?;
        let rep_sub_prop_handle = expect_handle(&mut reader, "RepSubProps element", 1)?;
        let presence_bit_offset = reader.absolute_position();
        let presence = reader.read_bit()?;
        let value_bit_offset = reader.absolute_position();
        let mut int_array_count = None;
        if presence {
            match kind {
                BlackboardValueKind::Bool => {
                    reader.read_bits(1)?;
                }
                BlackboardValueKind::Int | BlackboardValueKind::Float => {
                    reader.read_bits(32)?;
                }
                BlackboardValueKind::IntArray => {
                    let count_bit_position = reader.absolute_position();
                    let count = reader.read_bits(16)? as u16;
                    if count > 2_048 {
                        return Err(PlayerStateError::InvalidArrayCount {
                            group,
                            count,
                            bit_position: count_bit_position,
                        });
                    }
                    for _ in 0..count {
                        reader.read_bits(32)?;
                    }
                    int_array_count = Some(count);
                }
            }
        }
        let value_bit_length = reader.absolute_position() - value_bit_offset;

        let nested_terminator_bit_offset = reader.absolute_position();
        let nested_terminator = reader.serialize_int_packed()?;
        if nested_terminator != 0 {
            return Err(PlayerStateError::InvalidNestedTerminator {
                group,
                actual: nested_terminator,
                bit_position: nested_terminator_bit_offset,
            });
        }
        let next_outer_handle_bit_offset = reader.absolute_position();
        let next_outer_handle = reader.serialize_int_packed()?;
        let expected_next = if group == BLACKBOARD_GROUP_COUNT {
            0
        } else {
            (group + 1) as u32
        };
        if next_outer_handle != expected_next {
            return Err(PlayerStateError::InvalidHandle {
                field: "RepProps outer next",
                expected: expected_next,
                actual: next_outer_handle,
                bit_position: reader.absolute_position(),
            });
        }
        groups.push(BlackboardGroupSummary {
            group_handle: group as u32,
            prop_id,
            kind,
            rep_sub_props_count,
            rep_sub_prop_handle,
            presence,
            presence_bit_offset,
            value_bit_offset,
            value_bit_length,
            int_array_count,
            nested_terminator_bit_offset,
            next_outer_handle_bit_offset,
            next_outer_handle,
        });
        current_handle = next_outer_handle;
    }

    let outer_terminator_bit_offset = groups.last().map_or(reader.absolute_position(), |group| {
        group.next_outer_handle_bit_offset
    });
    let next_handle = expect_handle(&mut reader, "h51", BLACKBOARD_H51_HANDLE)?;
    let next_value_bit_offset = reader.absolute_position();
    Ok(PlayerStateH50Summary {
        h50_handle: BLACKBOARD_H50_HANDLE,
        array_count,
        groups,
        outer_terminator_bit_offset,
        next_handle,
        next_value_bit_offset,
        consumed_bits: next_value_bit_offset - h50_start,
    })
}
