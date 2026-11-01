use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

/// 分析模式开关：抓包从"半途"开始时，同一个通道会先看到一段旧的 partial-initial，
/// 紧接着又是一段新的 partial-initial（旧的永远等不到 final），严格模式会直接判死。
/// 打开这个开关后我们把旧链丢掉、从新链重新累积 —— **只给 dump-coordinates 这类
/// 分析入口用**，正式解码/证据链仍走严格模式（默认 false）。
pub static TOLERATE_OVERLAPPING_INITIAL: AtomicBool = AtomicBool::new(false);

pub fn tolerate_overlapping_initial() -> bool {
    TOLERATE_OVERLAPPING_INITIAL.load(Ordering::Relaxed)
}

pub fn set_tolerate_overlapping_initial(enabled: bool) {
    TOLERATE_OVERLAPPING_INITIAL.store(enabled, Ordering::Relaxed);
}

use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PartialKey {
    pub direction: Direction,
    pub channel_index: u32,
    pub channel_generation: u64,
}

#[derive(Clone, Debug)]
pub struct PartialFragment<'a> {
    pub key: PartialKey,
    pub reliable_sequence: Option<u16>,
    pub initial: bool,
    pub final_fragment: bool,
    pub data: &'a [u8],
    pub bit_length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReassembledBunch {
    pub key: PartialKey,
    pub fragment_count: usize,
    pub bit_length: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PartialError {
    #[error("partial fragment bit length exceeds its byte buffer")]
    BitLengthOutOfRange,
    #[error("overlapping partial-initial for channel {0}")]
    OverlappingInitial(u32),
    #[error("orphan partial fragment for channel {0}")]
    Orphan(u32),
    #[error("reliable sequence gap: expected {expected}, observed {observed}")]
    ReliableGap { expected: u16, observed: u16 },
    #[error("partial chain exceeds configured bit limit")]
    ChainTooLarge,
}

struct ActivePartial {
    last_reliable: Option<u16>,
    reliable_fragments: HashMap<u16, FragmentIdentity>,
    fragment_count: usize,
    bit_length: usize,
    data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FragmentIdentity {
    initial: bool,
    final_fragment: bool,
    bit_length: usize,
    digest: [u8; 32],
}

impl FragmentIdentity {
    fn from_fragment(fragment: &PartialFragment<'_>) -> Self {
        let whole_bytes = fragment.bit_length / 8;
        let remaining_bits = fragment.bit_length % 8;
        let mut hasher = Sha256::new();
        hasher.update(&fragment.data[..whole_bytes]);
        if remaining_bits != 0 {
            let mask = (1_u8 << remaining_bits) - 1;
            hasher.update([fragment.data[whole_bytes] & mask]);
        }
        Self {
            initial: fragment.initial,
            final_fragment: fragment.final_fragment,
            bit_length: fragment.bit_length,
            digest: hasher.finalize().into(),
        }
    }
}

pub struct PartialBunchAssembler {
    active: HashMap<PartialKey, ActivePartial>,
    max_bits: usize,
}

impl Default for PartialBunchAssembler {
    fn default() -> Self {
        Self::new(8 * 1024 * 1024)
    }
}

impl PartialBunchAssembler {
    pub fn new(max_bits: usize) -> Self {
        Self {
            active: HashMap::new(),
            max_bits,
        }
    }

    pub fn invalidate_all(&mut self) {
        self.active.clear();
    }

    pub fn invalidate(&mut self, key: PartialKey) {
        self.active.remove(&key);
    }

    pub fn feed(
        &mut self,
        fragment: PartialFragment<'_>,
    ) -> Result<Option<ReassembledBunch>, PartialError> {
        if fragment.bit_length > fragment.data.len().saturating_mul(8) {
            return Err(PartialError::BitLengthOutOfRange);
        }
        let reliable_identity = fragment
            .reliable_sequence
            .map(|sequence| (sequence, FragmentIdentity::from_fragment(&fragment)));
        // Reliable UDP may deliver the exact same partial fragment again while
        // the chain is still open. It is not a gap and must not destroy the
        // already assembled prefix/baseline.
        if let Some((sequence, identity)) = &reliable_identity
            && self
                .active
                .get(&fragment.key)
                .and_then(|active| active.reliable_fragments.get(sequence))
                == Some(identity)
        {
            return Ok(None);
        }
        if fragment.initial {
            if self.active.contains_key(&fragment.key) {
                self.active.remove(&fragment.key);
                return Err(PartialError::OverlappingInitial(fragment.key.channel_index));
            }
            self.active.insert(
                fragment.key,
                ActivePartial {
                    last_reliable: fragment.reliable_sequence,
                    reliable_fragments: HashMap::new(),
                    fragment_count: 0,
                    bit_length: 0,
                    data: Vec::new(),
                },
            );
        }
        let Some(active) = self.active.get(&fragment.key) else {
            return Err(PartialError::Orphan(fragment.key.channel_index));
        };
        if active.fragment_count != 0
            && let (Some(previous), Some(observed)) =
                (active.last_reliable, fragment.reliable_sequence)
        {
            let expected = previous.wrapping_add(1);
            if expected != observed {
                self.active.remove(&fragment.key);
                return Err(PartialError::ReliableGap { expected, observed });
            }
        }
        let new_length = active
            .bit_length
            .checked_add(fragment.bit_length)
            .filter(|length| *length <= self.max_bits);
        let Some(new_length) = new_length else {
            self.active.remove(&fragment.key);
            return Err(PartialError::ChainTooLarge);
        };
        let active = self.active.get_mut(&fragment.key).unwrap();
        append_lsb_bits(
            &mut active.data,
            active.bit_length,
            fragment.data,
            fragment.bit_length,
        );
        active.bit_length = new_length;
        active.fragment_count += 1;
        active.last_reliable = fragment.reliable_sequence;
        if let Some((sequence, identity)) = reliable_identity {
            active.reliable_fragments.insert(sequence, identity);
        }
        if !fragment.final_fragment {
            return Ok(None);
        }
        let active = self.active.remove(&fragment.key).unwrap();
        Ok(Some(ReassembledBunch {
            key: fragment.key,
            fragment_count: active.fragment_count,
            bit_length: active.bit_length,
            data: active.data,
        }))
    }
}

fn append_lsb_bits(output: &mut Vec<u8>, output_bits: usize, input: &[u8], input_bits: usize) {
    let final_bits = output_bits + input_bits;
    output.resize(final_bits.div_ceil(8), 0);
    for bit in 0..input_bits {
        let value = (input[bit >> 3] >> (bit & 7)) & 1;
        let destination = output_bits + bit;
        output[destination >> 3] |= value << (destination & 7);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concatenates_non_byte_aligned_fragments_and_rejects_gap() {
        let key = PartialKey {
            direction: Direction::ServerToClient,
            channel_index: 32,
            channel_generation: 1,
        };
        let mut assembler = PartialBunchAssembler::default();
        assert!(
            assembler
                .feed(PartialFragment {
                    key,
                    reliable_sequence: Some(9),
                    initial: true,
                    final_fragment: false,
                    data: &[0b0000_0101],
                    bit_length: 3,
                })
                .unwrap()
                .is_none()
        );
        let completed = assembler
            .feed(PartialFragment {
                key,
                reliable_sequence: Some(10),
                initial: false,
                final_fragment: true,
                data: &[0b0000_0011],
                bit_length: 2,
            })
            .unwrap()
            .unwrap();
        assert_eq!(completed.bit_length, 5);
        assert_eq!(completed.data, [0b0001_1101]);

        assembler
            .feed(PartialFragment {
                key,
                reliable_sequence: Some(12),
                initial: true,
                final_fragment: false,
                data: &[1],
                bit_length: 1,
            })
            .unwrap();
        assert_eq!(
            assembler.feed(PartialFragment {
                key,
                reliable_sequence: Some(14),
                initial: false,
                final_fragment: true,
                data: &[1],
                bit_length: 1,
            }),
            Err(PartialError::ReliableGap {
                expected: 13,
                observed: 14
            })
        );
    }

    #[test]
    fn exact_reliable_retransmissions_are_ignored_inside_an_open_chain() {
        let key = PartialKey {
            direction: Direction::ServerToClient,
            channel_index: 9,
            channel_generation: 2,
        };
        let mut assembler = PartialBunchAssembler::default();
        let fragment = |sequence, initial, final_fragment, data: &'static [u8]| PartialFragment {
            key,
            reliable_sequence: Some(sequence),
            initial,
            final_fragment,
            data,
            bit_length: 8,
        };
        assert!(
            assembler
                .feed(fragment(9, true, false, &[0x11]))
                .unwrap()
                .is_none()
        );
        // Initial and middle fragments may both be retransmitted verbatim.
        assert!(
            assembler
                .feed(fragment(9, true, false, &[0x11]))
                .unwrap()
                .is_none()
        );
        assert!(
            assembler
                .feed(fragment(10, false, false, &[0x22]))
                .unwrap()
                .is_none()
        );
        assert!(
            assembler
                .feed(fragment(10, false, false, &[0x22]))
                .unwrap()
                .is_none()
        );
        let completed = assembler
            .feed(fragment(11, false, true, &[0x33]))
            .unwrap()
            .unwrap();
        assert_eq!(completed.fragment_count, 3);
        assert_eq!(completed.data, [0x11, 0x22, 0x33]);
    }

    #[test]
    fn conflicting_retransmission_still_fails_closed() {
        let key = PartialKey {
            direction: Direction::ServerToClient,
            channel_index: 9,
            channel_generation: 2,
        };
        let mut assembler = PartialBunchAssembler::default();
        let fragment = |sequence, initial, final_fragment, data: &'static [u8]| PartialFragment {
            key,
            reliable_sequence: Some(sequence),
            initial,
            final_fragment,
            data,
            bit_length: 8,
        };
        assembler.feed(fragment(9, true, false, &[0x11])).unwrap();
        assembler.feed(fragment(10, false, false, &[0x22])).unwrap();
        assert_eq!(
            assembler.feed(fragment(10, false, false, &[0x99])),
            Err(PartialError::ReliableGap {
                expected: 11,
                observed: 10
            })
        );
        assert_eq!(
            assembler.feed(fragment(11, false, true, &[0x33])),
            Err(PartialError::Orphan(9))
        );
    }
}
