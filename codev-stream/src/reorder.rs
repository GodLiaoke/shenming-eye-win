use std::collections::{BTreeMap, VecDeque};

use thiserror::Error;

pub const DEFAULT_SEQUENCE_MODULUS: u64 = 0x4000;
pub const DEFAULT_REORDER_PACKETS: usize = 64;
pub const DEFAULT_REORDER_TIMEOUT_NS: u64 = 50_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sequenced<T> {
    pub raw_sequence: u16,
    pub unwrapped_sequence: u64,
    pub arrival_ns: u64,
    pub fingerprint: u64,
    pub value: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SequenceGap {
    pub first_missing: u64,
    pub last_missing: u64,
    pub resumed_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReorderOutput<T> {
    pub released: Vec<Sequenced<T>>,
    pub gap: Option<SequenceGap>,
    pub duplicate: bool,
    pub stale: bool,
}

impl<T> Default for ReorderOutput<T> {
    fn default() -> Self {
        Self {
            released: Vec::new(),
            gap: None,
            duplicate: false,
            stale: false,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReorderError {
    #[error("sequence modulus must be a power of two")]
    InvalidModulus,
    #[error("raw sequence {raw} is outside modulus {modulus}")]
    RawOutOfRange { raw: u16, modulus: u64 },
    #[error("conflicting duplicate sequence {sequence}")]
    ConflictingDuplicate { sequence: u64 },
}

struct Buffered<T> {
    raw: u16,
    arrival_ns: u64,
    fingerprint: u64,
    value: T,
}

pub struct SequenceReorderBuffer<T> {
    modulus: u64,
    packet_limit: usize,
    timeout_ns: u64,
    expected: Option<u64>,
    highest_seen: Option<u64>,
    gap_started_ns: Option<u64>,
    buffered: BTreeMap<u64, Buffered<T>>,
    recent: VecDeque<(u64, u64)>,
}

impl<T> Default for SequenceReorderBuffer<T> {
    fn default() -> Self {
        Self::new(
            DEFAULT_SEQUENCE_MODULUS,
            DEFAULT_REORDER_PACKETS,
            DEFAULT_REORDER_TIMEOUT_NS,
        )
        .expect("default reorder configuration is valid")
    }
}

impl<T> SequenceReorderBuffer<T> {
    pub fn new(modulus: u64, packet_limit: usize, timeout_ns: u64) -> Result<Self, ReorderError> {
        if modulus == 0 || !modulus.is_power_of_two() {
            return Err(ReorderError::InvalidModulus);
        }
        Ok(Self {
            modulus,
            packet_limit: packet_limit.max(1),
            timeout_ns,
            expected: None,
            highest_seen: None,
            gap_started_ns: None,
            buffered: BTreeMap::new(),
            recent: VecDeque::with_capacity(packet_limit.max(64)),
        })
    }

    pub const fn expected(&self) -> Option<u64> {
        self.expected
    }

    pub fn reset(&mut self) {
        self.expected = None;
        self.highest_seen = None;
        self.gap_started_ns = None;
        self.buffered.clear();
        self.recent.clear();
    }

    pub fn push(
        &mut self,
        raw_sequence: u16,
        arrival_ns: u64,
        fingerprint: u64,
        value: T,
    ) -> Result<ReorderOutput<T>, ReorderError> {
        if u64::from(raw_sequence) >= self.modulus {
            return Err(ReorderError::RawOutOfRange {
                raw: raw_sequence,
                modulus: self.modulus,
            });
        }
        let reference = self
            .highest_seen
            .or(self.expected.map(|value| value.saturating_sub(1)))
            .unwrap_or(u64::from(raw_sequence));
        let sequence = unwrap_near(u64::from(raw_sequence), reference, self.modulus);
        self.highest_seen = Some(self.highest_seen.map_or(sequence, |old| old.max(sequence)));

        if self.expected.is_none() {
            self.expected = Some(sequence);
        }
        let expected = self.expected.unwrap();
        if sequence < expected {
            let mut output = ReorderOutput::default();
            if let Some((_, previous)) = self.recent.iter().find(|(old, _)| *old == sequence) {
                if *previous != fingerprint {
                    return Err(ReorderError::ConflictingDuplicate { sequence });
                }
                output.duplicate = true;
            } else {
                output.stale = true;
            }
            return Ok(output);
        }
        if let Some(previous) = self.buffered.get(&sequence) {
            if previous.fingerprint != fingerprint {
                return Err(ReorderError::ConflictingDuplicate { sequence });
            }
            return Ok(ReorderOutput {
                duplicate: true,
                ..ReorderOutput::default()
            });
        }
        self.buffered.insert(
            sequence,
            Buffered {
                raw: raw_sequence,
                arrival_ns,
                fingerprint,
                value,
            },
        );
        if sequence > expected && self.gap_started_ns.is_none() {
            self.gap_started_ns = Some(arrival_ns);
        }
        let forced = self.buffered.len() >= self.packet_limit
            || self
                .gap_started_ns
                .is_some_and(|start| arrival_ns.saturating_sub(start) >= self.timeout_ns);
        Ok(self.release_ready(forced))
    }

    pub fn poll_timeout(&mut self, now_ns: u64) -> ReorderOutput<T> {
        let forced = self
            .gap_started_ns
            .is_some_and(|start| now_ns.saturating_sub(start) >= self.timeout_ns);
        self.release_ready(forced)
    }

    /// 返回"下一次必须调用 [`SequenceReorderBuffer::poll_timeout`] 的时刻"。
    ///
    /// 只有缓冲区正在等一个缺失序号（gap）时才有期限：`gap_started_ns + timeout_ns`。
    /// 没有 gap 时返回 `None`，执行器可以进入低频空闲等待，而不是 100Hz 空轮询。
    ///
    /// 返回的时刻可能已经过期（`<= now`），调用方应立即 poll 一次。
    pub fn next_deadline_ns(&self) -> Option<u64> {
        self.gap_started_ns
            .map(|start| start.saturating_add(self.timeout_ns))
    }

    fn release_ready(&mut self, force_gap: bool) -> ReorderOutput<T> {
        let mut output = ReorderOutput::default();
        let Some(mut expected) = self.expected else {
            return output;
        };
        if force_gap
            && !self.buffered.contains_key(&expected)
            && let Some((&first, _)) = self.buffered.first_key_value()
            && first > expected
        {
            output.gap = Some(SequenceGap {
                first_missing: expected,
                last_missing: first - 1,
                resumed_at: first,
            });
            expected = first;
            self.expected = Some(first);
        }
        while let Some(item) = self.buffered.remove(&expected) {
            let released = Sequenced {
                raw_sequence: item.raw,
                unwrapped_sequence: expected,
                arrival_ns: item.arrival_ns,
                fingerprint: item.fingerprint,
                value: item.value,
            };
            self.remember(expected, released.fingerprint);
            output.released.push(released);
            expected += 1;
            self.expected = Some(expected);
        }
        if self.buffered.is_empty() || self.buffered.contains_key(&expected) {
            self.gap_started_ns = None;
        } else if self.gap_started_ns.is_none() {
            self.gap_started_ns = self.buffered.values().map(|item| item.arrival_ns).min();
        }
        output
    }

    fn remember(&mut self, sequence: u64, fingerprint: u64) {
        let limit = self.packet_limit.max(64);
        self.recent.push_back((sequence, fingerprint));
        while self.recent.len() > limit {
            self.recent.pop_front();
        }
    }
}

fn unwrap_near(raw: u64, reference: u64, modulus: u64) -> u64 {
    let base = (reference / modulus) * modulus;
    let mut candidate = base + raw;
    let half = modulus / 2;
    if candidate.saturating_add(half) < reference {
        candidate = candidate.saturating_add(modulus);
    } else if candidate > reference.saturating_add(half) && candidate >= modulus {
        candidate -= modulus;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordered_packets_never_wait_for_timeout() {
        let mut reorder = SequenceReorderBuffer::default();
        for sequence in 10..13 {
            let output = reorder
                .push(sequence, 1, sequence.into(), sequence)
                .unwrap();
            assert_eq!(output.released.len(), 1);
            assert!(output.gap.is_none());
        }
    }

    /// 空闲时不该有期限：执行器据此低频等待，而不是 100Hz 空轮询。
    #[test]
    fn next_deadline_is_absent_until_a_gap_is_buffered() {
        let mut reorder = SequenceReorderBuffer::default();
        assert_eq!(reorder.next_deadline_ns(), None);
        reorder.push(10, 0, 10, "a").unwrap();
        assert_eq!(reorder.next_deadline_ns(), None);

        // 缺 11，12 先到 → 记下缺口起点，期限就是释放窗口的尽头。
        assert!(
            reorder
                .push(12, 1_000, 12, "c")
                .unwrap()
                .released
                .is_empty()
        );
        assert_eq!(
            reorder.next_deadline_ns(),
            Some(1_000 + DEFAULT_REORDER_TIMEOUT_NS)
        );

        // 缺口补齐 → 期限立刻撤销。
        assert_eq!(reorder.push(11, 2_000, 11, "b").unwrap().released.len(), 2);
        assert_eq!(reorder.next_deadline_ns(), None);
    }

    /// 死线到点时调用方 poll 一次就能释放，且释放后期限清空（不会反复醒）。
    #[test]
    fn expired_deadline_releases_the_gap_and_clears_itself() {
        let mut reorder = SequenceReorderBuffer::default();
        reorder.push(1, 0, 1, ()).unwrap();
        assert!(reorder.push(3, 0, 3, ()).unwrap().released.is_empty());

        let deadline = reorder.next_deadline_ns().expect("gap 必须给出死线");
        let output = reorder.poll_timeout(deadline);
        assert_eq!(
            output.gap.as_ref().map(|gap| gap.first_missing),
            Some(2),
            "死线到点必须把缺口标记出来"
        );
        assert_eq!(output.released.len(), 1, "缺口之后的包要一并释放");
        assert_eq!(reorder.next_deadline_ns(), None);
    }

    #[test]
    fn reorders_then_marks_real_gap_after_timeout() {
        let mut reorder = SequenceReorderBuffer::default();
        assert_eq!(reorder.push(10, 0, 10, "a").unwrap().released.len(), 1);
        assert!(reorder.push(12, 1, 12, "c").unwrap().released.is_empty());
        let output = reorder
            .push(13, DEFAULT_REORDER_TIMEOUT_NS + 1, 13, "d")
            .unwrap();
        assert_eq!(
            output.gap,
            Some(SequenceGap {
                first_missing: 11,
                last_missing: 11,
                resumed_at: 12
            })
        );
        assert_eq!(
            output
                .released
                .iter()
                .map(|item| item.value)
                .collect::<Vec<_>>(),
            ["c", "d"]
        );
    }

    #[test]
    fn wrap_and_conflicting_duplicates_are_explicit() {
        let mut reorder = SequenceReorderBuffer::default();
        reorder.push(0x3fff, 0, 7, ()).unwrap();
        let wrapped = reorder.push(0, 1, 8, ()).unwrap();
        assert_eq!(wrapped.released[0].unwrapped_sequence, 0x4000);
        assert!(reorder.push(0, 2, 8, ()).unwrap().duplicate);
        assert_eq!(
            reorder.push(0, 3, 9, ()),
            Err(ReorderError::ConflictingDuplicate { sequence: 0x4000 })
        );
    }
}
