use serde::{Deserialize, Serialize};

pub const MAX_TRACK_SLOTS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Continuity {
    Proven,
    #[default]
    Resyncing,
    Degraded,
    Stale,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityConfidence {
    Proven,
    #[default]
    Unresolved,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotValidity {
    pub continuity: Continuity,
    pub identity: IdentityConfidence,
    pub last_update_ns: Option<u64>,
    pub last_proven_ns: Option<u64>,
    pub gap_epoch: u64,
}

#[derive(Clone, Debug)]
pub struct ContinuityTracker {
    slots: [SlotValidity; MAX_TRACK_SLOTS],
    gap_epoch: u64,
}

impl Default for ContinuityTracker {
    fn default() -> Self {
        Self {
            slots: [SlotValidity::default(); MAX_TRACK_SLOTS],
            gap_epoch: 0,
        }
    }
}

impl ContinuityTracker {
    pub const fn slots(&self) -> &[SlotValidity; MAX_TRACK_SLOTS] {
        &self.slots
    }

    pub fn slot(&self, slot: u8) -> Option<SlotValidity> {
        self.slots.get(usize::from(slot)).copied()
    }

    pub fn reset_channel(&mut self) {
        self.gap_epoch = self.gap_epoch.saturating_add(1);
        for slot in &mut self.slots {
            let identity = slot.identity;
            *slot = SlotValidity {
                identity,
                gap_epoch: self.gap_epoch,
                ..SlotValidity::default()
            };
        }
    }

    pub fn mark_gap(&mut self) {
        self.gap_epoch = self.gap_epoch.saturating_add(1);
        for slot in &mut self.slots {
            slot.continuity = Continuity::Degraded;
            slot.gap_epoch = self.gap_epoch;
        }
    }

    pub fn set_identity(&mut self, slot: u8, confidence: IdentityConfidence) {
        if let Some(state) = self.slots.get_mut(usize::from(slot)) {
            state.identity = confidence;
        }
    }

    /// Update one position validity state.
    ///
    /// `independent_position` is true only when the wire update does not
    /// depend on current/baseline state (for example `use_baseline=false` or
    /// an explicitly absolute vector). Carry-forward records never resync.
    pub fn observe_position(
        &mut self,
        slot: u8,
        timestamp_ns: u64,
        fresh: bool,
        independent_position: bool,
    ) -> Option<SlotValidity> {
        let state = self.slots.get_mut(usize::from(slot))?;
        state.last_update_ns = Some(timestamp_ns);
        if fresh && independent_position {
            state.continuity = Continuity::Proven;
            state.last_proven_ns = Some(timestamp_ns);
        } else if state.continuity != Continuity::Proven {
            state.continuity = Continuity::Resyncing;
        }
        Some(*state)
    }

    pub fn mark_stale(&mut self, now_ns: u64, stale_after_ns: u64) {
        for slot in &mut self.slots {
            if slot.continuity == Continuity::Proven
                && slot
                    .last_update_ns
                    .is_some_and(|last| now_ns.saturating_sub(last) > stale_after_ns)
            {
                slot.continuity = Continuity::Stale;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGeneration {
    pub session_id: String,
    pub channel_generation: u64,
}

impl SessionGeneration {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            channel_generation: 0,
        }
    }

    pub fn reopen_channel(&mut self, continuity: &mut ContinuityTracker) {
        self.channel_generation = self.channel_generation.saturating_add(1);
        continuity.reset_channel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_requires_independent_fresh_position_to_recover() {
        let mut tracker = ContinuityTracker::default();
        tracker.observe_position(5, 1, true, true);
        assert_eq!(tracker.slot(5).unwrap().continuity, Continuity::Proven);
        tracker.mark_gap();
        assert_eq!(tracker.slot(5).unwrap().continuity, Continuity::Degraded);
        tracker.observe_position(5, 2, false, false);
        assert_eq!(tracker.slot(5).unwrap().continuity, Continuity::Resyncing);
        tracker.observe_position(5, 3, true, false);
        assert_eq!(tracker.slot(5).unwrap().continuity, Continuity::Resyncing);
        tracker.observe_position(5, 4, true, true);
        assert_eq!(tracker.slot(5).unwrap().continuity, Continuity::Proven);
    }
}
