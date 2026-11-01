//! Embeddable surface for the CodeV live proxy engine.
//!
//! The `codev-net` binary (`main.rs`) keeps its own copy of these modules and
//! helpers.  This library re-compiles the same sources so the proxy pipeline
//! (`proxy_runtime::run_proxy`) can be linked *in-process* on platforms that
//! cannot spawn the CLI as a subprocess (notably iOS/iPadOS).  The crate-root
//! items below mirror exactly the small set of symbols that `proxy_runtime`
//! and `proxy_pcap` resolve through `crate::`/`super::`.

use std::time::{SystemTime, UNIX_EPOCH};

use codev_assets::Vec2 as AssetVec2;
use codev_protocol::SlotContinuity;
use codev_stream::{A0Payload, Continuity, IdentityConfidence, PipelineGap};
use codev_web::{GapPayload, MapPoint, PositionView, Vec3 as WebVec3};

pub mod proxy_pcap;
pub mod proxy_runtime;

pub const SUPPORTED_BUILD: &str = "1.24.0.2911";
// Actor batches are sparse deltas rather than a ten-player heartbeat.  Give a
// quiet slot enough time to receive its next update before treating it as a
// despawn.
pub const LIVE_POSITION_STALE_AFTER_NS: u64 = 4_000_000_000;

pub fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn pipeline_gap_payload(gap: &PipelineGap) -> GapPayload {
    let first_missing = gap.first_missing.unwrap_or_default();
    GapPayload {
        first_missing,
        last_missing: gap.last_missing.unwrap_or(first_missing),
        reason: format!(
            "{:?} gap ({:?}); resumed at {:?}",
            gap.reason, gap.direction, gap.resumed_at
        ),
    }
}

pub fn actor_positions(
    actor: &A0Payload,
    calibration: Option<&codev_assets::MapCalibration>,
) -> Vec<PositionView> {
    actor
        .updates
        .iter()
        // A position reconstructed from an invalid baseline is not a stale
        // sample; its numeric value is unknown. Keep the last independently
        // valid point in EventHub and let gap/staleness state degrade that
        // point instead of replacing it with a guessed coordinate.
        .filter(|update| update.position_valid)
        .map(|update| {
            let state = update.state;
            let mut position = PositionView::unresolved(
                update.slot,
                actor.timestamp_ns,
                WebVec3 {
                    x: state.position.x,
                    y: state.position.y,
                    z: state.position.z,
                },
                state.rotation_degrees.z,
            );
            position.pitch = state.rotation_degrees.x;
            position.fresh = update.fresh_movement();
            position.continuity = match update.continuity {
                SlotContinuity::Continuous => Continuity::Proven,
                SlotContinuity::Discontinuous => Continuity::Degraded,
                SlotContinuity::Unknown => Continuity::Resyncing,
            };
            // 阵营优先级：BatchData 的 2 bit state_index（实测本机五人恒为 0，
            // 敌人为 1/2/3；三局真实抓包 100% 吻合，而且第一帧就有）> 出生点几何
            // 判定（RoundCampClassifier，需要开局几个包才 commit）。
            if update.state_index == 0 {
                position.camp_id = Some(codev_stream::LOCAL_CAMP_ID);
                position.identity_confidence = IdentityConfidence::Proven;
            } else if let Some(assignment) = actor
                .camp_assignments
                .iter()
                .find(|assignment| assignment.slot == update.slot)
            {
                position.camp_id = Some(assignment.camp_id);
                position.identity_confidence = IdentityConfidence::Proven;
            }
            apply_map(calibration, &mut position);
            position
        })
        .collect()
}

fn apply_map(calibration: Option<&codev_assets::MapCalibration>, position: &mut PositionView) {
    let Some(calibration) = calibration else {
        return;
    };
    if let Ok(map) =
        calibration.world_to_normalized(AssetVec2::new(position.world.x, position.world.y))
    {
        position.map = Some(MapPoint { u: map.x, v: map.y });
    }
}
