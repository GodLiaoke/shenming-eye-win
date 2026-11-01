//! Build fingerprinting, pinned minimap metadata, and coordinate transforms.
//!
//! Both embedded catalogs are deliberately fail-closed. A build requires four
//! exact static-artifact hashes. A map must be explicitly marked either
//! `proven` or `candidate`; candidates are usable for development rendering
//! while retaining their unresolved build-binding and orientation evidence.

mod build_fingerprint;

pub use build_fingerprint::{
    BuildEvidenceKind, BuildFingerprint, BuildFingerprintCatalog, BuildFingerprintError,
    BuildFingerprintHashes, BuildFingerprintManifest, BuildFingerprintPaths,
    EMBEDDED_BUILD_MANIFEST,
};

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const EMBEDDED_MANIFEST: &str = include_str!("../assets/maps/manifest.json");

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Vec2 {
    pub x: f64,
    pub y: f64,
}

impl Vec2 {
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationStatus {
    Proven,
    Candidate,
    Unverified,
}

impl CalibrationStatus {
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Proven | Self::Candidate)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationStatus {
    Verified,
    #[default]
    Unverified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuildBindingEvidence {
    pub exact: bool,
    pub present: bool,
    pub package_id: String,
    pub status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MapCalibration {
    pub build_id: String,
    #[serde(default)]
    pub pak_sha256: String,
    pub map_id: u32,
    #[serde(default)]
    pub name: String,
    pub object_path: String,
    pub level_center: Vec2,
    pub level_size: Vec2,
    pub default_rotation_degrees: f64,
    pub image_rotation_degrees: f64,
    /// Exact bottom-image rotation recovered from the native render path.
    /// It remains `None` until the composition has been proven.
    pub background_rotation_degrees: Option<f64>,
    pub texture_path: String,
    pub texture_width: u32,
    pub texture_height: u32,
    #[serde(default)]
    pub texture_sha256: String,
    #[serde(default)]
    pub source_pak: String,
    #[serde(default)]
    pub source_texture_path: String,
    #[serde(default)]
    pub source_texture_sha256: String,
    #[serde(default)]
    pub build_binding: VerificationStatus,
    #[serde(
        default,
        alias = "source_pak_binding",
        skip_serializing_if = "Option::is_none"
    )]
    pub build_binding_evidence: Option<BuildBindingEvidence>,
    #[serde(default)]
    pub orientation_verified: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blockers: Vec<String>,
    pub status: CalibrationStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MapManifest {
    pub schema_version: u32,
    pub maps: Vec<MapCalibration>,
}

#[derive(Debug, Error, PartialEq)]
pub enum MapError {
    #[error("invalid embedded map manifest: {0}")]
    InvalidManifest(String),
    #[error("unsupported CodeV build {build_id}")]
    UnsupportedBuild { build_id: String },
    #[error("map {map_id} has no usable calibration for build {build_id}")]
    UnsupportedMap { build_id: String, map_id: u32 },
    #[error("map {map_id} has an invalid level size ({x}, {y})")]
    InvalidLevelSize { map_id: u32, x: f64, y: f64 },
    #[error("map {map_id} background rotation is not proven")]
    RotationUnproven { map_id: u32 },
}

#[derive(Clone, Debug)]
pub struct MapCatalog {
    manifest: MapManifest,
}

impl MapCatalog {
    pub fn embedded() -> Result<Self, MapError> {
        Self::from_json(EMBEDDED_MANIFEST)
    }

    pub fn from_json(json: &str) -> Result<Self, MapError> {
        let manifest: MapManifest = serde_json::from_str(json)
            .map_err(|error| MapError::InvalidManifest(error.to_string()))?;
        if manifest.schema_version != 1 {
            return Err(MapError::InvalidManifest(format!(
                "unsupported schema version {}",
                manifest.schema_version
            )));
        }
        let mut identities = HashSet::with_capacity(manifest.maps.len());
        for entry in &manifest.maps {
            if !identities.insert((entry.build_id.as_str(), entry.map_id)) {
                return Err(MapError::InvalidManifest(format!(
                    "duplicate map {} for build {}",
                    entry.map_id, entry.build_id
                )));
            }
            match entry.status {
                CalibrationStatus::Proven => entry.validate_proven_manifest_entry()?,
                CalibrationStatus::Candidate => entry.validate_candidate_manifest_entry()?,
                CalibrationStatus::Unverified => {}
            }
        }
        Ok(Self { manifest })
    }

    pub const fn manifest(&self) -> &MapManifest {
        &self.manifest
    }

    pub fn calibration(&self, build_id: &str, map_id: u32) -> Result<&MapCalibration, MapError> {
        let build_exists = self
            .manifest
            .maps
            .iter()
            .any(|entry| entry.build_id == build_id);
        if !build_exists {
            return Err(MapError::UnsupportedBuild {
                build_id: build_id.to_owned(),
            });
        }
        self.manifest
            .maps
            .iter()
            .find(|entry| {
                entry.build_id == build_id && entry.map_id == map_id && entry.status.is_usable()
            })
            .ok_or_else(|| MapError::UnsupportedMap {
                build_id: build_id.to_owned(),
                map_id,
            })
    }
}

impl MapCalibration {
    fn validate_proven_manifest_entry(&self) -> Result<(), MapError> {
        self.validate_common_manifest_entry()?;
        let background = self.proven_background_rotation()?;
        if !angles_equivalent(background, self.image_rotation_degrees) {
            return Err(MapError::InvalidManifest(format!(
                "map {} background rotation does not match MapImageRotation",
                self.map_id
            )));
        }
        if self.build_binding != VerificationStatus::Verified
            || !self.orientation_verified
            || !self
                .build_binding_evidence
                .as_ref()
                .is_some_and(|binding| binding.exact && binding.present)
        {
            return Err(MapError::InvalidManifest(format!(
                "map {} is proven without verified build and orientation evidence",
                self.map_id
            )));
        }
        Ok(())
    }

    fn validate_candidate_manifest_entry(&self) -> Result<(), MapError> {
        self.validate_transform_manifest_entry()?;
        if (self.build_binding == VerificationStatus::Verified && self.orientation_verified)
            || (self.build_binding == VerificationStatus::Verified
                && !self
                    .build_binding_evidence
                    .as_ref()
                    .is_some_and(|binding| binding.exact))
        {
            return Err(MapError::InvalidManifest(format!(
                "map {} candidate does not retain an unresolved evidence gate",
                self.map_id
            )));
        }
        Ok(())
    }

    fn validate_transform_manifest_entry(&self) -> Result<(), MapError> {
        self.validate_size()?;
        let finite = self.level_center.x.is_finite()
            && self.level_center.y.is_finite()
            && self.default_rotation_degrees.is_finite()
            && self.image_rotation_degrees.is_finite()
            && self.background_rotation_degrees.is_none_or(f64::is_finite);
        if !finite
            || self.build_id.is_empty()
            || !self.object_path.starts_with("/Game/")
            || self.texture_width == 0
            || self.texture_height == 0
            || !is_safe_relative_path(&self.texture_path)
        {
            return Err(MapError::InvalidManifest(format!(
                "map {} has incomplete transform metadata",
                self.map_id
            )));
        }
        Ok(())
    }

    fn validate_common_manifest_entry(&self) -> Result<(), MapError> {
        self.validate_size()?;
        let finite = self.level_center.x.is_finite()
            && self.level_center.y.is_finite()
            && self.default_rotation_degrees.is_finite()
            && self.image_rotation_degrees.is_finite()
            && self.background_rotation_degrees.is_none_or(f64::is_finite);
        let binding_is_complete = self.build_binding_evidence.as_ref().is_some_and(|binding| {
            binding.present && !binding.package_id.is_empty() && !binding.status.is_empty()
        });
        if !finite
            || self.build_id.is_empty()
            || self.name.is_empty()
            || !self.object_path.starts_with("/Game/")
            || self.texture_width == 0
            || self.texture_height == 0
            || !is_sha256(&self.pak_sha256)
            || !is_sha256(&self.texture_sha256)
            || !is_sha256(&self.source_texture_sha256)
            || !is_safe_relative_path(&self.texture_path)
            || !is_safe_relative_path(&self.source_pak)
            || !is_safe_relative_path(&self.source_texture_path)
            || !binding_is_complete
        {
            return Err(MapError::InvalidManifest(format!(
                "map {} has incomplete provenance or texture metadata",
                self.map_id
            )));
        }
        Ok(())
    }

    fn validate_size(&self) -> Result<(), MapError> {
        if !self.level_size.x.is_finite()
            || !self.level_size.y.is_finite()
            || self.level_size.x <= 0.0
            || self.level_size.y <= 0.0
        {
            return Err(MapError::InvalidLevelSize {
                map_id: self.map_id,
                x: self.level_size.x,
                y: self.level_size.y,
            });
        }
        Ok(())
    }

    /// Native `GetMapPosition`, expressed in resolution-independent UV.
    pub fn world_to_normalized(&self, world: Vec2) -> Result<Vec2, MapError> {
        self.validate_size()?;
        Ok(Vec2::new(
            0.5 - (world.x - self.level_center.x) / self.level_size.x,
            0.5 - (world.y - self.level_center.y) / self.level_size.y,
        ))
    }

    /// Native `GetLevelPosition`, inverse of [`Self::world_to_normalized`].
    pub fn normalized_to_world(&self, map: Vec2) -> Result<Vec2, MapError> {
        self.validate_size()?;
        Ok(Vec2::new(
            self.level_center.x + self.level_size.x * (0.5 - map.x),
            self.level_center.y + self.level_size.y * (0.5 - map.y),
        ))
    }

    pub fn proven_background_rotation(&self) -> Result<f64, MapError> {
        self.background_rotation_degrees
            .ok_or(MapError::RotationUnproven {
                map_id: self.map_id,
            })
    }

    /// Rotation used for a browser preview. Candidates deliberately fall back
    /// to `MapImageRotation`; callers must keep their unverified badge visible.
    pub fn display_background_rotation(&self) -> f64 {
        self.background_rotation_degrees
            .unwrap_or(self.image_rotation_degrees)
    }

    /// Native map-widget heading. `DefaultRotation` changes marker heading,
    /// but it does not rotate the world/UV position transform.
    pub fn world_yaw_to_map_heading(&self, world_yaw_degrees: f64) -> f64 {
        self.default_rotation_degrees - world_yaw_degrees
    }
}

fn angles_equivalent(left: f64, right: f64) -> bool {
    let delta = (left - right).rem_euclid(360.0);
    delta <= 1e-9 || (360.0 - delta) <= 1e-9
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|component| !component.is_empty() && component != "." && component != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    fn research_fixture(relative: &str) -> Option<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(relative);
        fs::read_to_string(path).ok()
    }

    fn calibration() -> MapCalibration {
        MapCalibration {
            build_id: "test".into(),
            pak_sha256: "00".repeat(32),
            map_id: 1003,
            name: "Test".into(),
            object_path: "/Game/Test".into(),
            level_center: Vec2::new(100.0, -200.0),
            level_size: Vec2::new(2_000.0, 4_000.0),
            default_rotation_degrees: 0.0,
            image_rotation_degrees: 90.0,
            background_rotation_degrees: Some(90.0),
            texture_path: "test.webp".into(),
            texture_width: 1024,
            texture_height: 1024,
            texture_sha256: "11".repeat(32),
            source_pak: "test.pak".into(),
            source_texture_path: "source/test.uasset".into(),
            source_texture_sha256: "22".repeat(32),
            build_binding: VerificationStatus::Verified,
            build_binding_evidence: Some(BuildBindingEvidence {
                exact: true,
                present: true,
                package_id: "test".into(),
                status: "exact".into(),
            }),
            orientation_verified: true,
            blockers: Vec::new(),
            status: CalibrationStatus::Proven,
        }
    }

    #[test]
    fn corrected_ascent_haven_bitmaps_remain_candidate_evidence() {
        let Some(canonical_evidence) =
            research_fixture("analysis/v2/map-manifest-1.24.0.2911.json")
        else {
            eprintln!("research fixture unavailable; skipping map evidence cross-check");
            return;
        };
        let canonical: serde_json::Value = serde_json::from_str(&canonical_evidence).unwrap();
        assert_eq!(canonical["publishable_maps"], serde_json::json!([]));

        let expected = [
            (
                1,
                "e85a2147871e633a2ffdb62b0a07fd3e953f65afa7d8b515fe1e77c2815185d4",
            ),
            (
                1004,
                "848703d601a529dbb9cfeb1c8d184bcd2be90a7357ed3e46570b985407c87740",
            ),
        ];
        let maps = canonical["maps"].as_array().unwrap();
        for (map_id, mip_sha256) in expected {
            let map = maps.iter().find(|entry| entry["map_id"] == map_id).unwrap();
            let texture = &map["runtime_texture"];
            assert_eq!(texture["present"], true);
            assert_eq!(texture["pixel_format"], "PF_ASTC_4x4");
            assert_eq!(texture["mip_count"], 11);
            assert_eq!(texture["inline_mip_offset"], 367);
            assert_eq!(texture["texture_sha256"], mip_sha256);
            assert_eq!(
                map["blockers"],
                serde_json::json!(["authorized_pcap_landmark_orientation_validation_missing"])
            );
        }

        let Some(derivative_evidence) =
            research_fixture("analysis/v2/runtime-minimap-audit-v2/manifest.json")
        else {
            eprintln!("research derivative unavailable; skipping map evidence cross-check");
            return;
        };
        let derivative: serde_json::Value = serde_json::from_str(&derivative_evidence).unwrap();
        assert_eq!(derivative["map_publication_gate"], "blocked");
        assert_eq!(derivative["publishable_maps"], serde_json::json!([]));
        for item in derivative["derivatives"].as_array().unwrap() {
            let gate = &item["browser_derivative_gate"];
            assert_eq!(gate["browser_ready"], true);
            assert_eq!(gate["opaque_magenta_pixel_count"], 0);
            assert_eq!(gate["alpha_mode"], "preserve_source_alpha");
            assert_eq!(gate["chroma_key"], "none");
            assert_eq!(
                gate["source_uv_rect"],
                serde_json::json!([0.0, 0.0, 1.0, 1.0])
            );
            assert_eq!(gate["uv_scale"], serde_json::json!([1.0, 1.0]));
            assert_eq!(gate["uv_offset"], serde_json::json!([0.0, 0.0]));
        }

        let embedded = MapCatalog::embedded().unwrap();
        assert_eq!(embedded.manifest().maps.len(), 9);
        let ascent = embedded.calibration("1.24.0.2911", 1).unwrap();
        assert_eq!(ascent.status, CalibrationStatus::Candidate);
        assert_eq!(ascent.build_binding, VerificationStatus::Unverified);
        assert!(!ascent.orientation_verified);
        assert_eq!(ascent.display_background_rotation(), 180.0);
    }

    #[test]
    fn legacy_unverified_manifest_is_parseable_but_not_usable() {
        let Some(candidate_evidence) =
            research_fixture("analysis/v2/map-candidate-manifest-20260815.json")
        else {
            eprintln!("research candidate unavailable; skipping legacy-manifest cross-check");
            return;
        };
        let candidate = MapCatalog::from_json(&candidate_evidence).unwrap();
        let embedded = MapCatalog::embedded().unwrap();
        assert_eq!(candidate.manifest().maps.len(), 9);
        for map in &candidate.manifest().maps {
            assert_eq!(
                map.world_to_normalized(map.level_center).unwrap(),
                Vec2::new(0.5, 0.5)
            );
            assert_eq!(
                map.normalized_to_world(Vec2::new(0.5, 0.5)).unwrap(),
                map.level_center
            );
            let imported = embedded
                .manifest()
                .maps
                .iter()
                .find(|entry| entry.map_id == map.map_id)
                .unwrap();
            assert_eq!(imported.build_id, map.build_id);
            assert_eq!(imported.name, map.name);
            assert_eq!(imported.pak_sha256, map.pak_sha256);
            assert_eq!(imported.object_path, map.object_path);
            assert_eq!(imported.level_center, map.level_center);
            assert_eq!(imported.level_size, map.level_size);
            assert_eq!(
                imported.default_rotation_degrees,
                map.default_rotation_degrees
            );
            assert_eq!(imported.image_rotation_degrees, map.image_rotation_degrees);
            assert_eq!(imported.source_pak, map.source_pak);
            assert_eq!(imported.source_texture_path, map.texture_path);
            assert_eq!(imported.source_texture_sha256, map.texture_sha256);
            assert_eq!(imported.build_binding_evidence, map.build_binding_evidence);
        }
        for map_id in [1, 2, 1003, 1004, 1009, 1010, 1011, 1012] {
            assert!(matches!(
                candidate.calibration("1.24.0.2911", map_id),
                Err(MapError::UnsupportedMap { .. })
            ));
        }
    }

    #[test]
    fn native_transform_flips_both_axes_and_round_trips() {
        let map = calibration();
        assert_eq!(
            map.world_to_normalized(Vec2::new(100.0, -200.0)).unwrap(),
            Vec2::new(0.5, 0.5)
        );
        assert_eq!(
            map.world_to_normalized(Vec2::new(1_100.0, 1_800.0))
                .unwrap(),
            Vec2::new(0.0, 0.0)
        );
        for world in [
            Vec2::new(-900.0, -2_200.0),
            Vec2::new(100.0, -200.0),
            Vec2::new(1_100.0, 1_800.0),
        ] {
            let normalized = map.world_to_normalized(world).unwrap();
            let recovered = map.normalized_to_world(normalized).unwrap();
            assert!((recovered.x - world.x).abs() < 1e-9);
            assert!((recovered.y - world.y).abs() < 1e-9);
        }
    }

    #[test]
    fn native_heading_uses_default_rotation_without_changing_uv() {
        let mut map = calibration();
        map.default_rotation_degrees = 90.0;
        let world = Vec2::new(350.0, 600.0);
        let before = map.world_to_normalized(world).unwrap();
        assert_eq!(map.world_yaw_to_map_heading(30.0), 60.0);
        map.default_rotation_degrees = -90.0;
        assert_eq!(map.world_yaw_to_map_heading(30.0), -120.0);
        assert_eq!(map.world_to_normalized(world).unwrap(), before);
    }

    #[test]
    fn catalog_rejects_unverified_or_unknown_maps() {
        let json = serde_json::json!({
            "schema_version": 1,
            "maps": [{
                "build_id": "1.24.0.2911",
                "pak_sha256": "00",
                "map_id": 1003,
                "object_path": "/Game/Test",
                "level_center": {"x": 0.0, "y": 0.0},
                "level_size": {"x": 1.0, "y": 1.0},
                "default_rotation_degrees": 0.0,
                "image_rotation_degrees": 0.0,
                "background_rotation_degrees": null,
                "texture_path": "",
                "texture_width": 0,
                "texture_height": 0,
                "texture_sha256": "",
                "status": "unverified"
            }]
        });
        let catalog = MapCatalog::from_json(&json.to_string()).unwrap();
        assert!(matches!(
            catalog.calibration("1.24.0.2911", 1003),
            Err(MapError::UnsupportedMap { .. })
        ));
        assert!(matches!(
            catalog.calibration("other", 1003),
            Err(MapError::UnsupportedBuild { .. })
        ));
    }

    #[test]
    fn explicit_candidate_status_allows_transform_preview_without_provenance_claims() {
        let json = serde_json::json!({
            "schema_version": 1,
            "maps": [{
                "build_id": "1.24.0.2911",
                "map_id": 1003,
                "object_path": "/Game/Maps/Icebox",
                "level_center": {"x": 10.0, "y": 20.0},
                "level_size": {"x": 100.0, "y": 200.0},
                "default_rotation_degrees": 90.0,
                "image_rotation_degrees": 0.0,
                "background_rotation_degrees": null,
                "texture_path": "preview.png",
                "texture_width": 1024,
                "texture_height": 1024,
                "status": "candidate"
            }]
        });
        let catalog = MapCatalog::from_json(&json.to_string()).unwrap();
        let map = catalog.calibration("1.24.0.2911", 1003).unwrap();
        assert_eq!(
            map.world_to_normalized(map.level_center).unwrap(),
            Vec2::new(0.5, 0.5)
        );
        assert_eq!(map.build_binding, VerificationStatus::Unverified);
        assert!(!map.orientation_verified);
    }

    #[test]
    fn proven_catalog_entries_are_strict_and_unique() {
        let entry = serde_json::json!({
            "build_id": "1.24.0.2911",
            "pak_sha256": "00".repeat(32),
            "map_id": 1003,
            "name": "Test",
            "object_path": "/Game/Maps/Test",
            "level_center": {"x": 0.0, "y": 0.0},
            "level_size": {"x": 100.0, "y": 100.0},
            "default_rotation_degrees": 90.0,
            "image_rotation_degrees": -90.0,
            "background_rotation_degrees": 270.0,
            "texture_path": "maps/test.webp",
            "texture_width": 1024,
            "texture_height": 1024,
            "texture_sha256": "11".repeat(32),
            "source_pak": "test.pak",
            "source_texture_path": "source/test.uasset",
            "source_texture_sha256": "22".repeat(32),
            "build_binding": "verified",
            "build_binding_evidence": {
                "exact": true,
                "present": true,
                "package_id": "test",
                "status": "exact"
            },
            "orientation_verified": true,
            "status": "proven"
        });
        let valid = serde_json::json!({"schema_version": 1, "maps": [entry.clone()]});
        assert!(MapCatalog::from_json(&valid.to_string()).is_ok());

        let duplicate =
            serde_json::json!({"schema_version": 1, "maps": [entry.clone(), entry.clone()]});
        assert!(matches!(
            MapCatalog::from_json(&duplicate.to_string()),
            Err(MapError::InvalidManifest(message)) if message.contains("duplicate map")
        ));

        let mut unsafe_path = entry.clone();
        unsafe_path["texture_path"] = serde_json::json!("../secret.webp");
        let unsafe_document = serde_json::json!({"schema_version": 1, "maps": [unsafe_path]});
        assert!(MapCatalog::from_json(&unsafe_document.to_string()).is_err());

        let mut conflicting_rotation = entry;
        conflicting_rotation["background_rotation_degrees"] = serde_json::json!(180.0);
        let conflicting_document =
            serde_json::json!({"schema_version": 1, "maps": [conflicting_rotation]});
        assert!(MapCatalog::from_json(&conflicting_document.to_string()).is_err());
    }

    #[test]
    fn embedded_candidates_are_usable_and_unknown_maps_stay_closed() {
        let catalog = MapCatalog::embedded().unwrap();
        let expected = [1, 2, 1003, 1004, 1009, 1010, 1011, 1012, 1013];
        assert_eq!(catalog.manifest().maps.len(), expected.len());
        for map_id in expected {
            let map = catalog.calibration("1.24.0.2911", map_id).unwrap();
            assert_eq!(map.status, CalibrationStatus::Candidate);
            assert_eq!(map.build_binding, VerificationStatus::Unverified);
            assert!(!map.blockers.is_empty());
            assert_eq!(
                map.world_to_normalized(map.level_center).unwrap(),
                Vec2::new(0.5, 0.5)
            );
            assert_eq!(
                map.normalized_to_world(Vec2::new(0.5, 0.5)).unwrap(),
                map.level_center
            );
        }
        // 1013 的标定来自整局抓包反解（161k 个真实坐标 99.33% 落在可走区），
        // 几何已验证；其余候选底图仍只有截图级别的证据。
        for map_id in [1, 2, 1003, 1004, 1009, 1010, 1011, 1012] {
            let map = catalog.calibration("1.24.0.2911", map_id).unwrap();
            assert!(!map.orientation_verified);
        }
        let tianshu = catalog.calibration("1.24.0.2911", 1013).unwrap();
        assert!(tianshu.orientation_verified);
        assert_eq!(tianshu.image_rotation_degrees, -90.0);
        assert_eq!(tianshu.level_size, Vec2::new(14445.8, 14234.4));
        assert_eq!(
            tianshu.object_path,
            "/Game/Maps/Plummet/levels/MAP_Plummet_Main"
        );
        let sunset = catalog.calibration("1.24.0.2911", 1011).unwrap();
        assert_eq!(sunset.image_rotation_degrees, -90.0);
        assert_eq!(sunset.background_rotation_degrees, None);
        assert_eq!(sunset.display_background_rotation(), -90.0);
        assert!(matches!(
            catalog.calibration("1.24.0.2911", 9999),
            Err(MapError::UnsupportedMap { .. })
        ));
        assert!(matches!(
            catalog.calibration("1.24.0.9999", 1),
            Err(MapError::UnsupportedBuild { .. })
        ));
    }

    #[test]
    fn embedded_browser_bitmaps_match_manifest_hashes_and_dimensions() {
        use sha2::{Digest, Sha256};

        let files: [(u32, &[u8]); 9] = [
            (1, include_bytes!("../assets/maps/map-1-ascent.png")),
            (2, include_bytes!("../assets/maps/map-2-bind.png")),
            (1003, include_bytes!("../assets/maps/map-1003-icebox.png")),
            (1004, include_bytes!("../assets/maps/map-1004-haven.png")),
            (1009, include_bytes!("../assets/maps/map-1009-pearl.png")),
            (1010, include_bytes!("../assets/maps/map-1010-lotus.png")),
            (1011, include_bytes!("../assets/maps/map-1011-sunset.png")),
            (1012, include_bytes!("../assets/maps/map-1012-abyss.png")),
            (
                1013,
                include_bytes!("../assets/maps/map-1013-tianshu-yunque.png"),
            ),
        ];
        let catalog = MapCatalog::embedded().unwrap();
        for (map_id, bytes) in files {
            let map = catalog.calibration("1.24.0.2911", map_id).unwrap();
            assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
            assert_eq!(u32::from_be_bytes(bytes[16..20].try_into().unwrap()), 1024);
            assert_eq!(u32::from_be_bytes(bytes[20..24].try_into().unwrap()), 1024);
            assert_eq!(format!("{:x}", Sha256::digest(bytes)), map.texture_sha256);
        }
    }
}
