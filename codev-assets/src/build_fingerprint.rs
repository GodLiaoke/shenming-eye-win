//! Fail-closed identification of protocol builds from static-file evidence.
//!
//! A build is identified only when the CodeV executable, base PAK, authorized
//! protocol fixture, and field schema all match one embedded fingerprint. This
//! module never inspects or attaches to a running game process.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const EMBEDDED_BUILD_MANIFEST: &str = include_str!("../assets/builds/manifest.json");

const EVIDENCE_KINDS: [BuildEvidenceKind; 4] = [
    BuildEvidenceKind::CodevBinary,
    BuildEvidenceKind::BasePak,
    BuildEvidenceKind::ProtocolFixturePcap,
    BuildEvidenceKind::FieldSchema,
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildFingerprintManifest {
    pub schema_version: u32,
    pub builds: Vec<BuildFingerprint>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildFingerprint {
    pub build_id: String,
    pub codev_binary_sha256: String,
    pub base_pak_sha256: String,
    pub protocol_fixture_pcap_sha256: String,
    pub field_schema_sha256: String,
}

impl BuildFingerprint {
    fn hash_for(&self, kind: BuildEvidenceKind) -> &str {
        match kind {
            BuildEvidenceKind::CodevBinary => &self.codev_binary_sha256,
            BuildEvidenceKind::BasePak => &self.base_pak_sha256,
            BuildEvidenceKind::ProtocolFixturePcap => &self.protocol_fixture_pcap_sha256,
            BuildEvidenceKind::FieldSchema => &self.field_schema_sha256,
        }
    }

    fn hash_tuple(&self) -> [&str; 4] {
        [
            &self.codev_binary_sha256,
            &self.base_pak_sha256,
            &self.protocol_fixture_pcap_sha256,
            &self.field_schema_sha256,
        ]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BuildEvidenceKind {
    CodevBinary,
    BasePak,
    ProtocolFixturePcap,
    FieldSchema,
}

impl BuildEvidenceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodevBinary => "codev_binary",
            Self::BasePak => "base_pak",
            Self::ProtocolFixturePcap => "protocol_fixture_pcap",
            Self::FieldSchema => "field_schema",
        }
    }
}

impl fmt::Display for BuildEvidenceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Runtime-provided SHA-256 evidence.
///
/// `Option` is intentional: absence is represented explicitly and rejected
/// before matching. Use [`Self::complete`] for the normal all-four path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildFingerprintHashes {
    pub codev_binary_sha256: Option<String>,
    pub base_pak_sha256: Option<String>,
    pub protocol_fixture_pcap_sha256: Option<String>,
    pub field_schema_sha256: Option<String>,
}

impl BuildFingerprintHashes {
    pub fn complete(
        codev_binary_sha256: impl Into<String>,
        base_pak_sha256: impl Into<String>,
        protocol_fixture_pcap_sha256: impl Into<String>,
        field_schema_sha256: impl Into<String>,
    ) -> Self {
        Self {
            codev_binary_sha256: Some(codev_binary_sha256.into()),
            base_pak_sha256: Some(base_pak_sha256.into()),
            protocol_fixture_pcap_sha256: Some(protocol_fixture_pcap_sha256.into()),
            field_schema_sha256: Some(field_schema_sha256.into()),
        }
    }

    fn hash_for(&self, kind: BuildEvidenceKind) -> Option<&str> {
        match kind {
            BuildEvidenceKind::CodevBinary => self.codev_binary_sha256.as_deref(),
            BuildEvidenceKind::BasePak => self.base_pak_sha256.as_deref(),
            BuildEvidenceKind::ProtocolFixturePcap => self.protocol_fixture_pcap_sha256.as_deref(),
            BuildEvidenceKind::FieldSchema => self.field_schema_sha256.as_deref(),
        }
    }
}

/// Static artifact paths whose contents will be hashed with SHA-256.
///
/// The artifacts are streamed from disk; no process memory is read. Use
/// [`Self::complete`] for the normal all-four path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BuildFingerprintPaths {
    pub codev_binary: Option<PathBuf>,
    pub base_pak: Option<PathBuf>,
    pub protocol_fixture_pcap: Option<PathBuf>,
    pub field_schema: Option<PathBuf>,
}

impl BuildFingerprintPaths {
    pub fn complete(
        codev_binary: impl Into<PathBuf>,
        base_pak: impl Into<PathBuf>,
        protocol_fixture_pcap: impl Into<PathBuf>,
        field_schema: impl Into<PathBuf>,
    ) -> Self {
        Self {
            codev_binary: Some(codev_binary.into()),
            base_pak: Some(base_pak.into()),
            protocol_fixture_pcap: Some(protocol_fixture_pcap.into()),
            field_schema: Some(field_schema.into()),
        }
    }

    fn path_for(&self, kind: BuildEvidenceKind) -> Option<&Path> {
        match kind {
            BuildEvidenceKind::CodevBinary => self.codev_binary.as_deref(),
            BuildEvidenceKind::BasePak => self.base_pak.as_deref(),
            BuildEvidenceKind::ProtocolFixturePcap => self.protocol_fixture_pcap.as_deref(),
            BuildEvidenceKind::FieldSchema => self.field_schema.as_deref(),
        }
    }
}

#[derive(Debug, Error)]
pub enum BuildFingerprintError {
    #[error("invalid embedded build manifest: {0}")]
    InvalidManifest(String),
    #[error("missing required build evidence: {kind}")]
    MissingEvidence { kind: BuildEvidenceKind },
    #[error("invalid SHA-256 for build evidence {kind}")]
    InvalidEvidenceHash { kind: BuildEvidenceKind },
    #[error("build evidence {kind} is not a regular file: {path}")]
    EvidenceNotRegularFile {
        kind: BuildEvidenceKind,
        path: PathBuf,
    },
    #[error("failed to read build evidence {kind} from {path}: {source}")]
    ReadEvidence {
        kind: BuildEvidenceKind,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsupported CodeV build fingerprint")]
    UnsupportedFingerprint,
}

#[derive(Clone, Debug)]
pub struct BuildFingerprintCatalog {
    manifest: BuildFingerprintManifest,
}

impl BuildFingerprintCatalog {
    pub fn embedded() -> Result<Self, BuildFingerprintError> {
        Self::from_json(EMBEDDED_BUILD_MANIFEST)
    }

    pub fn from_json(json: &str) -> Result<Self, BuildFingerprintError> {
        let manifest: BuildFingerprintManifest = serde_json::from_str(json)
            .map_err(|error| BuildFingerprintError::InvalidManifest(error.to_string()))?;
        validate_manifest(&manifest)?;
        Ok(Self { manifest })
    }

    pub const fn manifest(&self) -> &BuildFingerprintManifest {
        &self.manifest
    }

    /// Identify a supported build from four caller-computed SHA-256 values.
    ///
    /// Missing or non-canonical hashes fail before matching. A near match never
    /// returns a build: all four values must match the same embedded entry.
    pub fn identify_hashes(
        &self,
        hashes: &BuildFingerprintHashes,
    ) -> Result<&BuildFingerprint, BuildFingerprintError> {
        for kind in EVIDENCE_KINDS {
            let hash = hashes
                .hash_for(kind)
                .ok_or(BuildFingerprintError::MissingEvidence { kind })?;
            if !is_canonical_sha256(hash) {
                return Err(BuildFingerprintError::InvalidEvidenceHash { kind });
            }
        }

        self.manifest
            .builds
            .iter()
            .find(|build| {
                EVIDENCE_KINDS
                    .into_iter()
                    .all(|kind| hashes.hash_for(kind) == Some(build.hash_for(kind)))
            })
            .ok_or(BuildFingerprintError::UnsupportedFingerprint)
    }

    /// Hash four static files and identify the one exactly matching build.
    ///
    /// The presence of all paths is validated before any file is opened. Files
    /// are read through a bounded buffer so large PAKs are not loaded in memory.
    pub fn identify_files(
        &self,
        paths: &BuildFingerprintPaths,
    ) -> Result<&BuildFingerprint, BuildFingerprintError> {
        for kind in EVIDENCE_KINDS {
            paths
                .path_for(kind)
                .ok_or(BuildFingerprintError::MissingEvidence { kind })?;
        }

        let mut calculated = Vec::with_capacity(EVIDENCE_KINDS.len());
        for kind in EVIDENCE_KINDS {
            let path = paths
                .path_for(kind)
                .expect("all evidence paths were validated above");
            calculated.push(hash_regular_file(kind, path)?);
        }
        let hashes = BuildFingerprintHashes::complete(
            calculated[0].clone(),
            calculated[1].clone(),
            calculated[2].clone(),
            calculated[3].clone(),
        );
        self.identify_hashes(&hashes)
    }
}

fn validate_manifest(manifest: &BuildFingerprintManifest) -> Result<(), BuildFingerprintError> {
    if manifest.schema_version != 1 {
        return Err(BuildFingerprintError::InvalidManifest(format!(
            "unsupported schema version {}",
            manifest.schema_version
        )));
    }
    if manifest.builds.is_empty() {
        return Err(BuildFingerprintError::InvalidManifest(
            "manifest contains no supported builds".to_owned(),
        ));
    }

    let mut build_ids = HashSet::with_capacity(manifest.builds.len());
    let mut fingerprints = HashSet::with_capacity(manifest.builds.len());
    for build in &manifest.builds {
        if !is_canonical_build_id(&build.build_id) {
            return Err(BuildFingerprintError::InvalidManifest(format!(
                "invalid build id {:?}",
                build.build_id
            )));
        }
        if !build_ids.insert(build.build_id.as_str()) {
            return Err(BuildFingerprintError::InvalidManifest(format!(
                "duplicate build id {}",
                build.build_id
            )));
        }
        for kind in EVIDENCE_KINDS {
            if !is_canonical_sha256(build.hash_for(kind)) {
                return Err(BuildFingerprintError::InvalidManifest(format!(
                    "build {} has invalid {kind} SHA-256",
                    build.build_id
                )));
            }
        }
        if !fingerprints.insert(build.hash_tuple()) {
            return Err(BuildFingerprintError::InvalidManifest(format!(
                "duplicate four-factor fingerprint for build {}",
                build.build_id
            )));
        }
    }
    Ok(())
}

fn hash_regular_file(
    kind: BuildEvidenceKind,
    path: &Path,
) -> Result<String, BuildFingerprintError> {
    let file = File::open(path).map_err(|source| BuildFingerprintError::ReadEvidence {
        kind,
        path: path.to_owned(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| BuildFingerprintError::ReadEvidence {
            kind,
            path: path.to_owned(),
            source,
        })?;
    if !metadata.is_file() {
        return Err(BuildFingerprintError::EvidenceNotRegularFile {
            kind,
            path: path.to_owned(),
        });
    }

    let mut reader = BufReader::with_capacity(1024 * 1024, file);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read =
            reader
                .read(&mut buffer)
                .map_err(|source| BuildFingerprintError::ReadEvidence {
                    kind,
                    path: path.to_owned(),
                    source,
                })?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn is_canonical_build_id(value: &str) -> bool {
    let segments = value.split('.').collect::<Vec<_>>();
    segments.len() == 4
        && segments
            .iter()
            .all(|segment| !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit()))
}

fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn research_fixture(relative: &str) -> Option<String> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .join(relative);
        fs::read_to_string(path).ok()
    }

    fn exact_hashes() -> BuildFingerprintHashes {
        BuildFingerprintHashes::complete(
            "f23d77908127e627bc4c55cca39208ab6899f86ff1a7beea3bc2e0f797c03357",
            "7e1c74124a0ebf1e2ac696eb7c9287787ac0311a5660a22cd2f3c095c2ab55db",
            "82c779ed1212d600794683226c15c7d7751fc06a1632163be7566adbbc49e2e7",
            "217018bf7a167ab7d65ca9c019c088ae3783521071fc5196e20683997ed91a32",
        )
    }

    fn replace_hash(
        hashes: &mut BuildFingerprintHashes,
        kind: BuildEvidenceKind,
        value: Option<String>,
    ) {
        match kind {
            BuildEvidenceKind::CodevBinary => hashes.codev_binary_sha256 = value,
            BuildEvidenceKind::BasePak => hashes.base_pak_sha256 = value,
            BuildEvidenceKind::ProtocolFixturePcap => {
                hashes.protocol_fixture_pcap_sha256 = value;
            }
            BuildEvidenceKind::FieldSchema => hashes.field_schema_sha256 = value,
        }
    }

    #[test]
    fn exact_four_factor_match_identifies_only_the_supported_build() {
        let Some(build_evidence) =
            research_fixture("analysis/v2/build-fingerprint-1.24.0.2911.json")
        else {
            eprintln!("research fixture unavailable; skipping evidence cross-check");
            return;
        };
        let catalog = BuildFingerprintCatalog::embedded().unwrap();
        let build = catalog.identify_hashes(&exact_hashes()).unwrap();
        assert_eq!(build.build_id, "1.24.0.2911");
        assert_eq!(catalog.manifest().builds.len(), 1);

        let evidence: serde_json::Value = serde_json::from_str(&build_evidence).unwrap();
        assert_eq!(evidence["build_id"], build.build_id);
        assert_eq!(
            evidence["evidence"]["codev_binary"]["sha256"],
            build.codev_binary_sha256
        );
        assert_eq!(
            evidence["evidence"]["base_pak"]["sha256"],
            build.base_pak_sha256
        );
        assert_eq!(
            evidence["evidence"]["protocol_fixture_pcap"]["sha256"],
            build.protocol_fixture_pcap_sha256
        );
        assert_eq!(
            evidence["evidence"]["field_schema"]["sha256"],
            build.field_schema_sha256
        );
        assert_eq!(evidence["map_publication_gate"], "blocked");
        let maps = crate::MapCatalog::embedded().unwrap();
        assert_eq!(maps.manifest().maps.len(), 9);
        assert!(maps.manifest().maps.iter().all(|map| {
            map.status == crate::CalibrationStatus::Candidate
                && map.build_binding == crate::VerificationStatus::Unverified
                && !map.orientation_verified
        }));
    }

    #[test]
    fn every_missing_or_malformed_factor_fails_closed() {
        let catalog = BuildFingerprintCatalog::embedded().unwrap();
        for kind in EVIDENCE_KINDS {
            let mut hashes = exact_hashes();
            replace_hash(&mut hashes, kind, None);
            assert!(matches!(
                catalog.identify_hashes(&hashes),
                Err(BuildFingerprintError::MissingEvidence { kind: actual }) if actual == kind
            ));

            for malformed in [
                String::new(),
                "0".repeat(63),
                "g".repeat(64),
                exact_hashes().hash_for(kind).unwrap().to_ascii_uppercase(),
            ] {
                let mut hashes = exact_hashes();
                replace_hash(&mut hashes, kind, Some(malformed));
                assert!(matches!(
                    catalog.identify_hashes(&hashes),
                    Err(BuildFingerprintError::InvalidEvidenceHash { kind: actual })
                        if actual == kind
                ));
            }
        }
    }

    #[test]
    fn changing_any_single_factor_is_unsupported() {
        let catalog = BuildFingerprintCatalog::embedded().unwrap();
        for kind in EVIDENCE_KINDS {
            let mut hashes = exact_hashes();
            replace_hash(&mut hashes, kind, Some("0".repeat(64)));
            assert!(matches!(
                catalog.identify_hashes(&hashes),
                Err(BuildFingerprintError::UnsupportedFingerprint)
            ));
        }
    }

    #[test]
    fn static_files_are_streamed_and_hashed_before_matching() {
        let manifest = serde_json::json!({
            "schema_version": 1,
            "builds": [{
                "build_id": "9.8.7.6",
                "codev_binary_sha256": "9a3a45d01531a20e89ac6ae10b0b0beb0492acd7216a368aa062d1a5fecaf9cd",
                "base_pak_sha256": "43729710aeaf3be1874292ea05bfa12ecc622373ed9fc2cdc08c93119faeca23",
                "protocol_fixture_pcap_sha256": "2ea88c7a30351b12a4dcfc06cdce2af6eab18416176466c2500cb6ef74f745bf",
                "field_schema_sha256": "df0ad6e43880f09c90ebf95f19110178aba6890df0010ebda7485029e2b543b4"
            }]
        });
        let catalog = BuildFingerprintCatalog::from_json(&manifest.to_string()).unwrap();
        let directory = TestDirectory::new();
        let binary = directory.write("CodeV", b"binary");
        let pak = directory.write("base.pak", b"pak");
        let pcap = directory.write("fixture.pcap", b"protocol");
        let schema = directory.write("fields.json", b"schema");
        let paths = BuildFingerprintPaths::complete(&binary, &pak, &pcap, &schema);

        let build = catalog.identify_files(&paths).unwrap();
        assert_eq!(build.build_id, "9.8.7.6");

        fs::write(&schema, b"changed").unwrap();
        assert!(matches!(
            catalog.identify_files(&paths),
            Err(BuildFingerprintError::UnsupportedFingerprint)
        ));
    }

    #[test]
    fn file_identification_rejects_missing_and_non_regular_inputs() {
        let catalog = BuildFingerprintCatalog::embedded().unwrap();
        assert!(matches!(
            catalog.identify_files(&BuildFingerprintPaths::default()),
            Err(BuildFingerprintError::MissingEvidence {
                kind: BuildEvidenceKind::CodevBinary
            })
        ));

        let directory = TestDirectory::new();
        let pak = directory.write("base.pak", b"pak");
        let pcap = directory.write("fixture.pcap", b"protocol");
        let schema = directory.write("fields.json", b"schema");
        let paths = BuildFingerprintPaths::complete(&directory.path, pak, pcap, schema);
        assert!(matches!(
            catalog.identify_files(&paths),
            Err(BuildFingerprintError::EvidenceNotRegularFile {
                kind: BuildEvidenceKind::CodevBinary,
                ..
            })
        ));
    }

    #[test]
    fn malformed_or_ambiguous_manifests_are_rejected() {
        let entry = serde_json::to_value(exact_manifest_entry()).unwrap();

        let empty = serde_json::json!({"schema_version": 1, "builds": []});
        assert!(BuildFingerprintCatalog::from_json(&empty.to_string()).is_err());

        let duplicate_id = serde_json::json!({
            "schema_version": 1,
            "builds": [entry.clone(), entry.clone()]
        });
        assert!(matches!(
            BuildFingerprintCatalog::from_json(&duplicate_id.to_string()),
            Err(BuildFingerprintError::InvalidManifest(message))
                if message.contains("duplicate build id")
        ));

        let mut duplicate_fingerprint = entry.clone();
        duplicate_fingerprint["build_id"] = serde_json::json!("1.24.0.2912");
        let duplicate_fingerprint = serde_json::json!({
            "schema_version": 1,
            "builds": [entry.clone(), duplicate_fingerprint]
        });
        assert!(matches!(
            BuildFingerprintCatalog::from_json(&duplicate_fingerprint.to_string()),
            Err(BuildFingerprintError::InvalidManifest(message))
                if message.contains("duplicate four-factor fingerprint")
        ));

        let mut uppercase = entry;
        uppercase["codev_binary_sha256"] = serde_json::json!(
            exact_hashes()
                .codev_binary_sha256
                .unwrap()
                .to_ascii_uppercase()
        );
        let uppercase = serde_json::json!({"schema_version": 1, "builds": [uppercase]});
        assert!(BuildFingerprintCatalog::from_json(&uppercase.to_string()).is_err());

        let unknown_field = serde_json::json!({
            "schema_version": 1,
            "builds": [exact_manifest_entry()],
            "unexpected": true
        });
        assert!(BuildFingerprintCatalog::from_json(&unknown_field.to_string()).is_err());
    }

    fn exact_manifest_entry() -> BuildFingerprint {
        let hashes = exact_hashes();
        BuildFingerprint {
            build_id: "1.24.0.2911".to_owned(),
            codev_binary_sha256: hashes.codev_binary_sha256.unwrap(),
            base_pak_sha256: hashes.base_pak_sha256.unwrap(),
            protocol_fixture_pcap_sha256: hashes.protocol_fixture_pcap_sha256.unwrap(),
            field_schema_sha256: hashes.field_schema_sha256.unwrap(),
        }
    }

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "codev-assets-build-fingerprint-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.path.join(name);
            fs::write(&path, bytes).unwrap();
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
