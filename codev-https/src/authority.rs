use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::normalize_domain;

const MAX_CA_FILE_BYTES: u64 = 1024 * 1024;
const AUTHORITY_METADATA_FILE: &str = "ca-meta.json";
const AUTHORITY_METADATA_SCHEMA_VERSION: u32 = 1;

/// A public CA artifact that is suitable for serving from the authenticated
/// control panel.  The artifact never contains the CA private key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaArtifactKind {
    Pem,
    Der,
    Mobileconfig,
    Readme,
}

impl CaArtifactKind {
    pub const fn filename(self) -> &'static str {
        match self {
            Self::Pem => "codev-ca.pem",
            Self::Der => "codev-ca.der",
            Self::Mobileconfig => "codev-ca.mobileconfig",
            Self::Readme => "README-iOS.txt",
        }
    }

    pub const fn content_type(self) -> &'static str {
        match self {
            Self::Pem => "application/x-pem-file",
            Self::Der => "application/pkix-cert",
            Self::Mobileconfig => "application/x-apple-aspen-config",
            Self::Readme => "text/plain; charset=utf-8",
        }
    }
}

/// A copy-owned artifact returned by [`MitmAuthority::public_artifact`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaPublicArtifact {
    pub kind: CaArtifactKind,
    pub filename: &'static str,
    pub content_type: &'static str,
    pub bytes: Vec<u8>,
}

impl CaPublicArtifact {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// All public CA artifacts in one allocation-friendly value.  This is useful
/// for API handlers that need to expose several download choices while
/// keeping the authority's private key entirely internal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaPublicArtifacts {
    pub pem: Vec<u8>,
    pub der: Vec<u8>,
    pub mobileconfig: Vec<u8>,
    pub readme: Vec<u8>,
}

impl CaPublicArtifacts {
    pub fn get(&self, kind: CaArtifactKind) -> CaPublicArtifact {
        let bytes = match kind {
            CaArtifactKind::Pem => self.pem.clone(),
            CaArtifactKind::Der => self.der.clone(),
            CaArtifactKind::Mobileconfig => self.mobileconfig.clone(),
            CaArtifactKind::Readme => self.readme.clone(),
        };
        CaPublicArtifact {
            kind,
            filename: kind.filename(),
            content_type: kind.content_type(),
            bytes,
        }
    }
}

/// Public status for the HTTPS inspection CA.  `generated_at_unix` is the
/// UTC Unix timestamp at which this CA was first created (or the certificate
/// file's modification time for authorities created by older releases).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaStatus {
    pub enabled: bool,
    pub fingerprint_sha256: String,
    pub generated_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AuthorityMetadata {
    schema_version: u32,
    generated_at_unix: u64,
}

pub struct MitmAuthority {
    directory: PathBuf,
    certificate_pem: String,
    certificate_der: Vec<u8>,
    private_key_pem: Zeroizing<String>,
    fingerprint_sha256: String,
    generated_at_unix: u64,
}

impl std::fmt::Debug for MitmAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MitmAuthority")
            .field("directory", &self.directory)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .field("generated_at_unix", &self.generated_at_unix)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

pub struct LeafIdentity {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl MitmAuthority {
    pub fn load_or_generate(directory: impl AsRef<Path>) -> Result<Self, AuthorityError> {
        let directory = directory.as_ref();
        create_private_directory(directory)?;
        let certificate_path = directory.join("ca-cert.pem");
        let key_path = directory.join("ca-key.pem");
        let metadata_path = directory.join(AUTHORITY_METADATA_FILE);
        let (certificate_pem, private_key_pem, generated_at_unix) =
            match (certificate_path.try_exists()?, key_path.try_exists()?) {
                (true, true) => {
                    let generated_at_unix =
                        read_generation_metadata(&metadata_path, &certificate_path)?;
                    (
                        read_private_file(&certificate_path)?,
                        Zeroizing::new(read_private_file(&key_path)?),
                        generated_at_unix,
                    )
                }
                (false, false) => {
                    let (certificate, key) = generate_ca()?;
                    let generated_at_unix = epoch_seconds();
                    write_private_file(&certificate_path, certificate.as_bytes())?;
                    write_private_file(&key_path, key.as_bytes())?;
                    let metadata = AuthorityMetadata {
                        schema_version: AUTHORITY_METADATA_SCHEMA_VERSION,
                        generated_at_unix,
                    };
                    let metadata_bytes = serde_json::to_vec(&metadata)?;
                    write_private_file(&metadata_path, &metadata_bytes)?;
                    (certificate, Zeroizing::new(key), generated_at_unix)
                }
                _ => return Err(AuthorityError::IncompleteAuthority),
            };
        let key = KeyPair::from_pem(&private_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&certificate_pem, key)?;
        drop(issuer);
        let certificate_der = pem_to_der(&certificate_pem)?;
        let fingerprint_sha256 = format!("{:x}", Sha256::digest(&certificate_der));
        Ok(Self {
            directory: directory.to_path_buf(),
            certificate_pem,
            certificate_der,
            private_key_pem,
            fingerprint_sha256,
            generated_at_unix,
        })
    }

    pub fn fingerprint_sha256(&self) -> &str {
        &self.fingerprint_sha256
    }

    /// Return the Unix timestamp at which the CA was generated.
    pub const fn generated_at_unix(&self) -> u64 {
        self.generated_at_unix
    }

    /// Alias retained for API callers that use the shorter status terminology.
    pub const fn generated_at(&self) -> u64 {
        self.generated_at_unix
    }

    /// Return a privacy-preserving status snapshot for the control panel.
    pub fn status(&self) -> CaStatus {
        CaStatus {
            enabled: true,
            fingerprint_sha256: self.fingerprint_sha256.clone(),
            generated_at_unix: self.generated_at_unix,
        }
    }

    /// Explicitly named alias for callers that distinguish CA status from
    /// other component status values.
    pub fn ca_status(&self) -> CaStatus {
        self.status()
    }

    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Return the DER-encoded public CA certificate.  The private key is not
    /// represented by this value or by any of the public artifact helpers.
    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    /// Build all download artifacts in memory without touching the private
    /// key files on disk.
    pub fn public_artifacts(&self) -> CaPublicArtifacts {
        CaPublicArtifacts {
            pem: self.certificate_pem.as_bytes().to_vec(),
            der: self.certificate_der.clone(),
            mobileconfig: self.mobileconfig_bytes(),
            readme: self.readme_bytes(),
        }
    }

    /// Return one public download artifact by kind.
    pub fn public_artifact(&self, kind: CaArtifactKind) -> CaPublicArtifact {
        self.public_artifacts().get(kind)
    }

    /// Return the iOS configuration profile containing only the public DER
    /// certificate.
    pub fn mobileconfig(&self) -> Vec<u8> {
        self.mobileconfig_bytes()
    }

    /// Return the iOS installation instructions and public fingerprint.
    pub fn readme(&self) -> Vec<u8> {
        self.readme_bytes()
    }

    pub fn export_public(&self, directory: impl AsRef<Path>) -> Result<(), AuthorityError> {
        let directory = directory.as_ref();
        create_private_directory(directory)?;
        let artifacts = self.public_artifacts();
        write_private_file(
            &directory.join(CaArtifactKind::Pem.filename()),
            &artifacts.pem,
        )?;
        write_private_file(
            &directory.join(CaArtifactKind::Der.filename()),
            &artifacts.der,
        )?;
        write_private_file(
            &directory.join(CaArtifactKind::Mobileconfig.filename()),
            &artifacts.mobileconfig,
        )?;
        write_private_file(
            &directory.join(CaArtifactKind::Readme.filename()),
            &artifacts.readme,
        )?;
        Ok(())
    }

    fn mobileconfig_bytes(&self) -> Vec<u8> {
        let profile_identifier = &self.fingerprint_sha256[..16];
        let profile_uuid = &self.fingerprint_sha256[..12];
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>PayloadCertificateFileName</key><string>codev-ca.der</string>
<key>PayloadContent</key><data>{}</data>
<key>PayloadDescription</key><string>CodeV authorized HTTPS inspection CA</string>
<key>PayloadDisplayName</key><string>CodeV Inspection CA</string>
<key>PayloadIdentifier</key><string>local.codev.ca.{profile_identifier}</string>
<key>PayloadType</key><string>com.apple.security.root</string>
<key>PayloadUUID</key><string>00000000-0000-4000-8000-{profile_uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>CodeV Authorized Inspection</string>
<key>PayloadIdentifier</key><string>local.codev.profile.{profile_identifier}</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>00000000-0000-4000-9000-{profile_uuid}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
"#,
            BASE64.encode(&self.certificate_der)
        )
        .into_bytes()
    }

    fn readme_bytes(&self) -> Vec<u8> {
        format!(
            "CodeV HTTPS inspection CA\n\nSHA-256: {}\nGenerated at (UTC Unix): {}\n\nInstall codev-ca.der on the authorized iOS device, then enable full trust in Settings > General > About > Certificate Trust Settings. Never install this CA on an unrelated device.\n",
            self.fingerprint_sha256, self.generated_at_unix
        )
        .into_bytes()
    }

    pub fn leaf_identity(&self, host: &str) -> Result<LeafIdentity, AuthorityError> {
        let host = normalize_domain(host).map_err(|_| AuthorityError::InvalidHost)?;
        let mut params = CertificateParams::new(vec![host])?;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let leaf_key = KeyPair::generate()?;
        let ca_key = KeyPair::from_pem(&self.private_key_pem)?;
        let issuer = Issuer::from_ca_cert_pem(&self.certificate_pem, ca_key)?;
        let certificate = params.signed_by(&leaf_key, &issuer)?;
        let leaf_der = certificate.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into();
        Ok(LeafIdentity {
            certificate_chain: vec![leaf_der, CertificateDer::from(self.certificate_der.clone())],
            private_key,
        })
    }

    pub fn server_config(&self, host: &str) -> Result<Arc<ServerConfig>, AuthorityError> {
        let leaf = self.leaf_identity(host)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(leaf.certificate_chain, leaf.private_key)
            .map_err(AuthorityError::Rustls)?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(config))
    }
}

fn generate_ca() -> Result<(String, String), AuthorityError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, "CodeV Authorized Inspection CA");
    distinguished_name.push(DnType::OrganizationName, "CodeV Internal Development");
    params.distinguished_name = distinguished_name;
    let certificate = params.self_signed(&key)?;
    Ok((certificate.pem(), key.serialize_pem()))
}

fn pem_to_der(pem: &str) -> Result<Vec<u8>, AuthorityError> {
    let (_, contents) = pem
        .split_once("-----BEGIN CERTIFICATE-----")
        .ok_or(AuthorityError::InvalidCertificate)?;
    let (body, _) = contents
        .split_once("-----END CERTIFICATE-----")
        .ok_or(AuthorityError::InvalidCertificate)?;
    use std::io::BufReader;
    let encoded = format!("-----BEGIN CERTIFICATE-----{body}-----END CERTIFICATE-----");
    let mut reader = BufReader::new(encoded.as_bytes());
    rustls::pki_types::pem::PemObject::from_pem_reader(&mut reader)
        .map(|certificate: CertificateDer<'static>| certificate.as_ref().to_vec())
        .map_err(|_| AuthorityError::InvalidCertificate)
}

fn read_generation_metadata(
    metadata_path: &Path,
    certificate_path: &Path,
) -> Result<u64, AuthorityError> {
    if metadata_path.try_exists()? {
        let value = read_private_file(metadata_path)?;
        let metadata: AuthorityMetadata = serde_json::from_str(&value)?;
        if metadata.schema_version != AUTHORITY_METADATA_SCHEMA_VERSION {
            return Err(AuthorityError::InvalidMetadata(format!(
                "unsupported schema version {}",
                metadata.schema_version
            )));
        }
        return Ok(metadata.generated_at_unix);
    }

    // Authorities created before the metadata sidecar was introduced remain
    // loadable.  Their certificate file's mtime is the closest available
    // creation marker and is exposed with the same public semantics.
    let metadata = certificate_path.symlink_metadata()?;
    if !metadata.is_file() {
        return Err(AuthorityError::InvalidCertificate);
    }
    Ok(metadata
        .modified()?
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs())
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CA directory is a symlink",
        ));
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn read_private_file(path: &Path) -> io::Result<String> {
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CA_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid CA file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "CA file must be 0600",
            ));
        }
    }
    let mut value = String::with_capacity(usize::try_from(metadata.len()).unwrap_or_default());
    File::open(path)?
        .take(MAX_CA_FILE_BYTES + 1)
        .read_to_string(&mut value)?;
    if value.len() as u64 > MAX_CA_FILE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "CA file is too large",
        ));
    }
    Ok(value)
}

#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("CA I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("CA generation error: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("TLS configuration error: {0}")]
    Rustls(rustls::Error),
    #[error("CA directory contains only one of certificate/key")]
    IncompleteAuthority,
    #[error("invalid CA certificate")]
    InvalidCertificate,
    #[error("invalid CA metadata: {0}")]
    InvalidMetadata(String),
    #[error("CA metadata parse error: {0}")]
    Metadata(#[from] serde_json::Error),
    #[error("invalid leaf hostname")]
    InvalidHost,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_persists_and_mints_host_specific_leaves() {
        let directory = tempfile::tempdir().unwrap();
        let authority = MitmAuthority::load_or_generate(directory.path()).unwrap();
        let fingerprint = authority.fingerprint_sha256().to_owned();
        let leaf = authority.leaf_identity("api.example.com").unwrap();
        assert_eq!(leaf.certificate_chain.len(), 2);
        let loaded = MitmAuthority::load_or_generate(directory.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256(), fingerprint);
        assert!(loaded.server_config("api.example.com").is_ok());
        assert!(loaded.server_config("127.0.0.1").is_err());
    }

    #[test]
    fn public_export_never_contains_the_private_key() {
        let directory = tempfile::tempdir().unwrap();
        let export = tempfile::tempdir().unwrap();
        let authority = MitmAuthority::load_or_generate(directory.path()).unwrap();
        authority.export_public(export.path()).unwrap();
        let certificate = fs::read_to_string(export.path().join("codev-ca.pem")).unwrap();
        assert!(certificate.contains("BEGIN CERTIFICATE"));
        for kind in [
            CaArtifactKind::Pem,
            CaArtifactKind::Der,
            CaArtifactKind::Mobileconfig,
            CaArtifactKind::Readme,
        ] {
            let bytes = fs::read(export.path().join(kind.filename())).unwrap();
            assert!(
                !bytes
                    .windows(b"PRIVATE KEY".len())
                    .any(|window| window == b"PRIVATE KEY")
            );
        }
        assert!(!export.path().join("ca-key.pem").exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(export.path()).unwrap().permissions().mode() & 0o777,
                0o700
            );
            for kind in [
                CaArtifactKind::Pem,
                CaArtifactKind::Der,
                CaArtifactKind::Mobileconfig,
                CaArtifactKind::Readme,
            ] {
                assert_eq!(
                    fs::metadata(export.path().join(kind.filename()))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o777,
                    0o600
                );
            }
        }
    }

    #[test]
    fn public_artifacts_and_status_are_stable_across_reload() {
        let directory = tempfile::tempdir().unwrap();
        let authority = MitmAuthority::load_or_generate(directory.path()).unwrap();
        let artifacts = authority.public_artifacts();
        assert_eq!(artifacts.pem, authority.certificate_pem().as_bytes());
        assert_eq!(artifacts.der, authority.certificate_der());
        assert!(
            artifacts
                .mobileconfig
                .windows(b"PayloadContent".len())
                .any(|window| window == b"PayloadContent")
        );
        assert!(
            artifacts
                .readme
                .windows(authority.fingerprint_sha256().len())
                .any(|window| window == authority.fingerprint_sha256().as_bytes())
        );
        for bytes in [
            &artifacts.pem,
            &artifacts.der,
            &artifacts.mobileconfig,
            &artifacts.readme,
        ] {
            assert!(
                !bytes
                    .windows(b"PRIVATE KEY".len())
                    .any(|window| window == b"PRIVATE KEY")
            );
        }

        let status = authority.status();
        assert!(status.enabled);
        assert_eq!(status.fingerprint_sha256, authority.fingerprint_sha256());
        assert_eq!(status.generated_at_unix, authority.generated_at_unix());
        assert!(status.generated_at_unix > 0);
        let loaded = MitmAuthority::load_or_generate(directory.path()).unwrap();
        assert_eq!(loaded.status(), status);

        let pem = authority.public_artifact(CaArtifactKind::Pem);
        assert_eq!(pem.filename, "codev-ca.pem");
        assert_eq!(pem.content_type, "application/x-pem-file");
        assert_eq!(pem.as_bytes(), authority.certificate_pem().as_bytes());
    }

    #[test]
    fn legacy_authority_without_metadata_uses_certificate_mtime() {
        let directory = tempfile::tempdir().unwrap();
        let authority = MitmAuthority::load_or_generate(directory.path()).unwrap();
        let original = authority.fingerprint_sha256().to_owned();
        fs::remove_file(directory.path().join(AUTHORITY_METADATA_FILE)).unwrap();
        let loaded = MitmAuthority::load_or_generate(directory.path()).unwrap();
        assert_eq!(loaded.fingerprint_sha256(), original);
        assert!(loaded.generated_at_unix() > 0);
    }
}
