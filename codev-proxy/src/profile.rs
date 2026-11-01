//! Long-lived, independently revocable Shadowrocket profiles.
//!
//! Profile metadata intentionally contains no secret.  The corresponding
//! SOCKS credential is held by [`TokenStore`], which persists only a salted
//! hash.  The clear secret is returned exactly at create/rotate time so a
//! caller can immediately build an importable profile.

use std::collections::{BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{TokenLimits, TokenStore};

const PROFILE_SCHEMA_VERSION: u32 = 1;
const MAX_PROFILE_ID_BYTES: usize = 96;
const MAX_LABEL_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMetadata {
    pub profile_id: String,
    pub username: String,
    pub label: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub generation: u64,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileStatus {
    #[serde(flatten)]
    pub metadata: ProfileMetadata,
    pub expired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileCredential {
    pub metadata: ProfileMetadata,
    pub secret: String,
}

#[derive(Clone)]
pub struct ProfileStore {
    path: Option<PathBuf>,
    inner: Arc<Mutex<HashMap<String, ProfileMetadata>>>,
}

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("profile store I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("profile store TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("profile store TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),
    #[error("profile token error: {0}")]
    Token(#[from] crate::TokenError),
    #[error("profile not found: {0}")]
    NotFound(String),
    #[error("profile label or id is invalid")]
    InvalidInput,
    #[error("profile store path is unsafe")]
    UnsafePath,
    #[error("subscription token is invalid")]
    InvalidSubscription,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedProfileStore {
    schema_version: u32,
    profiles: Vec<ProfileMetadata>,
}

impl ProfileStore {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref().to_owned();
        if !path.exists() {
            return Ok(Self::new(Some(path)));
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ProfileError::UnsafePath);
        }
        let text = fs::read_to_string(&path)?;
        let persisted: PersistedProfileStore = toml::from_str(&text)?;
        if persisted.schema_version != PROFILE_SCHEMA_VERSION {
            return Err(ProfileError::InvalidInput);
        }
        let mut profiles = HashMap::with_capacity(persisted.profiles.len());
        for profile in persisted.profiles {
            validate_metadata(&profile)?;
            if profiles
                .insert(profile.profile_id.clone(), profile)
                .is_some()
            {
                return Err(ProfileError::InvalidInput);
            }
        }
        Ok(Self {
            path: Some(path),
            inner: Arc::new(Mutex::new(profiles)),
        })
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn save(&self) -> Result<(), ProfileError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let mut profiles: Vec<_> = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .cloned()
            .collect();
        profiles.sort_by(|left, right| left.profile_id.cmp(&right.profile_id));
        let encoded = toml::to_string_pretty(&PersistedProfileStore {
            schema_version: PROFILE_SCHEMA_VERSION,
            profiles,
        })?;
        write_private_atomic(path, encoded.as_bytes())
    }

    pub fn list(&self) -> Vec<ProfileStatus> {
        let now = epoch_seconds();
        let mut values: Vec<_> = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .cloned()
            .map(|metadata| ProfileStatus {
                expired: metadata.expires_at <= now,
                metadata,
            })
            .collect();
        values.sort_by(|left, right| left.metadata.profile_id.cmp(&right.metadata.profile_id));
        values
    }

    pub fn get(&self, profile_id: &str) -> Option<ProfileStatus> {
        let now = epoch_seconds();
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(profile_id)
            .cloned()
            .map(|metadata| ProfileStatus {
                expired: metadata.expires_at <= now,
                metadata,
            })
    }

    pub fn create(
        &self,
        tokens: &TokenStore,
        limits: TokenLimits,
        ttl_secs: u64,
        label: Option<&str>,
    ) -> Result<ProfileCredential, ProfileError> {
        let label = normalize_label(label)?;
        let profile_id = unique_profile_id(&self.inner);
        let credential = tokens.create_token(None, ttl_secs, limits)?;
        let metadata = ProfileMetadata {
            profile_id: profile_id.clone(),
            username: credential.username.clone(),
            label,
            created_at: epoch_seconds(),
            expires_at: credential.expires_at,
            generation: 1,
            revoked: false,
        };
        validate_metadata(&metadata)?;
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(profile_id, metadata.clone());
        if let Err(error) = self.save() {
            let _ = tokens.remove_token(&credential.username);
            return Err(error);
        }
        Ok(ProfileCredential {
            metadata,
            secret: credential.secret,
        })
    }

    pub fn rotate(
        &self,
        tokens: &TokenStore,
        profile_id: &str,
        ttl_secs: u64,
    ) -> Result<ProfileCredential, ProfileError> {
        let (username, mut metadata) = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(profile_id)
            .cloned()
            .map(|metadata| (metadata.username.clone(), metadata))
            .ok_or_else(|| ProfileError::NotFound(profile_id.to_owned()))?;
        let credential = tokens.rotate_token(&username, ttl_secs)?;
        metadata.expires_at = credential.expires_at;
        metadata.generation = metadata.generation.wrapping_add(1).max(1);
        metadata.revoked = false;
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(profile_id.to_owned(), metadata.clone());
        self.save()?;
        Ok(ProfileCredential {
            metadata,
            secret: credential.secret,
        })
    }

    pub fn revoke(
        &self,
        tokens: &TokenStore,
        profile_id: &str,
    ) -> Result<ProfileStatus, ProfileError> {
        let mut metadata = self
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(profile_id)
            .cloned()
            .ok_or_else(|| ProfileError::NotFound(profile_id.to_owned()))?;
        if !tokens.revoke_token(&metadata.username) {
            return Err(ProfileError::NotFound(profile_id.to_owned()));
        }
        metadata.revoked = true;
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .insert(profile_id.to_owned(), metadata.clone());
        self.save()?;
        Ok(ProfileStatus {
            expired: metadata.expires_at <= epoch_seconds(),
            metadata,
        })
    }

    /// Authenticate a subscription bearer of the form `username.secret`.
    /// The permit is dropped immediately, so this check does not consume a
    /// long-lived SOCKS connection quota.
    pub fn authenticate_subscription(
        &self,
        tokens: &TokenStore,
        profile_id: &str,
        bearer: &str,
    ) -> Result<ProfileStatus, ProfileError> {
        let status = self
            .get(profile_id)
            .ok_or_else(|| ProfileError::NotFound(profile_id.to_owned()))?;
        if status.metadata.revoked || status.expired {
            return Err(ProfileError::InvalidSubscription);
        }
        let (username, secret) = bearer
            .split_once('.')
            .ok_or(ProfileError::InvalidSubscription)?;
        if username != status.metadata.username || secret.is_empty() {
            return Err(ProfileError::InvalidSubscription);
        }
        let _permit = tokens
            .authenticate(username, secret.as_bytes())
            .map_err(|_| ProfileError::InvalidSubscription)?;
        Ok(status)
    }
}

pub type ProfileManager = ProfileStore;

pub fn render_shadowrocket_conf(
    host: &str,
    port: u16,
    username: &str,
    secret: &str,
    allow_hosts: &[String],
    allow_ports: &[u16],
) -> Result<String, ProfileError> {
    render_shadowrocket_conf_inner(host, port, username, secret, allow_hosts, allow_ports)
}

/// Backwards-compatible entry point for the live-capture profile.
///
/// Live profiles deliberately use the same selective rules as downloaded
/// profiles. Routing unmatched traffic to the restricted CodeV proxy would
/// make ordinary web and app connections fail at the server allowlist.
pub fn render_shadowrocket_conf_live(
    host: &str,
    port: u16,
    username: &str,
    secret: &str,
    allow_hosts: &[String],
    allow_ports: &[u16],
) -> Result<String, ProfileError> {
    render_shadowrocket_conf(host, port, username, secret, allow_hosts, allow_ports)
}

fn render_shadowrocket_conf_inner(
    host: &str,
    port: u16,
    username: &str,
    secret: &str,
    allow_hosts: &[String],
    allow_ports: &[u16],
) -> Result<String, ProfileError> {
    let host = shadowrocket_host(host)?;
    validate_conf_atom(username)?;
    validate_conf_atom(secret)?;
    if port == 0 || allow_hosts.is_empty() || allow_ports.is_empty() {
        return Err(ProfileError::InvalidInput);
    }
    let rules = allow_hosts
        .iter()
        .map(|allowed| shadowrocket_rule(allowed))
        .collect::<Result<BTreeSet<_>, _>>()?
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    let port_rules = allow_ports
        .iter()
        .copied()
        // Port-only rules must be limited to the dedicated MNA/radar ports.
        // Login/control ports such as 1883, 8013, and 8085 are shared by
        // endpoints whose public source IP must remain the phone's direct IP.
        // Known game hosts on those ports still match the DOMAIN/IP rules
        // above, while freshly announced MNA endpoints retain these fallbacks.
        .filter(|value| matches!(value, 15_806 | 17_500))
        .map(|value| format!("DST-PORT,{value},CodeV"))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
        .join("\n");
    // OAuth and ordinary HTTPS must remain direct so an external identity
    // provider (for example WeChat login) does not inherit the game exit.
    // CodeV game hosts and dedicated ports are matched above first. The
    // remaining non-DNS/non-QUIC UDP traffic is routed through CodeV because
    // the live game endpoint uses a session-selected destination port rather
    // than only the historically observed 15806/17500 ports. Shadowrocket's
    // PROTOCOL matcher is valid only as a nested logical rule, so NOT(TCP) is
    // used for the final UDP-family catch-all.
    let dynamic_udp_rules = [
        "AND,((PROTOCOL,UDP),(DST-PORT,53)),DIRECT",
        "AND,((PROTOCOL,UDP),(DST-PORT,443)),DIRECT",
        "NOT,((PROTOCOL,TCP)),CodeV",
    ]
    .join("\n");
    Ok(format!(
        "[General]\nprefer-ipv6 = false\nudp-policy-not-supported-behaviour = DIRECT\n\n[Proxy]\nCodeV-SOCKS = socks5, {host}, {port}, {username}, {secret}, udp-relay=true\n\n[Proxy Group]\nCodeV = select, CodeV-SOCKS\n\n[Rule]\n{rules}\n{port_rules}\n{dynamic_udp_rules}\nFINAL,DIRECT\n"
    ))
}

/// Render the standard Shadowrocket subscription body: standard Base64 of a
/// newline-free node list.  A CodeV subscription deliberately contains one
/// five-field SOCKS5 node, which is the portable Subscribe format accepted by
/// Shadowrocket.  UDP relay remains enabled in the separately downloadable
/// full `.conf` artifact, where Shadowrocket's optional proxy parameters are
/// unambiguous.
pub fn render_shadowrocket_subscription(
    host: &str,
    port: u16,
    username: &str,
    secret: &str,
) -> Result<String, ProfileError> {
    let host = shadowrocket_host(host)?;
    validate_conf_atom(username)?;
    validate_conf_atom(secret)?;
    if port == 0 {
        return Err(ProfileError::InvalidInput);
    }
    let node = format!("CodeV=socks5,{host},{port},{username},{secret}");
    Ok(BASE64_STANDARD.encode(node))
}

/// Render a self-contained SOCKS5 node URI that can be copied, scanned, or
/// handed directly to Shadowrocket without a follow-up subscription request.
/// User-info and the display label are encoded as URI components; an IPv6
/// literal keeps the canonical brackets required inside a URI authority.
pub fn render_socks5_node_uri(
    host: &str,
    port: u16,
    username: &str,
    secret: &str,
    label: &str,
) -> Result<String, ProfileError> {
    let host = shadowrocket_host(host)?;
    if port == 0
        || username.is_empty()
        || username.len() > u8::MAX as usize
        || secret.is_empty()
        || secret.len() > u8::MAX as usize
        || label.is_empty()
    {
        return Err(ProfileError::InvalidInput);
    }
    if username.chars().any(char::is_control)
        || secret.chars().any(char::is_control)
        || label.chars().any(char::is_control)
    {
        return Err(ProfileError::InvalidInput);
    }
    Ok(format!(
        "socks5://{}:{}@{host}:{port}#{}",
        percent_encode_uri_component(username),
        percent_encode_uri_component(secret),
        percent_encode_uri_component(label)
    ))
}

fn percent_encode_uri_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            output.push(byte as char);
        } else {
            output.push('%');
            output.push_str(&format!("{byte:02X}"));
        }
    }
    output
}

fn shadowrocket_rule(value: &str) -> Result<String, ProfileError> {
    if value.is_empty() || value.trim() != value || value.ends_with('.') {
        return Err(ProfileError::InvalidInput);
    }
    if let Some(suffix) = value.strip_prefix("*.") {
        let canonical = shadowrocket_host(suffix)?;
        if canonical.starts_with('[') || canonical.parse::<IpAddr>().is_ok() {
            return Err(ProfileError::InvalidInput);
        }
        return Ok(format!(
            "DOMAIN-SUFFIX,{},CodeV",
            canonical.to_ascii_lowercase()
        ));
    }
    let canonical = shadowrocket_host(value)?;
    let unbracketed = canonical.trim_matches(['[', ']']);
    match unbracketed.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => Ok(format!("IP-CIDR,{address}/32,CodeV,no-resolve")),
        Ok(IpAddr::V6(address)) => Ok(format!("IP-CIDR6,{address}/128,CodeV,no-resolve")),
        Err(_) => Ok(format!("DOMAIN,{},CodeV", canonical.to_ascii_lowercase())),
    }
}

/// Validate a comma-separated Shadowrocket field.  The format has no quoted
/// field grammar, so accepting delimiters or whitespace would silently change
/// the node/group/rule structure.  Reject those values instead of attempting
/// an ambiguous escape that different Shadowrocket versions may parse
/// differently.
fn validate_conf_atom(value: &str) -> Result<(), ProfileError> {
    if value.is_empty()
        || value.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, ',' | ';' | '#' | '=')
        })
    {
        return Err(ProfileError::InvalidInput);
    }
    Ok(())
}

fn shadowrocket_host(value: &str) -> Result<String, ProfileError> {
    if value.is_empty() || value.trim() != value {
        return Err(ProfileError::InvalidInput);
    }
    // Shadowrocket accepts bracketed IPv6 literals in the node field.  Allow
    // either spelling at the API boundary, but emit one canonical spelling so
    // generated files are stable across IPv4/IPv6 fixtures.
    let unbracketed = value
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(value);
    if unbracketed.is_empty() || unbracketed.contains(['[', ']']) {
        return Err(ProfileError::InvalidInput);
    }
    if let Ok(address) = unbracketed.parse::<IpAddr>() {
        return Ok(match address {
            IpAddr::V4(_) => address.to_string(),
            IpAddr::V6(_) => format!("[{address}]"),
        });
    }
    validate_conf_atom(value)?;
    if !value.is_ascii() || value.len() > 253 || value.starts_with('.') || value.ends_with('.') {
        return Err(ProfileError::InvalidInput);
    }
    if value.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(ProfileError::InvalidInput);
    }
    Ok(value.to_owned())
}

fn normalize_label(label: Option<&str>) -> Result<String, ProfileError> {
    let label = label.unwrap_or("CodeV Shadowrocket").trim();
    if label.is_empty() || label.len() > MAX_LABEL_BYTES || label.chars().any(char::is_control) {
        return Err(ProfileError::InvalidInput);
    }
    Ok(label.to_owned())
}

fn validate_metadata(metadata: &ProfileMetadata) -> Result<(), ProfileError> {
    if metadata.profile_id.is_empty()
        || metadata.profile_id.len() > MAX_PROFILE_ID_BYTES
        || metadata.username.is_empty()
        || metadata.label.is_empty()
        || metadata.label.len() > MAX_LABEL_BYTES
        || metadata.created_at == 0
        || metadata.expires_at == 0
        || metadata.generation == 0
        || metadata.profile_id.chars().any(char::is_control)
        || metadata.username.chars().any(char::is_control)
        || metadata.label.chars().any(char::is_control)
    {
        return Err(ProfileError::InvalidInput);
    }
    Ok(())
}

fn unique_profile_id(inner: &Arc<Mutex<HashMap<String, ProfileMetadata>>>) -> String {
    loop {
        let mut bytes = [0_u8; 12];
        rand::rng().fill_bytes(&mut bytes);
        let id = format!("sr_{}", hex_bytes(&bytes));
        if !inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .contains_key(&id)
        {
            return id;
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProfileError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if let Ok(metadata) = fs::symlink_metadata(parent) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ProfileError::UnsafePath);
        }
    } else {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let temp = parent.join(format!(".codev-profile-{:x}.tmp", rand::random::<u128>()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temp, path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn limits() -> TokenLimits {
        TokenLimits {
            max_connections: 2,
            max_udp_flows: 2,
            bytes_per_second: 1024,
            udp_idle_secs: 30,
        }
    }

    #[test]
    fn profile_round_trip_and_secret_is_not_persisted() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("profiles.toml");
        let store = ProfileStore::new(Some(path.clone()));
        let tokens = TokenStore::new();
        let credential = store
            .create(&tokens, limits(), 3600, Some("iPhone"))
            .unwrap();
        store.save().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&credential.secret));
        let loaded = ProfileStore::load(&path).unwrap();
        assert_eq!(loaded.list().len(), 1);
        assert_eq!(
            loaded
                .get(&credential.metadata.profile_id)
                .unwrap()
                .metadata
                .label,
            "iPhone"
        );
    }

    #[test]
    fn rotation_and_revoke_invalidate_subscription() {
        let directory = tempdir().unwrap();
        let store = ProfileStore::new(Some(directory.path().join("profiles.toml")));
        let tokens = TokenStore::new();
        let old = store.create(&tokens, limits(), 3600, None).unwrap();
        let old_bearer = format!("{}.{}", old.metadata.username, old.secret);
        assert!(
            store
                .authenticate_subscription(&tokens, &old.metadata.profile_id, &old_bearer)
                .is_ok()
        );
        let next = store
            .rotate(&tokens, &old.metadata.profile_id, 3600)
            .unwrap();
        assert!(
            store
                .authenticate_subscription(&tokens, &old.metadata.profile_id, &old_bearer)
                .is_err()
        );
        let next_bearer = format!("{}.{}", next.metadata.username, next.secret);
        assert!(
            store
                .authenticate_subscription(&tokens, &old.metadata.profile_id, &next_bearer)
                .is_ok()
        );
        store.revoke(&tokens, &old.metadata.profile_id).unwrap();
        assert!(
            store
                .authenticate_subscription(&tokens, &old.metadata.profile_id, &next_bearer)
                .is_err()
        );
    }

    #[test]
    fn shadowrocket_profile_has_only_allowlisted_proxy_node() {
        let allowed = vec![
            "*.codev.qq.com".to_owned(),
            "receiver.tdm.qq.com".to_owned(),
            "43.162.204.119".to_owned(),
            "2001:db8::20".to_owned(),
        ];
        let profile = render_shadowrocket_conf(
            "203.0.113.10",
            1080,
            "cv_user",
            "secret",
            &allowed,
            &[443, 1883, 8013, 8085, 15_806, 17_500],
        )
        .unwrap();
        assert!(
            profile.contains(
                "CodeV-SOCKS = socks5, 203.0.113.10, 1080, cv_user, secret, udp-relay=true"
            )
        );
        assert!(profile.contains("CodeV = select, CodeV-SOCKS"));
        assert!(profile.contains("[Rule]"));
        assert!(profile.contains("DOMAIN-SUFFIX,codev.qq.com,CodeV"));
        assert!(profile.contains("DOMAIN,receiver.tdm.qq.com,CodeV"));
        assert!(profile.contains("IP-CIDR,43.162.204.119/32,CodeV,no-resolve"));
        assert!(profile.contains("IP-CIDR6,2001:db8::20/128,CodeV,no-resolve"));
        assert!(profile.contains("DST-PORT,15806,CodeV"));
        assert!(profile.contains("DST-PORT,17500,CodeV"));
        assert!(!profile.contains("DST-PORT,443,CodeV"));
        assert!(!profile.contains("DST-PORT,1883,CodeV"));
        assert!(!profile.contains("DST-PORT,8013,CodeV"));
        assert!(!profile.contains("DST-PORT,8085,CodeV"));
        assert!(profile.contains("AND,((PROTOCOL,UDP),(DST-PORT,53)),DIRECT"));
        assert!(profile.contains("AND,((PROTOCOL,UDP),(DST-PORT,443)),DIRECT"));
        assert!(profile.contains("NOT,((PROTOCOL,TCP)),CodeV"));
        assert!(
            profile.find("DOMAIN-SUFFIX,codev.qq.com,CodeV").unwrap()
                < profile
                    .find("AND,((PROTOCOL,UDP),(DST-PORT,443)),DIRECT")
                    .unwrap()
        );
        assert!(
            profile.find("DST-PORT,15806,CodeV").unwrap()
                < profile.find("NOT,((PROTOCOL,TCP)),CodeV").unwrap()
        );
        assert!(profile.contains("udp-policy-not-supported-behaviour = DIRECT"));
        assert!(profile.contains("FINAL,DIRECT"));
        assert!(!profile.contains("FINAL,CodeV"));
        assert!(render_shadowrocket_conf("bad,host", 1080, "u", "s", &allowed, &[443]).is_err());
    }

    #[test]
    fn shadowrocket_profile_canonicalizes_ipv6_and_rejects_field_injection() {
        let allowed = vec!["game.example.com".to_owned()];
        let profile =
            render_shadowrocket_conf("2001:db8::10", 1080, "cv_user", "secret", &allowed, &[443])
                .unwrap();
        assert!(profile.contains(
            "CodeV-SOCKS = socks5, [2001:db8::10], 1080, cv_user, secret, udp-relay=true"
        ));
        assert!(
            render_shadowrocket_conf(
                "[2001:db8::10]",
                1080,
                "cv_user",
                "secret",
                &allowed,
                &[443]
            )
            .is_ok()
        );
        for (host, user, secret) in [
            ("game.example.com", "cv user", "secret"),
            ("game.example.com", "cv_user", "secret,other"),
            ("game.example.com", "cv_user", "secret\n[Rule]"),
            ("game example.com", "cv_user", "secret"),
        ] {
            assert!(render_shadowrocket_conf(host, 1080, user, secret, &allowed, &[443]).is_err());
        }
        assert!(render_shadowrocket_conf("host", 1080, "user", "secret", &[], &[443]).is_err());
        assert!(
            render_shadowrocket_conf(
                "host",
                1080,
                "user",
                "secret",
                &["*.127.0.0.1".into()],
                &[443],
            )
            .is_err()
        );
    }

    #[test]
    fn live_profile_keeps_unrelated_web_traffic_direct() {
        let profile = render_shadowrocket_conf_live(
            "203.0.113.10",
            1080,
            "cv_user",
            "secret",
            &["*.codev.qq.com".into()],
            &[80, 443, 15_806],
        )
        .unwrap();
        assert!(profile.contains("udp-relay=true"));
        // *.codev.qq.com:443 matches this game-specific host rule.
        assert!(profile.contains("DOMAIN-SUFFIX,codev.qq.com,CodeV"));
        // example.com:443 reaches FINAL,DIRECT because there is no global
        // shared-web-port rule.
        assert!(!profile.contains("DST-PORT,80,CodeV"));
        assert!(!profile.contains("DST-PORT,443,CodeV"));
        // A dedicated game endpoint can still be selected by port.
        assert!(profile.contains("DST-PORT,15806,CodeV"));
        // Session-selected game UDP ports are proxied while DNS and QUIC stay
        // direct. This lets external OAuth complete without losing game UDP.
        assert!(profile.contains("AND,((PROTOCOL,UDP),(DST-PORT,53)),DIRECT"));
        assert!(profile.contains("AND,((PROTOCOL,UDP),(DST-PORT,443)),DIRECT"));
        assert!(profile.contains("NOT,((PROTOCOL,TCP)),CodeV"));
        assert!(profile.contains("FINAL,DIRECT"));
        assert!(!profile.contains("FINAL,CodeV"));
    }

    #[test]
    fn shadowrocket_subscription_decodes_to_exactly_one_udp_socks5_node() {
        let encoded =
            render_shadowrocket_subscription("203.0.113.10", 1080, "cv_user", "secret").unwrap();
        assert!(!encoded.contains(['\r', '\n']));
        let decoded = BASE64_STANDARD.decode(encoded).unwrap();
        let decoded = String::from_utf8(decoded).unwrap();
        assert_eq!(decoded.lines().count(), 1);
        assert_eq!(decoded, "CodeV=socks5,203.0.113.10,1080,cv_user,secret");
    }

    #[test]
    fn shadowrocket_subscription_canonicalizes_ipv6_and_rejects_injection() {
        let encoded =
            render_shadowrocket_subscription("2001:db8::10", 1080, "cv_user", "secret").unwrap();
        let decoded = String::from_utf8(BASE64_STANDARD.decode(encoded).unwrap()).unwrap();
        assert_eq!(decoded, "CodeV=socks5,[2001:db8::10],1080,cv_user,secret");
        assert!(render_shadowrocket_subscription("host", 0, "user", "secret").is_err());
        assert!(render_shadowrocket_subscription("host", 1080, "user", "secret\nnode").is_err());
    }

    #[test]
    fn socks5_node_uri_is_self_contained_and_component_encoded() {
        let node =
            render_socks5_node_uri("203.0.113.10", 1080, "cv user", "p@ss:/?#[]%", "CodeV 对局")
                .unwrap();
        assert_eq!(
            node,
            "socks5://cv%20user:p%40ss%3A%2F%3F%23%5B%5D%25@203.0.113.10:1080#CodeV%20%E5%AF%B9%E5%B1%80"
        );
        assert!(!node.contains(['\r', '\n']));
    }

    #[test]
    fn socks5_node_uri_canonicalizes_ipv6_and_rejects_invalid_fields() {
        assert_eq!(
            render_socks5_node_uri("2001:db8::10", 1080, "cv_user", "secret", "CodeV").unwrap(),
            "socks5://cv_user:secret@[2001:db8::10]:1080#CodeV"
        );
        assert!(render_socks5_node_uri("host", 0, "user", "secret", "CodeV").is_err());
        assert!(render_socks5_node_uri("host", 1080, "", "secret", "CodeV").is_err());
        assert!(render_socks5_node_uri("host", 1080, "user", "secret\n", "CodeV").is_err());
        assert!(render_socks5_node_uri("host", 1080, "user", "secret", "\0").is_err());
        assert!(render_socks5_node_uri("host", 1080, &"u".repeat(256), "secret", "CodeV").is_err());
        assert!(render_socks5_node_uri("host", 1080, "user", &"s".repeat(256), "CodeV").is_err());
    }
}
