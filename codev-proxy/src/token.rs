use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 免鉴权（C 方案）连接复用的内置匿名令牌用户名。
///
/// 固定名字，便于 `codev-net token list` 一眼看出它是哪来的；它的密码从不对外
/// 提供，因此无法被当成普通令牌使用。
pub const ANONYMOUS_USERNAME: &str = "cv_anonymous";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct TokenLimits {
    pub max_connections: u32,
    pub max_udp_flows: u32,
    pub bytes_per_second: u64,
    pub udp_idle_secs: u64,
}

impl TokenLimits {
    fn validate(self) -> Result<Self, TokenError> {
        if self.max_connections == 0
            || self.max_udp_flows == 0
            || self.bytes_per_second == 0
            || self.udp_idle_secs == 0
        {
            return Err(TokenError::InvalidLimits);
        }
        Ok(self)
    }
}

#[derive(Clone)]
pub struct TokenStore {
    inner: Arc<Mutex<TokenStoreInner>>,
}

#[derive(Default)]
struct TokenStoreInner {
    records: HashMap<String, TokenRecord>,
}

struct TokenRecord {
    salt: [u8; 16],
    secret_hash: [u8; 32],
    expires_at: u64,
    revoked: bool,
    generation: u64,
    limits: TokenLimits,
    active_connections: u32,
    active_udp_flows: u32,
    bandwidth_second: u64,
    bandwidth_bytes: u64,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TokenStoreInner::default())),
        }
    }

    pub fn create_token(
        &self,
        username: Option<&str>,
        ttl_secs: u64,
        limits: TokenLimits,
    ) -> Result<TokenCredential, TokenError> {
        if ttl_secs == 0 {
            return Err(TokenError::InvalidTtl);
        }
        let limits = limits.validate()?;
        let username = match username {
            Some(value) => validate_username(value)?.to_owned(),
            None => format!("cv_{}", random_text(9)),
        };
        let secret = random_text(32);
        let salt = random_bytes::<16>();
        let expires_at = epoch_seconds()
            .checked_add(ttl_secs)
            .ok_or(TokenError::InvalidTtl)?;
        let record = TokenRecord {
            salt,
            secret_hash: hash_secret(&salt, secret.as_bytes()),
            expires_at,
            revoked: false,
            generation: 1,
            limits,
            active_connections: 0,
            active_udp_flows: 0,
            bandwidth_second: 0,
            bandwidth_bytes: 0,
        };
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if inner.records.contains_key(&username) {
            return Err(TokenError::AlreadyExists(username));
        }
        inner.records.insert(username.clone(), record);
        Ok(TokenCredential {
            username,
            secret,
            expires_at,
        })
    }

    /// Replace the authentication secret while revoking the old generation.
    /// Existing tunnels are invalidated on their next quota check, their old
    /// counters cannot affect the new generation, and the previous secret can
    /// no longer authenticate.
    pub fn rotate_token(
        &self,
        username: &str,
        ttl_secs: u64,
    ) -> Result<TokenCredential, TokenError> {
        if ttl_secs == 0 {
            return Err(TokenError::InvalidTtl);
        }
        let secret = random_text(32);
        let salt = random_bytes::<16>();
        let expires_at = epoch_seconds()
            .checked_add(ttl_secs)
            .ok_or(TokenError::InvalidTtl)?;
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let record = inner
            .records
            .get_mut(username)
            .ok_or_else(|| TokenError::NotFound(username.to_owned()))?;
        record.salt = salt;
        record.secret_hash = hash_secret(&salt, secret.as_bytes());
        record.expires_at = expires_at;
        record.revoked = false;
        record.generation = record.generation.wrapping_add(1).max(1);
        record.active_connections = 0;
        record.active_udp_flows = 0;
        record.bandwidth_second = 0;
        record.bandwidth_bytes = 0;
        Ok(TokenCredential {
            username: username.to_owned(),
            secret,
            expires_at,
        })
    }

    pub fn revoke_token(&self, username: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        match inner.records.get_mut(username) {
            Some(record) => {
                record.revoked = true;
                true
            }
            None => false,
        }
    }

    pub fn remove_token(&self, username: &str) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .records
            .remove(username)
            .is_some()
    }

    pub fn list(&self) -> Vec<TokenStatus> {
        let now = epoch_seconds();
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut statuses = inner
            .records
            .iter()
            .map(|(username, record)| TokenStatus {
                username: username.clone(),
                expires_at: record.expires_at,
                revoked: record.revoked,
                expired: record.expires_at <= now,
                active_connections: record.active_connections,
                active_udp_flows: record.active_udp_flows,
                limits: record.limits,
            })
            .collect::<Vec<_>>();
        statuses.sort_by(|left, right| left.username.cmp(&right.username));
        statuses
    }

    /// 免鉴权连接用的内置匿名令牌 —— 确保它存在（不存在则现造一个）。
    ///
    /// C 方案（节点免鉴权）下 SOCKS5 握手不再提供密码，但下游仍要用
    /// [`ConnectionPermit`] 做连接数/UDP 流/带宽的计量与限流，所以这里准备一个
    /// **谁也不知道密码**的固定令牌：它的 secret 只在本函数里生成后被立即丢弃，
    /// 因此只能通过 [`Self::anonymous_permit`]（免鉴权路径）使用。
    ///
    /// 已存在且未过期/未吊销时**原样保留**（不动它的过期时间与实时计数）。
    /// 返回 `true` 表示确实新建了记录（调用方据此决定是否落盘）。
    pub fn ensure_anonymous_token(
        &self,
        ttl_secs: u64,
        limits: TokenLimits,
    ) -> Result<bool, TokenError> {
        {
            let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
            match inner.records.get(ANONYMOUS_USERNAME) {
                None => {}
                Some(record) => {
                    if !record.revoked && record.expires_at > epoch_seconds() {
                        return Ok(false);
                    }
                    // 过期或已吊销：换一条新的，否则免鉴权会永久 401。
                    inner.records.remove(ANONYMOUS_USERNAME);
                }
            }
        }
        // 不把凭据交出去：匿名令牌没有可用的密码。
        let _credential = self.create_token(Some(ANONYMOUS_USERNAME), ttl_secs, limits)?;
        Ok(true)
    }

    /// 免鉴权路径的许可：与 [`Self::authenticate`] 同构，但**不校验密码**
    /// （匿名令牌的密码本来就不对外）。仍然完整执行：
    /// 记录存在性 → 未吊销/未过期 → 连接数上限 → `active_connections` 计数。
    pub fn anonymous_permit(&self) -> Result<ConnectionPermit, TokenError> {
        let now = epoch_seconds();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let record = inner
            .records
            .get_mut(ANONYMOUS_USERNAME)
            .ok_or(TokenError::AuthenticationFailed)?;
        if record.revoked || record.expires_at <= now {
            return Err(TokenError::AuthenticationFailed);
        }
        if record.active_connections >= record.limits.max_connections {
            return Err(TokenError::ConnectionLimit);
        }
        record.active_connections += 1;
        Ok(ConnectionPermit {
            meter: QuotaMeter {
                store: self.clone(),
                username: ANONYMOUS_USERNAME.to_owned(),
                generation: record.generation,
            },
            released: false,
        })
    }

    pub fn authenticate(
        &self,
        username: &str,
        secret: &[u8],
    ) -> Result<ConnectionPermit, TokenError> {
        let now = epoch_seconds();
        let mut inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let record = inner
            .records
            .get_mut(username)
            .ok_or(TokenError::AuthenticationFailed)?;
        let candidate = hash_secret(&record.salt, secret);
        if record.revoked
            || record.expires_at <= now
            || !constant_time_eq(&record.secret_hash, &candidate)
        {
            return Err(TokenError::AuthenticationFailed);
        }
        if record.active_connections >= record.limits.max_connections {
            return Err(TokenError::ConnectionLimit);
        }
        record.active_connections += 1;
        Ok(ConnectionPermit {
            meter: QuotaMeter {
                store: self.clone(),
                username: username.to_owned(),
                generation: record.generation,
            },
            released: false,
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), TokenError> {
        let path = path.as_ref();
        let parent = validate_token_parent(path)?;
        reject_unsafe_existing_path(path)?;
        let file = self.to_persisted();
        let serialized = toml::to_string_pretty(&file)
            .map_err(|error| TokenError::Persistence(error.to_string()))?;
        let (temporary_path, mut output) = create_secure_temp_file(parent, path)?;
        let result = (|| {
            output.write_all(serialized.as_bytes())?;
            output.sync_all()?;
            drop(output);
            #[cfg(not(unix))]
            if path.exists() {
                // Windows rename does not replace an existing file. The
                // final-component symlink check above and the remove-before-
                // rename sequence ensure a symlink is never followed.
                fs::remove_file(path)?;
            }
            fs::rename(&temporary_path, path)?;
            #[cfg(unix)]
            {
                // Persist the directory entry as well as the file contents.
                let directory = OpenOptions::new().read(true).open(parent)?;
                directory.sync_all()?;
            }
            Ok::<(), io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result.map_err(TokenError::Io)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, TokenError> {
        let mut input = String::new();
        let mut input_file = open_secure_read(path.as_ref())?;
        input_file.read_to_string(&mut input)?;
        let persisted: PersistedTokenFile =
            toml::from_str(&input).map_err(|error| TokenError::Persistence(error.to_string()))?;
        if persisted.schema_version != 1 {
            return Err(TokenError::Persistence(format!(
                "unsupported token store version {}",
                persisted.schema_version
            )));
        }
        let mut records = HashMap::new();
        for token in persisted.tokens {
            validate_username(&token.username)?;
            token.limits.validate()?;
            let salt = decode_array::<16>(&token.salt)?;
            let secret_hash = decode_array::<32>(&token.secret_hash)?;
            if records
                .insert(
                    token.username.clone(),
                    TokenRecord {
                        salt,
                        secret_hash,
                        expires_at: token.expires_at,
                        revoked: token.revoked,
                        generation: token.generation.max(1),
                        limits: token.limits,
                        active_connections: 0,
                        active_udp_flows: 0,
                        bandwidth_second: 0,
                        bandwidth_bytes: 0,
                    },
                )
                .is_some()
            {
                return Err(TokenError::Persistence(format!(
                    "duplicate username {}",
                    token.username
                )));
            }
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(TokenStoreInner { records })),
        })
    }

    /// Atomically replace the in-memory credential set from a separately
    /// loaded store.  Credentials that are byte-for-byte the same generation
    /// retain their live quota counters; a revoke, rotate, delete, or changed
    /// hash therefore invalidates old permits without allowing a replacement
    /// record to inherit stale usage.
    pub fn reload_from(&self, replacement: TokenStore) {
        if Arc::ptr_eq(&self.inner, &replacement.inner) {
            return;
        }
        let mut incoming = replacement
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut current = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut records = std::mem::take(&mut incoming.records);
        for (username, next) in &mut records {
            let Some(previous) = current.records.get(username) else {
                continue;
            };
            if previous.salt == next.salt
                && previous.secret_hash == next.secret_hash
                && previous.generation == next.generation
                && previous.revoked == next.revoked
            {
                next.active_connections = previous.active_connections;
                next.active_udp_flows = previous.active_udp_flows;
                next.bandwidth_second = previous.bandwidth_second;
                next.bandwidth_bytes = previous.bandwidth_bytes;
            } else if previous.revoked != next.revoked
                || previous.salt != next.salt
                || previous.secret_hash != next.secret_hash
            {
                // A hand-authored replacement may reset generation to one;
                // advance it here so permits from the old secret cannot
                // continue using the new record.
                next.generation = previous.generation.wrapping_add(1).max(1);
            }
        }
        current.records = records;
    }

    fn to_persisted(&self) -> PersistedTokenFile {
        let inner = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        let mut tokens = inner
            .records
            .iter()
            .map(|(username, record)| PersistedToken {
                username: username.clone(),
                salt: URL_SAFE_NO_PAD.encode(record.salt),
                secret_hash: URL_SAFE_NO_PAD.encode(record.secret_hash),
                expires_at: record.expires_at,
                revoked: record.revoked,
                generation: record.generation,
                limits: record.limits,
            })
            .collect::<Vec<_>>();
        tokens.sort_by(|left, right| left.username.cmp(&right.username));
        PersistedTokenFile {
            schema_version: 1,
            tokens,
        }
    }
}

pub struct TokenCredential {
    pub username: String,
    pub secret: String,
    pub expires_at: u64,
}

impl fmt::Debug for TokenCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenCredential")
            .field("username", &self.username)
            .field("secret", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TokenStatus {
    pub username: String,
    pub expires_at: u64,
    pub revoked: bool,
    pub expired: bool,
    pub active_connections: u32,
    pub active_udp_flows: u32,
    pub limits: TokenLimits,
}

pub struct ConnectionPermit {
    meter: QuotaMeter,
    released: bool,
}

impl ConnectionPermit {
    pub fn meter(&self) -> QuotaMeter {
        self.meter.clone()
    }

    pub fn username(&self) -> &str {
        &self.meter.username
    }
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut inner = self
            .meter
            .store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(record) = inner.records.get_mut(&self.meter.username)
            && record.generation == self.meter.generation
        {
            record.active_connections = record.active_connections.saturating_sub(1);
        }
    }
}

#[derive(Clone)]
pub struct QuotaMeter {
    store: TokenStore,
    username: String,
    generation: u64,
}

impl QuotaMeter {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn udp_idle_timeout(&self) -> Result<std::time::Duration, TokenError> {
        let mut inner = self
            .store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let record = active_record(&mut inner, &self.username, self.generation)?;
        Ok(std::time::Duration::from_secs(record.limits.udp_idle_secs))
    }

    pub fn charge_bytes(&self, bytes: usize) -> Result<(), TokenError> {
        let now = epoch_seconds();
        let bytes = u64::try_from(bytes).map_err(|_| TokenError::BandwidthLimit)?;
        let mut inner = self
            .store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let record = active_record(&mut inner, &self.username, self.generation)?;
        if record.bandwidth_second != now {
            record.bandwidth_second = now;
            record.bandwidth_bytes = 0;
        }
        let total = record
            .bandwidth_bytes
            .checked_add(bytes)
            .ok_or(TokenError::BandwidthLimit)?;
        if total > record.limits.bytes_per_second {
            return Err(TokenError::BandwidthLimit);
        }
        record.bandwidth_bytes = total;
        Ok(())
    }

    pub fn acquire_udp_flow(&self) -> Result<UdpFlowPermit, TokenError> {
        let mut inner = self
            .store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let record = active_record(&mut inner, &self.username, self.generation)?;
        if record.active_udp_flows >= record.limits.max_udp_flows {
            return Err(TokenError::UdpFlowLimit);
        }
        record.active_udp_flows += 1;
        Ok(UdpFlowPermit {
            meter: self.clone(),
            released: false,
        })
    }
}

pub struct UdpFlowPermit {
    meter: QuotaMeter,
    released: bool,
}

impl Drop for UdpFlowPermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        self.released = true;
        let mut inner = self
            .meter
            .store
            .inner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(record) = inner.records.get_mut(&self.meter.username)
            && record.generation == self.meter.generation
        {
            record.active_udp_flows = record.active_udp_flows.saturating_sub(1);
        }
    }
}

fn active_record<'a>(
    inner: &'a mut TokenStoreInner,
    username: &str,
    generation: u64,
) -> Result<&'a mut TokenRecord, TokenError> {
    let record = inner
        .records
        .get_mut(username)
        .ok_or(TokenError::RevokedOrRotated)?;
    if record.generation != generation || record.revoked || record.expires_at <= epoch_seconds() {
        return Err(TokenError::RevokedOrRotated);
    }
    Ok(record)
}

fn validate_username(username: &str) -> Result<&str, TokenError> {
    if username.is_empty()
        || username.len() > 255
        || !username.is_ascii()
        || username
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(TokenError::InvalidUsername);
    }
    Ok(username)
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0_u8; N];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

fn random_text(bytes: usize) -> String {
    let mut random = vec![0_u8; bytes];
    rand::rng().fill_bytes(&mut random);
    URL_SAFE_NO_PAD.encode(random)
}

fn hash_secret(salt: &[u8; 16], secret: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"codev-proxy-token-v1\0");
    digest.update(salt);
    digest.update(secret);
    digest.finalize().into()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn decode_array<const N: usize>(encoded: &str) -> Result<[u8; N], TokenError> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|error| TokenError::Persistence(error.to_string()))?;
    decoded
        .try_into()
        .map_err(|_| TokenError::Persistence(format!("expected {N} decoded bytes")))
}

fn validate_token_parent(path: &Path) -> Result<&Path, TokenError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.file_name().is_none() {
        return Err(TokenError::UnsafePath(path.display().to_string()));
    }
    let metadata = fs::symlink_metadata(parent)?;
    // We intentionally inspect only the immediate parent. macOS commonly
    // exposes /tmp through a system symlink (/var -> /private/var); rejecting
    // every ancestor would make a valid private store path unusable. The
    // final component is protected by O_NOFOLLOW on Unix below.
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(TokenError::UnsafePath(parent.display().to_string()));
    }
    Ok(parent)
}

fn reject_unsafe_existing_path(path: &Path) -> Result<(), TokenError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(TokenError::UnsafePath(path.display().to_string()))
        }
        Ok(metadata) if !metadata.is_file() => {
            Err(TokenError::UnsafePath(path.display().to_string()))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(TokenError::Io(error)),
    }
}

fn open_secure_read(path: &Path) -> Result<File, TokenError> {
    validate_token_parent(path)?;
    reject_unsafe_existing_path(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(TokenError::UnsafePath(path.display().to_string()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode = metadata.mode() & 0o7777;
        if mode != 0o600 {
            return Err(TokenError::InsecurePermissions(mode));
        }
    }
    Ok(file)
}

fn create_secure_temp_file(parent: &Path, path: &Path) -> Result<(PathBuf, File), TokenError> {
    let filename = path
        .file_name()
        .ok_or_else(|| TokenError::UnsafePath(path.display().to_string()))?;
    for _ in 0..16 {
        let mut temporary_name = OsString::from(".");
        temporary_name.push(filename);
        temporary_name.push(".tmp-");
        temporary_name.push(random_text(12));
        let temporary_path = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.create_new(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW).mode(0o600);
        }
        match options.open(&temporary_path) {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(TokenError::Io(error)),
        }
    }
    Err(TokenError::UnsafePath(format!(
        "unable to allocate a private temporary token file beside {}",
        path.display()
    )))
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Deserialize, Serialize)]
struct PersistedTokenFile {
    schema_version: u16,
    tokens: Vec<PersistedToken>,
}

#[derive(Deserialize, Serialize)]
struct PersistedToken {
    username: String,
    salt: String,
    secret_hash: String,
    expires_at: u64,
    revoked: bool,
    generation: u64,
    limits: TokenLimits,
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("token username is invalid")]
    InvalidUsername,
    #[error("token lifetime is invalid")]
    InvalidTtl,
    #[error("token limits must be non-zero")]
    InvalidLimits,
    #[error("token already exists: {0}")]
    AlreadyExists(String),
    #[error("token not found: {0}")]
    NotFound(String),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("token connection limit reached")]
    ConnectionLimit,
    #[error("token UDP flow limit reached")]
    UdpFlowLimit,
    #[error("token bandwidth limit reached")]
    BandwidthLimit,
    #[error("token was revoked, expired or rotated")]
    RevokedOrRotated,
    #[error("token store I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unsafe token store path: {0}")]
    UnsafePath(String),
    #[error("token store permissions must be exactly 0600 (got {0:o})")]
    InsecurePermissions(u32),
    #[error("invalid token store: {0}")]
    Persistence(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> TokenLimits {
        TokenLimits {
            max_connections: 1,
            max_udp_flows: 1,
            bytes_per_second: 16,
            udp_idle_secs: 30,
        }
    }

    #[test]
    fn anonymous_permit_needs_the_builtin_token_and_obeys_limits() {
        let store = TokenStore::new();
        // 没有匿名令牌时不放行（绝不能"缺记录 == 免限流"）。
        assert!(matches!(
            store.anonymous_permit(),
            Err(TokenError::AuthenticationFailed)
        ));
        assert_eq!(store.ensure_anonymous_token(60, limits()).unwrap(), true);
        // 幂等：已经存在就不再动它。
        assert_eq!(store.ensure_anonymous_token(60, limits()).unwrap(), false);
        assert_eq!(
            store
                .list()
                .iter()
                .filter(|status| status.username == ANONYMOUS_USERNAME)
                .count(),
            1
        );

        let permit = store.anonymous_permit().unwrap();
        assert_eq!(permit.username(), ANONYMOUS_USERNAME);
        assert!(matches!(
            store.anonymous_permit(),
            Err(TokenError::ConnectionLimit)
        ));
        drop(permit);
        assert!(store.anonymous_permit().is_ok());
    }

    #[test]
    fn anonymous_token_is_replaced_once_expired_or_revoked() {
        let store = TokenStore::new();
        assert_eq!(store.ensure_anonymous_token(1, limits()).unwrap(), true);
        assert!(store.revoke_token(ANONYMOUS_USERNAME));
        // 已吊销 → 重新造一条，免鉴权不会永久 401。
        assert_eq!(store.ensure_anonymous_token(60, limits()).unwrap(), true);
        assert!(store.anonymous_permit().is_ok());
    }

    #[test]
    fn credentials_are_hashed_and_authentication_is_bounded() {
        let store = TokenStore::new();
        let credential = store.create_token(Some("phone"), 60, limits()).unwrap();
        let permit = store
            .authenticate(&credential.username, credential.secret.as_bytes())
            .unwrap();
        assert!(matches!(
            store.authenticate(&credential.username, credential.secret.as_bytes()),
            Err(TokenError::ConnectionLimit)
        ));
        assert!(matches!(
            store.authenticate(&credential.username, b"wrong"),
            Err(TokenError::AuthenticationFailed)
        ));
        drop(permit);
        assert!(
            store
                .authenticate(&credential.username, credential.secret.as_bytes())
                .is_ok()
        );
    }

    #[test]
    fn revoke_and_rotation_invalidate_old_secrets() {
        let store = TokenStore::new();
        let old = store.create_token(Some("ios"), 60, limits()).unwrap();
        assert!(store.revoke_token("ios"));
        assert!(store.authenticate("ios", old.secret.as_bytes()).is_err());
        let new = store.rotate_token("ios", 60).unwrap();
        assert!(store.authenticate("ios", old.secret.as_bytes()).is_err());
        assert!(store.authenticate("ios", new.secret.as_bytes()).is_ok());
        assert!(!format!("{new:?}").contains(&new.secret));
    }

    #[test]
    fn reload_replaces_credentials_without_reviving_old_permits() {
        let active = TokenStore::new();
        let old = active.create_token(Some("ios"), 60, limits()).unwrap();
        let permit = active.authenticate("ios", old.secret.as_bytes()).unwrap();

        let replacement = TokenStore::new();
        let new = replacement.create_token(Some("ios"), 60, limits()).unwrap();
        active.reload_from(replacement);
        assert!(active.authenticate("ios", old.secret.as_bytes()).is_err());
        assert!(active.authenticate("ios", new.secret.as_bytes()).is_ok());
        assert!(matches!(
            permit.meter().charge_bytes(1),
            Err(TokenError::RevokedOrRotated)
        ));
    }

    #[test]
    fn udp_and_bandwidth_quotas_release_atomically() {
        let store = TokenStore::new();
        let credential = store.create_token(Some("quota"), 60, limits()).unwrap();
        let permit = store
            .authenticate("quota", credential.secret.as_bytes())
            .unwrap();
        let meter = permit.meter();
        let flow = meter.acquire_udp_flow().unwrap();
        assert!(matches!(
            meter.acquire_udp_flow(),
            Err(TokenError::UdpFlowLimit)
        ));
        meter.charge_bytes(16).unwrap();
        assert!(matches!(
            meter.charge_bytes(1),
            Err(TokenError::BandwidthLimit)
        ));
        drop(flow);
        assert!(meter.acquire_udp_flow().is_ok());
    }

    #[test]
    fn persistence_contains_no_plaintext_secret() {
        let store = TokenStore::new();
        let credential = store.create_token(Some("saved"), 60, limits()).unwrap();
        let path = unique_path("persistence");
        store.save(&path).unwrap();
        let contents = fs::read_to_string(&path).unwrap();
        assert!(!contents.contains(&credential.secret));
        let loaded = TokenStore::load(&path).unwrap();
        assert!(
            loaded
                .authenticate("saved", credential.secret.as_bytes())
                .is_ok()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn relative_token_paths_use_the_current_directory_safely() {
        let name = format!(
            "codev-proxy-relative-token-{}-{}.toml",
            std::process::id(),
            random_text(8)
        );
        let path = PathBuf::from(name);
        let store = TokenStore::new();
        store.save(&path).unwrap();
        assert!(TokenStore::load(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn save_and_load_reject_final_and_parent_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let directory = unique_path("symlink");
        fs::create_dir_all(&directory).unwrap();
        let store = TokenStore::new();
        let target = directory.join("target.toml");
        store.save(&target).unwrap();
        let before = fs::read(&target).unwrap();

        let final_link = directory.join("final-link.toml");
        symlink(&target, &final_link).unwrap();
        assert!(matches!(
            store.save(&final_link),
            Err(TokenError::UnsafePath(_))
        ));
        assert!(matches!(
            TokenStore::load(&final_link),
            Err(TokenError::UnsafePath(_))
        ));
        assert_eq!(fs::read(&target).unwrap(), before);

        let real_parent = directory.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        let parent_link = directory.join("parent-link");
        symlink(&real_parent, &parent_link).unwrap();
        let through_parent = parent_link.join("tokens.toml");
        assert!(matches!(
            store.save(&through_parent),
            Err(TokenError::UnsafePath(_))
        ));
        assert!(matches!(
            TokenStore::load(&through_parent),
            Err(TokenError::UnsafePath(_))
        ));

        fs::remove_file(final_link).unwrap();
        fs::remove_file(target).unwrap();
        fs::remove_file(parent_link).unwrap();
        fs::remove_dir(real_parent).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn load_rejects_non_regular_and_non_private_files_while_save_repairs_mode() {
        use std::os::unix::fs::PermissionsExt;

        let directory = unique_path("permissions-dir");
        fs::create_dir_all(&directory).unwrap();
        let store = TokenStore::new();
        assert!(matches!(
            store.save(&directory),
            Err(TokenError::UnsafePath(_))
        ));
        assert!(matches!(
            TokenStore::load(&directory),
            Err(TokenError::UnsafePath(_))
        ));
        fs::remove_dir(&directory).unwrap();

        let path = unique_path("permissions");
        store.save(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            TokenStore::load(&path),
            Err(TokenError::InsecurePermissions(0o640))
        ));

        // save() writes a new 0600 inode rather than chmod'ing an attacker
        // controlled file through a link.
        store.save(&path).unwrap();
        assert_eq!(
            fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
        assert!(TokenStore::load(&path).is_ok());
        fs::remove_file(path).unwrap();
    }

    fn unique_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "codev-proxy-token-{label}-{}-{}-{}.toml",
            std::process::id(),
            epoch_seconds(),
            random_text(8)
        ))
    }
}

