use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use codev_https::MitmAuthority;
use codev_proxy::{
    ProfileCredential, ProfileError, ProfileStatus, ProfileStore, ProxyConfig, TokenStore,
};
use tokio::sync::Mutex;

use crate::mirror_access::MirrorAccess;

/// Runtime-owned services exposed to the authenticated control panel.  Replay
/// and pcap-only hubs leave these fields empty, so their surfaces remain
/// read-only and no proxy/CA material is accidentally fabricated.
#[derive(Clone, Default)]
pub struct PanelServices {
    pub proxy: Option<Arc<ProxyPanelService>>,
    pub ca: Option<Arc<CaPanelService>>,
}

#[derive(Clone)]
pub struct ProxyPanelService {
    pub config: ProxyConfig,
    pub tokens: TokenStore,
    pub token_path: PathBuf,
    pub profiles: ProfileStore,
    pub public_base_url: Option<String>,
    /// 是否允许私网地址 Host（局域网共享面板）。
    pub allow_lan_hosts: bool,
    /// 异地观看写入端的房间令牌自校验（`None` = 该路由仍走统一会话中间件）。
    pub mirror_access: Option<Arc<MirrorAccess>>,
    grants: Arc<Mutex<HashMap<String, DownloadGrant>>>,
}

#[derive(Clone, Debug)]
struct DownloadGrant {
    profile_id: String,
    secret: String,
    expires_at: u64,
}

impl ProxyPanelService {
    pub fn new(
        config: ProxyConfig,
        tokens: TokenStore,
        token_path: impl AsRef<Path>,
        profiles: ProfileStore,
        public_base_url: Option<String>,
        allow_lan_hosts: bool,
    ) -> Self {
        Self {
            config,
            tokens,
            token_path: token_path.as_ref().to_owned(),
            profiles,
            public_base_url,
            allow_lan_hosts,
            mirror_access: None,
            grants: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// 打开"房间令牌自校验"（异地观看写入端）。不调用 = 保持原行为。
    pub fn with_mirror_access(mut self, access: Option<Arc<MirrorAccess>>) -> Self {
        self.mirror_access = access;
        self
    }

    pub fn create_profile(&self, label: Option<&str>) -> Result<ProfileCredential, ProfileError> {
        let limits = self.config.token_limits();
        let credential =
            self.profiles
                .create(&self.tokens, limits, self.config.profile_ttl_secs, label)?;
        self.tokens
            .save(&self.token_path)
            .map_err(ProfileError::Token)?;
        Ok(credential)
    }

    pub fn rotate_profile(&self, profile_id: &str) -> Result<ProfileCredential, ProfileError> {
        let credential =
            self.profiles
                .rotate(&self.tokens, profile_id, self.config.profile_ttl_secs)?;
        self.tokens
            .save(&self.token_path)
            .map_err(ProfileError::Token)?;
        Ok(credential)
    }

    pub fn revoke_profile(&self, profile_id: &str) -> Result<ProfileStatus, ProfileError> {
        let status = self.profiles.revoke(&self.tokens, profile_id)?;
        self.tokens
            .save(&self.token_path)
            .map_err(ProfileError::Token)?;
        Ok(status)
    }

    pub async fn issue_download_grant(&self, credential: &ProfileCredential) -> String {
        let nonce = format!("d_{:032x}", rand::random::<u128>());
        self.grants.lock().await.insert(
            nonce.clone(),
            DownloadGrant {
                profile_id: credential.metadata.profile_id.clone(),
                secret: format!("{}.{}", credential.metadata.username, credential.secret),
                expires_at: epoch_seconds().saturating_add(15 * 60),
            },
        );
        nonce
    }

    pub async fn resolve_download_grant(&self, profile_id: &str, nonce: &str) -> Option<String> {
        let mut grants = self.grants.lock().await;
        let grant = grants.get(nonce)?.clone();
        if grant.profile_id != profile_id || grant.expires_at <= epoch_seconds() {
            grants.remove(nonce);
            return None;
        }
        Some(grant.secret)
    }
}

#[derive(Clone)]
pub struct CaPanelService {
    pub authority: Arc<MitmAuthority>,
}

impl CaPanelService {
    pub fn new(authority: Arc<MitmAuthority>) -> Self {
        Self { authority }
    }
}

fn epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
