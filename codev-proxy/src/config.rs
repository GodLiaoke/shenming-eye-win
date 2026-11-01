use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProxyFileConfig {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub mitm: MitmRoutingConfig,
}

impl ProxyFileConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    pub fn runtime(&self) -> RuntimeProxyConfig {
        RuntimeProxyConfig {
            proxy: self.proxy.clone(),
            block_quic: self.mitm.block_quic,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.proxy.validate()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub listen: SocketAddr,
    pub token_store: Option<PathBuf>,
    /// Public address advertised in generated Shadowrocket profiles.  It is
    /// deliberately separate from `listen`, which may bind a wildcard.
    pub advertised_host: Option<String>,
    pub advertised_port: Option<u16>,
    pub profile_ttl_secs: u64,
    pub profile_store: Option<PathBuf>,
    pub token_ttl_secs: u64,
    pub udp_idle_secs: u64,
    /// Optional inclusive port range used for RFC 1928 UDP relay sockets.
    /// `None` preserves the legacy OS-selected ephemeral-port behaviour.
    pub udp_relay_ports: Option<UdpRelayPortRange>,
    pub handshake_timeout_secs: u64,
    pub max_total_connections: usize,
    pub max_connections_per_token: u32,
    pub max_udp_flows_per_token: u32,
    pub bytes_per_second_per_token: u64,
    /// Diagnostic-only escape hatch for a credentialed profile. Host/IP
    /// targets may use any public address and non-DNS port, while DNS blocking,
    /// quotas and non-public-address rejection remain enforced.
    pub allow_any_public_target: bool,
    /// Mobile full-device SOCKS routing needs DNS packets too. Kept opt-in so
    /// server profiles retain their original strict DNS policy.
    pub allow_dns_proxying: bool,
    pub allow_hosts: Vec<String>,
    pub allow_ports: Vec<u16>,
    /// C 方案：节点免鉴权。
    ///
    /// `true` 时 SOCKS5 握手接受 **no-auth (0x00)** 方法，客户端只要 ip+端口
    /// 就能连（不再需要用户名密码）；同时**仍然接受** password (0x02)，所以
    /// 老客户端已下发的账号密码配置不会失效。
    ///
    /// 默认 `false`：行为与以前完全一致（只接受密码鉴权）。
    /// 打开后，免鉴权连接复用内置的**匿名令牌**做限流/配额计量
    /// （见 [`crate::TokenStore::anonymous_permit`]）。
    pub allow_anonymous: bool,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:1080".parse().unwrap(),
            token_store: None,
            advertised_host: None,
            advertised_port: None,
            profile_ttl_secs: 365 * 24 * 60 * 60,
            profile_store: None,
            token_ttl_secs: 3_600,
            udp_idle_secs: 30,
            udp_relay_ports: None,
            handshake_timeout_secs: 10,
            max_total_connections: 256,
            max_connections_per_token: 8,
            max_udp_flows_per_token: 16,
            bytes_per_second_per_token: 16 * 1024 * 1024,
            allow_any_public_target: false,
            allow_dns_proxying: false,
            allow_hosts: Vec::new(),
            allow_ports: Vec::new(),
            allow_anonymous: false,
        }
    }
}

impl ProxyConfig {
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        Ok(ProxyFileConfig::from_toml(input)?.proxy)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.token_ttl_secs == 0 {
            return Err(ConfigError::Invalid("token_ttl_secs must be non-zero"));
        }
        if self.profile_ttl_secs == 0 {
            return Err(ConfigError::Invalid("profile_ttl_secs must be non-zero"));
        }
        if self.advertised_port == Some(0) {
            return Err(ConfigError::Invalid("advertised_port must be non-zero"));
        }
        if let Some(host) = self.advertised_host.as_deref() {
            validate_advertised_host(host)?;
        }
        if self.udp_idle_secs == 0 {
            return Err(ConfigError::Invalid("udp_idle_secs must be non-zero"));
        }
        if let Some(range) = self.udp_relay_ports {
            range.validate()?;
        }
        if self.handshake_timeout_secs == 0 {
            return Err(ConfigError::Invalid(
                "handshake_timeout_secs must be non-zero",
            ));
        }
        if self.max_total_connections == 0
            || self.max_connections_per_token == 0
            || self.max_udp_flows_per_token == 0
            || self.bytes_per_second_per_token == 0
        {
            return Err(ConfigError::Invalid(
                "connection, UDP-flow and bandwidth limits must be non-zero",
            ));
        }
        if self.allow_hosts.is_empty() || self.allow_ports.is_empty() {
            return Err(ConfigError::Invalid(
                "allow_hosts and allow_ports must both be non-empty",
            ));
        }
        if self.allow_ports.contains(&0) {
            return Err(ConfigError::Invalid(
                "port zero is never permitted in the allowlist",
            ));
        }
        if self.allow_ports.contains(&53) && !self.allow_dns_proxying {
            return Err(ConfigError::Invalid(
                "DNS proxying on port 53 is never permitted",
            ));
        }
        for host in &self.allow_hosts {
            validate_allow_host(host)?;
        }
        Ok(())
    }

    pub fn token_limits(&self) -> crate::TokenLimits {
        crate::TokenLimits {
            max_connections: self.max_connections_per_token,
            max_udp_flows: self.max_udp_flows_per_token,
            bytes_per_second: self.bytes_per_second_per_token,
            udp_idle_secs: self.udp_idle_secs,
        }
    }
}

fn validate_advertised_host(host: &str) -> Result<(), ConfigError> {
    if host.trim() != host || host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(ConfigError::Invalid("advertised_host is invalid"));
    }
    let bare_host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if bare_host.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    if host.starts_with("*.") {
        return Err(ConfigError::Invalid(
            "advertised_host must be an exact host",
        ));
    }
    validate_allow_host(host)
}

/// Inclusive, fixed UDP relay port pool.
///
/// A socket owns its selected port for the entire lifetime of one UDP
/// association. Binding is delegated to the operating system, so concurrent
/// associations can never be assigned the same address/port tuple.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct UdpRelayPortRange {
    pub start: u16,
    pub end: u16,
}

impl UdpRelayPortRange {
    pub fn validate(self) -> Result<(), ConfigError> {
        if self.start == 0 || self.end == 0 {
            return Err(ConfigError::Invalid(
                "udp_relay_ports must not contain port zero",
            ));
        }
        if self.start > self.end {
            return Err(ConfigError::Invalid(
                "udp_relay_ports.start must be less than or equal to end",
            ));
        }
        Ok(())
    }

    pub(crate) fn len(self) -> u32 {
        u32::from(self.end) - u32::from(self.start) + 1
    }
}

fn validate_allow_host(host: &str) -> Result<(), ConfigError> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host == "*" || host.len() > 253 || !host.is_ascii() {
        return Err(ConfigError::InvalidOwned(format!(
            "invalid or unsafe allowed host {host:?}"
        )));
    }
    let bare = host.strip_prefix("*.").unwrap_or(host);
    if bare.is_empty()
        || bare.starts_with('.')
        || bare.ends_with('.')
        || bare.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        // IP literals contain ':' or labels that are numeric and dots. Parse
        // them before applying the DNS-label validation.
        if host.parse::<std::net::IpAddr>().is_err() {
            return Err(ConfigError::InvalidOwned(format!(
                "invalid allowed host {host:?}"
            )));
        }
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct RuntimeProxyConfig {
    pub proxy: ProxyConfig,
    pub block_quic: bool,
}

impl From<ProxyConfig> for RuntimeProxyConfig {
    fn from(proxy: ProxyConfig) -> Self {
        Self {
            proxy,
            block_quic: false,
        }
    }
}

impl RuntimeProxyConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.proxy.validate()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct MitmRoutingConfig {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub ca_dir: Option<PathBuf>,
    pub block_quic: bool,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid proxy configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid proxy configuration: {0}")]
    InvalidOwned(String),
    #[error("invalid TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposed_toml_shape_loads() {
        let parsed = ProxyFileConfig::from_toml(
            r#"
                [proxy]
                listen = "0.0.0.0:1080"
                token_ttl_secs = 3600
                udp_idle_secs = 30
                udp_relay_ports = { start = 20000, end = 20127 }
                allow_hosts = ["game.example.com", "*.edge.example.com"]
                allow_ports = [443, 10000, 10001]

                [mitm]
                enabled = true
                domains = ["game.example.com"]
                ca_dir = "/var/lib/codev/ca"
                block_quic = true
            "#,
        )
        .unwrap();
        assert_eq!(parsed.proxy.listen.port(), 1080);
        assert_eq!(
            parsed.proxy.udp_relay_ports,
            Some(UdpRelayPortRange {
                start: 20000,
                end: 20127,
            })
        );
        assert!(parsed.runtime().block_quic);
    }

    #[test]
    fn empty_or_open_allowlists_and_dns_are_rejected() {
        let mut config = ProxyConfig::default();
        assert!(config.validate().is_err());
        config.allow_hosts = vec!["*".into()];
        config.allow_ports = vec![443];
        assert!(config.validate().is_err());
        config.allow_hosts = vec!["game.example.com".into()];
        config.allow_ports = vec![53];
        assert!(config.validate().is_err());
    }

    #[test]
    fn advertised_profile_endpoint_rejects_delimiter_injection() {
        let mut config = ProxyConfig {
            allow_hosts: vec!["game.example.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        config.advertised_host = Some("game example.com".into());
        assert!(config.validate().is_err());
        config.advertised_host = Some("[2001:db8::10]".into());
        assert!(config.validate().is_ok());
        config.advertised_host = Some("*.example.com".into());
        assert!(config.validate().is_err());
        config.advertised_host = Some("例.example.com".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn udp_relay_port_range_is_optional_but_strict_when_configured() {
        let mut config = ProxyConfig {
            allow_hosts: vec!["game.example.com".into()],
            allow_ports: vec![443],
            ..Default::default()
        };
        assert!(config.validate().is_ok());

        config.udp_relay_ports = Some(UdpRelayPortRange {
            start: 20_000,
            end: 20_127,
        });
        assert!(config.validate().is_ok());

        config.udp_relay_ports = Some(UdpRelayPortRange {
            start: 20_001,
            end: 20_000,
        });
        assert!(config.validate().is_err());

        config.udp_relay_ports = Some(UdpRelayPortRange { start: 0, end: 1 });
        assert!(config.validate().is_err());
    }
}
