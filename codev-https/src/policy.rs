use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MitmDecision {
    Intercept,
    Tunnel,
    BlockQuic,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MitmPolicy {
    pub enabled: bool,
    pub domains: Vec<String>,
    pub ports: Vec<u16>,
    pub block_quic: bool,
}

impl MitmPolicy {
    pub fn validate(mut self) -> Result<Self, PolicyError> {
        if self.enabled && self.domains.is_empty() {
            return Err(PolicyError::EmptyAllowlist);
        }
        if self.ports.is_empty() {
            self.ports.push(443);
        }
        self.domains = self
            .domains
            .into_iter()
            .map(|domain| normalize_domain(&domain))
            .collect::<Result<Vec<_>, _>>()?;
        self.domains.sort_unstable();
        self.domains.dedup();
        self.ports.sort_unstable();
        self.ports.dedup();
        Ok(self)
    }

    pub fn decide(&self, host: &str, port: u16, udp: bool) -> MitmDecision {
        if !self.enabled {
            return MitmDecision::Tunnel;
        }
        let Ok(host) = normalize_domain(host) else {
            return MitmDecision::Reject;
        };
        let allowed = self.ports.contains(&port)
            && self
                .domains
                .iter()
                .any(|pattern| domain_matches(pattern, &host));
        if !allowed {
            return MitmDecision::Tunnel;
        }
        if udp && port == 443 && self.block_quic {
            MitmDecision::BlockQuic
        } else if udp {
            MitmDecision::Tunnel
        } else {
            MitmDecision::Intercept
        }
    }
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        pattern == host
    }
}

pub fn normalize_domain(value: &str) -> Result<String, PolicyError> {
    let value = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels = value.strip_prefix("*.").unwrap_or(&value);
    if value.is_empty()
        || value.len() > 253
        || labels.parse::<IpAddr>().is_ok()
        || labels.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(PolicyError::InvalidDomain);
    }
    Ok(value)
}

pub fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_v4(address),
        IpAddr::V6(address) => is_public_v6(address),
    }
}

fn is_public_v4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_multicast()
        || address.is_unspecified()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0))
}

fn is_public_v6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || address
            .to_ipv4_mapped()
            .is_some_and(|value| !is_public_v4(value)))
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("HTTPS interception requires a non-empty domain allowlist")]
    EmptyAllowlist,
    #[error("invalid HTTPS allowlist domain")]
    InvalidDomain,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_intercepts_only_allowlisted_tcp_and_blocks_matching_quic() {
        let policy = MitmPolicy {
            enabled: true,
            domains: vec!["api.example.com".into(), "*.game.example".into()],
            ports: vec![443],
            block_quic: true,
        }
        .validate()
        .unwrap();
        assert_eq!(
            policy.decide("API.EXAMPLE.COM", 443, false),
            MitmDecision::Intercept
        );
        assert_eq!(
            policy.decide("a.game.example", 443, true),
            MitmDecision::BlockQuic
        );
        assert_eq!(
            policy.decide("game.example", 443, false),
            MitmDecision::Tunnel
        );
        assert_eq!(
            policy.decide("other.example", 443, false),
            MitmDecision::Tunnel
        );
    }

    #[test]
    fn private_and_special_addresses_are_never_public() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fc00::1",
        ] {
            assert!(!is_public_address(value.parse().unwrap()), "{value}");
        }
        assert!(is_public_address("1.1.1.1".parse().unwrap()));
        assert!(is_public_address("2606:4700:4700::1111".parse().unwrap()));
    }
}
