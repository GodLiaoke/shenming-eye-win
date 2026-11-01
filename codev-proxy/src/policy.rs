use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain { port, .. } => *port,
        }
    }

    pub fn host(&self) -> String {
        match self {
            Self::Ip(address) => address.ip().to_string(),
            Self::Domain { host, .. } => host.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct StrictTargetPolicy {
    exact_hosts: HashSet<String>,
    wildcard_suffixes: Vec<String>,
    ports: HashSet<u16>,
    allow_any_public_target: bool,
    allow_dns_proxying: bool,
    dynamic_targets: DynamicTargetStore,
}

/// Session-bound IP/port targets learned only after an authenticated MNA or
/// MITM session material is installed.  This keeps IP-literal game servers
/// behind the SOCKS path when a later match receives a fresh address, without
/// widening the configured port policy or creating an open relay.
#[derive(Clone, Default)]
pub struct DynamicTargetStore {
    targets: Arc<RwLock<HashSet<SocketAddr>>>,
    /// Ports announced by an authenticated session.  Until the first valid
    /// encrypted UDP tuple is proven, the game may use a VIP/DNS resolution
    /// that is not byte-for-byte equal to the control-plane IP.  Keeping the
    /// port as a short-lived candidate lets the parser see that first packet;
    /// the runtime narrows the store to the proven address immediately after
    /// lock.
    session_ports: Arc<RwLock<HashSet<u16>>>,
}

impl std::fmt::Debug for DynamicTargetStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DynamicTargetStore(<redacted>)")
    }
}

impl DynamicTargetStore {
    pub fn replace(&self, target: Option<SocketAddr>) {
        let mut targets = self
            .targets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut ports = self
            .session_ports
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        targets.clear();
        ports.clear();
        if let Some(target) = target {
            targets.insert(target);
        }
    }

    /// Replace exact session endpoints and retain their ports as a bounded
    /// pre-lock candidate set.  The port fallback is intentionally session
    /// scoped and is narrowed by the decoder after SGNet/UE validation.
    pub fn replace_session_targets(&self, targets: &[SocketAddr], port: u16) {
        let mut exact = self
            .targets
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut ports = self
            .session_ports
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        exact.clear();
        ports.clear();
        if port != 0 {
            ports.insert(port);
        }
        for target in targets {
            exact.insert(*target);
            ports.insert(target.port());
        }
    }

    /// Narrow an already authenticated session to the tuple that passed the
    /// protocol proof.  No other destination remains eligible afterwards.
    pub fn lock_exact(&self, target: SocketAddr) {
        self.replace(Some(target));
    }

    pub fn clear(&self) {
        self.replace(None);
    }

    fn contains(&self, target: SocketAddr) -> bool {
        self.targets
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&target)
    }

    fn contains_port(&self, port: u16) -> bool {
        self.session_ports
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains(&port)
    }
}

impl StrictTargetPolicy {
    pub fn new(allow_hosts: &[String], allow_ports: &[u16]) -> Self {
        Self::new_with_public_target_override(allow_hosts, allow_ports, false)
    }

    pub fn new_with_public_target_override(
        allow_hosts: &[String],
        allow_ports: &[u16],
        allow_any_public_target: bool,
    ) -> Self {
        let mut exact_hosts = HashSet::new();
        let mut wildcard_suffixes = Vec::new();
        for host in allow_hosts {
            let normalized = normalize_host(host);
            if let Some(suffix) = normalized.strip_prefix("*.") {
                wildcard_suffixes.push(suffix.to_owned());
            } else {
                exact_hosts.insert(normalized);
            }
        }
        Self {
            exact_hosts,
            wildcard_suffixes,
            ports: allow_ports.iter().copied().collect(),
            allow_any_public_target,
            allow_dns_proxying: false,
            dynamic_targets: DynamicTargetStore::default(),
        }
    }

    pub fn with_dynamic_targets(mut self, targets: DynamicTargetStore) -> Self {
        self.dynamic_targets = targets;
        self
    }

    pub fn with_dns_proxying(mut self, enabled: bool) -> Self {
        self.allow_dns_proxying = enabled;
        self
    }

    pub fn authorize(&self, target: &TargetAddr) -> Result<(), PolicyError> {
        if target.port() == 53 && !self.allow_dns_proxying {
            return Err(PolicyError::DnsForbidden);
        }
        let host = normalize_host(&target.host());
        let exact = self.exact_hosts.contains(&host);
        let wildcard = matches!(target, TargetAddr::Domain { .. })
            && self.wildcard_suffixes.iter().any(|suffix| {
                host.len() > suffix.len()
                    && host.ends_with(suffix)
                    && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            });
        let dynamic = matches!(target, TargetAddr::Ip(address)
            if self.dynamic_targets.contains(*address));
        let dynamic_port = self.dynamic_targets.contains_port(target.port());

        // An authenticated session may announce a fresh game port and a VIP
        // that was not present in the static profile.  Permit only public IP
        // literals on that one session port until the decoder proves a tuple;
        // `lock_exact` then removes this temporary widening.  Domain targets
        // still need the configured exact/wildcard host, so this cannot turn
        // the proxy into an arbitrary domain relay.
        let session_ip_candidate = matches!(target, TargetAddr::Ip(_)) && dynamic_port;
        let host_allowed =
            exact || wildcard || dynamic || session_ip_candidate || self.allow_any_public_target;
        if !host_allowed {
            return Err(PolicyError::HostNotAllowed(host));
        }
        if let TargetAddr::Ip(address) = target {
            ensure_public_ip(address.ip())?;
        }
        if !self.allow_any_public_target && !self.ports.contains(&target.port()) && !dynamic_port {
            return Err(PolicyError::PortNotAllowed(target.port()));
        }
        Ok(())
    }

    /// Admit only a public IP literal to the bounded MNA probation path.
    /// The TCP relay still withholds all application bytes until the protocol
    /// magic is proven, so this does not turn an authenticated profile into a
    /// general-purpose open proxy when Tencent rotates a control endpoint.
    pub fn authorize_mna_probation(&self, target: &TargetAddr) -> Result<(), PolicyError> {
        if target.port() == 53 {
            return Err(PolicyError::DnsForbidden);
        }
        match target {
            TargetAddr::Ip(address) => ensure_public_ip(address.ip()),
            TargetAddr::Domain { host, .. } => {
                Err(PolicyError::HostNotAllowed(normalize_host(host)))
            }
        }
    }
}

pub trait TargetResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, PolicyError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTargetResolver;

impl TargetResolver for SystemTargetResolver {
    fn resolve<'a>(
        &'a self,
        target: &'a TargetAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, PolicyError>> + Send + 'a>> {
        Box::pin(async move {
            let addresses = match target {
                TargetAddr::Ip(address) => vec![*address],
                TargetAddr::Domain { host, port } => {
                    resolve_domain(host, *port).await?
                }
            };
            if addresses.is_empty() {
                return Err(PolicyError::Resolution("no addresses returned".into()));
            }
            // Reject the complete answer if any member is non-public. Picking a
            // different address would leave a DNS-rebinding path open.
            for address in &addresses {
                ensure_public_ip(address.ip())?;
            }
            let mut unique = Vec::with_capacity(addresses.len());
            for address in addresses {
                if !unique.contains(&address) {
                    unique.push(address);
                }
            }
            Ok(unique)
        })
    }
}

async fn resolve_domain(host: &str, port: u16) -> Result<Vec<SocketAddr>, PolicyError> {
    #[cfg(target_os = "ios")]
    {
        return resolve_domain_via_physical_dns(host, port).await;
    }
    #[cfg(not(target_os = "ios"))]
    {
        tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| PolicyError::Resolution(error.to_string()))
            .map(Iterator::collect)
    }
}

#[cfg(target_os = "ios")]
async fn resolve_domain_via_physical_dns(
    host: &str,
    port: u16,
) -> Result<Vec<SocketAddr>, PolicyError> {
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    const SERVERS: [SocketAddr; 2] = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)), 53),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(119, 29, 29, 29)), 53),
    ];
    let mut addresses = Vec::new();
    let mut last_error = String::from("没有收到 DNS 回包");
    for qtype in [1_u16, 28_u16] {
        let id = dns_query_id(host, qtype);
        let query = build_dns_query(host, id, qtype).map_err(PolicyError::Resolution)?;
        let mut resolved = false;
        for server in SERVERS {
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|error| PolicyError::Resolution(error.to_string()))?;
            crate::netbind::prepare_udp(&socket)
                .map_err(|error| PolicyError::Resolution(format!("物理出口绑定失败：{error}")))?;
            if let Err(error) = socket.send_to(&query, server).await {
                last_error = error.to_string();
                continue;
            }
            let mut response = [0_u8; 1500];
            match timeout(Duration::from_millis(900), socket.recv_from(&mut response)).await {
                Ok(Ok((size, _))) => match parse_dns_addresses(&response[..size], id, qtype) {
                    Ok(found) if !found.is_empty() => {
                        addresses.extend(found.into_iter().map(|ip| SocketAddr::new(ip, port)));
                        resolved = true;
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => last_error = error,
                },
                Ok(Err(error)) => last_error = error.to_string(),
                Err(_) => last_error = "DNS 查询超时".into(),
            }
        }
        if !resolved && qtype == 1 {
            continue;
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        Err(PolicyError::Resolution(last_error))
    } else {
        Ok(addresses)
    }
}

fn dns_query_id(host: &str, qtype: u16) -> u16 {
    let mut hash = 0x4d59_u32 ^ u32::from(qtype);
    for byte in host.as_bytes() {
        hash = hash.rotate_left(5) ^ u32::from(*byte);
    }
    (hash as u16).max(1)
}

fn build_dns_query(host: &str, id: u16, qtype: u16) -> Result<Vec<u8>, String> {
    let mut packet = Vec::with_capacity(256);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("域名格式无效".into());
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn parse_dns_addresses(packet: &[u8], id: u16, qtype: u16) -> Result<Vec<IpAddr>, String> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err("DNS 回包标识不匹配".into());
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x000f != 0 {
        return Err(format!("DNS 返回码 {}", flags & 0x000f));
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        skip_dns_name(packet, &mut offset)?;
        if offset.checked_add(4).filter(|end| *end <= packet.len()).is_none() {
            return Err("DNS 问题段截断".into());
        }
        offset += 4;
    }
    let mut result = Vec::new();
    for _ in 0..answers {
        skip_dns_name(packet, &mut offset)?;
        if offset.checked_add(10).filter(|end| *end <= packet.len()).is_none() {
            return Err("DNS 答案段截断".into());
        }
        let answer_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let class = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
        let length = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset.checked_add(length).filter(|end| *end <= packet.len()).is_none() {
            return Err("DNS 记录数据截断".into());
        }
        if class == 1 && answer_type == qtype {
            match (qtype, length) {
                (1, 4) => result.push(IpAddr::V4(Ipv4Addr::new(
                    packet[offset], packet[offset + 1], packet[offset + 2], packet[offset + 3],
                ))),
                (28, 16) => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&packet[offset..offset + 16]);
                    result.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += length;
    }
    Ok(result)
}

fn skip_dns_name(packet: &[u8], offset: &mut usize) -> Result<(), String> {
    loop {
        let length = *packet.get(*offset).ok_or_else(|| "DNS 名称截断".to_string())?;
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        if length & 0xc0 == 0xc0 {
            if packet.get(*offset).is_none() {
                return Err("DNS 压缩指针截断".into());
            }
            *offset += 1;
            return Ok(());
        }
        if length & 0xc0 != 0 {
            return Err("DNS 名称标签无效".into());
        }
        let end = offset
            .checked_add(length as usize)
            .ok_or_else(|| "DNS 名称过长".to_string())?;
        if end > packet.len() {
            return Err("DNS 名称标签截断".into());
        }
        *offset = end;
    }
}

pub fn ensure_public_ip(ip: IpAddr) -> Result<(), PolicyError> {
    let forbidden = match ip {
        IpAddr::V4(ip) => forbidden_v4(ip),
        IpAddr::V6(ip) => forbidden_v6(ip),
    };
    if forbidden {
        Err(PolicyError::NonPublicAddress(ip))
    } else {
        Ok(())
    }
}

fn forbidden_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || octets[0] == 0
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240
}

fn forbidden_v6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return forbidden_v4(mapped);
    }
    let segments = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00 // unique local fc00::/7
        || (segments[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        || (segments[0] & 0xffc0) == 0xfec0 // deprecated site-local fec0::/10
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("target host is not allowed: {0}")]
    HostNotAllowed(String),
    #[error("target port is not allowed: {0}")]
    PortNotAllowed(u16),
    #[error("DNS proxying is forbidden")]
    DnsForbidden,
    #[error("target resolved to a non-public address: {0}")]
    NonPublicAddress(IpAddr),
    #[error("target resolution failed: {0}")]
    Resolution(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_physical_dns_answers_without_system_resolver() {
        let response = dns_response_for_a("example.com", [93, 184, 216, 34]);
        let addresses = super::parse_dns_addresses(&response, 0x1234, 1).unwrap();
        assert_eq!(addresses, vec!["93.184.216.34".parse::<std::net::IpAddr>().unwrap()]);
    }

    fn dns_response_for_a(host: &str, address: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        for label in host.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        packet.extend_from_slice(&address);
        packet
    }
    use super::*;

    #[test]
    fn exact_and_subdomain_targets_require_both_allowlists() {
        let policy = StrictTargetPolicy::new(
            &["game.example.com".into(), "*.edge.example.com".into()],
            &[443, 10000],
        );
        assert!(
            policy
                .authorize(&TargetAddr::Domain {
                    host: "GAME.EXAMPLE.COM.".into(),
                    port: 443,
                })
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Domain {
                    host: "a.edge.example.com".into(),
                    port: 10000,
                })
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Domain {
                    host: "edge.example.com".into(),
                    port: 10000,
                })
                .is_err()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Domain {
                    host: "game.example.com".into(),
                    port: 80,
                })
                .is_err()
        );
    }

    #[test]
    fn authenticated_dynamic_ip_target_is_limited_to_one_public_host_and_port() {
        let dynamic = DynamicTargetStore::default();
        let policy = StrictTargetPolicy::new(&["game.example.com".into()], &[15_806])
            .with_dynamic_targets(dynamic.clone());
        dynamic.replace(Some("8.8.8.8:15806".parse().unwrap()));
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:15806".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.9:15806".parse().unwrap()))
                .is_err()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:17500".parse().unwrap()))
                .is_err()
        );
        dynamic.clear();
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:15806".parse().unwrap()))
                .is_err()
        );
    }

    #[test]
    fn session_port_fallback_accepts_fresh_public_vip_until_tuple_lock() {
        let dynamic = DynamicTargetStore::default();
        let policy = StrictTargetPolicy::new(&["game.example.com".into()], &[15_806])
            .with_dynamic_targets(dynamic.clone());
        dynamic.replace_session_targets(&[], 17_500);
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.9:17500".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.9:17501".parse().unwrap()))
                .is_err()
        );
        dynamic.lock_exact("8.8.8.9:17500".parse().unwrap());
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.10:17500".parse().unwrap()))
                .is_err()
        );
    }

    #[test]
    fn non_public_ranges_are_rejected() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fc00::1",
            "ff02::1",
        ] {
            assert!(ensure_public_ip(value.parse().unwrap()).is_err(), "{value}");
        }
        assert!(ensure_public_ip("8.8.8.8".parse().unwrap()).is_ok());
        assert!(ensure_public_ip("2606:4700:4700::1111".parse().unwrap()).is_ok());
    }

    #[test]
    fn mna_probation_accepts_only_public_ip_literals() {
        let policy = StrictTargetPolicy::new(&["game.example.com".into()], &[15_806]);
        assert!(
            policy
                .authorize_mna_probation(&TargetAddr::Ip("8.8.8.8:52621".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize_mna_probation(&TargetAddr::Ip("192.168.1.8:52621".parse().unwrap()))
                .is_err()
        );
        assert!(
            policy
                .authorize_mna_probation(&TargetAddr::Ip("8.8.8.8:53".parse().unwrap()))
                .is_err()
        );
        assert!(
            policy
                .authorize_mna_probation(&TargetAddr::Domain {
                    host: "rotated.example.com".into(),
                    port: 52621,
                })
                .is_err()
        );
    }

    #[test]
    fn diagnostic_public_target_override_allows_public_ports_but_keeps_address_guards() {
        let policy = StrictTargetPolicy::new_with_public_target_override(
            &["game.example.com".into()],
            &[80, 443],
            true,
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:443".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Domain {
                    host: "login.example.net".into(),
                    port: 443,
                })
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:8080".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("127.0.0.1:443".parse().unwrap()))
                .is_err()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("8.8.8.8:53".parse().unwrap()))
                .is_err()
        );
    }
    #[test]
    fn mobile_dns_opt_in_allows_public_dns_but_not_lan_targets() {
        let policy = StrictTargetPolicy::new_with_public_target_override(
            &["game.example.com".into()],
            &[443],
            true,
        )
        .with_dns_proxying(true);
        assert!(
            policy
                .authorize(&TargetAddr::Ip("223.5.5.5:53".parse().unwrap()))
                .is_ok()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("127.0.0.1:53".parse().unwrap()))
                .is_err()
        );
        assert!(
            policy
                .authorize(&TargetAddr::Ip("192.168.1.1:53".parse().unwrap()))
                .is_err()
        );
    }
}
