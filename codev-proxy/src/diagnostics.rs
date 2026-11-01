use serde::{Deserialize, Serialize};

/// One independently testable layer in the local proxy path.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProxyProbeLayer {
    pub ok: bool,
    pub detail: String,
}

/// Redacted proxy self-check result. It intentionally contains no credentials,
/// target payloads, or full URLs so it can be shown in a support screen.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
pub struct ProxyDiagnostics {
    pub listener: ProxyProbeLayer,
    pub socks_handshake: ProxyProbeLayer,
    pub dns: ProxyProbeLayer,
    pub tcp: ProxyProbeLayer,
    pub udp: ProxyProbeLayer,
    pub interface: Option<String>,
}

impl ProxyDiagnostics {
    pub fn listener_failed(detail: impl Into<String>) -> Self {
        Self {
            listener: ProxyProbeLayer {
                ok: false,
                detail: detail.into(),
            },
            ..Self::default()
        }
    }

    pub fn overall_ok(&self) -> bool {
        self.listener.ok && self.socks_handshake.ok && self.dns.ok && self.tcp.ok && self.udp.ok
    }
}

#[cfg(test)]
mod tests {
    use super::{ProxyDiagnostics, ProxyProbeLayer};

    #[test]
    fn listener_only_failure_is_not_reported_as_a_healthy_proxy() {
        let diagnostics = ProxyDiagnostics::listener_failed("端口未监听");
        assert!(!diagnostics.overall_ok());
        assert!(!diagnostics.listener.ok);
        assert_eq!(diagnostics.listener.detail, "端口未监听");
    }

    #[test]
    fn tcp_dns_udp_failures_remain_separate_layers() {
        let diagnostics = ProxyDiagnostics {
            listener: ProxyProbeLayer {
                ok: true,
                detail: "监听正常".into(),
            },
            socks_handshake: ProxyProbeLayer {
                ok: true,
                detail: "握手正常".into(),
            },
            dns: ProxyProbeLayer {
                ok: false,
                detail: "DNS失败".into(),
            },
            tcp: ProxyProbeLayer {
                ok: false,
                detail: "TCP外网失败".into(),
            },
            udp: ProxyProbeLayer {
                ok: false,
                detail: "UDP中继失败".into(),
            },
            interface: Some("ifindex=4 192.168.1.2".into()),
        };
        assert!(!diagnostics.overall_ok());
        assert!(diagnostics.listener.ok);
        assert!(diagnostics.socks_handshake.ok);
        assert!(!diagnostics.dns.ok);
        assert!(!diagnostics.tcp.ok);
        assert!(!diagnostics.udp.ok);
    }
}
