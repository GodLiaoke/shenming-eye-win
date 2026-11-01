//! 让代理自己的出站连接绕开系统 VPN 隧道。
//!
//! 单机形态下链路是：
//! `游戏 → 系统 TUN(Shadowrocket) → 本进程 SOCKS5(2025) → 出站连接`
//! 最后这一步的出站连接同样会被 TUN 捕获、又送回本进程，形成死循环，
//! 表现就是「连上代理后整台手机没网」。
//!
//! 把出站 socket 绑到物理网卡（Wi-Fi / 蜂窝）之后，这些连接从物理出口直接
//! 出去，不经过隧道，回环消失，单机 + 悬浮窗才成立。
//!
//! Darwin 的 `IP_BOUND_IF` 只影响发送路径，所以同时用于接收本机 SOCKS
//! 客户端报文的 UDP 中继 socket 也不受影响。
//!
//! 只在 iOS 上生效；macOS / Windows 构建行为完全不变。

#[cfg(target_os = "ios")]
mod platform {
    use std::io;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    use tokio::net::{TcpSocket, UdpSocket};

    /// Darwin 的 `IP_BOUND_IF`。
    const IP_BOUND_IF: libc::c_int = 25;
    const IPV6_BOUND_IF: libc::c_int = 125;

    /// 候选物理网卡，按优先级排列：先 Wi-Fi，再蜂窝。
    const CANDIDATES: [&str; 4] = ["en0", "pdp_ip0", "pdp_ip1", "pdp_ip2"];

    /// 缓存一份物理网卡信息。Wi-Fi / 蜂窝会随时切换，所以只缓存一小段时间，
    /// 避免对局中途切网后还在用已经消失的接口号。
    const CACHE_TTL: Duration = Duration::from_secs(2);

    struct Cache {
        initialized: bool,
        at: Instant,
        value: Option<(u32, Ipv4Addr)>,
    }

    static CACHED: OnceLock<Mutex<Cache>> = OnceLock::new();

    fn bound_interface() -> Option<(u32, Ipv4Addr)> {
        let cell = CACHED.get_or_init(|| {
            Mutex::new(Cache {
                initialized: false,
                at: Instant::now(),
                value: None,
            })
        });
        let mut cache = cell.lock().unwrap_or_else(|error| error.into_inner());
        if !cache.initialized || cache.at.elapsed() >= CACHE_TTL {
            cache.value = probe();
            cache.at = Instant::now();
            cache.initialized = true;
        }
        cache.value
    }

    /// 找到第一个「已启用且有 IPv4 地址」的物理网卡。
    fn probe() -> Option<(u32, Ipv4Addr)> {
        let mut best: Option<(usize, u32, Ipv4Addr)> = None;
        unsafe {
            let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut head) != 0 {
                return None;
            }
            let mut cursor = head;
            while !cursor.is_null() {
                let entry = &*cursor;
                cursor = entry.ifa_next;
                if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
                    continue;
                }
                if (*entry.ifa_addr).sa_family as i32 != libc::AF_INET {
                    continue;
                }
                if entry.ifa_flags & libc::IFF_UP as u32 == 0 {
                    continue;
                }
                let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
                let Some(rank) = CANDIDATES.iter().position(|candidate| *candidate == name) else {
                    continue;
                };
                let index = libc::if_nametoindex(entry.ifa_name);
                if index == 0 {
                    continue;
                }
                let sin = entry.ifa_addr as *const libc::sockaddr_in;
                let address = Ipv4Addr::from(u32::from_be((*sin).sin_addr.s_addr));
                if address.is_loopback() || address.is_unspecified() {
                    continue;
                }
                if best
                    .as_ref()
                    .map(|current| rank < current.0)
                    .unwrap_or(true)
                {
                    best = Some((rank, index, address));
                }
            }
            libc::freeifaddrs(head);
        }
        best.map(|(_, index, address)| (index, address))
    }

    fn set_bound_interface(fd: RawFd, index: u32, ipv6: bool) -> io::Result<()> {
        let value = index as libc::c_int;
        let result = unsafe {
            libc::setsockopt(
                fd,
                if ipv6 {
                    libc::IPPROTO_IPV6
                } else {
                    libc::IPPROTO_IP
                },
                if ipv6 { IPV6_BOUND_IF } else { IP_BOUND_IF },
                (&value as *const libc::c_int).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    /// 出站 TCP：优先 `IP_BOUND_IF`，失败则退化为把源地址绑到物理网卡地址
    /// （Darwin 会据此选择物理出口）。找不到物理网卡时保持原行为。
    pub fn prepare_tcp(socket: &TcpSocket) -> io::Result<()> {
        let Some((index, address)) = bound_interface() else {
            return Ok(());
        };
        let ipv6 = socket.local_addr()?.is_ipv6();
        if set_bound_interface(socket.as_raw_fd(), index, ipv6).is_ok() {
            return Ok(());
        }
        if ipv6 {
            return Err(io::Error::last_os_error());
        }
        socket.bind(SocketAddr::new(IpAddr::V4(address), 0))
    }

    /// 出站 UDP（中继 socket）：只设置发送出口，接收本机客户端报文不受影响。
    pub fn prepare_udp(socket: &UdpSocket) -> io::Result<()> {
        let Some((index, _)) = bound_interface() else {
            return Ok(());
        };
        set_bound_interface(socket.as_raw_fd(), index, socket.local_addr()?.is_ipv6())
    }

    pub fn prepare_udp_destination(socket: &UdpSocket, destination: SocketAddr) -> io::Result<()> {
        if !super::udp_uses_physical_interface(destination) {
            // Replies to the authenticated loopback/LAN client must use the
            // normal local route, not the physical-only outbound route.
            return set_bound_interface(socket.as_raw_fd(), 0, socket.local_addr()?.is_ipv6());
        }
        let index = bound_interface().map_or(0, |(index, _)| index);
        if index == 0 {
            return Ok(());
        }
        set_bound_interface(socket.as_raw_fd(), index, socket.local_addr()?.is_ipv6())
    }

    /// 诊断用：当前绑定的物理出口。
    pub fn interface_summary() -> Option<String> {
        let (index, address) = bound_interface()?;
        Some(format!("ifindex={index} {address}"))
    }
}

#[cfg(not(target_os = "ios"))]
mod platform {
    use std::io;
    use tokio::net::{TcpSocket, UdpSocket};

    pub fn prepare_tcp(_socket: &TcpSocket) -> io::Result<()> {
        Ok(())
    }

    pub fn prepare_udp(_socket: &UdpSocket) -> io::Result<()> {
        Ok(())
    }

    pub fn prepare_udp_destination(
        _socket: &UdpSocket,
        _destination: std::net::SocketAddr,
    ) -> io::Result<()> {
        Ok(())
    }

    pub fn interface_summary() -> Option<String> {
        None
    }
}

pub use platform::{interface_summary, prepare_tcp, prepare_udp, prepare_udp_destination};

fn udp_uses_physical_interface(destination: std::net::SocketAddr) -> bool {
    crate::ensure_public_ip(destination.ip()).is_ok()
}

/// 便于调用点忽略失败：绑定失败不应该让代理整体不可用。
#[inline]
pub fn try_prepare_tcp(socket: &tokio::net::TcpSocket) {
    let _ = prepare_tcp(socket);
}

/// 便于调用点忽略失败。
#[inline]
pub fn try_prepare_udp(socket: &tokio::net::UdpSocket) {
    let _ = prepare_udp(socket);
}

#[cfg(test)]
mod tests {
    #[test]
    fn udp_replies_to_local_clients_do_not_use_the_physical_outbound_route() {
        assert!(!super::udp_uses_physical_interface(
            "127.0.0.1:2222".parse().unwrap()
        ));
        assert!(!super::udp_uses_physical_interface(
            "192.168.1.8:2222".parse().unwrap()
        ));
        assert!(!super::udp_uses_physical_interface(
            "[::1]:2222".parse().unwrap()
        ));
        assert!(super::udp_uses_physical_interface(
            "223.5.5.5:53".parse().unwrap()
        ));
    }
}
