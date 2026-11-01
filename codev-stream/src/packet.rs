use std::fmt;

use thiserror::Error;

use crate::{CapturedPacket, DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_NULL, DLT_RAW};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpAddress {
    V4([u8; 4]),
    V6([u8; 16]),
}

impl fmt::Display for IpAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4(bytes) => std::net::Ipv4Addr::from(*bytes).fmt(formatter),
            Self::V6(bytes) => std::net::Ipv6Addr::from(*bytes).fmt(formatter),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ip: IpAddress,
    pub port: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportKind {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityStatus {
    Valid,
    Invalid,
    OffloadSeed,
    Disabled,
    NotApplicable,
    NotValidated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketIntegrity {
    pub ipv4_header_checksum: IntegrityStatus,
    pub udp_checksum: IntegrityStatus,
    pub ipv4_header_checksum_value: Option<u16>,
    pub udp_checksum_value: Option<u16>,
    pub udp_checksum_reason: Option<&'static str>,
}

#[derive(Clone, Copy, Debug)]
pub struct TransportPacket<'a> {
    pub capture_index: u64,
    pub timestamp_ns: u64,
    pub source: Endpoint,
    pub destination: Endpoint,
    pub kind: TransportKind,
    pub tcp_sequence: Option<u32>,
    pub tcp_flags: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PacketError {
    #[error("unsupported link type {0}")]
    UnsupportedLinkType(u32),
    #[error("truncated {layer} header: need {needed}, have {available}")]
    Truncated {
        layer: &'static str,
        needed: usize,
        available: usize,
    },
    #[error("unsupported network ethertype 0x{0:04x}")]
    UnsupportedEtherType(u16),
    #[error("unsupported IP protocol {0}")]
    UnsupportedIpProtocol(u8),
    #[error("fragmented IP packets are not accepted by the session parser")]
    Fragmented,
    #[error("invalid {0} length")]
    InvalidLength(&'static str),
}

pub fn parse_transport(packet: &CapturedPacket) -> Result<TransportPacket<'_>, PacketError> {
    let (ethertype, network) = link_payload(packet.link_type, &packet.data)?;
    let (source_ip, destination_ip, protocol, transport) = match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4(network)?,
        ETHERTYPE_IPV6 => parse_ipv6(network)?,
        other => return Err(PacketError::UnsupportedEtherType(other)),
    };
    match protocol {
        6 => parse_tcp(packet, source_ip, destination_ip, transport),
        17 => parse_udp(packet, source_ip, destination_ip, transport),
        other => Err(PacketError::UnsupportedIpProtocol(other)),
    }
}

/// Validate IPv4 and UDP checksums without treating a host-side checksum
/// offload seed as wire corruption.
pub fn validate_packet_integrity(packet: &CapturedPacket) -> Result<PacketIntegrity, PacketError> {
    let (ethertype, network) = link_payload(packet.link_type, &packet.data)?;
    if ethertype != ETHERTYPE_IPV4 {
        return Ok(PacketIntegrity {
            ipv4_header_checksum: IntegrityStatus::NotApplicable,
            udp_checksum: IntegrityStatus::NotApplicable,
            ipv4_header_checksum_value: None,
            udp_checksum_value: None,
            udp_checksum_reason: None,
        });
    }
    need(network, 20, "IPv4")?;
    let header_length = usize::from(network[0] & 0x0f) * 4;
    if header_length < 20 {
        return Err(PacketError::InvalidLength("IPv4 header"));
    }
    need(network, header_length, "IPv4")?;
    let total_length = usize::from(u16::from_be_bytes([network[2], network[3]]));
    if total_length < header_length || total_length > network.len() {
        return Err(PacketError::InvalidLength("IPv4 total"));
    }
    let ipv4_header_checksum = if packet.link_type == DLT_EN10MB {
        if folded_ones_complement_sum(&network[..header_length]) == 0xffff {
            IntegrityStatus::Valid
        } else {
            IntegrityStatus::Invalid
        }
    } else {
        IntegrityStatus::NotValidated
    };
    let ipv4_header_checksum_value = Some(u16::from_be_bytes([network[10], network[11]]));
    if network[9] != 17 {
        return Ok(PacketIntegrity {
            ipv4_header_checksum,
            udp_checksum: IntegrityStatus::NotApplicable,
            ipv4_header_checksum_value,
            udp_checksum_value: None,
            udp_checksum_reason: None,
        });
    }
    let fragment = u16::from_be_bytes([network[6], network[7]]);
    if fragment & 0x3fff != 0 {
        return Ok(PacketIntegrity {
            ipv4_header_checksum,
            udp_checksum: IntegrityStatus::NotValidated,
            ipv4_header_checksum_value,
            udp_checksum_value: None,
            udp_checksum_reason: None,
        });
    }
    let udp = &network[header_length..total_length];
    need(udp, 8, "UDP")?;
    let udp_length = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if udp_length < 8 || udp_length > udp.len() {
        return Ok(PacketIntegrity {
            ipv4_header_checksum,
            udp_checksum: IntegrityStatus::NotValidated,
            ipv4_header_checksum_value,
            udp_checksum_value: None,
            udp_checksum_reason: None,
        });
    }
    let checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if checksum == 0 {
        return Ok(PacketIntegrity {
            ipv4_header_checksum,
            udp_checksum: IntegrityStatus::Disabled,
            ipv4_header_checksum_value,
            udp_checksum_value: Some(checksum),
            udp_checksum_reason: None,
        });
    }
    let mut pseudo = [0_u8; 12];
    pseudo[..8].copy_from_slice(&network[12..20]);
    pseudo[9] = 17;
    pseudo[10..12].copy_from_slice(&(udp_length as u16).to_be_bytes());
    let complete = folded_ones_complement_sum_parts([&pseudo[..], &udp[..udp_length]]);
    let udp_checksum = if complete == 0xffff {
        IntegrityStatus::Valid
    } else if checksum == folded_ones_complement_sum(&pseudo) {
        IntegrityStatus::OffloadSeed
    } else {
        IntegrityStatus::Invalid
    };
    let udp_checksum_reason = (udp_checksum == IntegrityStatus::OffloadSeed).then_some(
        "captured value is the folded IPv4 pseudo-header sum written before NIC offload",
    );
    Ok(PacketIntegrity {
        ipv4_header_checksum,
        udp_checksum,
        ipv4_header_checksum_value,
        udp_checksum_value: Some(checksum),
        udp_checksum_reason,
    })
}

fn folded_ones_complement_sum(data: &[u8]) -> u16 {
    folded_ones_complement_sum_parts([data])
}

fn folded_ones_complement_sum_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> u16 {
    let mut total = 0_u64;
    let mut pending = None;
    for part in parts {
        let mut bytes = part;
        if let Some(high) = pending.take() {
            if let Some((&low, rest)) = bytes.split_first() {
                total += u64::from(u16::from_be_bytes([high, low]));
                bytes = rest;
            } else {
                pending = Some(high);
                continue;
            }
        }
        let mut pairs = bytes.chunks_exact(2);
        total += pairs
            .by_ref()
            .map(|pair| u64::from(u16::from_be_bytes([pair[0], pair[1]])))
            .sum::<u64>();
        pending = pairs.remainder().first().copied();
    }
    if let Some(high) = pending {
        total += u64::from(high) << 8;
    }
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    total as u16
}

fn need(data: &[u8], length: usize, layer: &'static str) -> Result<(), PacketError> {
    if data.len() < length {
        Err(PacketError::Truncated {
            layer,
            needed: length,
            available: data.len(),
        })
    } else {
        Ok(())
    }
}

fn link_payload(link_type: u32, data: &[u8]) -> Result<(u16, &[u8]), PacketError> {
    match link_type {
        DLT_EN10MB => {
            need(data, 14, "Ethernet")?;
            let mut offset = 14;
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                need(data, offset + 4, "VLAN")?;
                ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
            }
            Ok((ethertype, &data[offset..]))
        }
        DLT_LINUX_SLL => {
            need(data, 16, "Linux cooked v1")?;
            Ok((u16::from_be_bytes([data[14], data[15]]), &data[16..]))
        }
        DLT_LINUX_SLL2 => {
            need(data, 20, "Linux cooked v2")?;
            Ok((u16::from_be_bytes([data[0], data[1]]), &data[20..]))
        }
        DLT_NULL => {
            need(data, 4, "loopback")?;
            let family_le = u32::from_le_bytes(data[..4].try_into().unwrap());
            let family_be = u32::from_be_bytes(data[..4].try_into().unwrap());
            let ethertype = match (family_le, family_be) {
                (2, _) | (_, 2) => ETHERTYPE_IPV4,
                (30, _) | (_, 30) | (10, _) | (_, 10) => ETHERTYPE_IPV6,
                _ => return Err(PacketError::UnsupportedEtherType(0)),
            };
            Ok((ethertype, &data[4..]))
        }
        DLT_RAW => {
            need(data, 1, "raw IP")?;
            match data[0] >> 4 {
                4 => Ok((ETHERTYPE_IPV4, data)),
                6 => Ok((ETHERTYPE_IPV6, data)),
                _ => Err(PacketError::UnsupportedEtherType(0)),
            }
        }
        other => Err(PacketError::UnsupportedLinkType(other)),
    }
}

fn parse_ipv4(data: &[u8]) -> Result<(IpAddress, IpAddress, u8, &[u8]), PacketError> {
    need(data, 20, "IPv4")?;
    if data[0] >> 4 != 4 {
        return Err(PacketError::InvalidLength("IPv4 version"));
    }
    let header_length = usize::from(data[0] & 0x0f) * 4;
    if header_length < 20 {
        return Err(PacketError::InvalidLength("IPv4 header"));
    }
    need(data, header_length, "IPv4")?;
    let total_length = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if total_length < header_length || total_length > data.len() {
        return Err(PacketError::InvalidLength("IPv4 total"));
    }
    let fragment = u16::from_be_bytes([data[6], data[7]]);
    if fragment & 0x3fff != 0 {
        return Err(PacketError::Fragmented);
    }
    Ok((
        IpAddress::V4(data[12..16].try_into().unwrap()),
        IpAddress::V4(data[16..20].try_into().unwrap()),
        data[9],
        &data[header_length..total_length],
    ))
}

fn parse_ipv6(data: &[u8]) -> Result<(IpAddress, IpAddress, u8, &[u8]), PacketError> {
    need(data, 40, "IPv6")?;
    if data[0] >> 4 != 6 {
        return Err(PacketError::InvalidLength("IPv6 version"));
    }
    let payload_length = usize::from(u16::from_be_bytes([data[4], data[5]]));
    let boundary = 40_usize
        .checked_add(payload_length)
        .ok_or(PacketError::InvalidLength("IPv6 payload"))?;
    if boundary > data.len() {
        return Err(PacketError::InvalidLength("IPv6 payload"));
    }
    let source = IpAddress::V6(data[8..24].try_into().unwrap());
    let destination = IpAddress::V6(data[24..40].try_into().unwrap());
    let mut protocol = data[6];
    let mut offset = 40;
    loop {
        match protocol {
            0 | 43 | 60 => {
                need(&data[..boundary], offset + 2, "IPv6 extension")?;
                let next = data[offset];
                let length = (usize::from(data[offset + 1]) + 1) * 8;
                need(&data[..boundary], offset + length, "IPv6 extension")?;
                protocol = next;
                offset += length;
            }
            44 => return Err(PacketError::Fragmented),
            _ => break,
        }
    }
    Ok((source, destination, protocol, &data[offset..boundary]))
}

fn parse_tcp<'a>(
    packet: &CapturedPacket,
    source_ip: IpAddress,
    destination_ip: IpAddress,
    data: &'a [u8],
) -> Result<TransportPacket<'a>, PacketError> {
    need(data, 20, "TCP")?;
    let header_length = usize::from(data[12] >> 4) * 4;
    if header_length < 20 || header_length > data.len() {
        return Err(PacketError::InvalidLength("TCP header"));
    }
    Ok(TransportPacket {
        capture_index: packet.index,
        timestamp_ns: packet.timestamp_ns,
        source: Endpoint {
            ip: source_ip,
            port: u16::from_be_bytes([data[0], data[1]]),
        },
        destination: Endpoint {
            ip: destination_ip,
            port: u16::from_be_bytes([data[2], data[3]]),
        },
        kind: TransportKind::Tcp,
        tcp_sequence: Some(u32::from_be_bytes(data[4..8].try_into().unwrap())),
        tcp_flags: (u16::from(data[12] & 1) << 8) | u16::from(data[13]),
        payload: &data[header_length..],
    })
}

fn parse_udp<'a>(
    packet: &CapturedPacket,
    source_ip: IpAddress,
    destination_ip: IpAddress,
    data: &'a [u8],
) -> Result<TransportPacket<'a>, PacketError> {
    need(data, 8, "UDP")?;
    let length = usize::from(u16::from_be_bytes([data[4], data[5]]));
    if length < 8 || length > data.len() {
        return Err(PacketError::InvalidLength("UDP datagram"));
    }
    Ok(TransportPacket {
        capture_index: packet.index,
        timestamp_ns: packet.timestamp_ns,
        source: Endpoint {
            ip: source_ip,
            port: u16::from_be_bytes([data[0], data[1]]),
        },
        destination: Endpoint {
            ip: destination_ip,
            port: u16::from_be_bytes([data[2], data[3]]),
        },
        kind: TransportKind::Udp,
        tcp_sequence: None,
        tcp_flags: 0,
        payload: &data[8..length],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ethernet_ipv4_udp_without_copying_payload() {
        let mut data = vec![0_u8; 14 + 20 + 8 + 3];
        data[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        let ip = 14;
        data[ip] = 0x45;
        data[ip + 2..ip + 4].copy_from_slice(&(31_u16).to_be_bytes());
        data[ip + 9] = 17;
        data[ip + 12..ip + 16].copy_from_slice(&[10, 0, 0, 1]);
        data[ip + 16..ip + 20].copy_from_slice(&[10, 0, 0, 2]);
        let udp = ip + 20;
        data[udp..udp + 2].copy_from_slice(&1234_u16.to_be_bytes());
        data[udp + 2..udp + 4].copy_from_slice(&5678_u16.to_be_bytes());
        data[udp + 4..udp + 6].copy_from_slice(&11_u16.to_be_bytes());
        data[udp + 8..udp + 11].copy_from_slice(b"abc");
        let capture = CapturedPacket {
            index: 7,
            timestamp_ns: 9,
            original_length: data.len() as u32,
            link_type: DLT_EN10MB,
            data,
        };
        let parsed = parse_transport(&capture).unwrap();
        assert_eq!(parsed.kind, TransportKind::Udp);
        assert_eq!(parsed.source.port, 1234);
        assert_eq!(parsed.destination.port, 5678);
        assert_eq!(parsed.payload, b"abc");
    }
}
