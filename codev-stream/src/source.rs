use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use thiserror::Error;

pub const DLT_NULL: u32 = 0;
pub const DLT_EN10MB: u32 = 1;
pub const DLT_RAW: u32 = 12;
pub const DLT_LINUX_SLL: u32 = 113;
pub const DLT_LINUX_SLL2: u32 = 276;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedPacket {
    pub index: u64,
    pub timestamp_ns: u64,
    pub original_length: u32,
    pub link_type: u32,
    pub data: Vec<u8>,
}

pub trait PacketSource {
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>, SourceError>;
}

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("capture I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported capture format: {0}")]
    UnsupportedFormat(String),
    #[error("invalid PCAP: {0}")]
    InvalidPcap(String),
    #[cfg(feature = "live-capture")]
    #[error("libpcap error: {0}")]
    Pcap(#[from] pcap::Error),
}

#[derive(Clone, Copy, Debug)]
enum ByteOrder {
    Little,
    Big,
}

pub struct S0PcapSource<R: Read> {
    reader: R,
    order: ByteOrder,
    nanosecond_resolution: bool,
    link_type: u32,
    index: u64,
}

impl S0PcapSource<BufReader<File>> {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        Self::new(BufReader::new(File::open(path)?))
    }
}

impl<R: Read> S0PcapSource<R> {
    pub fn new(mut reader: R) -> Result<Self, SourceError> {
        let mut header = [0_u8; 24];
        reader.read_exact(&mut header)?;
        let (order, nanosecond_resolution) = match &header[..4] {
            [0xd4, 0xc3, 0xb2, 0xa1] => (ByteOrder::Little, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (ByteOrder::Little, true),
            [0xa1, 0xb2, 0xc3, 0xd4] => (ByteOrder::Big, false),
            [0xa1, 0xb2, 0x3c, 0x4d] => (ByteOrder::Big, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                return Err(SourceError::UnsupportedFormat(
                    "PCAP-NG is not accepted by the strict classic-PCAP reader".into(),
                ));
            }
            magic => {
                return Err(SourceError::InvalidPcap(format!(
                    "unknown magic {:02x?}",
                    magic
                )));
            }
        };
        let version_major = read_u16(&header[4..6], order);
        let version_minor = read_u16(&header[6..8], order);
        if (version_major, version_minor) != (2, 4) {
            return Err(SourceError::InvalidPcap(format!(
                "unsupported version {version_major}.{version_minor}"
            )));
        }
        let snaplen = read_u32(&header[16..20], order);
        if snaplen == 0 {
            return Err(SourceError::InvalidPcap("zero snapshot length".into()));
        }
        let link_type = read_u32(&header[20..24], order);
        if !matches!(
            link_type,
            DLT_NULL | DLT_EN10MB | DLT_RAW | DLT_LINUX_SLL | DLT_LINUX_SLL2
        ) {
            return Err(SourceError::UnsupportedFormat(format!(
                "link type {link_type}"
            )));
        }
        Ok(Self {
            reader,
            order,
            nanosecond_resolution,
            link_type,
            index: 0,
        })
    }
}

impl<R: Read> PacketSource for S0PcapSource<R> {
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>, SourceError> {
        let mut header = [0_u8; 16];
        let mut read = 0;
        while read < header.len() {
            match self.reader.read(&mut header[read..])? {
                0 if read == 0 => return Ok(None),
                // 抓包文件仍可能在被写入（引擎滚动分片、代理抓到一半就打包），
                // 尾部的半条记录属于正常情况：按 EOF 处理，别把整包判为损坏。
                0 => return Ok(None),
                count => read += count,
            }
        }
        let seconds = read_u32(&header[0..4], self.order);
        let fraction = read_u32(&header[4..8], self.order);
        let captured_length = read_u32(&header[8..12], self.order);
        let original_length = read_u32(&header[12..16], self.order);
        if captured_length > original_length || captured_length > 16 * 1024 * 1024 {
            return Err(SourceError::InvalidPcap(format!(
                "invalid captured/original lengths {captured_length}/{original_length}"
            )));
        }
        let fraction_ns = if self.nanosecond_resolution {
            u64::from(fraction)
        } else {
            u64::from(fraction) * 1_000
        };
        if fraction_ns >= 1_000_000_000 {
            return Err(SourceError::InvalidPcap(format!(
                "timestamp fraction {fraction} is out of range"
            )));
        }
        let mut data = vec![0_u8; captured_length as usize];
        let mut filled = 0;
        while filled < data.len() {
            match self.reader.read(&mut data[filled..])? {
                0 => return Ok(None),
                count => filled += count,
            }
        }
        let packet = CapturedPacket {
            index: self.index,
            timestamp_ns: u64::from(seconds) * 1_000_000_000 + fraction_ns,
            original_length,
            link_type: self.link_type,
            data,
        };
        self.index += 1;
        Ok(Some(packet))
    }
}

fn read_u16(bytes: &[u8], order: ByteOrder) -> u16 {
    let bytes = [bytes[0], bytes[1]];
    match order {
        ByteOrder::Little => u16::from_le_bytes(bytes),
        ByteOrder::Big => u16::from_be_bytes(bytes),
    }
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match order {
        ByteOrder::Little => u32::from_le_bytes(bytes),
        ByteOrder::Big => u32::from_be_bytes(bytes),
    }
}

#[cfg(feature = "live-capture")]
pub struct S0LiveSource {
    capture: pcap::Capture<pcap::Active>,
    link_type: u32,
    index: u64,
}

#[cfg(feature = "live-capture")]
impl S0LiveSource {
    pub fn open(device: &str, filter: &str) -> Result<Self, SourceError> {
        let mut capture = pcap::Capture::from_device(device)?
            .promisc(true)
            .immediate_mode(true)
            // A finite read timeout lets the owner poll cancellation and the
            // 50 ms UDP reorder deadline even when an interface is idle.
            .timeout(50)
            .snaplen(65_535)
            .open()?;
        capture.filter(filter, true)?;
        let link_type = capture.get_datalink().0 as u32;
        if !matches!(
            link_type,
            DLT_NULL | DLT_EN10MB | DLT_RAW | DLT_LINUX_SLL | DLT_LINUX_SLL2
        ) {
            return Err(SourceError::UnsupportedFormat(format!(
                "live link type {link_type}"
            )));
        }
        Ok(Self {
            capture,
            link_type,
            index: 0,
        })
    }

    pub fn devices() -> Result<Vec<String>, SourceError> {
        Ok(pcap::Device::list()?
            .into_iter()
            .filter(|device| {
                !device.addresses.is_empty() && device.flags.is_up() && device.flags.is_running()
            })
            .map(|device| device.name)
            .collect())
    }

    /// Select the first capture-ready, non-loopback interface.  The order is
    /// libpcap's platform order, which already places the default route near
    /// the front on supported desktop systems.
    pub fn auto_device() -> Result<Option<String>, SourceError> {
        Ok(pcap::Device::list()?
            .into_iter()
            .find(|device| {
                !device.addresses.is_empty()
                    && device.flags.is_up()
                    && device.flags.is_running()
                    && !device.flags.is_loopback()
            })
            .map(|device| device.name))
    }

    pub fn set_filter(&mut self, filter: &str) -> Result<(), SourceError> {
        self.capture.filter(filter, true)?;
        Ok(())
    }

    pub fn capture_stats(&mut self) -> Result<LiveCaptureStats, SourceError> {
        let stats = self.capture.stats()?;
        Ok(LiveCaptureStats {
            received: u64::from(stats.received),
            dropped: u64::from(stats.dropped),
            interface_dropped: u64::from(stats.if_dropped),
        })
    }
}

#[cfg(feature = "live-capture")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveCaptureStats {
    pub received: u64,
    pub dropped: u64,
    pub interface_dropped: u64,
}

#[cfg(feature = "live-capture")]
impl PacketSource for S0LiveSource {
    fn next_packet(&mut self) -> Result<Option<CapturedPacket>, SourceError> {
        let packet = match self.capture.next_packet() {
            Ok(packet) => packet,
            Err(pcap::Error::TimeoutExpired) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let timestamp_ns = u64::try_from(packet.header.ts.tv_sec)
            .unwrap_or_default()
            .saturating_mul(1_000_000_000)
            .saturating_add(
                u64::try_from(packet.header.ts.tv_usec)
                    .unwrap_or_default()
                    .saturating_mul(1_000),
            );
        let output = CapturedPacket {
            index: self.index,
            timestamp_ns,
            original_length: packet.header.len,
            link_type: self.link_type,
            data: packet.data.to_vec(),
        };
        self.index += 1;
        Ok(Some(output))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn classic_pcap_is_incremental_and_timestamp_exact() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&0_i32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&DLT_EN10MB.to_le_bytes());
        bytes.extend_from_slice(&12_u32.to_le_bytes());
        bytes.extend_from_slice(&345_678_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 2, 3]);
        let mut source = S0PcapSource::new(Cursor::new(bytes)).unwrap();
        let packet = source.next_packet().unwrap().unwrap();
        assert_eq!(packet.timestamp_ns, 12_345_678_000);
        assert_eq!(packet.data, [1, 2, 3]);
        assert!(source.next_packet().unwrap().is_none());
    }
}
