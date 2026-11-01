//! Build-pinned PacketHandler, Unreal packet, bunch, and PackageMap wire model.
//!
//! Known header fields are decoded into typed values and re-encoded through a
//! fresh [`codev_protocol::Lsb0Writer`].  Only channel/Oodle payload regions
//! whose semantics are explicitly unresolved are copied as opaque bit spans.
//! This separation makes a byte-for-byte round trip meaningful without
//! pretending unknown payload bytes have acquired semantics.

use codev_protocol::{BitWriteError, DecodeError, Lsb0Reader, Lsb0Writer};
use thiserror::Error;

pub const OODLE_RAW_SIZE_MODULUS: u32 = 1024;
pub const PACKET_INFO_MODULUS: u32 = 1024;
pub const RELIABLE_SEQUENCE_MODULUS: u32 = 1024;
pub const CHANNEL_CLOSE_REASON_COUNT: u32 = 15;
pub const MAX_PACKET_BYTES: u32 = 1024;
pub const MAX_NETGUID_EXPORTS: u32 = 2048;
pub const MAX_NETGUID_OUTER_DEPTH: usize = 16;
pub const HARD_CODED_NAME_MAX: u32 = 702;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketHandlerEnvelope {
    pub archive_bit_length: usize,
    pub oodle_flag: bool,
    pub header_bit_length: usize,
    pub raw_size: Option<u16>,
    pub payload_bit_length: usize,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketWireProof {
    pub handler: PacketHandlerEnvelope,
    pub unreal: Option<UnrealPacketEnvelope>,
    pub rebuilt_inner: Vec<u8>,
    pub package_map_export_prefixes: u64,
    pub netguid_records: u64,
    pub package_map_exports: Vec<ProvenPackageMapExport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenPackageMapExport {
    pub bunch_index: usize,
    pub prefix: PackageMapExportPrefix,
}

impl PacketHandlerEnvelope {
    pub const fn pass_through(&self) -> bool {
        !self.oodle_flag
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PacketNotifyHeader {
    pub history_byte_count: u8,
    pub ack_raw: u16,
    pub packet_raw: u16,
    pub history: Vec<u8>,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub payload_bit_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrealPacketEnvelope {
    pub archive_bit_length: usize,
    pub terminal_bit_offset: usize,
    pub notify: PacketNotifyHeader,
    pub packet_info_serialized: bool,
    pub has_packet_info_payload: bool,
    pub packet_info_timestamp_ms: Option<u16>,
    pub packet_info_timing_compensation_present: Option<bool>,
    pub packet_info_timing_compensation_ms: Option<u8>,
    pub bunches: Vec<UnrealBunch>,
    pub consumed_bits: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnrealBunch {
    pub bit_offset: usize,
    pub header_bit_length: usize,
    pub channel_index: u32,
    pub control: bool,
    pub open: bool,
    pub close: bool,
    pub close_reason: Option<u32>,
    pub dormant: bool,
    pub replication_paused: bool,
    pub reliable: bool,
    pub partial: bool,
    pub partial_initial: bool,
    pub partial_final: bool,
    pub has_package_map_exports: bool,
    pub has_must_be_mapped_guids: bool,
    pub reliable_sequence_raw: Option<u16>,
    pub channel_name: Option<SerializedName>,
    pub data_bit_offset: usize,
    pub data_bit_length: usize,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SerializedName {
    HardCoded {
        comparison_index: u32,
        bit_offset: usize,
        bit_length: usize,
    },
    StringBacked {
        value: FString,
        number: i32,
        bit_offset: usize,
        bit_length: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FStringEncoding {
    Utf8,
    Utf16Le,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FString {
    pub signed_length: i32,
    pub raw: Vec<u8>,
    pub value: String,
    pub encoding: FStringEncoding,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageMapExportPrefix {
    pub alternate_layout: bool,
    pub export_count: u32,
    pub exports: Vec<NetGuidExport>,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetGuidExport {
    pub netguid: u32,
    pub flags: Option<u8>,
    pub outer: Option<Box<NetGuidExport>>,
    pub path: Option<FString>,
    pub network_checksum: Option<u32>,
    pub bit_offset: usize,
    pub bit_length: usize,
}

impl PackageMapExportPrefix {
    pub fn record_count(&self) -> u64 {
        self.exports.iter().map(NetGuidExport::record_count).sum()
    }
}

impl NetGuidExport {
    pub fn record_count(&self) -> u64 {
        1 + self.outer.as_deref().map_or(0, Self::record_count)
    }
}

pub fn parse_packet_handler_envelope(data: &[u8]) -> Result<PacketHandlerEnvelope, WireError> {
    let archive_bits = archive_bit_length(data)?;
    let mut reader = Lsb0Reader::new(data, archive_bits)?;
    let oodle_flag = reader.read_bit()?;
    let raw_size = if oodle_flag {
        Some((reader.serialize_int(OODLE_RAW_SIZE_MODULUS)? + 1) as u16)
    } else {
        None
    };
    let header_bit_length = reader.position();
    let payload_bit_length = reader.bits_left();
    let payload = extract_lsb_bits(data, header_bit_length, payload_bit_length)?;
    skip_bits(&mut reader, payload_bit_length)?;
    Ok(PacketHandlerEnvelope {
        archive_bit_length: archive_bits,
        oodle_flag,
        header_bit_length,
        raw_size,
        payload_bit_length,
        payload,
    })
}

pub fn packet_handler_payload(envelope: &PacketHandlerEnvelope) -> Result<&[u8], WireError> {
    if !envelope.pass_through() {
        return Err(WireError::CompressedPayload);
    }
    if envelope.payload_bit_length == 0 {
        return Err(WireError::EmptyPassThroughPayload);
    }
    if !bit_at(&envelope.payload, envelope.payload_bit_length - 1) {
        return Err(WireError::MissingNestedTerminal);
    }
    Ok(&envelope.payload)
}

pub fn reencode_packet_handler_envelope(
    envelope: &PacketHandlerEnvelope,
) -> Result<Vec<u8>, WireError> {
    let mut writer = Lsb0Writer::with_capacity(envelope.archive_bit_length + 1);
    writer.write_bit(envelope.oodle_flag);
    if envelope.oodle_flag {
        let raw_size = envelope.raw_size.ok_or(WireError::MissingOodleRawSize)?;
        if !(1..=OODLE_RAW_SIZE_MODULUS as u16).contains(&raw_size) {
            return Err(WireError::InvalidOodleRawSize(raw_size));
        }
        writer.serialize_int(u32::from(raw_size) - 1, OODLE_RAW_SIZE_MODULUS)?;
    } else if envelope.raw_size.is_some() {
        return Err(WireError::UnexpectedOodleRawSize);
    }
    writer.write_bit_slice(&envelope.payload, 0, envelope.payload_bit_length)?;
    require_length("P0", writer.position(), envelope.archive_bit_length)?;
    writer.write_bit(true);
    Ok(writer.into_bytes())
}

/// Compositionally rebuild one complete PacketHandler archive.
///
/// PackageMap prefixes are rebuilt first and joined only with their explicit
/// unknown channel tails. Those bunches rebuild the Unreal archive, which then
/// replaces the PacketHandler payload before the outer archive is rebuilt.
pub fn prove_packet_handler_wire(data: &[u8]) -> Result<PacketWireProof, WireError> {
    let handler = parse_packet_handler_envelope(data)?;
    if !handler.pass_through() {
        let rebuilt_inner = reencode_packet_handler_envelope(&handler)?;
        require_wire_match("P0", &rebuilt_inner, data)?;
        return Ok(PacketWireProof {
            handler,
            unreal: None,
            rebuilt_inner,
            package_map_export_prefixes: 0,
            netguid_records: 0,
            package_map_exports: Vec::new(),
        });
    }

    let ue_payload = packet_handler_payload(&handler)?;
    let unreal = parse_unreal_packet(ue_payload)?;
    let mut composed_unreal = unreal.clone();
    let mut package_map_export_prefixes = 0_u64;
    let mut netguid_records = 0_u64;
    let mut package_map_exports = Vec::new();
    for (bunch_index, bunch) in composed_unreal.bunches.iter_mut().enumerate() {
        if !bunch.has_package_map_exports {
            continue;
        }
        let prefix = parse_package_map_exports(&bunch.data, bunch.data_bit_length)?;
        let rebuilt_prefix = reencode_package_map_exports(&prefix)?;
        let original_prefix = extract_lsb_bits(&bunch.data, 0, prefix.bit_length)?;
        require_wire_match("PackageMap export", &rebuilt_prefix, &original_prefix)?;

        let mut rebuilt_data = Lsb0Writer::with_capacity(bunch.data_bit_length);
        rebuilt_data.write_bit_slice(&rebuilt_prefix, 0, prefix.bit_length)?;
        rebuilt_data.write_bit_slice(
            &bunch.data,
            prefix.bit_length,
            bunch.data_bit_length - prefix.bit_length,
        )?;
        require_length("bunch data", rebuilt_data.position(), bunch.data_bit_length)?;
        bunch.data = rebuilt_data.into_bytes();
        package_map_export_prefixes += 1;
        netguid_records += prefix.record_count();
        package_map_exports.push(ProvenPackageMapExport {
            bunch_index,
            prefix,
        });
    }

    let rebuilt_unreal = reencode_unreal_packet(&composed_unreal)?;
    require_wire_match("U0 packet", &rebuilt_unreal, ue_payload)?;
    let mut composed_handler = handler.clone();
    composed_handler.payload = rebuilt_unreal;
    let rebuilt_inner = reencode_packet_handler_envelope(&composed_handler)?;
    require_wire_match("P0", &rebuilt_inner, data)?;
    Ok(PacketWireProof {
        handler,
        unreal: Some(unreal),
        rebuilt_inner,
        package_map_export_prefixes,
        netguid_records,
        package_map_exports,
    })
}

pub fn parse_unreal_packet(data: &[u8]) -> Result<UnrealPacketEnvelope, WireError> {
    let archive_bits = archive_bit_length(data)?;
    let mut reader = Lsb0Reader::new(data, archive_bits)?;
    let notify_start = reader.position();
    let packed = reader.read_bits(32)?;
    let history_byte_count = ((packed & 0x0f) + 1) as u8;
    let ack_raw = ((packed >> 4) & 0x3fff) as u16;
    let packet_raw = ((packed >> 18) & 0x3fff) as u16;
    let mut history = Vec::with_capacity(usize::from(history_byte_count));
    for _ in 0..history_byte_count {
        history.push(reader.read_bits(8)? as u8);
    }
    let notify = PacketNotifyHeader {
        history_byte_count,
        ack_raw,
        packet_raw,
        history,
        bit_offset: notify_start,
        bit_length: reader.position() - notify_start,
        payload_bit_offset: reader.position(),
    };

    // EngineNetVersion 20 always serializes the PacketInfo-present bit.
    let has_packet_info_payload = reader.read_bit()?;
    let mut packet_info_timestamp_ms = None;
    let mut compensation_present = None;
    let mut compensation_ms = None;
    if has_packet_info_payload {
        packet_info_timestamp_ms = Some(reader.serialize_int(PACKET_INFO_MODULUS)? as u16);
        let present = reader.read_bit()?;
        compensation_present = Some(present);
        if present {
            compensation_ms = Some(reader.read_bits(8)? as u8);
        }
    }

    let mut bunches = Vec::new();
    while reader.bits_left() != 0 {
        bunches.push(parse_unreal_bunch(data, &mut reader)?);
    }
    Ok(UnrealPacketEnvelope {
        archive_bit_length: archive_bits,
        terminal_bit_offset: archive_bits,
        notify,
        packet_info_serialized: true,
        has_packet_info_payload,
        packet_info_timestamp_ms,
        packet_info_timing_compensation_present: compensation_present,
        packet_info_timing_compensation_ms: compensation_ms,
        bunches,
        consumed_bits: reader.position(),
    })
}

pub fn reencode_unreal_packet(envelope: &UnrealPacketEnvelope) -> Result<Vec<u8>, WireError> {
    let notify = &envelope.notify;
    if !(1..=16).contains(&notify.history_byte_count)
        || notify.history.len() != usize::from(notify.history_byte_count)
        || notify.ack_raw >= 0x4000
        || notify.packet_raw >= 0x4000
    {
        return Err(WireError::InvalidPacketNotify);
    }
    let mut writer = Lsb0Writer::with_capacity(envelope.archive_bit_length + 1);
    let packed = (u32::from(notify.packet_raw) << 18)
        | (u32::from(notify.ack_raw) << 4)
        | (u32::from(notify.history_byte_count) - 1);
    writer.write_bits(packed, 32)?;
    for &byte in &notify.history {
        writer.write_bits(u32::from(byte), 8)?;
    }
    if !envelope.packet_info_serialized {
        return Err(WireError::PacketInfoNotSerialized);
    }
    writer.write_bit(envelope.has_packet_info_payload);
    if envelope.has_packet_info_payload {
        let timestamp = envelope
            .packet_info_timestamp_ms
            .ok_or(WireError::MissingPacketInfoTimestamp)?;
        writer.serialize_int(u32::from(timestamp), PACKET_INFO_MODULUS)?;
        let compensation = envelope
            .packet_info_timing_compensation_present
            .ok_or(WireError::MissingPacketInfoCompensationFlag)?;
        writer.write_bit(compensation);
        if compensation {
            writer.write_bits(
                u32::from(
                    envelope
                        .packet_info_timing_compensation_ms
                        .ok_or(WireError::MissingPacketInfoCompensation)?,
                ),
                8,
            )?;
        } else if envelope.packet_info_timing_compensation_ms.is_some() {
            return Err(WireError::UnexpectedPacketInfoCompensation);
        }
    } else if envelope.packet_info_timestamp_ms.is_some()
        || envelope.packet_info_timing_compensation_present.is_some()
        || envelope.packet_info_timing_compensation_ms.is_some()
    {
        return Err(WireError::UnexpectedPacketInfoPayload);
    }
    for bunch in &envelope.bunches {
        encode_unreal_bunch(&mut writer, bunch)?;
    }
    require_length("U0", writer.position(), envelope.archive_bit_length)?;
    writer.write_bit(true);
    Ok(writer.into_bytes())
}

fn parse_unreal_bunch(data: &[u8], reader: &mut Lsb0Reader<'_>) -> Result<UnrealBunch, WireError> {
    let start = reader.position();
    let channel_index = reader.serialize_int_packed()?;
    let control = reader.read_bit()?;
    let open = control && reader.read_bit()?;
    let close = control && reader.read_bit()?;
    let close_reason = if close {
        Some(reader.serialize_int(CHANNEL_CLOSE_REASON_COUNT)?)
    } else {
        None
    };
    let dormant = close_reason == Some(1);
    let replication_paused = reader.read_bit()?;
    let reliable = reader.read_bit()?;
    let has_package_map_exports = reader.read_bit()?;
    let has_must_be_mapped_guids = reader.read_bit()?;
    let partial = reader.read_bit()?;
    let reliable_sequence_raw = if reliable {
        Some(reader.serialize_int(RELIABLE_SEQUENCE_MODULUS)? as u16)
    } else {
        None
    };
    let partial_initial = partial && reader.read_bit()?;
    let partial_final = partial && reader.read_bit()?;
    let channel_name = if open || reliable {
        Some(parse_serialized_name(data, reader)?)
    } else {
        None
    };
    let data_bit_length = reader.serialize_int(8 * MAX_PACKET_BYTES)? as usize;
    let data_bit_offset = reader.position();
    let bunch_data = extract_lsb_bits(data, data_bit_offset, data_bit_length)?;
    skip_bits(reader, data_bit_length)?;
    Ok(UnrealBunch {
        bit_offset: start,
        header_bit_length: data_bit_offset - start,
        channel_index,
        control,
        open,
        close,
        close_reason,
        dormant,
        replication_paused,
        reliable,
        partial,
        partial_initial,
        partial_final,
        has_package_map_exports,
        has_must_be_mapped_guids,
        reliable_sequence_raw,
        channel_name,
        data_bit_offset,
        data_bit_length,
        data: bunch_data,
    })
}

fn encode_unreal_bunch(writer: &mut Lsb0Writer, bunch: &UnrealBunch) -> Result<(), WireError> {
    let start = writer.position();
    writer.serialize_int_packed(bunch.channel_index)?;
    writer.write_bit(bunch.control);
    if bunch.control {
        writer.write_bit(bunch.open);
        writer.write_bit(bunch.close);
        if bunch.close {
            writer.serialize_int(
                bunch.close_reason.ok_or(WireError::MissingCloseReason)?,
                CHANNEL_CLOSE_REASON_COUNT,
            )?;
        } else if bunch.close_reason.is_some() {
            return Err(WireError::UnexpectedCloseReason);
        }
    } else if bunch.open || bunch.close || bunch.close_reason.is_some() {
        return Err(WireError::InvalidControlFlags);
    }
    writer.write_bit(bunch.replication_paused);
    writer.write_bit(bunch.reliable);
    writer.write_bit(bunch.has_package_map_exports);
    writer.write_bit(bunch.has_must_be_mapped_guids);
    writer.write_bit(bunch.partial);
    if bunch.reliable {
        writer.serialize_int(
            u32::from(
                bunch
                    .reliable_sequence_raw
                    .ok_or(WireError::MissingReliableSequence)?,
            ),
            RELIABLE_SEQUENCE_MODULUS,
        )?;
    } else if bunch.reliable_sequence_raw.is_some() {
        return Err(WireError::UnexpectedReliableSequence);
    }
    if bunch.partial {
        writer.write_bit(bunch.partial_initial);
        writer.write_bit(bunch.partial_final);
    } else if bunch.partial_initial || bunch.partial_final {
        return Err(WireError::InvalidPartialFlags);
    }
    if bunch.open || bunch.reliable {
        encode_serialized_name(
            writer,
            bunch
                .channel_name
                .as_ref()
                .ok_or(WireError::MissingChannelName)?,
        )?;
    } else if bunch.channel_name.is_some() {
        return Err(WireError::UnexpectedChannelName);
    }
    writer.serialize_int(bunch.data_bit_length as u32, 8 * MAX_PACKET_BYTES)?;
    let header_length = writer.position() - start;
    require_length("bunch header", header_length, bunch.header_bit_length)?;
    writer.write_bit_slice(&bunch.data, 0, bunch.data_bit_length)?;
    Ok(())
}

fn parse_serialized_name(
    data: &[u8],
    reader: &mut Lsb0Reader<'_>,
) -> Result<SerializedName, WireError> {
    let start = reader.position();
    if reader.read_bit()? {
        let comparison_index = reader.serialize_int_packed()?;
        if comparison_index > HARD_CODED_NAME_MAX {
            return Err(WireError::HardCodedNameOutOfRange(comparison_index));
        }
        Ok(SerializedName::HardCoded {
            comparison_index,
            bit_offset: start,
            bit_length: reader.position() - start,
        })
    } else {
        let value = parse_fstring(data, reader)?;
        let number = reader.read_bits(32)? as i32;
        Ok(SerializedName::StringBacked {
            value,
            number,
            bit_offset: start,
            bit_length: reader.position() - start,
        })
    }
}

fn encode_serialized_name(writer: &mut Lsb0Writer, name: &SerializedName) -> Result<(), WireError> {
    match name {
        SerializedName::HardCoded {
            comparison_index, ..
        } => {
            if *comparison_index > HARD_CODED_NAME_MAX {
                return Err(WireError::HardCodedNameOutOfRange(*comparison_index));
            }
            writer.write_bit(true);
            writer.serialize_int_packed(*comparison_index)?;
        }
        SerializedName::StringBacked { value, number, .. } => {
            writer.write_bit(false);
            encode_fstring(writer, value)?;
            writer.write_bits(*number as u32, 32)?;
        }
    }
    Ok(())
}

pub fn parse_package_map_exports(
    data: &[u8],
    bit_length: usize,
) -> Result<PackageMapExportPrefix, WireError> {
    let mut reader = Lsb0Reader::new(data, bit_length)?;
    let start = reader.position();
    let alternate_layout = reader.read_bit()?;
    if alternate_layout {
        return Err(WireError::AlternatePackageMapLayout);
    }
    let export_count = reader.read_bits(32)?;
    if export_count > MAX_NETGUID_EXPORTS {
        return Err(WireError::NetGuidExportCount(export_count));
    }
    let mut exports = Vec::with_capacity(export_count as usize);
    for _ in 0..export_count {
        exports.push(parse_netguid_export(data, &mut reader, 0)?);
    }
    Ok(PackageMapExportPrefix {
        alternate_layout,
        export_count,
        exports,
        bit_offset: start,
        bit_length: reader.position() - start,
    })
}

pub fn reencode_package_map_exports(prefix: &PackageMapExportPrefix) -> Result<Vec<u8>, WireError> {
    if prefix.alternate_layout {
        return Err(WireError::AlternatePackageMapLayout);
    }
    if prefix.export_count as usize != prefix.exports.len() {
        return Err(WireError::NetGuidExportCountMismatch);
    }
    let mut writer = Lsb0Writer::with_capacity(prefix.bit_length);
    writer.write_bit(false);
    writer.write_bits(prefix.export_count, 32)?;
    for export in &prefix.exports {
        encode_netguid_export(&mut writer, export)?;
    }
    require_length("PackageMap export", writer.position(), prefix.bit_length)?;
    Ok(writer.into_bytes())
}

fn parse_netguid_export(
    data: &[u8],
    reader: &mut Lsb0Reader<'_>,
    depth: usize,
) -> Result<NetGuidExport, WireError> {
    if depth > MAX_NETGUID_OUTER_DEPTH {
        return Err(WireError::NetGuidOuterDepth);
    }
    let start = reader.position();
    let netguid = reader.serialize_int_packed()?;
    if netguid == 0 {
        return Ok(NetGuidExport {
            netguid,
            flags: None,
            outer: None,
            path: None,
            network_checksum: None,
            bit_offset: start,
            bit_length: reader.position() - start,
        });
    }
    let flags = reader.read_bits(8)? as u8;
    let mut outer = None;
    let mut path = None;
    let mut network_checksum = None;
    if flags & 1 != 0 {
        outer = Some(Box::new(parse_netguid_export(data, reader, depth + 1)?));
        path = Some(parse_fstring(data, reader)?);
        if flags & 4 != 0 {
            network_checksum = Some(reader.read_bits(32)?);
        }
    }
    Ok(NetGuidExport {
        netguid,
        flags: Some(flags),
        outer,
        path,
        network_checksum,
        bit_offset: start,
        bit_length: reader.position() - start,
    })
}

fn encode_netguid_export(writer: &mut Lsb0Writer, export: &NetGuidExport) -> Result<(), WireError> {
    let start = writer.position();
    writer.serialize_int_packed(export.netguid)?;
    if export.netguid == 0 {
        if export.flags.is_some()
            || export.outer.is_some()
            || export.path.is_some()
            || export.network_checksum.is_some()
        {
            return Err(WireError::InvalidZeroNetGuid);
        }
        require_length("zero N0", writer.position() - start, export.bit_length)?;
        return Ok(());
    }
    let flags = export.flags.ok_or(WireError::MissingNetGuidFlags)?;
    writer.write_bits(u32::from(flags), 8)?;
    if flags & 1 != 0 {
        encode_netguid_export(
            writer,
            export
                .outer
                .as_deref()
                .ok_or(WireError::MissingNetGuidOuter)?,
        )?;
        encode_fstring(
            writer,
            export.path.as_ref().ok_or(WireError::MissingNetGuidPath)?,
        )?;
        if flags & 4 != 0 {
            writer.write_bits(
                export
                    .network_checksum
                    .ok_or(WireError::MissingNetGuidChecksum)?,
                32,
            )?;
        } else if export.network_checksum.is_some() {
            return Err(WireError::UnexpectedNetGuidChecksum);
        }
    } else if export.outer.is_some() || export.path.is_some() || export.network_checksum.is_some() {
        return Err(WireError::UnexpectedNetGuidMetadata);
    }
    require_length("N0", writer.position() - start, export.bit_length)?;
    Ok(())
}

fn parse_fstring(data: &[u8], reader: &mut Lsb0Reader<'_>) -> Result<FString, WireError> {
    let start = reader.position();
    let signed_length = reader.read_bits(32)? as i32;
    if signed_length == i32::MIN {
        return Err(WireError::FStringLength);
    }
    let (unit_count, width, encoding) = if signed_length < 0 {
        (
            signed_length.unsigned_abs() as usize,
            16,
            FStringEncoding::Utf16Le,
        )
    } else {
        (signed_length as usize, 8, FStringEncoding::Utf8)
    };
    if unit_count > reader.bits_left() / width {
        return Err(WireError::FStringLength);
    }
    let raw_start = reader.position();
    let raw = extract_lsb_bits(data, raw_start, unit_count * width)?;
    skip_bits(reader, unit_count * width)?;
    let value = match encoding {
        FStringEncoding::Utf8 => {
            if raw.last().is_some_and(|byte| *byte != 0) {
                return Err(WireError::FStringTerminator);
            }
            let body = if raw.is_empty() {
                &raw[..]
            } else {
                &raw[..raw.len() - 1]
            };
            String::from_utf8(body.to_vec()).map_err(|_| WireError::FStringEncoding)?
        }
        FStringEncoding::Utf16Le => {
            if raw.len() < 2 || raw[raw.len() - 2..] != [0, 0] {
                return Err(WireError::FStringTerminator);
            }
            let units = raw[..raw.len() - 2]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units).map_err(|_| WireError::FStringEncoding)?
        }
    };
    Ok(FString {
        signed_length,
        raw,
        value,
        encoding,
        bit_offset: start,
        bit_length: reader.position() - start,
    })
}

fn encode_fstring(writer: &mut Lsb0Writer, value: &FString) -> Result<(), WireError> {
    let expected_bytes = match value.encoding {
        FStringEncoding::Utf8 => value.signed_length.max(0) as usize,
        FStringEncoding::Utf16Le => value.signed_length.unsigned_abs() as usize * 2,
    };
    if value.signed_length == i32::MIN || value.raw.len() != expected_bytes {
        return Err(WireError::FStringLength);
    }
    match value.encoding {
        FStringEncoding::Utf8 if value.signed_length < 0 => {
            return Err(WireError::FStringEncoding);
        }
        FStringEncoding::Utf16Le if value.signed_length >= 0 => {
            return Err(WireError::FStringEncoding);
        }
        FStringEncoding::Utf8 => {
            if value.raw.last().is_some_and(|byte| *byte != 0) {
                return Err(WireError::FStringTerminator);
            }
        }
        FStringEncoding::Utf16Le => {
            if value.raw.len() < 2 || value.raw[value.raw.len() - 2..] != [0, 0] {
                return Err(WireError::FStringTerminator);
            }
        }
    }
    writer.write_bits(value.signed_length as u32, 32)?;
    writer.write_bit_slice(&value.raw, 0, value.raw.len() * 8)?;
    Ok(())
}

pub fn archive_bit_length(data: &[u8]) -> Result<usize, WireError> {
    let Some(&last) = data.last() else {
        return Err(WireError::MissingTerminal);
    };
    if last == 0 {
        return Err(WireError::MissingTerminal);
    }
    Ok((data.len() - 1) * 8 + (7 - last.leading_zeros() as usize))
}

pub fn extract_lsb_bits(
    data: &[u8],
    start_bit: usize,
    bit_length: usize,
) -> Result<Vec<u8>, WireError> {
    let end = start_bit
        .checked_add(bit_length)
        .filter(|end| *end <= data.len().saturating_mul(8))
        .ok_or(WireError::BitRange {
            start_bit,
            bit_length,
            buffer_bits: data.len().saturating_mul(8),
        })?;
    let mut output = vec![0_u8; bit_length.div_ceil(8)];
    for source in start_bit..end {
        if bit_at(data, source) {
            let destination = source - start_bit;
            output[destination >> 3] |= 1 << (destination & 7);
        }
    }
    Ok(output)
}

fn bit_at(data: &[u8], bit: usize) -> bool {
    (data[bit >> 3] >> (bit & 7)) & 1 != 0
}

fn skip_bits(reader: &mut Lsb0Reader<'_>, mut count: usize) -> Result<(), DecodeError> {
    while count >= 32 {
        reader.read_bits(32)?;
        count -= 32;
    }
    if count != 0 {
        reader.read_bits(count as u8)?;
    }
    Ok(())
}

fn require_length(layer: &'static str, actual: usize, expected: usize) -> Result<(), WireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(WireError::ReencodeLength {
            layer,
            actual,
            expected,
        })
    }
}

fn require_wire_match(
    layer: &'static str,
    actual: &[u8],
    expected: &[u8],
) -> Result<(), WireError> {
    if actual == expected {
        Ok(())
    } else {
        Err(WireError::WireMismatch { layer })
    }
}

#[derive(Debug, Error)]
pub enum WireError {
    #[error("bit decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("bit encode error: {0}")]
    Encode(#[from] BitWriteError),
    #[error("archive lacks its highest-set terminal marker")]
    MissingTerminal,
    #[error("bit range {start_bit}+{bit_length} exceeds {buffer_bits} buffer bits")]
    BitRange {
        start_bit: usize,
        bit_length: usize,
        buffer_bits: usize,
    },
    #[error("compressed P0 payload cannot be parsed as U0")]
    CompressedPayload,
    #[error("pass-through P0 payload is empty")]
    EmptyPassThroughPayload,
    #[error("pass-through P0 payload lacks its nested terminal marker")]
    MissingNestedTerminal,
    #[error("compressed P0 envelope lacks raw size")]
    MissingOodleRawSize,
    #[error("P0 raw size {0} is invalid")]
    InvalidOodleRawSize(u16),
    #[error("pass-through P0 envelope unexpectedly has raw size")]
    UnexpectedOodleRawSize,
    #[error("PacketNotify fields violate their fixed widths")]
    InvalidPacketNotify,
    #[error("this build requires the PacketInfo presence bit")]
    PacketInfoNotSerialized,
    #[error("PacketInfo payload lacks timestamp")]
    MissingPacketInfoTimestamp,
    #[error("PacketInfo payload lacks compensation-present bit")]
    MissingPacketInfoCompensationFlag,
    #[error("PacketInfo compensation flag lacks its byte")]
    MissingPacketInfoCompensation,
    #[error("PacketInfo has compensation byte while flag is clear")]
    UnexpectedPacketInfoCompensation,
    #[error("PacketInfo fields are present while the payload bit is clear")]
    UnexpectedPacketInfoPayload,
    #[error("closed bunch lacks a close reason")]
    MissingCloseReason,
    #[error("non-closed bunch unexpectedly has a close reason")]
    UnexpectedCloseReason,
    #[error("bunch open/close flags are set while control is clear")]
    InvalidControlFlags,
    #[error("reliable bunch lacks its modulo-1024 sequence")]
    MissingReliableSequence,
    #[error("unreliable bunch unexpectedly has a reliable sequence")]
    UnexpectedReliableSequence,
    #[error("non-partial bunch has partial-initial/final flags")]
    InvalidPartialFlags,
    #[error("open/reliable bunch lacks its serialized channel name")]
    MissingChannelName,
    #[error("closed/unreliable bunch unexpectedly has a channel name")]
    UnexpectedChannelName,
    #[error("hard-coded FName index {0} exceeds the build table")]
    HardCodedNameOutOfRange(u32),
    #[error("alternate PackageMap export layout is unsupported")]
    AlternatePackageMapLayout,
    #[error("PackageMap N0 export count {0} exceeds the build bound")]
    NetGuidExportCount(u32),
    #[error("PackageMap export count disagrees with its vector")]
    NetGuidExportCountMismatch,
    #[error("PackageMap N0 outer recursion exceeds the build bound")]
    NetGuidOuterDepth,
    #[error("zero N0 unexpectedly has export metadata")]
    InvalidZeroNetGuid,
    #[error("non-zero N0 lacks flags")]
    MissingNetGuidFlags,
    #[error("exported N0 lacks outer")]
    MissingNetGuidOuter,
    #[error("exported N0 lacks path")]
    MissingNetGuidPath,
    #[error("N0 checksum flag lacks checksum")]
    MissingNetGuidChecksum,
    #[error("N0 without checksum flag unexpectedly has checksum")]
    UnexpectedNetGuidChecksum,
    #[error("non-exported N0 unexpectedly has outer/path/checksum")]
    UnexpectedNetGuidMetadata,
    #[error("FString length exceeds its enclosing bit archive")]
    FStringLength,
    #[error("FString lacks its terminal null")]
    FStringTerminator,
    #[error("FString bytes do not match their declared encoding")]
    FStringEncoding,
    #[error("{layer} re-encoded {actual} bits; expected {expected}")]
    ReencodeLength {
        layer: &'static str,
        actual: usize,
        expected: usize,
    },
    #[error("{layer} semantic re-encode changed wire bytes")]
    WireMismatch { layer: &'static str },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        C0Cipher, Direction, PacketSource, S0PcapSource, TransportKind, discover_primary_udp_flow,
        parse_transport, recover_enter_game_session_from_classic_pcap,
    };
    use std::path::Path;

    #[test]
    fn packet_handler_semantic_reencode_preserves_nested_and_outer_terminals() {
        let original = [0, 0b0000_0011];
        let parsed = parse_packet_handler_envelope(&original).unwrap();
        assert!(parsed.pass_through());
        assert_eq!(parsed.header_bit_length, 1);
        assert_eq!(packet_handler_payload(&parsed).unwrap(), &[0x80]);
        assert_eq!(reencode_packet_handler_envelope(&parsed).unwrap(), original);
    }

    #[test]
    fn package_map_zero_export_prefix_round_trips_from_typed_fields() {
        let prefix = parse_package_map_exports(&[0; 5], 33).unwrap();
        assert_eq!(prefix.export_count, 0);
        assert_eq!(prefix.bit_length, 33);
        assert_eq!(reencode_package_map_exports(&prefix).unwrap(), vec![0; 5]);
    }

    #[test]
    fn real_first_pass_through_packet_round_trips_all_known_headers() {
        // Small synthetic UE ACK-only archive: notify(history=1, ids=0), one
        // zero history byte, PacketInfo absent, nested terminal. It is wrapped
        // in PacketHandler flag=0 plus an outer terminal.
        let mut ue = Lsb0Writer::default();
        ue.write_bits(0, 32).unwrap();
        ue.write_bits(0, 8).unwrap();
        ue.write_bit(false);
        ue.write_bit(true);
        let ue = ue.into_bytes();
        let unreal = parse_unreal_packet(&ue).unwrap();
        assert!(unreal.bunches.is_empty());
        assert_eq!(reencode_unreal_packet(&unreal).unwrap(), ue);

        let mut outer = Lsb0Writer::default();
        outer.write_bit(false);
        outer.write_bit_slice(&ue, 0, 42).unwrap();
        outer.write_bit(true);
        let outer = outer.into_bytes();
        let handler = parse_packet_handler_envelope(&outer).unwrap();
        assert_eq!(reencode_packet_handler_envelope(&handler).unwrap(), outer);
    }

    #[test]
    fn private_full_capture_semantically_round_trips_every_wire_envelope() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !pcap.is_file() {
            return;
        }
        let recovered = recover_enter_game_session_from_classic_pcap(&pcap).unwrap();
        let cipher =
            C0Cipher::from_packet_key(&recovered.session.packet_key, recovered.session.g0_id);
        let mut discovery = S0PcapSource::open(&pcap).unwrap();
        let flow = discover_primary_udp_flow(&mut discovery).unwrap();
        let mut source = S0PcapSource::open(&pcap).unwrap();
        let mut handlers = 0_u64;
        let mut unreal_packets = 0_u64;
        let mut export_prefixes = 0_u64;
        let mut netguid_records = 0_u64;
        while let Some(packet) = source.next_packet().unwrap() {
            let Ok(transport) = parse_transport(&packet) else {
                continue;
            };
            if transport.kind != TransportKind::Udp
                || !flow.key.contains(transport.source, transport.destination)
            {
                continue;
            }
            let direction = if transport.source == flow.client {
                Direction::ClientToServer
            } else {
                Direction::ServerToClient
            };
            let logical = match direction {
                Direction::ClientToServer => {
                    cipher.crypt_client_datagram(transport.payload).unwrap()
                }
                Direction::ServerToClient => cipher.crypt_server_datagram(transport.payload),
            };
            let inner = match direction {
                Direction::ClientToServer => &logical[10..],
                Direction::ServerToClient => &logical,
            };
            let proof = prove_packet_handler_wire(inner).unwrap();
            handlers += 1;
            if !proof.handler.pass_through() {
                continue;
            }
            unreal_packets += 1;
            export_prefixes += proof.package_map_export_prefixes;
            netguid_records += proof.netguid_records;
        }
        assert_eq!(handlers, 12_414);
        assert_eq!(unreal_packets, 12_410);
        assert_eq!(export_prefixes, 512);
        assert_eq!(netguid_records, 2_469);
    }
}
