use std::collections::BTreeMap;
use std::fmt;

use aes::Aes128;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use codev_conceal as conceal;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MNA_MAGIC: [u8; 6] = [0x33, 0x66, 0x00, 0x0b, 0x00, 0x0c];
pub const MNA_CLIENT_HELLO: u16 = 0x1001;
pub const MNA_SERVER_HELLO: u16 = 0x1002;
pub const MNA_CLIENT_AUTH: u16 = 0x2001;
pub const MNA_SERVER_AUTH: u16 = 0x2002;
pub const MNA_CLOSE: u16 = 0x5002;
pub const MNA_SERVER_AUTH_FINAL: u16 = 0x6002;
pub const MNA_DATA: u16 = 0x4013;
pub const ENTER_GAME_NOTIFY_COMMAND: u64 = 3_888_815;
pub const REENTER_GAME_NOTIFY_COMMAND: u64 = 5_856_028;
pub const MNA_BASE_HEADER_LENGTH: usize = 21;
pub const MNA_CBC_IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct W0Frame {
    pub message_type: u16,
    pub direction_marker: u8,
    pub sequence: u32,
    pub header_version: u16,
    pub protocol_version: u16,
    pub header: Vec<u8>,
    pub payload: Vec<u8>,
}

impl W0Frame {
    pub fn encrypted(&self) -> bool {
        matches!(
            self.message_type,
            MNA_CLIENT_AUTH | MNA_SERVER_AUTH | MNA_SERVER_AUTH_FINAL | MNA_DATA
        )
    }

    pub fn extension_header(&self) -> &[u8] {
        &self.header[MNA_BASE_HEADER_LENGTH..]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Zeroize)]
pub struct MnaCommonHead {
    pub command_id: u64,
    pub sequence_id: Option<u64>,
    pub error_id: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct W0ApplicationMessage {
    pub direction_marker: u8,
    pub transport_sequence: u32,
    pub client_sequence: Option<u32>,
    pub head: MnaCommonHead,
    pub body: Vec<u8>,
    pub body_plaintext_offset: usize,
}

impl fmt::Debug for W0ApplicationMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("W0ApplicationMessage")
            .field("direction_marker", &self.direction_marker)
            .field("transport_sequence", &self.transport_sequence)
            .field("client_sequence", &self.client_sequence)
            .field("head", &self.head)
            .field("body", &"<redacted>")
            .field("body_length", &self.body.len())
            .field("body_plaintext_offset", &self.body_plaintext_offset)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct W0RosterEntry {
    /// Authenticated `Match.pb` descriptor field 3 (`Name`, optional string).
    /// This is the stable roster name projected by the Python v2 compatibility
    /// document.  The session parser requires a non-empty value rather than
    /// substituting the semantically distinct `DisplayName` field.
    pub name: String,
    /// Authenticated descriptor field 16 (`DisplayName`, optional string).
    /// It is an independent presentation alias and must never replace `Name`
    /// for stable identity.  Missing and explicit protobuf-default empty values
    /// both project to `None`.
    pub display_name: Option<String>,
    /// Descriptor field 5 (`Uid`). Kept private to the control/identity
    /// layer; public realtime messages must not expose it. Decimal text
    /// preserves the Python v2 JSON type and avoids JSON integer precision
    /// loss for this protobuf `int64` identity.
    pub uid: String,
    /// Descriptor field 20 (`OpenId`). Kept private to the control/identity
    /// layer; public realtime messages must not expose it.
    pub open_id: String,
    pub agent_id: u32,
    pub skin_id: u32,
    pub selected_backpack_id: u32,
    pub camp_id: u64,
    pub position_slot: u32,
    /// Descriptor field 18 (`DeviceName`) 是否存在。机器人/无客户端条目没有这个字段；
    /// 真人玩家一定带。用来在本机对局里指认"哪一条是自己"（绝不外发原始值）。
    pub device_tag: bool,
}

impl fmt::Debug for W0RosterEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("W0RosterEntry")
            .field("name", &"<redacted>")
            .field("display_name", &"<redacted>")
            .field("uid", &"<redacted>")
            .field("open_id", &"<redacted>")
            .field("agent_id", &self.agent_id)
            .field("skin_id", &self.skin_id)
            .field("selected_backpack_id", &self.selected_backpack_id)
            .field("camp_id", &self.camp_id)
            .field("position_slot", &self.position_slot)
            .field("device_tag", &self.device_tag)
            .finish()
    }
}

/// Sensitive session material recovered only from a descriptor-exact MNA
/// Enter/ReEnterGameNotify. PacketKey is zeroized when this value is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct EnterGameSession {
    /// Descriptor field 1 (`IP`), which may be a hostname.
    pub server_ip: String,
    /// Descriptor field 18 (`VIP`). It is authenticated control-plane
    /// metadata, but is not assumed to equal the packet-level UDP peer (the
    /// pinned fixture uses a different resolved address).
    pub server_vip: Option<String>,
    pub server_port: u16,
    pub packet_key: Zeroizing<String>,
    pub g0_id: u64,
    pub map_id: u32,
    pub g1_mode: u32,
    pub s0_mode: u32,
    pub roster: Vec<W0RosterEntry>,
    /// MNA frame sequence that carried this descriptor-valid notification.
    /// PCAP packet indices belong to the capture-source layer and are not
    /// available to this application-message parser.
    pub source_mna_sequence: u32,
    pub reenter: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MnaFieldEvidence {
    pub path: String,
    pub field_number: u32,
    pub declared_type: &'static str,
    pub wire_type: u8,
    pub plaintext_start: usize,
    pub plaintext_end: usize,
    pub value_start: usize,
    pub value_end: usize,
}

pub struct ParsedEnterGameSession {
    pub session: EnterGameSession,
    pub map_id_evidence: MnaFieldEvidence,
    pub game_mode_evidence: MnaFieldEvidence,
    pub sub_game_mode_evidence: MnaFieldEvidence,
}

impl fmt::Debug for EnterGameSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnterGameSession")
            .field("server_endpoint", &"<redacted>")
            .field("packet_key", &"<redacted>")
            .field("g0_id", &"<redacted>")
            .field("map_id", &self.map_id)
            .field("g1_mode", &self.g1_mode)
            .field("s0_mode", &self.s0_mode)
            .field("roster_count", &self.roster.len())
            .field("source_mna_sequence", &self.source_mna_sequence)
            .field("reenter", &self.reenter)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum W0Error {
    #[error("M0 magic mismatch")]
    MagicMismatch,
    #[error("unsupported M0 message type 0x{0:04x}")]
    UnsupportedMessageType(u16),
    #[error("invalid M0 header length {0}")]
    InvalidHeaderLength(usize),
    #[error("M0 frame exceeds configured buffer")]
    FrameTooLarge,
    #[error("encrypted M0 payload is not AES-block aligned")]
    CiphertextAlignment,
    #[error("M0 decryption failed")]
    Decryption,
    #[error("invalid M0 random padding")]
    InvalidPadding,
    #[error("invalid M0 protobuf envelope: {0}")]
    InvalidEnvelope(&'static str),
    #[error("expected one M0 server-hello key, found {0}")]
    SessionKeyCount(usize),
    #[error("TCP reassembly conflict at sequence {0}")]
    TcpConflict(u64),
    #[error("TCP reassembly buffer exceeded its limit")]
    TcpBufferLimit,
    #[error("TCP reassembler was initialized more than once")]
    TcpAlreadyInitialized,
}

pub struct W0Framer {
    buffer: Vec<u8>,
    max_frame_bytes: usize,
}

impl Default for W0Framer {
    fn default() -> Self {
        Self::new(8 * 1024 * 1024)
    }
}

impl W0Framer {
    pub fn new(max_frame_bytes: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_frame_bytes,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<W0Frame>, W0Error> {
        if self.buffer.len().saturating_add(bytes.len()) > self.max_frame_bytes {
            return Err(W0Error::FrameTooLarge);
        }
        self.buffer.extend_from_slice(bytes);
        let mut frames = Vec::new();
        let mut consumed = 0;
        loop {
            let remaining = &self.buffer[consumed..];
            if remaining.len() < MNA_BASE_HEADER_LENGTH {
                break;
            }
            if remaining[..6] != MNA_MAGIC {
                return Err(W0Error::MagicMismatch);
            }
            let message_type = u16::from_be_bytes([remaining[6], remaining[7]]);
            if !matches!(
                message_type,
                MNA_CLIENT_HELLO
                    | MNA_SERVER_HELLO
                    | MNA_CLIENT_AUTH
                    | MNA_SERVER_AUTH
                    | MNA_CLOSE
                    | MNA_SERVER_AUTH_FINAL
                    | MNA_DATA
            ) {
                return Err(W0Error::UnsupportedMessageType(message_type));
            }
            let header_length = u32::from_be_bytes(remaining[13..17].try_into().unwrap()) as usize;
            let payload_length = u32::from_be_bytes(remaining[17..21].try_into().unwrap()) as usize;
            if header_length < MNA_BASE_HEADER_LENGTH {
                return Err(W0Error::InvalidHeaderLength(header_length));
            }
            if let Some(expected) = (match message_type {
                MNA_CLIENT_AUTH | MNA_SERVER_AUTH | MNA_CLOSE | MNA_SERVER_AUTH_FINAL => {
                    Some(MNA_BASE_HEADER_LENGTH)
                }
                MNA_DATA => Some(25),
                _ => None,
            }) && header_length != expected
            {
                return Err(W0Error::InvalidHeaderLength(header_length));
            }
            let frame_length = header_length
                .checked_add(payload_length)
                .filter(|length| *length <= self.max_frame_bytes)
                .ok_or(W0Error::FrameTooLarge)?;
            if remaining.len() < frame_length {
                break;
            }
            if matches!(
                message_type,
                MNA_CLIENT_AUTH | MNA_SERVER_AUTH | MNA_SERVER_AUTH_FINAL | MNA_DATA
            ) && !payload_length.is_multiple_of(16)
            {
                return Err(W0Error::CiphertextAlignment);
            }
            frames.push(W0Frame {
                message_type,
                direction_marker: remaining[8],
                sequence: u32::from_be_bytes(remaining[9..13].try_into().unwrap()),
                header_version: u16::from_be_bytes(remaining[2..4].try_into().unwrap()),
                protocol_version: u16::from_be_bytes(remaining[4..6].try_into().unwrap()),
                header: remaining[..header_length].to_vec(),
                payload: remaining[header_length..frame_length].to_vec(),
            });
            consumed += frame_length;
        }
        if consumed != 0 {
            self.buffer.drain(..consumed);
        }
        Ok(frames)
    }

    pub fn has_partial_frame(&self) -> bool {
        !self.buffer.is_empty()
    }
}

pub fn recover_mna_session_key(frames: &[W0Frame]) -> Result<Zeroizing<[u8; 16]>, W0Error> {
    let candidates: Vec<[u8; 16]> = frames
        .iter()
        .filter(|frame| frame.message_type == MNA_SERVER_HELLO)
        .filter_map(|frame| {
            let extension = frame.extension_header();
            (extension.len() >= 18 && extension[..2] == [0x02, 0x10])
                .then(|| extension[2..18].try_into().unwrap())
        })
        .collect();
    if candidates.len() != 1 {
        return Err(W0Error::SessionKeyCount(candidates.len()));
    }
    Ok(Zeroizing::new(candidates[0]))
}

pub fn decrypt_mna_frame(frame: &W0Frame, key: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, W0Error> {
    if !frame.encrypted() {
        return Ok(Zeroizing::new(frame.payload.clone()));
    }
    if !frame.payload.len().is_multiple_of(16) {
        return Err(W0Error::CiphertextAlignment);
    }
    let mut buffer = Zeroizing::new(frame.payload.clone());
    let decryptor = cbc::Decryptor::<Aes128>::new(key.into(), (&MNA_CBC_IV).into());
    decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buffer)
        .map_err(|_| W0Error::Decryption)?;
    Ok(buffer)
}

pub fn strip_mna_random_padding(plaintext: &mut Zeroizing<Vec<u8>>) -> Result<usize, W0Error> {
    let Some(&padding_length) = plaintext.last() else {
        return Err(W0Error::InvalidPadding);
    };
    let padding_length = usize::from(padding_length);
    if !(1..=32).contains(&padding_length)
        || padding_length > plaintext.len()
        || plaintext.len() < 6
        || plaintext[plaintext.len() - 6..plaintext.len() - 1] != *b"tsf4g"
    {
        return Err(W0Error::InvalidPadding);
    }
    let body_length = plaintext.len() - padding_length;
    if body_length == 0 {
        return Err(W0Error::InvalidPadding);
    }
    let remainder = body_length % 16;
    let expected = if remainder <= 10 {
        16 - remainder
    } else {
        32 - remainder
    };
    if padding_length != expected {
        return Err(W0Error::InvalidPadding);
    }
    plaintext[body_length..].zeroize();
    plaintext.truncate(body_length);
    Ok(padding_length)
}

pub fn parse_mna_application(
    plaintext: &[u8],
    direction_marker: u8,
    transport_sequence: u32,
) -> Result<W0ApplicationMessage, W0Error> {
    if direction_marker > 1 {
        return Err(W0Error::InvalidEnvelope("direction"));
    }
    let (client_sequence, start) = if direction_marker == 0 {
        if plaintext.len() < 4 {
            return Err(W0Error::InvalidEnvelope("client sequence"));
        }
        let sequence = u32::from_be_bytes(plaintext[..4].try_into().unwrap());
        if sequence != transport_sequence {
            return Err(W0Error::InvalidEnvelope("sequence mismatch"));
        }
        (Some(sequence), 4)
    } else {
        (None, 0)
    };
    let outer = parse_fields(&plaintext[start..])?;
    let expected: &[u32] = if direction_marker == 0 {
        if outer.len() == 2 { &[1, 2] } else { &[1] }
    } else if outer.len() == 2 {
        &[2, 1]
    } else {
        &[1]
    };
    if outer.iter().map(|field| field.number).collect::<Vec<_>>() != expected {
        return Err(W0Error::InvalidEnvelope("outer field order"));
    }
    let head_bytes = outer
        .iter()
        .find(|field| field.number == 1)
        .and_then(|field| field.bytes.as_deref())
        .ok_or(W0Error::InvalidEnvelope("CommonHead"))?;
    let head_fields = parse_fields(head_bytes)?;
    if head_fields.iter().any(|field| field.varint.is_none()) {
        return Err(W0Error::InvalidEnvelope("CommonHead wire type"));
    }
    let command_id =
        unique_varint(&head_fields, 1)?.ok_or(W0Error::InvalidEnvelope("command id"))?;
    let body_field = outer.iter().find(|field| field.number == 2);
    let body = body_field
        .and_then(|field| field.bytes.clone())
        .unwrap_or_default();
    let body_plaintext_offset = body_field.map_or(start, |field| start + field.value_start);
    Ok(W0ApplicationMessage {
        direction_marker,
        transport_sequence,
        client_sequence,
        head: MnaCommonHead {
            command_id,
            sequence_id: unique_varint(&head_fields, 2)?,
            error_id: unique_varint(&head_fields, 3)?,
        },
        body,
        body_plaintext_offset,
    })
}

/// Decode only the authenticated fields required by the UDP coordinate
/// session. Unknown protobuf fields remain ignored, while required fields,
/// wire types, uniqueness and the ten-player roster are strict.
pub fn parse_enter_game_session(
    message: &W0ApplicationMessage,
) -> Result<Option<EnterGameSession>, W0Error> {
    Ok(parse_enter_game_session_with_evidence(message)?.map(|parsed| parsed.session))
}

pub fn parse_enter_game_session_with_evidence(
    message: &W0ApplicationMessage,
) -> Result<Option<ParsedEnterGameSession>, W0Error> {
    match message.head.command_id {
        ENTER_GAME_NOTIFY_COMMAND => parse_enter_game_session_layout(
            message,
            false,
            SessionFieldLayout::ENTER,
            conceal::e0_notify(),
        )
        .map(Some),
        REENTER_GAME_NOTIFY_COMMAND => parse_enter_game_session_layout(
            message,
            true,
            SessionFieldLayout::REENTER,
            conceal::reenter_game_notify(),
        )
        .map(Some),
        _ => {
            // Some authenticated game modes use a different BKDR command ID
            // while retaining the descriptor-exact Enter/ReEnter body. Do not
            // trust the unknown command alone: require exactly one complete
            // layout to validate IP, port, packet key, game/map/mode fields,
            // and all ten roster entries before accepting session material.
            let enter = parse_enter_game_session_layout(
                message,
                false,
                SessionFieldLayout::ENTER,
                "AuthenticatedEnterLayout",
            );
            let reenter = parse_enter_game_session_layout(
                message,
                true,
                SessionFieldLayout::REENTER,
                "AuthenticatedReEnterLayout",
            );
            match (enter, reenter) {
                (Ok(parsed), Err(_)) | (Err(_), Ok(parsed)) => Ok(Some(parsed)),
                (Ok(_), Ok(_)) => Err(W0Error::InvalidEnvelope(
                    "ambiguous authenticated game-session layout",
                )),
                (Err(_), Err(_)) => Ok(None),
            }
        }
    }
}

/// Recover an Enter/ReEnter session body embedded inside an authenticated
/// server DATA plaintext whose outer application container is not the classic
/// one-message protobuf envelope.
///
/// Recent live traffic can batch or wrap the classic application message. We
/// therefore inspect only bounded length-delimited protobuf values already
/// covered by the recovered MNA AES session. A value is accepted only when the
/// complete descriptor-level Enter or ReEnter layout validates, including the
/// endpoint, packet key, game/map/mode fields, and exactly ten roster entries.
/// Ordinary protobuf values and arbitrary plaintext cannot install a session.
/// If a DATA frame contains multiple valid notifications, the last value in
/// wire order is the active notification.
pub fn recover_embedded_enter_game_session_with_evidence(
    plaintext: &[u8],
    direction_marker: u8,
    transport_sequence: u32,
) -> Option<ParsedEnterGameSession> {
    const MIN_SESSION_BODY_BYTES: usize = 128;
    const MAX_SESSION_BODY_BYTES: usize = 512 * 1024;
    const MAX_CANDIDATES: usize = 512;

    // Enter/ReEnter notifications are server-to-client control messages.
    if direction_marker != 1 {
        return None;
    }

    let mut candidates = 0_usize;
    let mut latest = None;
    for field_start in 0..plaintext.len() {
        let Some((value_start, value_end)) = length_delimited_value_at(plaintext, field_start)
        else {
            continue;
        };
        let value_length = value_end - value_start;
        if !(MIN_SESSION_BODY_BYTES..=MAX_SESSION_BODY_BYTES).contains(&value_length) {
            continue;
        }
        candidates += 1;
        if candidates > MAX_CANDIDATES {
            break;
        }
        let candidate = W0ApplicationMessage {
            direction_marker,
            transport_sequence,
            client_sequence: None,
            head: MnaCommonHead {
                // The compatibility path is deliberately body-authenticated;
                // an unrecognized wrapper command cannot weaken body checks.
                command_id: 0,
                sequence_id: None,
                error_id: None,
            },
            body: plaintext[value_start..value_end].to_vec(),
            body_plaintext_offset: value_start,
        };
        if let Ok(Some(parsed)) = parse_enter_game_session_with_evidence(&candidate) {
            latest = Some(parsed);
        }
    }
    latest
}

fn length_delimited_value_at(data: &[u8], field_start: usize) -> Option<(usize, usize)> {
    let mut offset = field_start;
    let tag = read_varint(data, &mut offset).ok()?;
    if tag >> 3 == 0 || tag & 7 != 2 {
        return None;
    }
    let length = usize::try_from(read_varint(data, &mut offset).ok()?).ok()?;
    let end = offset.checked_add(length)?;
    (end <= data.len()).then_some((offset, end))
}

fn parse_enter_game_session_layout(
    message: &W0ApplicationMessage,
    reenter: bool,
    layout: SessionFieldLayout,
    notification: &'static str,
) -> Result<ParsedEnterGameSession, W0Error> {
    let fields = parse_fields(&message.body)?;
    let server_ip = unique_bytes(&fields, 1)?
        .ok_or(W0Error::InvalidEnvelope(conceal::enter_game_notify_ip()))?;
    let server_ip = String::from_utf8(server_ip)
        .map_err(|_| W0Error::InvalidEnvelope(conceal::enter_game_notify_ip_utf8()))?;
    if server_ip.is_empty() {
        return Err(W0Error::InvalidEnvelope(
            conceal::enter_game_notify_ip_empty(),
        ));
    }
    let server_vip = unique_bytes(&fields, 18)?
        .map(|value| {
            String::from_utf8(value)
                .map_err(|_| W0Error::InvalidEnvelope(conceal::enter_game_notify_vip_utf8()))
        })
        .transpose()?;
    if server_vip.as_deref().is_some_and(str::is_empty) {
        return Err(W0Error::InvalidEnvelope(
            conceal::enter_game_notify_vip_empty(),
        ));
    }
    let server_port = required_nonnegative_int32(&fields, 2, conceal::enter_game_notify_port())?;
    let server_port = u16::try_from(server_port)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(W0Error::InvalidEnvelope(conceal::enter_game_notify_port()))?;
    let g0_id =
        required_positive_int64(&fields, layout.g0_id, conceal::enter_game_notify_game_id())?;
    let packet_key = unique_bytes(&fields, layout.packet_key)?.ok_or(W0Error::InvalidEnvelope(
        conceal::enter_game_notify_packet_key(),
    ))?;
    let packet_key = String::from_utf8(packet_key)
        .map_err(|_| W0Error::InvalidEnvelope(conceal::enter_game_notify_packet_key_utf8()))?;
    if packet_key.is_empty() {
        return Err(W0Error::InvalidEnvelope(
            conceal::enter_game_notify_packet_key_empty(),
        ));
    }
    let map_id =
        required_nonnegative_int32(&fields, layout.map_id, conceal::enter_game_notify_map_id())?;
    let g1_mode = required_nonnegative_int32(
        &fields,
        layout.g1_mode,
        conceal::enter_game_notify_game_mode(),
    )?;
    let s0_mode = required_nonnegative_int32(
        &fields,
        layout.s0_mode,
        conceal::enter_game_notify_sub_game_mode(),
    )?;
    let roster_values: Vec<_> = fields
        .iter()
        .filter(|field| field.number == layout.roster)
        .map(|field| {
            field
                .bytes
                .as_deref()
                .ok_or(W0Error::InvalidEnvelope("CampInfo wire type"))
                .and_then(parse_roster_entry)
        })
        .collect::<Result<_, _>>()?;
    if roster_values.len() != 10 {
        return Err(W0Error::InvalidEnvelope("CampInfo count is not ten"));
    }
    let map_id_evidence = required_field_evidence(
        &fields,
        layout.map_id,
        format!("{notification}.MapId"),
        "int32",
        message.body_plaintext_offset,
    )?;
    let game_mode_evidence = required_field_evidence(
        &fields,
        layout.g1_mode,
        format!("{notification}.GameMode"),
        "int32",
        message.body_plaintext_offset,
    )?;
    let sub_game_mode_evidence = required_field_evidence(
        &fields,
        layout.s0_mode,
        format!("{notification}.SubGameMode"),
        "int32",
        message.body_plaintext_offset,
    )?;
    let session = EnterGameSession {
        server_ip,
        server_vip,
        server_port,
        packet_key: Zeroizing::new(packet_key),
        g0_id,
        map_id,
        g1_mode,
        s0_mode,
        roster: roster_values,
        source_mna_sequence: message.transport_sequence,
        reenter,
    };
    Ok(ParsedEnterGameSession {
        session,
        map_id_evidence,
        game_mode_evidence,
        sub_game_mode_evidence,
    })
}

#[derive(Clone, Copy)]
struct SessionFieldLayout {
    g0_id: u32,
    packet_key: u32,
    g1_mode: u32,
    s0_mode: u32,
    map_id: u32,
    roster: u32,
}

impl SessionFieldLayout {
    const ENTER: Self = Self {
        g0_id: 7,
        packet_key: 8,
        g1_mode: 10,
        s0_mode: 11,
        map_id: 14,
        roster: 15,
    };

    const REENTER: Self = Self {
        g0_id: 11,
        packet_key: 13,
        g1_mode: 7,
        s0_mode: 8,
        map_id: 9,
        roster: 10,
    };
}

fn parse_roster_entry(data: &[u8]) -> Result<W0RosterEntry, W0Error> {
    let fields = parse_fields(data)?;
    if std::env::var_os("CODEV_ROSTER_IDS").is_some() {
        let mut line = String::from("[roster-ids]");
        for field in &fields {
            match (field.number, &field.varint, &field.bytes) {
                (1 | 2 | 4 | 5 | 11 | 15, Some(value), _) => {
                    line.push_str(&format!(" f{}={value}", field.number));
                }
                (3 | 18 | 20, None, Some(bytes)) => {
                    line.push_str(&format!(" f{}=<{}B>", field.number, bytes.len()));
                }
                (25 | 28, None, Some(bytes)) => {
                    line.push_str(&format!(
                        " f{}=0x{}",
                        field.number,
                        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ));
                }
                _ => {}
            }
        }
        eprintln!("{line}");
    }
    let agent_id = required_nonnegative_int32(&fields, 1, "MatchPlayerInfo.AgentId")?;
    if agent_id == 0 {
        return Err(W0Error::InvalidEnvelope("MatchPlayerInfo.AgentId"));
    }
    let skin_id = required_nonnegative_int32(&fields, 2, "MatchPlayerInfo.SkinId")?;
    let camp_id = required_positive_int64(&fields, 4, "MatchPlayerInfo.CampId")?;
    let uid = required_positive_int64(&fields, 5, "MatchPlayerInfo.Uid")?.to_string();
    let selected_backpack_id =
        required_nonnegative_int32(&fields, 8, "MatchPlayerInfo.SelectedBackpackId")?;
    let position_slot = unique_field_varint(&fields, 11)?
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(W0Error::InvalidEnvelope("MatchPlayerInfo.Pos"))?;
    let name = unique_bytes(&fields, 3)?
        .ok_or(W0Error::InvalidEnvelope("MatchPlayerInfo.Name missing"))?;
    let name = String::from_utf8(name)
        .map_err(|_| W0Error::InvalidEnvelope("MatchPlayerInfo.Name UTF-8"))?;
    validate_roster_name(&name, "MatchPlayerInfo.Name invalid")?;
    let display_name = unique_bytes(&fields, 16)?
        .map(|value| {
            String::from_utf8(value)
                .map_err(|_| W0Error::InvalidEnvelope("MatchPlayerInfo.DisplayName UTF-8"))
        })
        .transpose()?
        .filter(|value| !value.is_empty());
    if let Some(display_name) = display_name.as_deref() {
        validate_roster_name(display_name, "MatchPlayerInfo.DisplayName invalid")?;
    }
    let open_id =
        unique_bytes(&fields, 20)?.ok_or(W0Error::InvalidEnvelope("MatchPlayerInfo.OpenId"))?;
    let open_id = String::from_utf8(open_id)
        .map_err(|_| W0Error::InvalidEnvelope("MatchPlayerInfo.OpenId UTF-8"))?;
    if open_id.is_empty() {
        return Err(W0Error::InvalidEnvelope("MatchPlayerInfo.OpenId empty"));
    }
    let device_tag = unique_bytes(&fields, 18)?.is_some_and(|value| !value.is_empty());
    Ok(W0RosterEntry {
        name,
        display_name,
        uid,
        open_id,
        agent_id,
        skin_id,
        selected_backpack_id,
        camp_id,
        position_slot,
        device_tag,
    })
}

fn validate_roster_name(value: &str, error: &'static str) -> Result<(), W0Error> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(W0Error::InvalidEnvelope(error));
    }
    Ok(())
}

fn required_nonnegative_int32(
    fields: &[WireField],
    number: u32,
    name: &'static str,
) -> Result<u32, W0Error> {
    let value = unique_field_varint(fields, number)?.ok_or(W0Error::InvalidEnvelope(name))?;
    let value = i32::try_from(value).map_err(|_| W0Error::InvalidEnvelope(name))?;
    u32::try_from(value).map_err(|_| W0Error::InvalidEnvelope(name))
}

fn required_positive_int64(
    fields: &[WireField],
    number: u32,
    name: &'static str,
) -> Result<u64, W0Error> {
    let value = unique_field_varint(fields, number)?.ok_or(W0Error::InvalidEnvelope(name))?;
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .map(|value| value as u64)
        .ok_or(W0Error::InvalidEnvelope(name))
}

fn required_field_evidence(
    fields: &[WireField],
    number: u32,
    path: String,
    declared_type: &'static str,
    plaintext_base: usize,
) -> Result<MnaFieldEvidence, W0Error> {
    let mut matching = fields.iter().filter(|field| field.number == number);
    let field = matching
        .next()
        .ok_or(W0Error::InvalidEnvelope("field evidence missing"))?;
    if matching.next().is_some() {
        return Err(W0Error::InvalidEnvelope("duplicate field evidence"));
    }
    Ok(MnaFieldEvidence {
        path,
        field_number: field.number,
        declared_type,
        wire_type: field.wire_type,
        plaintext_start: plaintext_base + field.field_start,
        plaintext_end: plaintext_base + field.field_end,
        value_start: plaintext_base + field.value_start,
        value_end: plaintext_base + field.value_end,
    })
}

pub fn mna_key_fingerprint(key: &[u8; 16]) -> String {
    format!("{:x}", Sha256::digest(key))
}

#[derive(Clone, Debug)]
struct WireField {
    number: u32,
    wire_type: u8,
    varint: Option<u64>,
    bytes: Option<Vec<u8>>,
    field_start: usize,
    field_end: usize,
    value_start: usize,
    value_end: usize,
}

fn parse_fields(data: &[u8]) -> Result<Vec<WireField>, W0Error> {
    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < data.len() {
        let field_start = offset;
        let tag = read_varint(data, &mut offset)?;
        let number = u32::try_from(tag >> 3).map_err(|_| W0Error::InvalidEnvelope("field"))?;
        if number == 0 {
            return Err(W0Error::InvalidEnvelope("field zero"));
        }
        let wire_type = (tag & 7) as u8;
        match wire_type {
            0 => {
                let value_start = offset;
                let value = read_varint(data, &mut offset)?;
                fields.push(WireField {
                    number,
                    wire_type,
                    varint: Some(value),
                    bytes: None,
                    field_start,
                    field_end: offset,
                    value_start,
                    value_end: offset,
                });
            }
            2 => {
                let length = usize::try_from(read_varint(data, &mut offset)?)
                    .map_err(|_| W0Error::InvalidEnvelope("length"))?;
                let value_start = offset;
                let end = offset
                    .checked_add(length)
                    .filter(|end| *end <= data.len())
                    .ok_or(W0Error::InvalidEnvelope("truncated bytes"))?;
                fields.push(WireField {
                    number,
                    wire_type,
                    varint: None,
                    bytes: Some(data[offset..end].to_vec()),
                    field_start,
                    field_end: end,
                    value_start,
                    value_end: end,
                });
                offset = end;
            }
            _ => return Err(W0Error::InvalidEnvelope("wire type")),
        }
    }
    Ok(fields)
}

fn read_varint(data: &[u8], offset: &mut usize) -> Result<u64, W0Error> {
    let mut value = 0_u64;
    for shift in (0..70).step_by(7) {
        let byte = *data
            .get(*offset)
            .ok_or(W0Error::InvalidEnvelope("truncated varint"))?;
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(W0Error::InvalidEnvelope("oversized varint"))
}

fn unique_varint(fields: &[WireField], number: u32) -> Result<Option<u64>, W0Error> {
    let mut values = fields
        .iter()
        .filter(|field| field.number == number)
        .map(|field| field.varint);
    let first = values.next().flatten();
    if values.next().is_some() {
        return Err(W0Error::InvalidEnvelope("duplicate CommonHead field"));
    }
    Ok(first)
}

fn unique_field_varint(fields: &[WireField], number: u32) -> Result<Option<u64>, W0Error> {
    let matching: Vec<_> = fields
        .iter()
        .filter(|field| field.number == number)
        .collect();
    if matching.len() > 1 {
        return Err(W0Error::InvalidEnvelope("duplicate protobuf field"));
    }
    match matching.first() {
        None => Ok(None),
        Some(field) => field
            .varint
            .map(Some)
            .ok_or(W0Error::InvalidEnvelope("protobuf varint wire type")),
    }
}

fn unique_bytes(fields: &[WireField], number: u32) -> Result<Option<Vec<u8>>, W0Error> {
    let matching: Vec<_> = fields
        .iter()
        .filter(|field| field.number == number)
        .collect();
    if matching.len() > 1 {
        return Err(W0Error::InvalidEnvelope("duplicate protobuf field"));
    }
    match matching.first() {
        None => Ok(None),
        Some(field) => field
            .bytes
            .clone()
            .map(Some)
            .ok_or(W0Error::InvalidEnvelope("protobuf bytes wire type")),
    }
}

/// Gap/conflict-aware one-direction TCP byte reassembler.
pub struct TcpReassembler {
    expected: Option<u64>,
    reference: Option<u64>,
    pending: BTreeMap<u64, PendingTcpSegment>,
    pending_bytes: usize,
    max_pending_bytes: usize,
    gap: bool,
}

struct PendingTcpSegment {
    bytes: Vec<u8>,
    source: Option<TcpSourceProvenance>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSourceProvenance {
    pub capture_index: u64,
    pub timestamp_ns: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpReleasedChunk {
    pub bytes: Vec<u8>,
    pub source: TcpSourceProvenance,
}

impl TcpReassembler {
    pub fn new(max_pending_bytes: usize) -> Self {
        Self {
            expected: None,
            reference: None,
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_pending_bytes,
            gap: false,
        }
    }

    pub const fn has_gap(&self) -> bool {
        self.gap
    }

    pub fn pending_is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Anchor reassembly at the first payload sequence derived from a captured
    /// SYN/SYN-ACK. This makes a missing initial data segment observable as a
    /// gap instead of silently treating a late segment as the stream start.
    pub fn initialize(&mut self, next_sequence: u32) -> Result<(), W0Error> {
        if self.expected.is_some()
            || self.reference.is_some()
            || !self.pending.is_empty()
            || self.pending_bytes != 0
        {
            return Err(W0Error::TcpAlreadyInitialized);
        }
        self.expected = Some(u64::from(next_sequence));
        self.reference = Some(u64::from(next_sequence));
        Ok(())
    }

    /// Return true only when every byte through an observed FIN sequence has
    /// been released contiguously and no out-of-order segment remains.
    pub fn is_complete_at(&self, raw_end_sequence: u32) -> bool {
        let Some(expected) = self.expected else {
            return false;
        };
        let end = unwrap_tcp(raw_end_sequence, self.reference.unwrap_or(expected));
        !self.gap && self.pending.is_empty() && expected == end
    }

    pub fn push(&mut self, raw_sequence: u32, data: &[u8]) -> Result<Vec<u8>, W0Error> {
        Ok(self
            .push_segment(raw_sequence, data, None)?
            .into_iter()
            .flat_map(|segment| segment.bytes)
            .collect())
    }

    pub fn push_with_source(
        &mut self,
        raw_sequence: u32,
        data: &[u8],
        source: TcpSourceProvenance,
    ) -> Result<Vec<TcpReleasedChunk>, W0Error> {
        self.push_segment(raw_sequence, data, Some(source))?
            .into_iter()
            .map(|segment| {
                Ok(TcpReleasedChunk {
                    bytes: segment.bytes,
                    source: segment
                        .source
                        .ok_or(W0Error::InvalidEnvelope("missing TCP provenance"))?,
                })
            })
            .collect()
    }

    fn push_segment(
        &mut self,
        raw_sequence: u32,
        mut data: &[u8],
        source: Option<TcpSourceProvenance>,
    ) -> Result<Vec<PendingTcpSegment>, W0Error> {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let sequence = unwrap_tcp(
            raw_sequence,
            self.reference.unwrap_or(u64::from(raw_sequence)),
        );
        self.reference = Some(self.reference.map_or(sequence, |old| old.max(sequence)));
        if self.expected.is_none() {
            self.expected = Some(sequence);
        }
        let mut start = sequence;
        let expected = self.expected.unwrap();
        if start < expected {
            let overlap = usize::try_from(expected - start).unwrap_or(usize::MAX);
            if overlap >= data.len() {
                return Ok(Vec::new());
            }
            data = &data[overlap..];
            start = expected;
        }
        if let Some(previous) = self.pending.get(&start) {
            if previous.bytes != data {
                return Err(W0Error::TcpConflict(start));
            }
            return Ok(Vec::new());
        }
        if self.pending_bytes.saturating_add(data.len()) > self.max_pending_bytes {
            return Err(W0Error::TcpBufferLimit);
        }
        self.pending_bytes += data.len();
        self.pending.insert(
            start,
            PendingTcpSegment {
                bytes: data.to_vec(),
                source,
            },
        );
        let mut output = Vec::new();
        let mut expected = self.expected.unwrap();
        while let Some(segment) = self.pending.remove(&expected) {
            self.pending_bytes -= segment.bytes.len();
            expected += segment.bytes.len() as u64;
            output.push(segment);
        }
        self.expected = Some(expected);
        self.gap = self
            .pending
            .first_key_value()
            .is_some_and(|(&first, _)| first > expected);
        Ok(output)
    }
}

fn unwrap_tcp(raw: u32, reference: u64) -> u64 {
    const MODULUS: u64 = 1_u64 << 32;
    const HALF: u64 = 1_u64 << 31;
    let mut candidate = (reference / MODULUS) * MODULUS + u64::from(raw);
    if candidate.saturating_add(HALF) < reference {
        candidate = candidate.saturating_add(MODULUS);
    } else if candidate > reference.saturating_add(HALF) && candidate >= MODULUS {
        candidate -= MODULUS;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PacketSource, S0PcapSource, TransportKind, parse_transport};
    use std::collections::{HashMap, HashSet};
    use std::path::Path;

    fn frame(message_type: u16, extension: &[u8], payload: &[u8]) -> Vec<u8> {
        let header_length = MNA_BASE_HEADER_LENGTH + extension.len();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&MNA_MAGIC);
        bytes.extend_from_slice(&message_type.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&7_u32.to_be_bytes());
        bytes.extend_from_slice(&(header_length as u32).to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(extension);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn protobuf_varint(mut value: u64) -> Vec<u8> {
        let mut output = Vec::new();
        while value >= 0x80 {
            output.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        output.push(value as u8);
        output
    }

    fn protobuf_varint_field(output: &mut Vec<u8>, number: u32, value: u64) {
        output.extend(protobuf_varint(u64::from(number) << 3));
        output.extend(protobuf_varint(value));
    }

    fn protobuf_bytes_field(output: &mut Vec<u8>, number: u32, value: &[u8]) {
        output.extend(protobuf_varint((u64::from(number) << 3) | 2));
        output.extend(protobuf_varint(value.len() as u64));
        output.extend(value);
    }

    fn roster_entry_with_names(
        index: u32,
        name: Option<&[u8]>,
        display_name: Option<&[u8]>,
        invalid_open_id_wire_type: bool,
    ) -> Vec<u8> {
        let mut output = Vec::new();
        protobuf_varint_field(&mut output, 1, u64::from(3_000 + index));
        protobuf_varint_field(&mut output, 2, u64::from(20_000 + index));
        if let Some(name) = name {
            protobuf_bytes_field(&mut output, 3, name);
        }
        protobuf_varint_field(&mut output, 4, u64::from(index / 5 + 1));
        protobuf_varint_field(&mut output, 5, 100_000_000 + u64::from(index));
        protobuf_varint_field(&mut output, 8, u64::from(40_000 + index));
        protobuf_varint_field(&mut output, 11, u64::from(index % 5));
        if let Some(display_name) = display_name {
            protobuf_bytes_field(&mut output, 16, display_name);
        }
        if invalid_open_id_wire_type {
            protobuf_varint_field(&mut output, 20, u64::from(index + 1));
        } else {
            protobuf_bytes_field(&mut output, 20, format!("open-id-{index}").as_bytes());
        }
        output
    }

    fn roster_entry(index: u32, invalid_open_id_wire_type: bool) -> Vec<u8> {
        let name = format!("player-{index}");
        let display_name = (index == 0).then_some(b"presentation-alias".as_slice());
        roster_entry_with_names(
            index,
            Some(name.as_bytes()),
            display_name,
            invalid_open_id_wire_type,
        )
    }

    fn enter_game_message(reenter: bool, invalid_open_id_wire_type: bool) -> W0ApplicationMessage {
        let layout = if reenter {
            SessionFieldLayout::REENTER
        } else {
            SessionFieldLayout::ENTER
        };
        let mut body = Vec::new();
        protobuf_bytes_field(&mut body, 1, b"game.example.test");
        protobuf_varint_field(&mut body, 2, 15_806);
        protobuf_varint_field(&mut body, layout.g0_id, 9_000_000);
        protobuf_bytes_field(&mut body, layout.packet_key, b"packet-key");
        protobuf_varint_field(&mut body, layout.g1_mode, 102);
        protobuf_varint_field(&mut body, layout.s0_mode, 101_002);
        protobuf_varint_field(&mut body, layout.map_id, 1_003);
        for index in 0..10 {
            protobuf_bytes_field(
                &mut body,
                layout.roster,
                &roster_entry(index, invalid_open_id_wire_type && index == 0),
            );
        }
        W0ApplicationMessage {
            direction_marker: 1,
            transport_sequence: 613,
            client_sequence: None,
            head: MnaCommonHead {
                command_id: if reenter {
                    REENTER_GAME_NOTIFY_COMMAND
                } else {
                    ENTER_GAME_NOTIFY_COMMAND
                },
                sequence_id: Some(1),
                error_id: Some(0),
            },
            body,
            body_plaintext_offset: 0,
        }
    }

    #[test]
    fn incremental_framer_and_key_recovery_are_strict() {
        let key = [9_u8; 16];
        let mut extension = vec![0x02, 0x10];
        extension.extend_from_slice(&key);
        let raw = frame(MNA_SERVER_HELLO, &extension, b"");
        let mut framer = W0Framer::default();
        assert!(framer.feed(&raw[..10]).unwrap().is_empty());
        let frames = framer.feed(&raw[10..]).unwrap();
        assert_eq!(recover_mna_session_key(&frames).unwrap().as_ref(), &key);
        assert!(!framer.has_partial_frame());
    }

    #[test]
    fn close_frame_uses_the_base_header_and_is_not_ciphertext_aligned() {
        let raw = frame(MNA_CLOSE, &[], &[1, 2, 3]);
        let frames = W0Framer::default().feed(&raw).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].message_type, MNA_CLOSE);
        assert_eq!(frames[0].header.len(), MNA_BASE_HEADER_LENGTH);
        assert_eq!(frames[0].payload, [1, 2, 3]);
        assert!(!frames[0].encrypted());
    }

    #[test]
    fn tcp_reassembly_releases_only_contiguous_bytes() {
        let mut tcp = TcpReassembler::new(1024);
        assert_eq!(tcp.push(100, b"ab").unwrap(), b"ab");
        assert!(tcp.push(104, b"ef").unwrap().is_empty());
        assert!(tcp.has_gap());
        assert_eq!(tcp.push(102, b"cd").unwrap(), b"cdef");
        assert!(!tcp.has_gap());
    }

    #[test]
    fn enter_and_reenter_use_their_descriptor_exact_identity_layouts() {
        for reenter in [false, true] {
            let message = enter_game_message(reenter, false);
            let session = parse_enter_game_session(&message).unwrap().unwrap();
            assert_eq!(session.g1_mode, 102);
            assert_eq!(session.s0_mode, 101_002);
            assert_eq!(session.source_mna_sequence, 613);
            assert_eq!(session.reenter, reenter);
            assert_eq!(session.roster.len(), 10);
            for (index, player) in session.roster.iter().enumerate() {
                assert_eq!(player.name, format!("player-{index}"));
                assert_eq!(
                    player.display_name.as_deref(),
                    (index == 0).then_some("presentation-alias")
                );
                assert_eq!(player.uid, (100_000_000 + index as u64).to_string());
                assert_eq!(player.open_id, format!("open-id-{index}"));
                assert_eq!(player.skin_id, 20_000 + index as u32);
                assert_eq!(player.selected_backpack_id, 40_000 + index as u32);
            }
        }
    }

    #[test]
    fn authenticated_unknown_command_accepts_exactly_one_complete_session_layout() {
        for reenter in [false, true] {
            let mut message = enter_game_message(reenter, false);
            message.head.command_id = 9_999_991;
            let session = parse_enter_game_session(&message).unwrap().unwrap();
            assert_eq!(session.map_id, 1_003);
            assert_eq!(session.server_port, 15_806);
            assert_eq!(session.roster.len(), 10);
            assert_eq!(session.reenter, reenter);
        }

        let unrelated = W0ApplicationMessage {
            direction_marker: 1,
            transport_sequence: 1,
            client_sequence: None,
            head: MnaCommonHead {
                command_id: 9_999_992,
                sequence_id: None,
                error_id: None,
            },
            body: vec![0x08, 0x01],
            body_plaintext_offset: 0,
        };
        assert!(parse_enter_game_session(&unrelated).unwrap().is_none());
    }

    #[test]
    fn authenticated_wrapped_session_body_is_recovered_without_relaxing_layout() {
        for reenter in [false, true] {
            let message = enter_game_message(reenter, false);
            let mut head = Vec::new();
            protobuf_varint_field(&mut head, 1, 9_999_993);
            let mut wrapped = Vec::new();
            protobuf_bytes_field(&mut wrapped, 7, b"authenticated-wrapper-metadata");
            protobuf_bytes_field(&mut wrapped, 1, &head);
            protobuf_bytes_field(&mut wrapped, 2, &message.body);
            protobuf_varint_field(&mut wrapped, 9, 1);

            assert!(parse_mna_application(&wrapped, 1, 700).is_err());
            let recovered = recover_embedded_enter_game_session_with_evidence(&wrapped, 1, 700)
                .expect("wrapped authenticated session should be recovered");
            assert_eq!(recovered.session.map_id, 1_003);
            assert_eq!(recovered.session.server_port, 15_806);
            assert_eq!(recovered.session.roster.len(), 10);
            assert_eq!(recovered.session.reenter, reenter);
            assert!(recovered.map_id_evidence.plaintext_start > 0);
        }
    }

    #[test]
    fn embedded_session_recovery_rejects_client_and_unrelated_values() {
        let message = enter_game_message(false, false);
        let mut wrapped = Vec::new();
        protobuf_bytes_field(&mut wrapped, 2, &message.body);
        assert!(recover_embedded_enter_game_session_with_evidence(&wrapped, 0, 1).is_none());

        let mut unrelated = Vec::new();
        protobuf_bytes_field(&mut unrelated, 2, &[0x08, 0x01]);
        protobuf_bytes_field(&mut unrelated, 3, &[0x12; 512]);
        assert!(recover_embedded_enter_game_session_with_evidence(&unrelated, 1, 1).is_none());
    }

    #[test]
    fn roster_identity_wire_type_mismatch_fails_closed() {
        let message = enter_game_message(false, true);
        assert_eq!(
            parse_enter_game_session(&message),
            Err(W0Error::InvalidEnvelope("protobuf bytes wire type"))
        );
    }

    #[test]
    fn roster_name_and_display_name_keep_descriptor_exact_semantics() {
        let player = parse_roster_entry(&roster_entry_with_names(
            0,
            Some(b"stable-name"),
            Some(b"different-display-name"),
            false,
        ))
        .unwrap();
        assert_eq!(player.name, "stable-name");
        assert_eq!(
            player.display_name.as_deref(),
            Some("different-display-name")
        );

        let absent_display = parse_roster_entry(&roster_entry_with_names(
            0,
            Some(b"stable-name"),
            None,
            false,
        ))
        .unwrap();
        assert_eq!(absent_display.name, "stable-name");
        assert_eq!(absent_display.display_name, None);

        let empty_display = parse_roster_entry(&roster_entry_with_names(
            0,
            Some(b"stable-name"),
            Some(b""),
            false,
        ))
        .unwrap();
        assert_eq!(empty_display.display_name, None);

        for name in [None, Some(b"".as_slice())] {
            assert!(matches!(
                parse_roster_entry(&roster_entry_with_names(0, name, Some(b"alias"), false)),
                Err(W0Error::InvalidEnvelope(
                    "MatchPlayerInfo.Name missing" | "MatchPlayerInfo.Name invalid"
                ))
            ));
        }
    }

    #[test]
    fn roster_name_fields_reject_duplicates_wire_errors_and_truncation() {
        let mut duplicate_name = roster_entry_with_names(0, Some(b"stable"), None, false);
        protobuf_bytes_field(&mut duplicate_name, 3, b"second");
        assert_eq!(
            parse_roster_entry(&duplicate_name),
            Err(W0Error::InvalidEnvelope("duplicate protobuf field"))
        );

        let mut duplicate_display =
            roster_entry_with_names(0, Some(b"stable"), Some(b"alias"), false);
        protobuf_bytes_field(&mut duplicate_display, 16, b"second");
        assert_eq!(
            parse_roster_entry(&duplicate_display),
            Err(W0Error::InvalidEnvelope("duplicate protobuf field"))
        );

        let mut name_wire_type = roster_entry_with_names(0, None, None, false);
        protobuf_varint_field(&mut name_wire_type, 3, 1);
        assert_eq!(
            parse_roster_entry(&name_wire_type),
            Err(W0Error::InvalidEnvelope("protobuf bytes wire type"))
        );

        let mut display_wire_type = roster_entry_with_names(0, Some(b"stable"), None, false);
        protobuf_varint_field(&mut display_wire_type, 16, 1);
        assert_eq!(
            parse_roster_entry(&display_wire_type),
            Err(W0Error::InvalidEnvelope("protobuf bytes wire type"))
        );

        let mut truncated = roster_entry_with_names(0, Some(b"stable"), None, false);
        truncated.extend(protobuf_varint((16_u64 << 3) | 2));
        truncated.extend(protobuf_varint(4));
        truncated.extend_from_slice(b"ab");
        assert_eq!(
            parse_roster_entry(&truncated),
            Err(W0Error::InvalidEnvelope("truncated bytes"))
        );
    }

    #[test]
    fn private_capture_recovers_descriptor_exact_enter_game_session() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !fixture.is_file() {
            return;
        }
        let mut source = S0PcapSource::open(fixture).unwrap();
        let mut flows: HashMap<_, (TcpReassembler, W0Framer, bool)> = HashMap::new();
        let mut frames = Vec::new();
        while let Some(packet) = source.next_packet().unwrap() {
            let Ok(transport) = parse_transport(&packet) else {
                continue;
            };
            if transport.kind != TransportKind::Tcp || transport.payload.is_empty() {
                continue;
            }
            let flow = flows
                .entry((transport.source, transport.destination))
                .or_insert_with(|| {
                    (
                        TcpReassembler::new(2 * 1024 * 1024),
                        W0Framer::default(),
                        false,
                    )
                });
            let bytes = flow
                .0
                .push(transport.tcp_sequence.unwrap(), transport.payload)
                .unwrap();
            if bytes.is_empty() {
                continue;
            }
            if !flow.2 {
                if !bytes.starts_with(&MNA_MAGIC) {
                    continue;
                }
                flow.2 = true;
            }
            frames.extend(flow.1.feed(&bytes).unwrap());
        }
        let key = recover_mna_session_key(&frames).unwrap();
        let mut session = None;
        for frame in frames.iter().filter(|frame| frame.message_type == MNA_DATA) {
            let mut plaintext = decrypt_mna_frame(frame, &key).unwrap();
            strip_mna_random_padding(&mut plaintext).unwrap();
            let application =
                parse_mna_application(&plaintext, frame.direction_marker, frame.sequence).unwrap();
            if let Some(value) = parse_enter_game_session(&application).unwrap() {
                session = Some(value);
                break;
            }
        }
        let session = session.expect("EnterGameNotify was not recovered");
        assert_eq!(session.map_id, 1003);
        assert_eq!(session.g1_mode, 102);
        assert_eq!(session.s0_mode, 101_002);
        assert_eq!(session.source_mna_sequence, 613);
        assert_eq!(session.roster.len(), 10);
        assert_eq!(session.server_port, 15_806);
        assert_eq!(
            session
                .roster
                .iter()
                .map(|player| player.uid.as_str())
                .collect::<HashSet<_>>()
                .len(),
            10
        );
        assert_eq!(
            session
                .roster
                .iter()
                .map(|player| player.open_id.as_str())
                .collect::<HashSet<_>>()
                .len(),
            10
        );
        let mut identity_projection = Vec::new();
        for (index, player) in session.roster.iter().enumerate() {
            if index != 0 {
                identity_projection.push(b'\n');
            }
            let values = [
                player.uid.clone(),
                player.open_id.clone(),
                player.skin_id.to_string(),
                player.selected_backpack_id.to_string(),
            ];
            for (field_index, value) in values.iter().enumerate() {
                if field_index != 0 {
                    identity_projection.push(0);
                }
                identity_projection.extend_from_slice(value.as_bytes());
            }
            let debug = format!("{player:?}");
            assert!(!debug.contains(&player.uid));
            assert!(!debug.contains(&player.open_id));
        }
        assert_eq!(
            format!("{:x}", Sha256::digest(&identity_projection)),
            "4f2edbf832e843d1b266839b7f481aee753de8a7650798dde30dd590aff6faad"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(session.packet_key.as_bytes())),
            "ffd8b9874c622ab7134b20c503d7e40644ef240d8206cd121dae077ad051243f"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(session.g0_id.to_string().as_bytes())),
            "908e7da30fff4ca3ba84e6b2542c73c1884db3d59eb7b7d6e7c9bc41f7074eac"
        );
    }
}
