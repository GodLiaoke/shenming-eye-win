//! Bounded, typed projection of non-primary GCloud room/team signalling.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use codev_stream::{
    PacketSource, S0PcapSource, SelectedUdpFlow, SourceError, TransportKind, parse_transport,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_AUX_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_ROOMS: usize = 64;
const MAX_SIGNALS: usize = 256;
const MAX_IDS: usize = 256;
const MAX_TEXT_BYTES: usize = 4 * 1024;
const MAX_ACCESS_ENDPOINTS: usize = 64;
const MAX_JSON_CANDIDATES: usize = 64;

#[derive(Debug, Error)]
pub enum CompatibilityAuxiliaryError {
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("auxiliary signalling exceeded the bounded {0} limit")]
    Bound(&'static str),
    #[error("room_info contains an invalid {0}")]
    InvalidRoom(&'static str),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompatibilityAuxiliaryCapture {
    pub events: Vec<AuxiliaryVoiceEvent>,
    pub app_ids: Vec<String>,
    pub voice_rooms: Vec<VoiceRoomInfo>,
    pub team_signals: Vec<AuxiliaryTeamSignal>,
    pub open_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxiliaryVoiceEvent {
    pub timestamp_ns: u64,
    pub source_packet: u64,
    pub room: VoiceRoomInfo,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct VoiceRoomInfo {
    pub room_id: String,
    pub room_key: String,
    pub member_id: String,
    pub room_name: String,
    pub business_id: String,
    pub open_id: String,
    pub access_ip: Vec<String>,
    #[serde(default)]
    pub small_mian_liu_url: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuxiliaryTeamKind {
    IngameCamp,
    IngameTeam,
    PregameTeam,
}

impl AuxiliaryTeamKind {
    #[cfg(test)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngameCamp => "ingame_camp",
            Self::IngameTeam => "ingame_team",
            Self::PregameTeam => "pregame_team",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuxiliaryTeamSignal {
    pub kind: AuxiliaryTeamKind,
    pub id: String,
    pub first_source_packet: u64,
}

#[derive(Deserialize)]
struct RoomEnvelope {
    #[serde(rename = "type")]
    kind: String,
    info: VoiceRoomInfo,
}

pub fn scan_auxiliary_capture(
    pcap: &Path,
    primary: SelectedUdpFlow,
) -> Result<CompatibilityAuxiliaryCapture, CompatibilityAuxiliaryError> {
    let mut source = S0PcapSource::open(pcap)?;
    let mut rooms = BTreeMap::<String, VoiceRoomInfo>::new();
    let mut events = Vec::new();
    let mut app_ids = BTreeSet::new();
    let mut open_ids = BTreeSet::new();
    let mut signals = BTreeMap::<(AuxiliaryTeamKind, String), u64>::new();
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if transport.kind == TransportKind::Udp
            && primary
                .key
                .contains(transport.source, transport.destination)
        {
            continue;
        }
        let payload = transport.payload;
        if payload.is_empty() || payload.len() > MAX_AUX_PAYLOAD_BYTES {
            continue;
        }
        let source_packet = packet.index + 1;
        observe_marker(
            payload,
            b"__TeamID:",
            AuxiliaryTeamKind::PregameTeam,
            source_packet,
            &mut signals,
        )?;
        observe_marker(
            payload,
            b"__InGameTeamID:",
            AuxiliaryTeamKind::IngameTeam,
            source_packet,
            &mut signals,
        )?;
        observe_marker(
            payload,
            b"InGameCampID:",
            AuxiliaryTeamKind::IngameCamp,
            source_packet,
            &mut signals,
        )?;
        for marker in [b"appid=".as_slice(), b"app_id\":\"".as_slice()] {
            observe_decimal_values(payload, marker, &mut app_ids)?;
        }
        for marker in [b"openid=".as_slice(), b"open_id\":\"".as_slice()] {
            observe_decimal_values(payload, marker, &mut open_ids)?;
        }

        let Some(envelope) = json_envelope(payload)? else {
            continue;
        };
        if envelope.kind != "room_info" {
            continue;
        }
        validate_room(&envelope.info)?;
        if rooms.len() >= MAX_ROOMS && !rooms.contains_key(&envelope.info.room_id) {
            return Err(CompatibilityAuxiliaryError::Bound("room"));
        }
        if !envelope.info.open_id.is_empty() {
            insert_bounded_identifier(&mut open_ids, &envelope.info.open_id)?;
        }
        if let Some(app_id) = envelope.info.business_id.strip_prefix("gcloud.")
            && decimal_text(app_id)
        {
            insert_bounded_identifier(&mut app_ids, app_id)?;
        }
        let room_id = envelope.info.room_id.clone();
        if rooms.contains_key(&room_id) {
            continue;
        }
        events.push(AuxiliaryVoiceEvent {
            timestamp_ns: packet.timestamp_ns,
            source_packet,
            room: envelope.info.clone(),
        });
        rooms.insert(room_id, envelope.info);
    }
    events.sort_by_key(|event| event.timestamp_ns);
    Ok(CompatibilityAuxiliaryCapture {
        events,
        app_ids: app_ids.into_iter().collect(),
        voice_rooms: rooms.into_values().collect(),
        team_signals: signals
            .into_iter()
            .map(|((kind, id), first_source_packet)| AuxiliaryTeamSignal {
                kind,
                id,
                first_source_packet,
            })
            .collect(),
        open_ids: open_ids.into_iter().collect(),
    })
}

fn observe_marker(
    payload: &[u8],
    marker: &[u8],
    kind: AuxiliaryTeamKind,
    source_packet: u64,
    signals: &mut BTreeMap<(AuxiliaryTeamKind, String), u64>,
) -> Result<(), CompatibilityAuxiliaryError> {
    let mut cursor = 0_usize;
    while let Some(relative) = find_bytes(&payload[cursor..], marker) {
        let start = cursor + relative + marker.len();
        let end = decimal_end(payload, start);
        if end > start {
            let value = &payload[start..end];
            if value.len() > MAX_TEXT_BYTES {
                return Err(CompatibilityAuxiliaryError::Bound(
                    "team signal identifier length",
                ));
            }
            let key = (kind, String::from_utf8_lossy(value).into_owned());
            if !signals.contains_key(&key) {
                if signals.len() >= MAX_SIGNALS {
                    return Err(CompatibilityAuxiliaryError::Bound("team signal"));
                }
                signals.insert(key, source_packet);
            }
        }
        cursor = start.max(cursor + relative + 1);
    }
    Ok(())
}

fn observe_decimal_values(
    payload: &[u8],
    marker: &[u8],
    values: &mut BTreeSet<String>,
) -> Result<(), CompatibilityAuxiliaryError> {
    let mut cursor = 0_usize;
    while let Some(relative) = find_ascii_case_insensitive(&payload[cursor..], marker) {
        let start = cursor + relative + marker.len();
        let end = decimal_end(payload, start);
        if end > start {
            let value = std::str::from_utf8(&payload[start..end])
                .expect("ASCII-decimal scan always yields UTF-8");
            insert_bounded_identifier(values, value)?;
        }
        cursor = start.max(cursor + relative + 1);
    }
    Ok(())
}

fn insert_bounded_identifier(
    values: &mut BTreeSet<String>,
    value: &str,
) -> Result<(), CompatibilityAuxiliaryError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(CompatibilityAuxiliaryError::Bound("identifier length"));
    }
    if !values.contains(value) {
        if values.len() >= MAX_IDS {
            return Err(CompatibilityAuxiliaryError::Bound("identifier"));
        }
        values.insert(value.to_owned());
    }
    Ok(())
}

fn decimal_end(payload: &[u8], start: usize) -> usize {
    payload[start..]
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .map_or(payload.len(), |length| start + length)
}

fn decimal_text(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn find_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window.eq_ignore_ascii_case(needle))
        })
        .flatten()
}

fn json_envelope(payload: &[u8]) -> Result<Option<RoomEnvelope>, CompatibilityAuxiliaryError> {
    let mut candidates = 0_usize;
    for (start, pair) in payload.windows(2).enumerate() {
        if pair != b"{\"" {
            continue;
        }
        candidates += 1;
        if candidates > MAX_JSON_CANDIDATES {
            return Err(CompatibilityAuxiliaryError::Bound("JSON candidate"));
        }
        let mut deserializer = serde_json::Deserializer::from_slice(&payload[start..]);
        if let Ok(value) = RoomEnvelope::deserialize(&mut deserializer) {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn validate_room(room: &VoiceRoomInfo) -> Result<(), CompatibilityAuxiliaryError> {
    for (name, value) in [
        ("room_id", room.room_id.as_str()),
        ("room_key", room.room_key.as_str()),
        ("member_id", room.member_id.as_str()),
        ("room_name", room.room_name.as_str()),
        ("business_id", room.business_id.as_str()),
        ("open_id", room.open_id.as_str()),
    ] {
        if value.is_empty() || value.len() > MAX_TEXT_BYTES {
            return Err(CompatibilityAuxiliaryError::InvalidRoom(name));
        }
    }
    if room.access_ip.len() > MAX_ACCESS_ENDPOINTS
        || room.small_mian_liu_url.len() > MAX_ACCESS_ENDPOINTS
        || room
            .access_ip
            .iter()
            .chain(&room.small_mian_liu_url)
            .any(|value| value.len() > MAX_TEXT_BYTES)
    {
        return Err(CompatibilityAuxiliaryError::InvalidRoom("endpoint list"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_stream::{S0PcapSource, discover_primary_udp_flow};

    #[test]
    fn identifier_sets_reject_length_and_capacity_before_insertion() {
        let mut values = BTreeSet::new();
        let overlong = "1".repeat(MAX_TEXT_BYTES + 1);
        assert!(matches!(
            insert_bounded_identifier(&mut values, &overlong),
            Err(CompatibilityAuxiliaryError::Bound("identifier length"))
        ));
        assert!(values.is_empty());

        for index in 0..MAX_IDS {
            insert_bounded_identifier(&mut values, &index.to_string()).unwrap();
        }
        assert!(matches!(
            insert_bounded_identifier(&mut values, "999999"),
            Err(CompatibilityAuxiliaryError::Bound("identifier"))
        ));
        assert_eq!(values.len(), MAX_IDS);
    }

    #[test]
    fn team_signals_reject_length_and_capacity_before_insertion() {
        let mut signals = BTreeMap::new();
        let mut payload = b"__TeamID:".to_vec();
        payload.extend(std::iter::repeat_n(b'1', MAX_TEXT_BYTES + 1));
        assert!(matches!(
            observe_marker(
                &payload,
                b"__TeamID:",
                AuxiliaryTeamKind::PregameTeam,
                1,
                &mut signals,
            ),
            Err(CompatibilityAuxiliaryError::Bound(
                "team signal identifier length"
            ))
        ));
        assert!(signals.is_empty());

        for index in 0..MAX_SIGNALS {
            signals.insert(
                (AuxiliaryTeamKind::PregameTeam, index.to_string()),
                index as u64,
            );
        }
        assert!(matches!(
            observe_marker(
                b"__TeamID:999999",
                b"__TeamID:",
                AuxiliaryTeamKind::PregameTeam,
                1,
                &mut signals,
            ),
            Err(CompatibilityAuxiliaryError::Bound("team signal"))
        ));
        assert_eq!(signals.len(), MAX_SIGNALS);
    }

    #[test]
    fn json_candidate_scan_fails_closed_before_quadratic_suffix_work() {
        let payload = b"{\"".repeat(MAX_JSON_CANDIDATES + 1);
        assert!(matches!(
            json_envelope(&payload),
            Err(CompatibilityAuxiliaryError::Bound("JSON candidate"))
        ));
    }

    #[test]
    fn private_full_capture_recovers_canonical_auxiliary_metadata() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !pcap.is_file() {
            return;
        }
        let mut source = S0PcapSource::open(&pcap).unwrap();
        let flow = discover_primary_udp_flow(&mut source).unwrap();
        let auxiliary = scan_auxiliary_capture(&pcap, flow).unwrap();
        assert_eq!(auxiliary.events.len(), 3);
        assert_eq!(auxiliary.voice_rooms.len(), 3);
        assert_eq!(auxiliary.app_ids, ["256572112"]);
        assert_eq!(auxiliary.open_ids, ["10250660069838341336"]);
        assert_eq!(
            auxiliary
                .team_signals
                .iter()
                .map(|signal| (
                    signal.kind.as_str(),
                    signal.id.as_str(),
                    signal.first_source_packet,
                ))
                .collect::<Vec<_>>(),
            [
                ("ingame_camp", "579809563246361024", 2_752),
                ("ingame_team", "579809563246361026", 2_718),
                ("pregame_team", "444777136650993294", 1_958),
            ]
        );
        assert_eq!(
            auxiliary
                .events
                .iter()
                .map(|event| event.source_packet)
                .collect::<Vec<_>>(),
            [1_963, 2_719, 2_759]
        );
    }
}
