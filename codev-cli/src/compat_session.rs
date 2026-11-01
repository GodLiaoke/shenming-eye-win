//! Strict loader for the private Python compatibility-session artifact.
//!
//! This module deliberately exposes only an [`EnterGameSession`].  It never
//! implements serialization for the private input model, and its errors do not
//! include JSON values.  PacketKey, GameId-as-text, UID, OpenID, and roster
//! names are held in zeroizing temporary buffers while the document is
//! validated.

use std::collections::HashSet;
use std::fmt;
use std::io::{self, BufReader};
use std::path::Path;

use codev_stream::{ENTER_GAME_NOTIFY_COMMAND, EnterGameSession, W0RosterEntry};
use serde::Deserialize;
use serde::de::{self, Deserializer, Visitor};
use thiserror::Error;
use zeroize::Zeroizing;

const COMPATIBILITY_BUILD_DOTTED: &str = "1.24.0.2911";
const COMPATIBILITY_BUILD_CAPTURE: &str = "1.24.0 (2911)";
const MAX_SESSION_BYTES: u64 = 16 * 1024 * 1024;
const EXPECTED_ROSTER_LENGTH: usize = 10;

/// A fail-closed compatibility-session loading error.
///
/// JSON parser details are intentionally reduced to a line and column so an
/// invalid private value can never be copied into logs through this error.
#[derive(Debug, Error)]
pub enum CompatibilitySessionError {
    #[error("could not access the compatibility session: {0}")]
    Io(#[from] io::Error),
    #[error("compatibility session access controls could not be proven")]
    AccessControl,
    #[error("compatibility session exceeds the {MAX_SESSION_BYTES}-byte limit")]
    FileTooLarge,
    #[cfg(unix)]
    #[error("private compatibility session must have POSIX mode 0600")]
    PrivateFileMode,
    #[error("invalid compatibility session JSON at line {line}, column {column}")]
    Json { line: usize, column: usize },
    #[error("unsupported compatibility-session build")]
    UnsupportedBuild,
    #[error("invalid compatibility session: {0}")]
    Invalid(&'static str),
}

/// Load a Python decoder/session JSON file as an authenticated UDP session.
///
/// The accepted build is fixed to CodeV `1.24.0.2911`.  The legacy extractor's
/// display spelling (`1.24.0 (2911)`) is accepted as the same exact build.  A
/// private file must declare mode `0600`, and on POSIX its actual mode must
/// match.  Required fields, numeric ranges, the ten-player roster, duplicate
/// identities, duplicate camp positions, and the two possible roster copies
/// are all checked before an [`EnterGameSession`] is returned.
pub fn load_compatibility_enter_session(
    path: impl AsRef<Path>,
) -> Result<EnterGameSession, CompatibilitySessionError> {
    let file =
        codev_stream::open_private_session_file(path.as_ref()).map_err(|error| match error {
            codev_stream::SessionError::Io(error) => CompatibilitySessionError::Io(error),
            #[cfg(unix)]
            codev_stream::SessionError::InsecureSessionPermissions(_) => {
                CompatibilitySessionError::PrivateFileMode
            }
            _ => CompatibilitySessionError::AccessControl,
        })?;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_SESSION_BYTES {
        return Err(CompatibilitySessionError::FileTooLarge);
    }
    validate_private_file_mode(&metadata)?;

    let raw: RawSession = serde_json::from_reader(BufReader::new(file)).map_err(|error| {
        CompatibilitySessionError::Json {
            line: error.line(),
            column: error.column(),
        }
    })?;
    raw.into_session()
}

#[cfg(unix)]
fn validate_private_file_mode(
    metadata: &std::fs::Metadata,
) -> Result<(), CompatibilitySessionError> {
    use std::os::unix::fs::PermissionsExt;

    if metadata.permissions().mode() & 0o777 != 0o600 {
        return Err(CompatibilitySessionError::PrivateFileMode);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_mode(
    _metadata: &std::fs::Metadata,
) -> Result<(), CompatibilitySessionError> {
    Ok(())
}

#[derive(Deserialize)]
struct RawSession {
    build: String,
    control_plane: RawControlPlane,
    privacy: RawPrivacy,
}

impl RawSession {
    fn into_session(self) -> Result<EnterGameSession, CompatibilitySessionError> {
        if !matches!(
            self.build.as_str(),
            COMPATIBILITY_BUILD_DOTTED | COMPATIBILITY_BUILD_CAPTURE
        ) {
            return Err(CompatibilitySessionError::UnsupportedBuild);
        }
        self.privacy.validate()?;
        self.control_plane.into_session()
    }
}

#[derive(Deserialize)]
struct RawPrivacy {
    required_file_mode: String,
    contains_raw_packet_key: bool,
    contains_raw_game_id: bool,
    contains_raw_player_identifiers: bool,
}

impl RawPrivacy {
    fn validate(self) -> Result<(), CompatibilitySessionError> {
        if self.required_file_mode != "0600"
            || !self.contains_raw_packet_key
            || !self.contains_raw_game_id
            || !self.contains_raw_player_identifiers
        {
            return Err(CompatibilitySessionError::Invalid(
                "private-data declaration is absent or inconsistent",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawControlPlane {
    message_type: String,
    command_id: FlexibleUnsigned,
    e0_notify: RawEnterGameNotify,
    #[serde(default)]
    roster: Option<Vec<RawRosterEntry>>,
    mna_frame: RawMnaFrame,
}

impl RawControlPlane {
    fn into_session(mut self) -> Result<EnterGameSession, CompatibilitySessionError> {
        if self.message_type != codev_conceal::e0_notify()
            || self.command_id.value() != ENTER_GAME_NOTIFY_COMMAND
        {
            return Err(CompatibilitySessionError::Invalid(
                "control plane is not the expected notification",
            ));
        }

        let notify_roster = self
            .e0_notify
            .c0_info
            .take()
            .map(convert_roster)
            .transpose()?;
        let projected_roster = self.roster.take().map(convert_roster).transpose()?;
        let roster = match (notify_roster, projected_roster) {
            (Some(notify), Some(projected)) => {
                if notify != projected {
                    return Err(CompatibilitySessionError::Invalid(
                        "control_plane.roster disagrees with notification camp list",
                    ));
                }
                notify
            }
            (Some(roster), None) | (None, Some(roster)) => roster,
            (None, None) => {
                return Err(CompatibilitySessionError::Invalid(
                    "ten-player CampInfo/roster is missing",
                ));
            }
        };

        let notify = self.e0_notify;
        validate_endpoint_text(&notify.server_ip, "IP")?;
        if let Some(vip) = notify.server_vip.as_deref() {
            validate_endpoint_text(vip, "VIP")?;
        }
        if notify.packet_key.is_empty()
            || notify.packet_key.len() > 1024
            || notify.packet_key.chars().any(char::is_control)
        {
            return Err(CompatibilitySessionError::Invalid(
                "session key is empty, oversized, or contains control characters",
            ));
        }

        let server_port = checked_u16_positive(notify.server_port, "Port")?;
        let g0_id = checked_positive_i64(notify.g0_id.value(), "GameId")?;
        let map_id = checked_nonnegative_i32(notify.map_id, "MapId")?;
        let g1_mode = checked_nonnegative_i32(notify.g1_mode, "GameMode")?;
        let s0_mode = checked_nonnegative_i32(notify.s0_mode, "SubGameMode")?;
        let source_mna_sequence =
            checked_u32(self.mna_frame.mna_sequence, "mna_frame.mna_sequence")?;

        Ok(EnterGameSession {
            server_ip: notify.server_ip,
            server_vip: notify.server_vip,
            server_port,
            packet_key: notify.packet_key.into_zeroizing(),
            g0_id,
            map_id,
            g1_mode,
            s0_mode,
            roster,
            source_mna_sequence,
            reenter: false,
        })
    }
}

#[derive(Deserialize)]
struct RawMnaFrame {
    mna_sequence: FlexibleUnsigned,
}

struct RawEnterGameNotify {
    server_ip: String,
    server_vip: Option<String>,
    server_port: FlexibleUnsigned,
    packet_key: SensitiveText,
    g0_id: SensitiveDecimal,
    map_id: FlexibleUnsigned,
    g1_mode: FlexibleUnsigned,
    s0_mode: FlexibleUnsigned,
    c0_info: Option<Vec<RawRosterEntry>>,
}

impl<'de> Deserialize<'de> for RawEnterGameNotify {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let take =
            |map: &mut serde_json::Map<String, serde_json::Value>, name: &str| map.remove(name);
        let required = |map: &mut serde_json::Map<String, serde_json::Value>, name: &str| {
            take(map, name).ok_or_else(|| de::Error::missing_field("notification field"))
        };
        let server_ip = match take(&mut map, codev_conceal::ip()) {
            Some(serde_json::Value::String(text)) => text,
            _ => return Err(de::Error::missing_field("notification host")),
        };
        let server_vip = match take(&mut map, codev_conceal::vip()) {
            Some(serde_json::Value::String(text)) => Some(text),
            Some(serde_json::Value::Null) | None => None,
            Some(_) => return Err(de::Error::custom("invalid VIP")),
        };
        let server_port = serde_json::from_value(required(&mut map, codev_conceal::port())?)
            .map_err(de::Error::custom)?;
        let packet_key = serde_json::from_value(required(&mut map, codev_conceal::packet_key())?)
            .map_err(de::Error::custom)?;
        let g0_id = serde_json::from_value(required(&mut map, codev_conceal::g0_id())?)
            .map_err(de::Error::custom)?;
        let map_id = serde_json::from_value(required(&mut map, codev_conceal::map_id())?)
            .map_err(de::Error::custom)?;
        let g1_mode = serde_json::from_value(required(&mut map, codev_conceal::g1_mode())?)
            .map_err(de::Error::custom)?;
        let s0_mode = serde_json::from_value(required(&mut map, codev_conceal::s0_mode())?)
            .map_err(de::Error::custom)?;
        let c0_info = take(&mut map, codev_conceal::c0_info())
            .map(serde_json::from_value)
            .transpose()
            .map_err(de::Error::custom)?;
        Ok(Self {
            server_ip,
            server_vip,
            server_port,
            packet_key,
            g0_id,
            map_id,
            g1_mode,
            s0_mode,
            c0_info,
        })
    }
}

#[derive(Deserialize)]
struct RawRosterEntry {
    #[serde(rename = "Name", default)]
    name: Option<SensitiveText>,
    #[serde(rename = "DisplayName", default)]
    display_name: Option<SensitiveText>,
    #[serde(rename = "Uid")]
    uid: SensitiveDecimal,
    #[serde(rename = "OpenId")]
    open_id: SensitiveDecimal,
    #[serde(rename = "AgentId")]
    agent_id: FlexibleUnsigned,
    #[serde(rename = "SkinId")]
    skin_id: FlexibleUnsigned,
    #[serde(rename = "SelectedBackpackId")]
    selected_backpack_id: FlexibleUnsigned,
    #[serde(rename = "CampId")]
    camp_id: FlexibleUnsigned,
    #[serde(rename = "Pos")]
    position_slot: FlexibleUnsigned,
}

fn convert_roster(
    roster: Vec<RawRosterEntry>,
) -> Result<Vec<W0RosterEntry>, CompatibilitySessionError> {
    if roster.len() != EXPECTED_ROSTER_LENGTH {
        return Err(CompatibilitySessionError::Invalid(
            "CampInfo/roster count is not ten",
        ));
    }

    let mut seen_uids = HashSet::with_capacity(EXPECTED_ROSTER_LENGTH);
    let mut seen_open_ids = HashSet::with_capacity(EXPECTED_ROSTER_LENGTH);
    let mut seen_camp_positions = HashSet::with_capacity(EXPECTED_ROSTER_LENGTH);
    let mut converted = Vec::with_capacity(EXPECTED_ROSTER_LENGTH);
    for mut player in roster {
        // Authenticated Match.pb defines field 3 as Name and field 16 as the
        // independent optional DisplayName. Python v2 projects Name, so an
        // alias may never substitute for a missing stable name.
        let name = player
            .name
            .take()
            .ok_or(CompatibilitySessionError::Invalid("roster Name is missing"))?;
        if name.is_empty() || name.len() > 1024 || name.chars().any(char::is_control) {
            return Err(CompatibilitySessionError::Invalid(
                "roster Name is empty, oversized, or contains control characters",
            ));
        }
        let display_name = player.display_name.take().filter(|value| !value.is_empty());
        if display_name
            .as_ref()
            .is_some_and(|value| value.len() > 1024 || value.chars().any(char::is_control))
        {
            return Err(CompatibilitySessionError::Invalid(
                "roster DisplayName is oversized or contains control characters",
            ));
        }

        let uid_value = checked_positive_i64(player.uid.value(), "roster Uid")?;
        let open_id_value = player.open_id.value();
        if open_id_value == 0 {
            return Err(CompatibilitySessionError::Invalid(
                "roster OpenId is not positive",
            ));
        }
        let agent_id = checked_nonnegative_i32(player.agent_id, "roster AgentId")?;
        if agent_id == 0 {
            return Err(CompatibilitySessionError::Invalid(
                "roster AgentId is not positive",
            ));
        }
        let skin_id = checked_nonnegative_i32(player.skin_id, "roster SkinId")?;
        let selected_backpack_id =
            checked_nonnegative_i32(player.selected_backpack_id, "roster SelectedBackpackId")?;
        let camp_id = checked_positive_i64(player.camp_id.value(), "roster CampId")?;
        let position_slot = checked_u32(player.position_slot, "roster Pos")?;
        if position_slot == 0 {
            return Err(CompatibilitySessionError::Invalid(
                "roster Pos is not positive",
            ));
        }

        if !seen_uids.insert(uid_value)
            || !seen_open_ids.insert(open_id_value)
            || !seen_camp_positions.insert((camp_id, position_slot))
        {
            return Err(CompatibilitySessionError::Invalid(
                "roster contains a duplicate identity or camp position",
            ));
        }

        converted.push(W0RosterEntry {
            name: name.take(),
            display_name: display_name.map(SensitiveText::take),
            uid: player.uid.take_text(),
            open_id: player.open_id.take_text(),
            agent_id,
            skin_id,
            selected_backpack_id,
            camp_id,
            position_slot,
            device_tag: false,
        });
    }
    Ok(converted)
}

fn validate_endpoint_text(
    value: &str,
    field: &'static str,
) -> Result<(), CompatibilitySessionError> {
    if value.is_empty()
        || value.len() > 255
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CompatibilitySessionError::Invalid(match field {
            "IP" => "IP is empty, oversized, or invalid",
            "VIP" => "VIP is empty, oversized, or invalid",
            _ => "endpoint text is invalid",
        }));
    }
    Ok(())
}

fn checked_u16_positive(
    value: FlexibleUnsigned,
    field: &'static str,
) -> Result<u16, CompatibilitySessionError> {
    u16::try_from(value.value())
        .ok()
        .filter(|value| *value != 0)
        .ok_or(CompatibilitySessionError::Invalid(match field {
            "Port" => "Port is outside the TCP/UDP range",
            _ => "positive u16 field is outside its range",
        }))
}

fn checked_u32(
    value: FlexibleUnsigned,
    field: &'static str,
) -> Result<u32, CompatibilitySessionError> {
    u32::try_from(value.value()).map_err(|_| {
        CompatibilitySessionError::Invalid(match field {
            "roster Pos" => "roster Pos overflows uint32",
            "mna_frame.mna_sequence" => "MNA sequence overflows uint32",
            _ => "uint32 field is outside its range",
        })
    })
}

fn checked_nonnegative_i32(
    value: FlexibleUnsigned,
    field: &'static str,
) -> Result<u32, CompatibilitySessionError> {
    if value.value() > i32::MAX as u64 {
        return Err(CompatibilitySessionError::Invalid(match field {
            "MapId" => "MapId overflows the descriptor int32",
            "GameMode" => "GameMode overflows the descriptor int32",
            "SubGameMode" => "SubGameMode overflows the descriptor int32",
            "roster AgentId" => "roster AgentId overflows the descriptor int32",
            "roster SkinId" => "roster SkinId overflows the descriptor int32",
            "roster SelectedBackpackId" => {
                "roster SelectedBackpackId overflows the descriptor int32"
            }
            _ => "nonnegative int32 field is outside its range",
        }));
    }
    Ok(value.value() as u32)
}

fn checked_positive_i64(value: u64, field: &'static str) -> Result<u64, CompatibilitySessionError> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(CompatibilitySessionError::Invalid(match field {
            "GameId" => "GameId is outside the positive int64 range",
            "roster Uid" => "roster Uid is outside the positive int64 range",
            "roster CampId" => "roster CampId is outside the positive int64 range",
            _ => "positive int64 field is outside its range",
        }));
    }
    Ok(value)
}

#[derive(Clone, Copy)]
struct FlexibleUnsigned(u64);

impl FlexibleUnsigned {
    fn value(self) -> u64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FlexibleUnsigned {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UnsignedVisitor)
    }
}

struct UnsignedVisitor;

impl<'de> Visitor<'de> for UnsignedVisitor {
    type Value = FlexibleUnsigned;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an unsigned integer or an ASCII decimal string")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(FlexibleUnsigned(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        u64::try_from(value)
            .map(FlexibleUnsigned)
            .map_err(|_| E::custom("negative integer is not accepted"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        parse_decimal(value)
            .map(FlexibleUnsigned)
            .ok_or_else(|| E::custom("invalid or overflowing ASCII decimal string"))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point numbers are not accepted"))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("booleans are not accepted as integers"))
    }
}

struct SensitiveText(Zeroizing<String>);

impl SensitiveText {
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn chars(&self) -> std::str::Chars<'_> {
        self.0.chars()
    }

    fn take(mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    fn into_zeroizing(mut self) -> Zeroizing<String> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl<'de> Deserialize<'de> for SensitiveText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SensitiveTextVisitor)
    }
}

struct SensitiveTextVisitor;

impl<'de> Visitor<'de> for SensitiveTextVisitor {
    type Value = SensitiveText;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a private UTF-8 string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SensitiveText(Zeroizing::new(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SensitiveText(Zeroizing::new(value)))
    }

    fn visit_u64<E>(self, _value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("private string has the wrong JSON type"))
    }

    fn visit_i64<E>(self, _value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("private string has the wrong JSON type"))
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("private string has the wrong JSON type"))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("private string has the wrong JSON type"))
    }
}

struct SensitiveDecimal {
    text: Zeroizing<String>,
    value: u64,
}

impl SensitiveDecimal {
    fn value(&self) -> u64 {
        self.value
    }

    fn take_text(mut self) -> String {
        std::mem::take(&mut *self.text)
    }
}

impl<'de> Deserialize<'de> for SensitiveDecimal {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(SensitiveDecimalVisitor)
    }
}

struct SensitiveDecimalVisitor;

impl SensitiveDecimalVisitor {
    fn from_string<E>(value: String) -> Result<SensitiveDecimal, E>
    where
        E: de::Error,
    {
        let value = Zeroizing::new(value);
        let parsed = parse_decimal(&value)
            .ok_or_else(|| E::custom("invalid or overflowing private decimal string"))?;
        Ok(SensitiveDecimal {
            text: value,
            value: parsed,
        })
    }
}

impl<'de> Visitor<'de> for SensitiveDecimalVisitor {
    type Value = SensitiveDecimal;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a private unsigned integer or ASCII decimal string")
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SensitiveDecimal {
            text: Zeroizing::new(value.to_string()),
            value,
        })
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let value = u64::try_from(value)
            .map_err(|_| E::custom("negative private integer is not accepted"))?;
        self.visit_u64(value)
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::from_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Self::from_string(value)
    }

    fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("floating-point private number is not accepted"))
    }

    fn visit_bool<E>(self, _value: bool) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Err(E::custom("boolean private number is not accepted"))
    }
}

fn parse_decimal(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}
