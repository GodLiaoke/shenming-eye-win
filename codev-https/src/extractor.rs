use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use codev_session::{
    BrokerError, SessionId, SessionMaterial, SessionMaterialSource, UnresolvedRosterEntry,
};
use serde::Deserialize;
use serde::de::{self, Deserializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::mpsc;
use zeroize::{Zeroize, Zeroizing};

use crate::{PlaintextDirection, PlaintextRecord, PlaintextSink};

const MAX_SESSION_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOTAL_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

struct HttpsSessionEnvelope {
    packet_key: String,
    g0_id: GameId,
    map_id: Option<u32>,
    server_host: String,
    server_vip: Option<String>,
    server_port: u16,
    roster: Vec<HttpsRosterEntry>,
    reenter: bool,
}

impl<'de> Deserialize<'de> for HttpsSessionEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut map = serde_json::Map::deserialize(deserializer)?;
        let packet_key = take_aliased_string(&mut map, &codev_conceal::https_session_key_aliases())
            .ok_or_else(|| de::Error::custom("missing session key"))?;
        let g0_id = take_aliased_value(
            &mut map,
            &[
                codev_conceal::g0_id(),
                codev_conceal::game_id_mixed(),
                codev_conceal::game_id_snake(),
            ],
        )
        .ok_or_else(|| de::Error::custom("missing game id"))?;
        let map_id = match take_aliased_value(
            &mut map,
            &[
                codev_conceal::map_id(),
                codev_conceal::map_id_mixed(),
                codev_conceal::map_id_snake(),
            ],
        ) {
            None | Some(serde_json::Value::Null) => None,
            Some(value) => Some(value),
        };
        let server_host = take_aliased_string(
            &mut map,
            &[
                codev_conceal::ip(),
                codev_conceal::server(),
                codev_conceal::server_ip(),
            ],
        )
        .ok_or_else(|| de::Error::custom("missing server host"))?;
        let server_vip = take_aliased_string(
            &mut map,
            &[codev_conceal::vip(), codev_conceal::server_vip()],
        );
        let server_port = take_aliased_value(
            &mut map,
            &[codev_conceal::port(), codev_conceal::server_port()],
        )
        .ok_or_else(|| de::Error::custom("missing server port"))?;
        let roster = take_aliased_value(
            &mut map,
            &[codev_conceal::players(), codev_conceal::roster()],
        );
        let reenter = take_aliased_value(
            &mut map,
            &[codev_conceal::reenter(), codev_conceal::reenter_snake()],
        );
        if !map.is_empty() {
            return Err(de::Error::custom("unexpected HTTPS session field"));
        }
        Ok(Self {
            packet_key,
            g0_id: serde_json::from_value(g0_id).map_err(de::Error::custom)?,
            map_id: map_id
                .map(serde_json::from_value)
                .transpose()
                .map_err(de::Error::custom)?,
            server_host,
            server_vip,
            server_port: serde_json::from_value(server_port).map_err(de::Error::custom)?,
            roster: roster
                .map(serde_json::from_value)
                .transpose()
                .map_err(de::Error::custom)?
                .unwrap_or_default(),
            reenter: reenter
                .map(serde_json::from_value)
                .transpose()
                .map_err(de::Error::custom)?
                .unwrap_or(false),
        })
    }
}

fn take_aliased_value(
    map: &mut serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<serde_json::Value> {
    names.iter().find_map(|name| map.remove(*name))
}

fn take_aliased_string(
    map: &mut serde_json::Map<String, serde_json::Value>,
    names: &[&str],
) -> Option<String> {
    take_aliased_value(map, names).and_then(|value| match value {
        serde_json::Value::String(text) => Some(text),
        _ => None,
    })
}

#[derive(Deserialize)]
#[serde(untagged)]
enum GameId {
    Number(u64),
    Text(String),
}

impl GameId {
    fn parse_and_zeroize(&mut self) -> Result<u64, ExtractError> {
        match self {
            Self::Number(value) if *value != 0 => Ok(*value),
            Self::Number(_) => Err(ExtractError::InvalidGameId),
            Self::Text(value) => {
                let trimmed = value.trim();
                let parsed = if let Some(hex) = trimmed.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16)
                } else {
                    trimmed.parse()
                };
                value.zeroize();
                parsed
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or(ExtractError::InvalidGameId)
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HttpsRosterEntry {
    #[serde(default, alias = "DisplayName", alias = "display_name", alias = "name")]
    _display_name: Option<String>,
    #[serde(default, alias = "AgentId", alias = "agentID")]
    agent_id: u32,
    #[serde(default, alias = "CampId", alias = "campID")]
    camp_id: u32,
    #[serde(default, alias = "Position", alias = "position_slot")]
    position_slot: u32,
    /// 客户端设备字段是否存在（真人玩家带、机器人不带）。原值永不落盘。
    #[serde(default, alias = "DeviceName", alias = "device_name")]
    device_name: Option<String>,
}

pub fn extract_session_json(
    bytes: &[u8],
    session_id: SessionId,
    observed_ns: u64,
) -> Result<SessionMaterial, ExtractError> {
    if bytes.is_empty() || bytes.len() > MAX_SESSION_JSON_BYTES {
        return Err(ExtractError::InvalidLength);
    }
    let envelope: HttpsSessionEnvelope = serde_json::from_slice(bytes)?;
    envelope.into_material(session_id, observed_ns)
}

impl HttpsSessionEnvelope {
    fn into_material(
        mut self,
        session_id: SessionId,
        observed_ns: u64,
    ) -> Result<SessionMaterial, ExtractError> {
        let g0_id = self.g0_id.parse_and_zeroize()?;
        let packet_key = Zeroizing::new(std::mem::take(&mut self.packet_key));
        let roster = self
            .roster
            .into_iter()
            .map(|entry| UnresolvedRosterEntry {
                display_name: format!("player_c{}_p{}", entry.camp_id, entry.position_slot),
                agent_id: entry.agent_id,
                camp_id: entry.camp_id,
                position_slot: entry.position_slot,
                device_tag: entry.device_name.is_some_and(|name| !name.is_empty()),
                self_key: None,
            })
            .collect();
        SessionMaterial::new_with_vip(
            session_id,
            SessionMaterialSource::HttpsMitm,
            packet_key,
            g0_id,
            self.map_id,
            self.server_host,
            self.server_vip,
            self.server_port,
            roster,
            observed_ns,
            self.reenter,
        )
        .map_err(ExtractError::Broker)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtractionStatus {
    pub buffered_flows: usize,
    pub buffered_bytes: usize,
    pub emitted_sessions: u64,
    pub dropped_flows: u64,
    pub channel_full: u64,
}

struct ExtractorState {
    buffers: HashMap<(String, PlaintextDirection), Vec<u8>>,
    buffered_bytes: usize,
    status: ExtractionStatus,
}

/// Bounded plaintext observer for canonical JSON session envelopes.  It scans
/// only TLS flows already admitted by the HTTPS hostname allowlist.  Unknown
/// data stays opaque and a full output channel never blocks the relay.
pub struct SessionExtractionSink {
    sender: mpsc::Sender<SessionMaterial>,
    state: Mutex<ExtractorState>,
    max_flows: usize,
    max_flow_bytes: usize,
}

impl SessionExtractionSink {
    pub fn new(sender: mpsc::Sender<SessionMaterial>) -> Self {
        Self {
            sender,
            state: Mutex::new(ExtractorState {
                buffers: HashMap::new(),
                buffered_bytes: 0,
                status: ExtractionStatus::default(),
            }),
            max_flows: 128,
            max_flow_bytes: MAX_SESSION_JSON_BYTES,
        }
    }

    pub fn status(&self) -> ExtractionStatus {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut status = state.status.clone();
        status.buffered_flows = state.buffers.len();
        status.buffered_bytes = state.buffered_bytes;
        status
    }
}

impl PlaintextSink for SessionExtractionSink {
    fn observe(&self, record: PlaintextRecord<'_>) -> io::Result<()> {
        if record.direction != PlaintextDirection::ServerToClient || record.payload.is_empty() {
            return Ok(());
        }
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let key = (record.flow_id.to_owned(), record.direction);
        if !state.buffers.contains_key(&key) && state.buffers.len() >= self.max_flows {
            state.status.dropped_flows = state.status.dropped_flows.saturating_add(1);
            return Ok(());
        }
        let current_len = state.buffers.get(&key).map_or(0, Vec::len);
        let next_len = current_len.saturating_add(record.payload.len());
        if next_len > self.max_flow_bytes
            || state.buffered_bytes.saturating_add(record.payload.len()) > MAX_TOTAL_BUFFERED_BYTES
        {
            if let Some(previous) = state.buffers.remove(&key) {
                state.buffered_bytes = state.buffered_bytes.saturating_sub(previous.len());
            }
            state.status.dropped_flows = state.status.dropped_flows.saturating_add(1);
            return Ok(());
        }
        state
            .buffers
            .entry(key.clone())
            .or_default()
            .extend_from_slice(record.payload);
        state.buffered_bytes = state.buffered_bytes.saturating_add(record.payload.len());
        let buffer = state.buffers.get(&key).expect("buffer inserted above");
        if !contains_session_key(buffer) {
            return Ok(());
        }
        let mut material = None;
        for (attempts, start) in buffer
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte == b'{').then_some(index))
            .rev()
            .enumerate()
        {
            if attempts >= 64 {
                break;
            }
            let mut stream = serde_json::Deserializer::from_slice(&buffer[start..])
                .into_iter::<HttpsSessionEnvelope>();
            let Some(Ok(envelope)) = stream.next() else {
                continue;
            };
            let mut digest = Sha256::new();
            digest.update(record.flow_id.as_bytes());
            digest.update(record.capture_ns.to_le_bytes());
            let hex = format!("{:x}", digest.finalize());
            let session_id = SessionId::parse(format!("https-{}", &hex[..24]))
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if let Ok(value) = envelope.into_material(session_id, record.capture_ns) {
                material = Some(value);
                break;
            }
        }
        if let Some(material) = material {
            if let Some(previous) = state.buffers.remove(&key) {
                state.buffered_bytes = state.buffered_bytes.saturating_sub(previous.len());
            }
            match self.sender.try_send(material) {
                Ok(()) => {
                    state.status.emitted_sessions = state.status.emitted_sessions.saturating_add(1)
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    state.status.channel_full = state.status.channel_full.saturating_add(1)
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "session-material receiver is closed",
                    ));
                }
            }
        }
        Ok(())
    }

    fn close(&self, flow_id: &str) -> io::Result<()> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut removed_bytes = 0_usize;
        state.buffers.retain(|(buffer_flow_id, _), buffer| {
            if buffer_flow_id == flow_id {
                removed_bytes = removed_bytes.saturating_add(buffer.len());
                false
            } else {
                true
            }
        });
        state.buffered_bytes = state.buffered_bytes.saturating_sub(removed_bytes);
        Ok(())
    }
}

fn contains_session_key(bytes: &[u8]) -> bool {
    codev_conceal::contains_session_key_token(bytes)
}

#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("HTTPS session body length is invalid")]
    InvalidLength,
    #[error("invalid HTTPS session JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTPS GameId is invalid")]
    InvalidGameId,
    #[error("HTTPS session material is invalid: {0}")]
    Broker(#[from] BrokerError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_https_material_is_strict_and_private() {
        let session = extract_session_json(
            br#"{"PacketKey":"secret-key","GameId":"0x2a","MapId":1003,"IP":"203.0.113.8","Port":10001,"Players":[{"AgentId":7,"CampId":1,"Position":0}]}"#,
            SessionId::parse("https-1").unwrap(),
            10,
        )
        .unwrap();
        assert_eq!(session.g0_id, 42);
        assert_eq!(session.roster[0].display_name, "player_c1_p0");
        let debug = format!("{session:?}");
        assert!(!debug.contains("secret-key"));
        let vip = extract_session_json(
            br#"{"PacketKey":"secret-key","GameId":42,"IP":"game.example","VIP":"203.0.113.8","Port":10001}"#,
            SessionId::parse("https-vip").unwrap(),
            10,
        )
        .unwrap();
        assert_eq!(vip.server_vip.as_deref(), Some("203.0.113.8"));
        let lobby = extract_session_json(
            br#"{"PacketKey":"secret-key","GameId":42,"MapId":null,"IP":"203.0.113.8","Port":10001}"#,
            SessionId::parse("https-lobby").unwrap(),
            10,
        )
        .unwrap();
        assert_eq!(lobby.map_id, None);
        assert!(
            extract_session_json(
                br#"{"PacketKey":"x","GameId":1,"IP":"203.0.113.8","Port":1,"unexpected":true}"#,
                SessionId::parse("https-2").unwrap(),
                10,
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn streaming_sink_is_bounded_and_emits_without_blocking_tls() {
        let (sender, mut receiver) = mpsc::channel(1);
        let sink = SessionExtractionSink::new(sender);
        let body = br#"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"PacketKey":"secret-key","GameId":42,"MapId":1003,"IP":"203.0.113.8","Port":10001}"#;
        sink.observe(PlaintextRecord {
            capture_ns: 10,
            direction: PlaintextDirection::ServerToClient,
            flow_id: "flow-1",
            host: "api.example",
            payload: &body[..40],
        })
        .unwrap();
        sink.observe(PlaintextRecord {
            capture_ns: 11,
            direction: PlaintextDirection::ServerToClient,
            flow_id: "flow-1",
            host: "api.example",
            payload: &body[40..],
        })
        .unwrap();
        let material = receiver.recv().await.unwrap();
        assert_eq!(material.map_id, Some(1003));
        assert_eq!(sink.status().emitted_sessions, 1);
    }
}
