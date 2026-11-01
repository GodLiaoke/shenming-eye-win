//! Session-material arbitration shared by passive MNA capture, HTTPS
//! interception and private session files.
//!
//! The broker owns the only live copy of `PacketKey` and `GameId`.  Its public
//! snapshots deliberately contain neither value, nor any stable player
//! identifiers.  Replacing a session always advances the channel generation so
//! UDP baselines cannot bleed across reconnects or re-entry.

use std::fmt;

use codev_stream::{C0Cipher, EnterGameSession};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MAX_SESSION_ID_BYTES: usize = 128;
pub const MAX_ROSTER_ENTRIES: usize = 10;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionId(String);

impl SessionId {
    pub fn parse(value: impl Into<String>) -> Result<Self, BrokerError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_SESSION_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(BrokerError::InvalidSessionId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionMaterialSource {
    Mna,
    HttpsMitm,
    PrivateSession,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedRosterEntry {
    pub display_name: String,
    pub agent_id: u32,
    pub camp_id: u32,
    /// 阵营内位次（1..5）；贴槽要用。
    pub position_slot: u32,
    /// 该条是否带客户端设备字段（真人玩家带，机器人不带）。
    pub device_tag: bool,
    /// 本机玩家身份的 **哈希**（uid 的 FNV-1a 64），原始 uid/账号串永不外流。
    /// 引擎用它把"哪条 roster 记录是我"钉死；真人局里多个真人都带设备字段时靠它区分。
    pub self_key: Option<u64>,
}

/// uid 字符串的 FNV-1a 64 位哈希（只用于本机身份比对，不可逆推原始 uid）。
pub fn identity_hash(text: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in text.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SessionMaterial {
    #[zeroize(skip)]
    pub session_id: SessionId,
    #[zeroize(skip)]
    pub source: SessionMaterialSource,
    pub packet_key: Zeroizing<String>,
    pub g0_id: u64,
    #[zeroize(skip)]
    pub map_id: Option<u32>,
    #[zeroize(skip)]
    pub server_host: String,
    /// Optional virtual/edge address carried by MNA Enter/ReEnterGameNotify.
    /// It is kept as endpoint metadata only; the public projection never
    /// exposes it and the decoder still requires an encrypted UDP proof.
    #[zeroize(skip)]
    pub server_vip: Option<String>,
    #[zeroize(skip)]
    pub server_port: u16,
    #[zeroize(skip)]
    pub roster: Vec<UnresolvedRosterEntry>,
    #[zeroize(skip)]
    pub observed_ns: u64,
    #[zeroize(skip)]
    pub reenter: bool,
}

impl fmt::Debug for SessionMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMaterial")
            .field("session_id", &self.session_id)
            .field("source", &self.source)
            .field("packet_key", &"<redacted>")
            .field("g0_id", &"<redacted>")
            .field("map_id", &self.map_id)
            .field("server_host", &"<redacted>")
            .field(
                "server_vip",
                &self.server_vip.as_ref().map(|_| "<redacted>"),
            )
            .field("server_port", &self.server_port)
            .field("roster_count", &self.roster.len())
            .field("observed_ns", &self.observed_ns)
            .field("reenter", &self.reenter)
            .finish()
    }
}

impl SessionMaterial {
    pub fn from_mna(
        session_id: SessionId,
        session: EnterGameSession,
        observed_ns: u64,
    ) -> Result<Self, BrokerError> {
        let roster = session
            .roster
            .iter()
            .map(|entry| {
                Ok(UnresolvedRosterEntry {
                    display_name: format!("player_c{}_p{}", entry.camp_id, entry.position_slot),
                    agent_id: entry.agent_id,
                    camp_id: u32::try_from(entry.camp_id)
                        .map_err(|_| BrokerError::InvalidRoster)?,
                    position_slot: entry.position_slot,
                    device_tag: entry.device_tag,
                    self_key: Some(identity_hash(&entry.uid)),
                })
            })
            .collect::<Result<Vec<_>, BrokerError>>()?;
        Self::new_with_vip(
            session_id,
            SessionMaterialSource::Mna,
            session.packet_key.clone(),
            session.g0_id,
            Some(session.map_id),
            session.server_ip.clone(),
            session.server_vip.clone(),
            session.server_port,
            roster,
            observed_ns,
            session.reenter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_vip(
        session_id: SessionId,
        source: SessionMaterialSource,
        packet_key: Zeroizing<String>,
        g0_id: u64,
        map_id: Option<u32>,
        server_host: String,
        server_vip: Option<String>,
        server_port: u16,
        roster: Vec<UnresolvedRosterEntry>,
        observed_ns: u64,
        reenter: bool,
    ) -> Result<Self, BrokerError> {
        if server_vip
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 255)
        {
            return Err(BrokerError::InvalidEndpoint);
        }
        Self::new_inner(
            session_id,
            source,
            packet_key,
            g0_id,
            map_id,
            server_host,
            server_vip,
            server_port,
            roster,
            observed_ns,
            reenter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        source: SessionMaterialSource,
        packet_key: Zeroizing<String>,
        g0_id: u64,
        map_id: Option<u32>,
        server_host: String,
        server_port: u16,
        roster: Vec<UnresolvedRosterEntry>,
        observed_ns: u64,
        reenter: bool,
    ) -> Result<Self, BrokerError> {
        Self::new_inner(
            session_id,
            source,
            packet_key,
            g0_id,
            map_id,
            server_host,
            None,
            server_port,
            roster,
            observed_ns,
            reenter,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_inner(
        session_id: SessionId,
        source: SessionMaterialSource,
        packet_key: Zeroizing<String>,
        g0_id: u64,
        map_id: Option<u32>,
        server_host: String,
        server_vip: Option<String>,
        server_port: u16,
        roster: Vec<UnresolvedRosterEntry>,
        observed_ns: u64,
        reenter: bool,
    ) -> Result<Self, BrokerError> {
        if packet_key.is_empty() || packet_key.len() > 4096 {
            return Err(BrokerError::InvalidPacketKey);
        }
        if g0_id == 0 || server_host.is_empty() || server_host.len() > 255 || server_port == 0 {
            return Err(BrokerError::InvalidEndpoint);
        }
        if roster.len() > MAX_ROSTER_ENTRIES
            || roster.iter().any(|entry| {
                entry.display_name.is_empty()
                    || entry.display_name.len() > 256
                    || entry.camp_id == 0
            })
        {
            return Err(BrokerError::InvalidRoster);
        }
        Ok(Self {
            session_id,
            source,
            packet_key,
            g0_id,
            map_id,
            server_host,
            server_vip,
            server_port,
            roster,
            observed_ns,
            reenter,
        })
    }

    pub fn cipher(&self) -> C0Cipher {
        C0Cipher::from_packet_key(&self.packet_key, self.g0_id)
    }

    pub fn public_fingerprint(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(self.session_id.as_str().as_bytes());
        digest.update(self.observed_ns.to_le_bytes());
        digest.update(self.map_id.unwrap_or_default().to_le_bytes());
        format!("{:x}", digest.finalize())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerState {
    #[default]
    AwaitingSession,
    HttpsAuthenticated,
    MnaAuthenticated,
    PrivateSession,
    UdpLocked,
    Live,
    Degraded,
    Resyncing,
    Unrecoverable,
    Ended,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerSnapshot {
    pub state: BrokerState,
    pub session_id: Option<SessionId>,
    pub source: Option<SessionMaterialSource>,
    pub map_id: Option<u32>,
    pub channel_generation: u64,
    pub roster: Vec<UnresolvedRosterEntry>,
    pub detail: String,
}

pub struct SessionBroker {
    active: Option<SessionMaterial>,
    state: BrokerState,
    channel_generation: u64,
    /// Whether the current channel generation is open for material.  A
    /// transport close invalidates the active material immediately, while the
    /// following reopen (or the first material accepted after a close) starts
    /// exactly one new generation.  Keeping this bit separate from
    /// `BrokerState` makes duplicate close/reopen notifications idempotent.
    channel_open: bool,
    detail: String,
}

impl Default for SessionBroker {
    fn default() -> Self {
        Self {
            active: None,
            state: BrokerState::AwaitingSession,
            channel_generation: 0,
            channel_open: false,
            detail: "awaiting authenticated session material".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptDisposition {
    /// Material replaced the active session or opened a new channel.
    Installed,
    /// Material was an exact replay of the active authenticated session.
    Duplicate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub channel_generation: u64,
    pub disposition: AcceptDisposition,
}

impl SessionBroker {
    /// Accept authenticated session material and return the current channel
    /// generation.  This compatibility wrapper intentionally keeps the
    /// original return type; callers that need to avoid resetting their
    /// decoder on duplicate MNA notifications should use
    /// [`Self::accept_with_outcome`].
    pub fn accept(&mut self, material: SessionMaterial) -> Result<u64, BrokerError> {
        Ok(self.accept_with_outcome(material)?.channel_generation)
    }

    /// Accept material with explicit duplicate/new disposition.
    ///
    /// Repeated MNA notifications from the same control flow carry a fresh
    /// capture timestamp, so `observed_ns` is deliberately excluded from the
    /// duplicate comparison.  A duplicate keeps the active channel generation
    /// and all decoder baselines intact.  A different material, a re-entry
    /// notification, or material arriving after a close starts a fresh
    /// generation.
    pub fn accept_with_outcome(
        &mut self,
        material: SessionMaterial,
    ) -> Result<AcceptOutcome, BrokerError> {
        if matches!(self.state, BrokerState::Unrecoverable | BrokerState::Ended) {
            return Err(BrokerError::TerminalState);
        }

        if self.channel_open
            && self
                .active
                .as_ref()
                .is_some_and(|active| materials_are_duplicate(active, &material))
        {
            return Ok(AcceptOutcome {
                channel_generation: self.channel_generation,
                disposition: AcceptDisposition::Duplicate,
            });
        }

        // The first material on a channel, and the first material after an
        // explicit close, opens one generation.  Replacing material on an
        // already-open channel (for example ReEnterGameNotify) also advances
        // the generation so stale UDP baselines cannot bleed across sessions.
        // `reopen_channel` may already have reserved the fresh generation;
        // accepting its first material must not advance a second time.
        if self.active.is_some() || !self.channel_open {
            self.advance_generation()?;
        }
        self.channel_open = true;
        self.state = match material.source {
            SessionMaterialSource::Mna => BrokerState::MnaAuthenticated,
            SessionMaterialSource::HttpsMitm => BrokerState::HttpsAuthenticated,
            SessionMaterialSource::PrivateSession => BrokerState::PrivateSession,
        };
        self.detail = format!("authenticated {:?} session material", material.source);
        self.active = Some(material);
        Ok(AcceptOutcome {
            channel_generation: self.channel_generation,
            disposition: AcceptDisposition::Installed,
        })
    }

    /// Return whether material would be ignored as a duplicate of the active
    /// channel.  This lets an integration update public timestamps without
    /// resetting its private decoder state.
    pub fn is_duplicate_material(&self, material: &SessionMaterial) -> bool {
        self.channel_open
            && self
                .active
                .as_ref()
                .is_some_and(|active| materials_are_duplicate(active, material))
    }

    /// Mark the current transport channel closed.  Closing clears sensitive
    /// active material and makes the current generation unusable, but does not
    /// consume a second generation number.  Repeated close notifications are
    /// idempotent.
    pub fn close_channel(&mut self, detail: impl Into<String>) -> u64 {
        if !self.channel_open {
            return self.channel_generation;
        }
        self.active = None;
        self.state = BrokerState::AwaitingSession;
        self.channel_open = false;
        self.detail = bounded_detail(detail.into());
        self.channel_generation
    }

    /// Open a fresh transport channel.  A repeated reopen notification while
    /// already open is idempotent.  The next accepted material is installed in
    /// this generation without an additional increment.
    pub fn reopen_channel(&mut self, detail: impl Into<String>) -> Result<u64, BrokerError> {
        if matches!(self.state, BrokerState::Unrecoverable | BrokerState::Ended) {
            return Err(BrokerError::TerminalState);
        }
        if self.channel_open {
            return Ok(self.channel_generation);
        }
        self.advance_generation()?;
        self.channel_open = true;
        self.active = None;
        self.state = BrokerState::AwaitingSession;
        self.detail = bounded_detail(detail.into());
        Ok(self.channel_generation)
    }

    pub fn lock_udp(&mut self) -> Result<(), BrokerError> {
        self.require_active()?;
        if !matches!(
            self.state,
            BrokerState::HttpsAuthenticated
                | BrokerState::MnaAuthenticated
                | BrokerState::PrivateSession
                | BrokerState::Resyncing
        ) {
            return Err(BrokerError::InvalidTransition {
                from: self.state,
                to: BrokerState::UdpLocked,
            });
        }
        self.state = BrokerState::UdpLocked;
        self.detail = "authenticated UDP tuple locked".into();
        Ok(())
    }

    pub fn mark_live(&mut self) -> Result<(), BrokerError> {
        self.require_transition(BrokerState::UdpLocked, BrokerState::Live)?;
        self.state = BrokerState::Live;
        self.detail = "coordinate stream is live".into();
        Ok(())
    }

    pub fn mark_degraded(&mut self, detail: impl Into<String>) -> Result<(), BrokerError> {
        self.require_active()?;
        self.state = BrokerState::Degraded;
        self.detail = bounded_detail(detail.into());
        Ok(())
    }

    pub fn mark_resyncing(&mut self, detail: impl Into<String>) -> Result<(), BrokerError> {
        self.require_active()?;
        self.state = BrokerState::Resyncing;
        self.detail = bounded_detail(detail.into());
        Ok(())
    }

    pub fn mark_unrecoverable(&mut self, detail: impl Into<String>) {
        self.state = BrokerState::Unrecoverable;
        self.detail = bounded_detail(detail.into());
        self.active = None;
        self.channel_open = false;
    }

    pub fn end(&mut self, detail: impl Into<String>) {
        self.state = BrokerState::Ended;
        self.detail = bounded_detail(detail.into());
        self.active = None;
        self.channel_open = false;
    }

    pub fn active(&self) -> Option<&SessionMaterial> {
        self.active.as_ref()
    }

    pub fn snapshot(&self) -> BrokerSnapshot {
        BrokerSnapshot {
            state: self.state,
            session_id: self.active.as_ref().map(|value| value.session_id.clone()),
            source: self.active.as_ref().map(|value| value.source),
            map_id: self.active.as_ref().and_then(|value| value.map_id),
            channel_generation: self.channel_generation,
            roster: self
                .active
                .as_ref()
                .map_or_else(Vec::new, |value| value.roster.clone()),
            detail: self.detail.clone(),
        }
    }

    fn require_active(&self) -> Result<&SessionMaterial, BrokerError> {
        self.active.as_ref().ok_or(BrokerError::MissingMaterial)
    }

    fn advance_generation(&mut self) -> Result<(), BrokerError> {
        self.channel_generation = self
            .channel_generation
            .checked_add(1_u64 << 32)
            .ok_or(BrokerError::GenerationOverflow)?;
        Ok(())
    }

    fn require_transition(&self, from: BrokerState, to: BrokerState) -> Result<(), BrokerError> {
        self.require_active()?;
        if self.state != from {
            return Err(BrokerError::InvalidTransition {
                from: self.state,
                to,
            });
        }
        Ok(())
    }
}

/// Compare only authenticated session identity and endpoint material. Capture
/// timestamps and source-specific session IDs are intentionally not enough to
/// make a new game generation: MNA retransmissions commonly arrive with both
/// changed. The flow/session ID remains part of the identity so a reconnect
/// with the same key cannot silently reuse old baselines; a material from a
/// different source or control flow is therefore a new generation.
fn materials_are_duplicate(left: &SessionMaterial, right: &SessionMaterial) -> bool {
    if left.reenter != right.reenter
        || left.g0_id != right.g0_id
        || left.map_id != right.map_id
        || left.server_host != right.server_host
        || left.server_vip != right.server_vip
        || left.server_port != right.server_port
        || left.packet_key.as_bytes() != right.packet_key.as_bytes()
        || left.roster != right.roster
    {
        return false;
    }

    left.session_id == right.session_id && left.source == right.source
}

fn bounded_detail(mut detail: String) -> String {
    const MAX_DETAIL_BYTES: usize = 1024;
    if detail.len() <= MAX_DETAIL_BYTES {
        return detail;
    }
    let mut boundary = MAX_DETAIL_BYTES;
    while !detail.is_char_boundary(boundary) {
        boundary -= 1;
    }
    detail.truncate(boundary);
    detail
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BrokerError {
    #[error("invalid public session id")]
    InvalidSessionId,
    #[error("invalid packet key")]
    InvalidPacketKey,
    #[error("invalid session endpoint")]
    InvalidEndpoint,
    #[error("invalid unresolved roster")]
    InvalidRoster,
    #[error("session broker has no authenticated material")]
    MissingMaterial,
    #[error("session broker is terminal")]
    TerminalState,
    #[error("channel generation overflow")]
    GenerationOverflow,
    #[error("invalid broker transition from {from:?} to {to:?}")]
    InvalidTransition { from: BrokerState, to: BrokerState },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn material(source: SessionMaterialSource) -> SessionMaterial {
        material_with("session-1", source, 10, false)
    }

    fn material_with(
        session_id: &str,
        source: SessionMaterialSource,
        observed_ns: u64,
        reenter: bool,
    ) -> SessionMaterial {
        SessionMaterial::new(
            SessionId::parse(session_id).unwrap(),
            source,
            Zeroizing::new("packet-key".into()),
            42,
            Some(1003),
            "203.0.113.8".into(),
            10001,
            vec![UnresolvedRosterEntry {
                display_name: "player_c1_p0".into(),
                agent_id: 7,
                camp_id: 1,
                position_slot: 1,
                device_tag: true,
                self_key: Some(identity_hash("10000")),
            }],
            observed_ns,
            reenter,
        )
        .unwrap()
    }

    #[test]
    fn public_snapshot_never_serializes_private_material() {
        let mut broker = SessionBroker::default();
        broker
            .accept(material(SessionMaterialSource::HttpsMitm))
            .unwrap();
        let json = serde_json::to_string(&broker.snapshot()).unwrap();
        assert!(!json.contains("packet-key"));
        assert!(!json.contains("g0_id"));
        assert_eq!(broker.snapshot().state, BrokerState::HttpsAuthenticated);
    }

    #[test]
    fn replacing_a_session_advances_generation_and_resets_state() {
        let mut broker = SessionBroker::default();
        assert_eq!(
            broker.accept(material(SessionMaterialSource::Mna)).unwrap(),
            1_u64 << 32
        );
        broker.lock_udp().unwrap();
        broker.mark_live().unwrap();
        assert_eq!(
            broker
                .accept(material(SessionMaterialSource::HttpsMitm))
                .unwrap(),
            2_u64 << 32
        );
        assert_eq!(broker.snapshot().state, BrokerState::HttpsAuthenticated);
    }

    #[test]
    fn repeated_mna_is_idempotent_even_when_capture_time_changes() {
        let mut broker = SessionBroker::default();
        let first = broker
            .accept_with_outcome(material_with(
                "mna-flow-7",
                SessionMaterialSource::Mna,
                10,
                false,
            ))
            .unwrap();
        assert_eq!(first.disposition, AcceptDisposition::Installed);
        broker.lock_udp().unwrap();
        broker.mark_live().unwrap();

        let duplicate = broker
            .accept_with_outcome(material_with(
                "mna-flow-7",
                SessionMaterialSource::Mna,
                99,
                false,
            ))
            .unwrap();
        assert_eq!(duplicate.channel_generation, first.channel_generation);
        assert_eq!(duplicate.disposition, AcceptDisposition::Duplicate);
        assert_eq!(broker.snapshot().state, BrokerState::Live);
        assert_eq!(broker.snapshot().channel_generation, 1_u64 << 32);
    }

    #[test]
    fn reenter_starts_one_generation_and_duplicate_reenter_is_idempotent() {
        let mut broker = SessionBroker::default();
        let initial = broker
            .accept(material_with(
                "mna-flow-7",
                SessionMaterialSource::Mna,
                10,
                false,
            ))
            .unwrap();
        broker.lock_udp().unwrap();
        broker.mark_live().unwrap();

        let reenter = broker
            .accept_with_outcome(material_with(
                "mna-flow-7",
                SessionMaterialSource::Mna,
                20,
                true,
            ))
            .unwrap();
        assert_eq!(reenter.disposition, AcceptDisposition::Installed);
        assert_eq!(reenter.channel_generation, initial + (1_u64 << 32));
        assert_eq!(broker.snapshot().state, BrokerState::MnaAuthenticated);

        let duplicate = broker
            .accept_with_outcome(material_with(
                "mna-flow-7",
                SessionMaterialSource::Mna,
                21,
                true,
            ))
            .unwrap();
        assert_eq!(duplicate.disposition, AcceptDisposition::Duplicate);
        assert_eq!(duplicate.channel_generation, reenter.channel_generation);
        assert_eq!(broker.snapshot().state, BrokerState::MnaAuthenticated);
    }

    #[test]
    fn close_and_reopen_clear_material_and_reserve_exactly_one_generation() {
        let mut broker = SessionBroker::default();
        let first = broker.accept(material(SessionMaterialSource::Mna)).unwrap();
        broker.lock_udp().unwrap();
        broker.mark_live().unwrap();

        assert_eq!(broker.close_channel("control channel closed"), first);
        assert_eq!(broker.close_channel("duplicate close"), first);
        let closed = broker.snapshot();
        assert_eq!(closed.state, BrokerState::AwaitingSession);
        assert!(closed.session_id.is_none());
        assert!(broker.active().is_none());

        let reopened = broker.reopen_channel("control channel reopened").unwrap();
        assert_eq!(reopened, first + (1_u64 << 32));
        assert_eq!(broker.reopen_channel("duplicate reopen").unwrap(), reopened);
        assert_eq!(broker.snapshot().state, BrokerState::AwaitingSession);

        // The first material on the explicitly reopened channel uses the
        // reserved generation; it must not advance a second time.
        let accepted = broker
            .accept_with_outcome(material_with(
                "mna-flow-8",
                SessionMaterialSource::Mna,
                30,
                false,
            ))
            .unwrap();
        assert_eq!(accepted.channel_generation, reopened);
        assert_eq!(accepted.disposition, AcceptDisposition::Installed);
        assert_eq!(broker.snapshot().state, BrokerState::MnaAuthenticated);
    }

    #[test]
    fn different_control_flows_with_equal_payload_are_not_duplicates() {
        let mut broker = SessionBroker::default();
        let first = broker
            .accept_with_outcome(material_with(
                "mna-flow-1",
                SessionMaterialSource::Mna,
                1,
                false,
            ))
            .unwrap();
        let second = broker
            .accept_with_outcome(material_with(
                "mna-flow-2",
                SessionMaterialSource::Mna,
                2,
                false,
            ))
            .unwrap();
        assert_eq!(first.disposition, AcceptDisposition::Installed);
        assert_eq!(second.disposition, AcceptDisposition::Installed);
        assert_eq!(
            second.channel_generation,
            first.channel_generation + (1_u64 << 32)
        );
    }

    #[test]
    fn invalid_transitions_fail_closed() {
        let mut broker = SessionBroker::default();
        assert_eq!(broker.lock_udp(), Err(BrokerError::MissingMaterial));
        broker
            .accept(material(SessionMaterialSource::PrivateSession))
            .unwrap();
        assert!(matches!(
            broker.mark_live(),
            Err(BrokerError::InvalidTransition { .. })
        ));
        broker.end("done");
        assert_eq!(
            broker.accept(material(SessionMaterialSource::Mna)),
            Err(BrokerError::TerminalState)
        );
    }

    #[test]
    fn debug_output_is_redacted() {
        let debug = format!("{:?}", material(SessionMaterialSource::HttpsMitm));
        assert!(!debug.contains("packet-key"));
        assert!(!debug.contains("42"));
    }
}
