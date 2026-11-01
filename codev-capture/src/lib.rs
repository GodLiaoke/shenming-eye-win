//! Capture-neutral frame envelopes and bounded transport.
//!
//! The binary envelope is deliberately small and stable so a native host
//! capture agent can feed a container without serialising hot-path data as
//! JSON. Multi-byte integers are big endian and payload bytes follow the
//! fixed-size header directly.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TryRecvError, TrySendError};
use std::time::Duration;

use thiserror::Error;

pub const FRAME_MAGIC: [u8; 4] = *b"CVFR";
pub const FRAME_SCHEMA_VERSION: u16 = 1;
pub const FRAME_HEADER_LEN: usize = 32;
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;
pub const DEFAULT_FRAME_BUS_MAX_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    ClientToServer = 1,
    ServerToClient = 2,
}

impl TryFrom<u8> for Direction {
    type Error = CaptureError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::ClientToServer),
            2 => Ok(Self::ServerToClient),
            _ => Err(CaptureError::InvalidEnvelope(format!(
                "unknown direction {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Transport {
    Tcp = 1,
    Udp = 2,
}

impl TryFrom<u8> for Transport {
    type Error = CaptureError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(CaptureError::InvalidEnvelope(format!(
                "unknown transport {value}"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameOrigin {
    Pcap = 1,
    SocksTcp = 2,
    SocksUdp = 3,
    HttpsMitm = 4,
    MacHostAgent = 5,
    Replay = 6,
}

impl TryFrom<u8> for FrameOrigin {
    type Error = CaptureError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Pcap),
            2 => Ok(Self::SocksTcp),
            3 => Ok(Self::SocksUdp),
            4 => Ok(Self::HttpsMitm),
            5 => Ok(Self::MacHostAgent),
            6 => Ok(Self::Replay),
            _ => Err(CaptureError::InvalidEnvelope(format!(
                "unknown frame origin {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameEnvelope {
    pub schema_version: u16,
    pub capture_ns: u64,
    pub direction: Direction,
    pub transport: Transport,
    pub flow_id: u64,
    pub source: FrameOrigin,
    pub payload: Vec<u8>,
    /// Optional in-process route metadata. It is intentionally not part of
    /// the compact CVFR v1 wire header; host-agent transports may carry it in
    /// a future schema without changing application payload bytes.
    pub route: Option<FrameRoute>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameRoute {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl FrameEnvelope {
    pub fn new(
        capture_ns: u64,
        direction: Direction,
        transport: Transport,
        flow_id: u64,
        source: FrameOrigin,
        payload: Vec<u8>,
    ) -> Result<Self, CaptureError> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(CaptureError::PayloadTooLarge(payload.len()));
        }
        Ok(Self {
            schema_version: FRAME_SCHEMA_VERSION,
            capture_ns,
            direction,
            transport,
            flow_id,
            source,
            payload,
            route: None,
        })
    }

    pub fn new_with_route(
        capture_ns: u64,
        direction: Direction,
        transport: Transport,
        flow_id: u64,
        source: FrameOrigin,
        route: FrameRoute,
        payload: Vec<u8>,
    ) -> Result<Self, CaptureError> {
        let mut frame = Self::new(capture_ns, direction, transport, flow_id, source, payload)?;
        frame.route = Some(route);
        Ok(frame)
    }

    pub fn encode(&self) -> Result<Vec<u8>, CaptureError> {
        if self.schema_version != FRAME_SCHEMA_VERSION {
            return Err(CaptureError::UnsupportedVersion(self.schema_version));
        }
        if self.payload.len() > MAX_FRAME_PAYLOAD {
            return Err(CaptureError::PayloadTooLarge(self.payload.len()));
        }
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| CaptureError::PayloadTooLarge(self.payload.len()))?;
        let mut encoded = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        encoded.extend_from_slice(&FRAME_MAGIC);
        encoded.extend_from_slice(&self.schema_version.to_be_bytes());
        encoded.extend_from_slice(&(FRAME_HEADER_LEN as u16).to_be_bytes());
        encoded.extend_from_slice(&self.capture_ns.to_be_bytes());
        encoded.push(self.direction as u8);
        encoded.push(self.transport as u8);
        encoded.push(self.source as u8);
        encoded.push(0);
        encoded.extend_from_slice(&self.flow_id.to_be_bytes());
        encoded.extend_from_slice(&payload_len.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, CaptureError> {
        self.encode()
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, CaptureError> {
        if encoded.len() < FRAME_HEADER_LEN {
            return Err(CaptureError::InvalidEnvelope(
                "truncated frame header".into(),
            ));
        }
        if encoded[..4] != FRAME_MAGIC {
            return Err(CaptureError::InvalidEnvelope("invalid frame magic".into()));
        }
        let schema_version = u16::from_be_bytes([encoded[4], encoded[5]]);
        if schema_version != FRAME_SCHEMA_VERSION {
            return Err(CaptureError::UnsupportedVersion(schema_version));
        }
        let header_len = usize::from(u16::from_be_bytes([encoded[6], encoded[7]]));
        if header_len != FRAME_HEADER_LEN {
            return Err(CaptureError::InvalidEnvelope(format!(
                "unexpected header length {header_len}"
            )));
        }
        if encoded[19] != 0 {
            return Err(CaptureError::InvalidEnvelope(
                "non-zero reserved header byte".into(),
            ));
        }
        let payload_len = u32::from_be_bytes(encoded[28..32].try_into().unwrap()) as usize;
        if payload_len > MAX_FRAME_PAYLOAD {
            return Err(CaptureError::PayloadTooLarge(payload_len));
        }
        let expected_len = FRAME_HEADER_LEN
            .checked_add(payload_len)
            .ok_or(CaptureError::PayloadTooLarge(payload_len))?;
        if encoded.len() != expected_len {
            return Err(CaptureError::InvalidEnvelope(format!(
                "declared payload length {payload_len}, frame contains {} bytes",
                encoded.len().saturating_sub(FRAME_HEADER_LEN)
            )));
        }
        Ok(Self {
            schema_version,
            capture_ns: u64::from_be_bytes(encoded[8..16].try_into().unwrap()),
            direction: Direction::try_from(encoded[16])?,
            transport: Transport::try_from(encoded[17])?,
            source: FrameOrigin::try_from(encoded[18])?,
            flow_id: u64::from_be_bytes(encoded[20..28].try_into().unwrap()),
            payload: encoded[FRAME_HEADER_LEN..].to_vec(),
            route: None,
        })
    }

    pub fn from_bytes(encoded: &[u8]) -> Result<Self, CaptureError> {
        Self::decode(encoded)
    }
}

pub trait FrameSource {
    fn recv(&mut self) -> Result<Option<FrameEnvelope>, CaptureError>;
}

pub trait FrameTap: Send {
    fn observe(&mut self, frame: &FrameEnvelope);

    /// Give a tap a chance to release bounded protocol state whose deadline
    /// elapsed without a new capture frame.  Capture producers never wait on
    /// this hook; callers should invoke it from a small timer on the protocol
    /// executor.  The default keeps existing taps source-compatible.
    fn poll(&mut self, _now_ns: u64) {}

    /// 返回"下一次必须调用 [`FrameTap::poll`] 的时刻"（纳秒，`capture_time_ns` 同一时钟）。
    ///
    /// * `Some(deadline)` —— 执行器最迟应在该时刻醒来 `poll` 一次；
    /// * `None` —— 当前**没有**待释放的有界状态，执行器可以进入低频空闲等待。
    ///
    /// 默认实现返回 `Some(0)`（等价于"希望保持原来的短周期轮询"），
    /// 因此没有实现本方法的 tap 行为与之前完全一致。
    fn next_deadline_ns(&self) -> Option<u64> {
        Some(0)
    }

    /// Notify a protocol tap that one or more capture frames were dropped
    /// before the next frame reaches it. Implementations should invalidate
    /// baselines/reorder state; capture producers remain non-blocking.
    fn on_capture_gap(&mut self, _now_ns: u64) {}
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("capture I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported frame schema version {0}")]
    UnsupportedVersion(u16),
    #[error("invalid frame envelope: {0}")]
    InvalidEnvelope(String),
    #[error("frame payload is too large: {0} bytes")]
    PayloadTooLarge(usize),
    #[error("frame bus capacity must be greater than zero")]
    ZeroCapacity,
    #[error("frame bus byte capacity must be greater than zero")]
    ZeroByteCapacity,
    #[error("frame bus receiver has closed")]
    BusClosed,
}

/// A point-in-time view of a bounded frame bus.
///
/// `accepted_*` counts frames accepted by the channel, while `processed_*`
/// counts frames returned by one of the receiver methods.  `queue_depth` and
/// `queued_bytes` include a very short reservation window between the
/// non-blocking reservation and the channel's `try_send` call; this keeps the
/// counters bounded even when several capture producers race to enqueue.  All
/// counters are lock-free and may be observed while a producer or consumer is
/// active, so a snapshot can be transiently inconsistent across fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FrameBusMetrics {
    pub capacity: usize,
    pub max_bytes: u64,
    pub queue_depth: usize,
    pub queued_bytes: u64,
    pub accepted_frames: u64,
    pub accepted_bytes: u64,
    pub processed_frames: u64,
    pub processed_bytes: u64,
    pub dropped_frames: u64,
    pub dropped_bytes: u64,
    /// Monotonically increases once for every frame rejected because the bus
    /// was full.  A parser can compare this value with its last observation
    /// and mark a capture gap without requiring a blocking side channel.
    pub drop_epoch: u64,
}

struct FrameBusCounters {
    capacity: usize,
    max_bytes: u64,
    queue_depth: AtomicUsize,
    queued_bytes: AtomicU64,
    accepted_frames: AtomicU64,
    accepted_bytes: AtomicU64,
    processed_frames: AtomicU64,
    processed_bytes: AtomicU64,
    dropped_frames: AtomicU64,
    dropped_bytes: AtomicU64,
    drop_epoch: AtomicU64,
}

impl FrameBusCounters {
    fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            capacity,
            max_bytes: max_bytes as u64,
            queue_depth: AtomicUsize::new(0),
            queued_bytes: AtomicU64::new(0),
            accepted_frames: AtomicU64::new(0),
            accepted_bytes: AtomicU64::new(0),
            processed_frames: AtomicU64::new(0),
            processed_bytes: AtomicU64::new(0),
            dropped_frames: AtomicU64::new(0),
            dropped_bytes: AtomicU64::new(0),
            drop_epoch: AtomicU64::new(0),
        }
    }

    fn reserve(&self, bytes: u64) -> bool {
        if bytes > self.max_bytes {
            return false;
        }
        let reserved = self
            .queue_depth
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |depth| {
                (depth < self.capacity).then_some(depth + 1)
            })
            .is_ok();
        if reserved {
            let byte_reserved = loop {
                let queued = self.queued_bytes.load(Ordering::Acquire);
                let Some(next) = queued.checked_add(bytes) else {
                    break false;
                };
                if next > self.max_bytes {
                    break false;
                }
                if self
                    .queued_bytes
                    .compare_exchange(queued, next, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    break true;
                }
            };
            if !byte_reserved {
                self.queue_depth.fetch_sub(1, Ordering::AcqRel);
                return false;
            }
        }
        reserved
    }

    fn rollback_reservation(&self, bytes: u64) {
        self.queue_depth.fetch_sub(1, Ordering::AcqRel);
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }

    fn record_drop(&self, bytes: u64) {
        self.dropped_frames.fetch_add(1, Ordering::Relaxed);
        self.dropped_bytes.fetch_add(bytes, Ordering::Relaxed);
        // Publish the epoch last. A consumer that observes a newer epoch can
        // treat all preceding drops as one or more capture gaps.
        self.drop_epoch.fetch_add(1, Ordering::Release);
    }

    fn record_accepted(&self, bytes: u64) {
        self.accepted_frames.fetch_add(1, Ordering::Relaxed);
        self.accepted_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_processed(&self, bytes: u64) {
        self.queue_depth.fetch_sub(1, Ordering::AcqRel);
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
        self.processed_frames.fetch_add(1, Ordering::Relaxed);
        self.processed_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn snapshot(&self) -> FrameBusMetrics {
        FrameBusMetrics {
            capacity: self.capacity,
            max_bytes: self.max_bytes,
            queue_depth: self.queue_depth.load(Ordering::Acquire),
            queued_bytes: self.queued_bytes.load(Ordering::Acquire),
            accepted_frames: self.accepted_frames.load(Ordering::Relaxed),
            accepted_bytes: self.accepted_bytes.load(Ordering::Relaxed),
            processed_frames: self.processed_frames.load(Ordering::Relaxed),
            processed_bytes: self.processed_bytes.load(Ordering::Relaxed),
            dropped_frames: self.dropped_frames.load(Ordering::Relaxed),
            dropped_bytes: self.dropped_bytes.load(Ordering::Relaxed),
            drop_epoch: self.drop_epoch.load(Ordering::Acquire),
        }
    }
}

#[derive(Clone)]
pub struct FrameBusSender {
    sender: SyncSender<FrameEnvelope>,
    counters: Arc<FrameBusCounters>,
}

pub struct FrameBusReceiver {
    receiver: Receiver<FrameEnvelope>,
    counters: Arc<FrameBusCounters>,
}

pub fn bounded_frame_bus(
    capacity: usize,
) -> Result<(FrameBusSender, FrameBusReceiver), CaptureError> {
    bounded_frame_bus_with_limits(capacity, DEFAULT_FRAME_BUS_MAX_BYTES)
}

/// Build a non-blocking frame bus with both item and aggregate-byte limits.
/// A producer that would exceed either limit gets `Ok(false)` immediately;
/// no capture/read task waits for the parser.
pub fn bounded_frame_bus_with_limits(
    capacity: usize,
    max_bytes: usize,
) -> Result<(FrameBusSender, FrameBusReceiver), CaptureError> {
    if capacity == 0 {
        return Err(CaptureError::ZeroCapacity);
    }
    if max_bytes == 0 {
        return Err(CaptureError::ZeroByteCapacity);
    }
    let (sender, receiver) = mpsc::sync_channel(capacity);
    let counters = Arc::new(FrameBusCounters::new(capacity, max_bytes));
    Ok((
        FrameBusSender {
            sender,
            counters: Arc::clone(&counters),
        },
        FrameBusReceiver { receiver, counters },
    ))
}

impl FrameBusSender {
    /// Enqueue without ever back-pressuring the capture thread.
    ///
    /// A full queue drops the newest frame and increments `dropped_frames`.
    pub fn try_send(&self, frame: FrameEnvelope) -> Result<bool, CaptureError> {
        let bytes = frame.payload.len() as u64;
        // Reserve before touching the channel. This is a lock-free fast path
        // that prevents competing producers from ever waiting for capacity.
        // The reservation is rolled back if the receiver disappears or a
        // concurrent sender wins the channel's final slot.
        if !self.counters.reserve(bytes) {
            self.counters.record_drop(bytes);
            return Ok(false);
        }
        match self.sender.try_send(frame) {
            Ok(()) => {
                self.counters.record_accepted(bytes);
                Ok(true)
            }
            Err(TrySendError::Full(_)) => {
                self.counters.rollback_reservation(bytes);
                self.counters.record_drop(bytes);
                Ok(false)
            }
            Err(TrySendError::Disconnected(_)) => {
                self.counters.rollback_reservation(bytes);
                Err(CaptureError::BusClosed)
            }
        }
    }

    pub fn dropped_frames(&self) -> u64 {
        self.counters.snapshot().dropped_frames
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.counters.snapshot().dropped_bytes
    }

    pub fn drop_epoch(&self) -> u64 {
        self.counters.drop_epoch.load(Ordering::Acquire)
    }

    pub fn queue_depth(&self) -> usize {
        self.counters.queue_depth.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.counters.capacity
    }

    pub fn max_bytes(&self) -> u64 {
        self.counters.max_bytes
    }

    pub fn metrics(&self) -> FrameBusMetrics {
        self.counters.snapshot()
    }

    pub fn try_push(&self, frame: FrameEnvelope) -> Result<bool, CaptureError> {
        self.try_send(frame)
    }
}

impl FrameTap for FrameBusSender {
    fn observe(&mut self, frame: &FrameEnvelope) {
        let _ = self.try_send(frame.clone());
    }
}

impl FrameBusReceiver {
    fn mark_processed(&self, frame: FrameEnvelope) -> FrameEnvelope {
        self.counters.record_processed(frame.payload.len() as u64);
        frame
    }

    pub fn try_recv(&mut self) -> Result<Option<FrameEnvelope>, CaptureError> {
        match self.receiver.try_recv() {
            Ok(frame) => Ok(Some(self.mark_processed(frame))),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(CaptureError::BusClosed),
        }
    }

    /// Receive without blocking indefinitely. `Ok(None)` means the timeout
    /// elapsed; a disconnected sender remains an explicit `BusClosed` error,
    /// matching [`Self::try_recv`].
    pub fn recv_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<FrameEnvelope>, CaptureError> {
        match self.receiver.recv_timeout(timeout) {
            Ok(frame) => Ok(Some(self.mark_processed(frame))),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(CaptureError::BusClosed),
        }
    }

    pub fn dropped_bytes(&self) -> u64 {
        self.counters.snapshot().dropped_bytes
    }

    pub fn dropped_frames(&self) -> u64 {
        self.counters.snapshot().dropped_frames
    }

    pub fn drop_epoch(&self) -> u64 {
        self.counters.drop_epoch.load(Ordering::Acquire)
    }

    pub fn queue_depth(&self) -> usize {
        self.counters.queue_depth.load(Ordering::Acquire)
    }

    pub fn capacity(&self) -> usize {
        self.counters.capacity
    }

    pub fn max_bytes(&self) -> u64 {
        self.counters.max_bytes
    }

    pub fn metrics(&self) -> FrameBusMetrics {
        self.counters.snapshot()
    }
}

impl FrameSource for FrameBusReceiver {
    fn recv(&mut self) -> Result<Option<FrameEnvelope>, CaptureError> {
        match self.receiver.recv() {
            Ok(frame) => Ok(Some(self.mark_processed(frame))),
            Err(_) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> FrameEnvelope {
        FrameEnvelope::new(
            1_725_000_000_123,
            Direction::ClientToServer,
            Transport::Udp,
            42,
            FrameOrigin::SocksUdp,
            payload.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn binary_envelope_round_trips_exactly() {
        let original = frame(&[0, 1, 2, 255]);
        let encoded = original.encode().unwrap();
        assert_eq!(encoded.len(), FRAME_HEADER_LEN + 4);
        assert_eq!(FrameEnvelope::decode(&encoded).unwrap(), original);
    }

    #[test]
    fn envelope_rejects_version_length_and_reserved_corruption() {
        let mut encoded = frame(b"abc").encode().unwrap();
        encoded[5] = 2;
        assert!(matches!(
            FrameEnvelope::decode(&encoded),
            Err(CaptureError::UnsupportedVersion(2))
        ));

        let mut encoded = frame(b"abc").encode().unwrap();
        encoded[19] = 1;
        assert!(matches!(
            FrameEnvelope::decode(&encoded),
            Err(CaptureError::InvalidEnvelope(_))
        ));

        let mut encoded = frame(b"abc").encode().unwrap();
        encoded[31] = 9;
        assert!(matches!(
            FrameEnvelope::decode(&encoded),
            Err(CaptureError::InvalidEnvelope(_))
        ));
    }

    #[test]
    fn bounded_bus_drops_newest_without_blocking() {
        let (sender, mut receiver) = bounded_frame_bus(1).unwrap();
        assert!(sender.try_send(frame(b"first")).unwrap());
        assert!(!sender.try_send(frame(b"second")).unwrap());
        assert_eq!(sender.dropped_frames(), 1);
        assert_eq!(sender.dropped_bytes(), 6);
        assert_eq!(sender.drop_epoch(), 1);
        assert_eq!(sender.capacity(), 1);
        assert_eq!(sender.queue_depth(), 1);
        assert_eq!(
            sender.metrics(),
            FrameBusMetrics {
                capacity: 1,
                max_bytes: DEFAULT_FRAME_BUS_MAX_BYTES as u64,
                queue_depth: 1,
                queued_bytes: 5,
                accepted_frames: 1,
                accepted_bytes: 5,
                processed_frames: 0,
                processed_bytes: 0,
                dropped_frames: 1,
                dropped_bytes: 6,
                drop_epoch: 1,
            }
        );
        assert_eq!(receiver.try_recv().unwrap().unwrap().payload, b"first");
        assert!(receiver.try_recv().unwrap().is_none());
        assert_eq!(receiver.queue_depth(), 0);
        assert_eq!(receiver.metrics().processed_frames, 1);
        assert_eq!(receiver.metrics().processed_bytes, 5);
    }

    #[test]
    fn bounded_bus_enforces_aggregate_bytes_without_waiting() {
        let (sender, _receiver) = bounded_frame_bus_with_limits(8, 4).unwrap();
        assert!(sender.try_send(frame(b"1234")).unwrap());
        assert!(!sender.try_send(frame(b"5")).unwrap());
        assert_eq!(sender.metrics().queued_bytes, 4);
        assert_eq!(sender.metrics().dropped_bytes, 1);
        assert_eq!(sender.metrics().drop_epoch, 1);
        assert!(matches!(
            bounded_frame_bus_with_limits(1, 0),
            Err(CaptureError::ZeroByteCapacity)
        ));
    }

    #[test]
    fn recv_timeout_distinguishes_timeout_from_disconnect() {
        let (sender, mut receiver) = bounded_frame_bus(1).unwrap();
        assert!(receiver.recv_timeout(Duration::ZERO).unwrap().is_none());
        assert!(sender.try_send(frame(b"ready")).unwrap());
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .payload,
            b"ready"
        );
        drop(sender);
        assert!(matches!(
            receiver.recv_timeout(Duration::ZERO),
            Err(CaptureError::BusClosed)
        ));
    }

    #[test]
    fn cloned_senders_share_drop_epoch_and_queue_metrics() {
        let (sender, mut receiver) = bounded_frame_bus(2).unwrap();
        let clone = sender.clone();
        assert!(sender.try_send(frame(b"a")).unwrap());
        assert!(clone.try_send(frame(b"bb")).unwrap());
        assert!(!sender.try_send(frame(b"ccc")).unwrap());
        let metrics = clone.metrics();
        assert_eq!(metrics.capacity, 2);
        assert_eq!(metrics.queue_depth, 2);
        assert_eq!(metrics.queued_bytes, 3);
        assert_eq!(metrics.accepted_frames, 2);
        assert_eq!(metrics.dropped_frames, 1);
        assert_eq!(metrics.dropped_bytes, 3);
        assert_eq!(metrics.drop_epoch, 1);
        assert_eq!(receiver.try_recv().unwrap().unwrap().payload, b"a");
        assert_eq!(receiver.try_recv().unwrap().unwrap().payload, b"bb");
        assert_eq!(receiver.metrics().queue_depth, 0);
    }

    #[test]
    fn concurrent_producers_never_report_depth_above_capacity() {
        let capacity = 8;
        let (sender, mut receiver) = bounded_frame_bus(capacity).unwrap();
        let attempts = 4 * 100;
        let producers = (0..4)
            .map(|producer| {
                let sender = sender.clone();
                std::thread::spawn(move || {
                    for sequence in 0..100 {
                        let payload = [producer as u8, sequence as u8];
                        let _ = sender.try_send(frame(&payload));
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(sender);
        for producer in producers {
            producer.join().unwrap();
        }
        while let Ok(Some(_)) = receiver.try_recv() {
            assert!(receiver.queue_depth() <= capacity);
        }
        let metrics = receiver.metrics();
        assert_eq!(metrics.accepted_frames + metrics.dropped_frames, attempts);
        assert_eq!(metrics.processed_frames, metrics.accepted_frames);
        assert_eq!(metrics.queue_depth, 0);
        assert_eq!(metrics.queued_bytes, 0);
        assert_eq!(metrics.drop_epoch, metrics.dropped_frames);
    }

    #[test]
    fn disconnected_bus_is_explicit() {
        let (sender, receiver) = bounded_frame_bus(1).unwrap();
        drop(receiver);
        assert!(matches!(
            sender.try_send(frame(b"lost")),
            Err(CaptureError::BusClosed)
        ));
    }
}
