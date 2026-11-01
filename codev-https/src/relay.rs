use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    AuthorityError, MitmAuthority, PlaintextDirection, PlaintextRecord, PlaintextRecorder,
};

const RELAY_BUFFER_BYTES: usize = 16 * 1024;
const DEFAULT_OBSERVER_QUEUE_RECORDS: usize = 256;
const DEFAULT_OBSERVER_QUEUE_BYTES: usize = 4 * 1024 * 1024;

pub trait PlaintextSink: Send + Sync + 'static {
    fn observe(&self, record: PlaintextRecord<'_>) -> io::Result<()>;

    fn close(&self, _flow_id: &str) -> io::Result<()> {
        Ok(())
    }
}

impl PlaintextSink for PlaintextRecorder {
    fn observe(&self, record: PlaintextRecord<'_>) -> io::Result<()> {
        self.record(record).map(|_| ())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlaintextQueueStatus {
    pub capacity_records: usize,
    pub capacity_bytes: usize,
    pub queued_bytes: usize,
    pub enqueued_records: u64,
    pub processed_records: u64,
    pub dropped_records: u64,
    pub sink_errors: u64,
    pub worker_running: bool,
}

struct OwnedPlaintextRecord {
    capture_ns: u64,
    direction: PlaintextDirection,
    flow_id: String,
    host: String,
    payload: Vec<u8>,
}

enum ObserverMessage {
    Record(OwnedPlaintextRecord),
    Wake,
}

struct QueueCounters {
    queued_bytes: AtomicUsize,
    enqueued_records: AtomicU64,
    processed_records: AtomicU64,
    dropped_records: AtomicU64,
    sink_errors: AtomicU64,
    worker_running: AtomicBool,
}

/// A bounded, non-blocking adapter that owns all recorder/extractor work.
/// Relay tasks only copy an admitted chunk and call `try_send`; a slow or
/// failed observer can therefore degrade observation but never TLS forwarding.
pub struct BoundedPlaintextSink {
    sender: mpsc::SyncSender<ObserverMessage>,
    counters: Arc<QueueCounters>,
    pending_closes: Arc<Mutex<Vec<String>>>,
    capacity_records: usize,
    capacity_bytes: usize,
}

impl BoundedPlaintextSink {
    pub fn spawn(sink: Arc<dyn PlaintextSink>) -> Arc<Self> {
        Self::spawn_with_limits(
            sink,
            DEFAULT_OBSERVER_QUEUE_RECORDS,
            DEFAULT_OBSERVER_QUEUE_BYTES,
        )
    }

    pub fn spawn_with_limits(
        sink: Arc<dyn PlaintextSink>,
        capacity_records: usize,
        capacity_bytes: usize,
    ) -> Arc<Self> {
        let capacity_records = capacity_records.max(1);
        let capacity_bytes = capacity_bytes.max(1);
        let (sender, receiver) = mpsc::sync_channel(capacity_records);
        let counters = Arc::new(QueueCounters {
            queued_bytes: AtomicUsize::new(0),
            enqueued_records: AtomicU64::new(0),
            processed_records: AtomicU64::new(0),
            dropped_records: AtomicU64::new(0),
            sink_errors: AtomicU64::new(0),
            worker_running: AtomicBool::new(true),
        });
        let pending_closes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let worker_counters = Arc::clone(&counters);
        let worker_closes = Arc::clone(&pending_closes);
        thread::Builder::new()
            .name("codev-https-observer".into())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        ObserverMessage::Record(record) => {
                            worker_counters
                                .queued_bytes
                                .fetch_sub(record.payload.len(), Ordering::AcqRel);
                            let result = sink.observe(PlaintextRecord {
                                capture_ns: record.capture_ns,
                                direction: record.direction,
                                flow_id: &record.flow_id,
                                host: &record.host,
                                payload: &record.payload,
                            });
                            if result.is_err() {
                                worker_counters.sink_errors.fetch_add(1, Ordering::Relaxed);
                            }
                            worker_counters
                                .processed_records
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        ObserverMessage::Wake => {}
                    }
                    let closes = worker_closes
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .drain(..)
                        .collect::<Vec<_>>();
                    for flow_id in closes {
                        if sink.close(&flow_id).is_err() {
                            worker_counters.sink_errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                let closes = worker_closes
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .drain(..)
                    .collect::<Vec<_>>();
                for flow_id in closes {
                    if sink.close(&flow_id).is_err() {
                        worker_counters.sink_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
                worker_counters
                    .worker_running
                    .store(false, Ordering::Release);
            })
            .expect("failed to spawn bounded HTTPS observer worker");
        Arc::new(Self {
            sender,
            counters,
            pending_closes,
            capacity_records,
            capacity_bytes,
        })
    }

    pub fn status(&self) -> PlaintextQueueStatus {
        PlaintextQueueStatus {
            capacity_records: self.capacity_records,
            capacity_bytes: self.capacity_bytes,
            queued_bytes: self.counters.queued_bytes.load(Ordering::Acquire),
            enqueued_records: self.counters.enqueued_records.load(Ordering::Relaxed),
            processed_records: self.counters.processed_records.load(Ordering::Relaxed),
            dropped_records: self.counters.dropped_records.load(Ordering::Relaxed),
            sink_errors: self.counters.sink_errors.load(Ordering::Relaxed),
            worker_running: self.counters.worker_running.load(Ordering::Acquire),
        }
    }

    fn reserve_bytes(&self, bytes: usize) -> bool {
        self.counters
            .queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued
                    .checked_add(bytes)
                    .filter(|next| *next <= self.capacity_bytes)
            })
            .is_ok()
    }

    fn mark_drop(&self) {
        self.counters
            .dropped_records
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl PlaintextSink for BoundedPlaintextSink {
    fn observe(&self, record: PlaintextRecord<'_>) -> io::Result<()> {
        if !self.reserve_bytes(record.payload.len()) {
            self.mark_drop();
            return Ok(());
        }
        let payload_len = record.payload.len();
        let message = ObserverMessage::Record(OwnedPlaintextRecord {
            capture_ns: record.capture_ns,
            direction: record.direction,
            flow_id: record.flow_id.to_owned(),
            host: record.host.to_owned(),
            payload: record.payload.to_vec(),
        });
        match self.sender.try_send(message) {
            Ok(()) => {
                self.counters
                    .enqueued_records
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.counters
                    .queued_bytes
                    .fetch_sub(payload_len, Ordering::AcqRel);
                self.mark_drop();
            }
        }
        Ok(())
    }

    fn close(&self, flow_id: &str) -> io::Result<()> {
        self.pending_closes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(flow_id.to_owned());
        // Wake the worker when capacity is available. If the queue is full,
        // it drains pending closes after the next record.
        if self.sender.try_send(ObserverMessage::Wake).is_err() {
            return Ok(());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayReport {
    pub client_to_server_bytes: u64,
    pub server_to_client_bytes: u64,
}

pub struct TlsMitmRelay {
    authority: Arc<MitmAuthority>,
    client_config: Arc<ClientConfig>,
}

impl TlsMitmRelay {
    pub fn new(authority: Arc<MitmAuthority>) -> Self {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Self {
            authority,
            client_config: Arc::new(client_config),
        }
    }

    pub async fn intercept(
        &self,
        downstream: TcpStream,
        upstream: SocketAddr,
        host: &str,
        flow_id: &str,
        sink: Option<Arc<dyn PlaintextSink>>,
    ) -> Result<RelayReport, RelayError> {
        let upstream_tcp = TcpStream::connect(upstream).await?;
        self.intercept_streams(downstream, upstream_tcp, host, flow_id, sink)
            .await
    }

    pub async fn intercept_streams(
        &self,
        downstream: TcpStream,
        upstream_tcp: TcpStream,
        host: &str,
        flow_id: &str,
        sink: Option<Arc<dyn PlaintextSink>>,
    ) -> Result<RelayReport, RelayError> {
        let authority = Arc::clone(&self.authority);
        let owned_host = host.to_owned();
        let server_config =
            tokio::task::spawn_blocking(move || authority.server_config(&owned_host))
                .await
                .map_err(RelayError::ObserverWorker)??;
        let downstream = TlsAcceptor::from(server_config).accept(downstream).await?;
        let downstream_alpn = downstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|_| RelayError::InvalidHost)?;
        let mut upstream_config = (*self.client_config).clone();
        upstream_config.alpn_protocols = downstream_alpn.iter().cloned().collect();
        let upstream = TlsConnector::from(Arc::new(upstream_config))
            .connect(server_name, upstream_tcp)
            .await?;
        let upstream_alpn = upstream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        if upstream_alpn != downstream_alpn {
            return Err(RelayError::AlpnMismatch {
                downstream: downstream_alpn,
                upstream: upstream_alpn,
            });
        }
        let sink: Option<Arc<dyn PlaintextSink>> = sink
            .map(BoundedPlaintextSink::spawn)
            .map(|sink| sink as Arc<dyn PlaintextSink>);
        let (mut downstream_read, mut downstream_write) = tokio::io::split(downstream);
        let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
        let client_sink = sink.clone();
        let server_sink = sink.clone();
        let client_to_server = observed_copy(
            &mut downstream_read,
            &mut upstream_write,
            PlaintextDirection::ClientToServer,
            flow_id,
            host,
            client_sink,
        );
        let server_to_client = observed_copy(
            &mut upstream_read,
            &mut downstream_write,
            PlaintextDirection::ServerToClient,
            flow_id,
            host,
            server_sink,
        );
        let relay_result = tokio::try_join!(client_to_server, server_to_client);
        if let Some(sink) = sink.as_ref() {
            sink.close(flow_id)?;
        }
        let (client_to_server_bytes, server_to_client_bytes) = relay_result?;
        Ok(RelayReport {
            client_to_server_bytes,
            server_to_client_bytes,
        })
    }
}

async fn observed_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    direction: PlaintextDirection,
    flow_id: &str,
    host: &str,
    sink: Option<Arc<dyn PlaintextSink>>,
) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; RELAY_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(copied);
        }
        if let Some(sink) = sink.as_ref() {
            sink.observe(PlaintextRecord {
                capture_ns: now_ns(),
                direction,
                flow_id,
                host,
                payload: &buffer[..read],
            })?;
        }
        writer.write_all(&buffer[..read]).await?;
        copied = copied.saturating_add(read as u64);
    }
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("TLS authority error: {0}")]
    Authority(#[from] AuthorityError),
    #[error("TLS relay I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid upstream TLS hostname")]
    InvalidHost,
    #[error("HTTPS observer worker failed: {0}")]
    ObserverWorker(tokio::task::JoinError),
    #[error("upstream ALPN {upstream:?} did not mirror downstream ALPN {downstream:?}")]
    AlpnMismatch {
        downstream: Option<Vec<u8>>,
        upstream: Option<Vec<u8>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    struct SlowSink {
        observes: AtomicUsize,
        closes: Mutex<Vec<String>>,
        delay: Duration,
    }

    impl PlaintextSink for SlowSink {
        fn observe(&self, _record: PlaintextRecord<'_>) -> io::Result<()> {
            thread::sleep(self.delay);
            self.observes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn close(&self, flow_id: &str) -> io::Result<()> {
            self.closes
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(flow_id.to_owned());
            Ok(())
        }
    }

    fn record(payload: &[u8]) -> PlaintextRecord<'_> {
        PlaintextRecord {
            capture_ns: 1,
            direction: PlaintextDirection::ClientToServer,
            flow_id: "flow-1",
            host: "example.test",
            payload,
        }
    }

    #[test]
    fn observer_enqueue_is_non_blocking_and_bounded() {
        let sink = Arc::new(SlowSink {
            observes: AtomicUsize::new(0),
            closes: Mutex::new(Vec::new()),
            delay: Duration::from_millis(100),
        });
        let queue = BoundedPlaintextSink::spawn_with_limits(sink, 1, 8);
        let started = std::time::Instant::now();
        for _ in 0..32 {
            queue.observe(record(b"12345678")).unwrap();
        }
        assert!(started.elapsed() < Duration::from_millis(50));
        assert!(queue.status().dropped_records > 0);
    }

    #[test]
    fn close_is_delivered_after_queued_records_without_blocking() {
        let sink = Arc::new(SlowSink {
            observes: AtomicUsize::new(0),
            closes: Mutex::new(Vec::new()),
            delay: Duration::from_millis(1),
        });
        let queue = BoundedPlaintextSink::spawn_with_limits(
            Arc::clone(&sink) as Arc<dyn PlaintextSink>,
            2,
            1024,
        );
        queue.observe(record(b"hello")).unwrap();
        queue.close("flow-1").unwrap();
        thread::sleep(Duration::from_millis(50));
        assert_eq!(sink.closes.lock().unwrap().as_slice(), ["flow-1"]);
    }
}
