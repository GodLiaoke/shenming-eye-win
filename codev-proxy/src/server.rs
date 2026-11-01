use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codev_capture::{
    Direction, FrameBusSender, FrameEnvelope, FrameOrigin, FrameRoute, FrameTap, Transport,
    bounded_frame_bus_with_limits,
};
use fast_socks5::server::{Socks5ServerProtocol, SocksServerError, states};
use fast_socks5::util::target_addr::TargetAddr as OpenTargetAddr;
use fast_socks5::{
    ReplyError as OpenReplyError, Socks5Command, UdpHeaderError, new_udp_header, parse_udp_request,
};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Sleep, timeout};
use zeroize::Zeroize;

use crate::config::{ConfigError, RuntimeProxyConfig};
use crate::policy::{
    DynamicTargetStore, PolicyError, StrictTargetPolicy, SystemTargetResolver, TargetAddr,
    TargetResolver,
};
use crate::token::{ConnectionPermit, QuotaMeter, TokenError, TokenStore, UdpFlowPermit};

const RELAY_BUFFER: usize = 16 * 1024;
const UDP_BUFFER: usize = 65_535;
const FRAME_TAP_QUEUE_CAPACITY: usize = 1024;
const FRAME_TAP_QUEUE_MAX_BYTES: usize = 64 * 1024 * 1024;
/// 有待释放状态时的最长等待（原来固定 10ms，保留同样的节奏）
const FRAME_TAP_TIMER_WAIT_MS: u64 = 10;
/// 完全空闲（没有对局、没有待释放状态）时的等待：1 秒 4 次唤醒而不是 100 次
const FRAME_TAP_IDLE_WAIT_MS: u64 = 250;
const MNA_CONTROL_MAGIC: [u8; 6] = [0x33, 0x66, 0x00, 0x0b, 0x00, 0x0c];
const MIRROR_TARGET_PORT: u16 = 9;
const MIRROR_RECORD_HEADER_LEN: usize = 46;
const MIRROR_FLAG_CLOSE: u8 = 1;
const MAX_MIRROR_PAYLOAD: usize = 65_535;

/// 自检用：本文件源码（测试里断言关键调用，防止以后被删掉）
#[cfg(test)]
const INDEX_SERVER_SRC: &str = include_str!("server.rs");

type OpenSocksCommand = Socks5ServerProtocol<TcpStream, states::CommandRead>;

#[derive(Clone)]
pub struct TapHandle {
    sender: FrameBusSender,
}

impl TapHandle {
    pub fn new(tap: impl FrameTap + 'static) -> Self {
        // Keep protocol decoding off the socket tasks. A dedicated worker
        // owns all mutable parser state and consumes a bounded, try-send-only
        // queue; queue loss is surfaced to the tap as a capture gap.
        let (sender, mut receiver) =
            bounded_frame_bus_with_limits(FRAME_TAP_QUEUE_CAPACITY, FRAME_TAP_QUEUE_MAX_BYTES)
                .expect("static frame tap queue limits are non-zero");
        std::thread::Builder::new()
            .name("codev-frame-parser".into())
            .spawn(move || {
                let mut tap = tap;
                let mut observed_drop_epoch = 0_u64;
                loop {
                    let metrics = receiver.metrics();
                    if metrics.drop_epoch != observed_drop_epoch {
                        observed_drop_epoch = metrics.drop_epoch;
                        tap.on_capture_gap(capture_time_ns());
                    }
                    // 唤醒策略：只有"确实有待释放的有界状态"时才短周期醒来。
                    //   原来是无条件 10ms 定时（100Hz），空闲槽位也一直醒 → 每个槽位空转 ~3.7% 单核。
                    //   现在由 tap 给出"下一次必须 poll 的时刻"：
                    //     · 有期限（有 TCP 关闭在宽限期内 / 有锁定中的管线）→ 到点就醒，语义与原来一致；
                    //     · 有 UDP reorder gap 待释放 → 同样到 50ms 死线就醒（★ 这条必须算进来，
                    //       否则 gap 释放会被拖到空闲等待结束，最长 250ms）；
                    //     · 没有期限（没有对局、没有待释放状态）→ 低频等待，收到帧会被立刻唤醒。
                    let wait = match tap.next_deadline_ns() {
                        Some(deadline) => {
                            let now = capture_time_ns();
                            let remaining_ms = deadline.saturating_sub(now) / 1_000_000;
                            Duration::from_millis(remaining_ms.clamp(1, FRAME_TAP_TIMER_WAIT_MS))
                        }
                        None => Duration::from_millis(FRAME_TAP_IDLE_WAIT_MS),
                    };
                    match receiver.recv_timeout(wait) {
                        Ok(Some(frame)) => {
                            tap.observe(&frame);
                        }
                        Ok(None) => tap.poll(capture_time_ns()),
                        Err(_) => break,
                    }
                }
            })
            .expect("frame parser worker must start");
        Self { sender }
    }

    pub fn observe(&self, frame: &FrameEnvelope) {
        let _ = self.sender.try_send(frame.clone());
    }

    /// Poll protocol state that has a bounded release deadline (for example
    /// the UDP 50 ms reorder window).  This is deliberately separate from
    /// `observe`: a quiet capture stream must not strand a valid packet in a
    /// reorder buffer indefinitely.
    pub fn poll(&self, now_ns: u64) {
        // Worker 线程自己按 `FrameTap::next_deadline_ns()` 的期限轮询
        // （见 `TapHandle::new` 里的循环）。这个 hook 保留只为兼容旧调用方，
        // 不做事：调用它既不会释放状态，也不该被用来当定时器。
        // 注意：之前 proxy_runtime 用一个 100Hz 的任务调本函数"兜底"，
        // 那实际上只是把 tokio 运行时每 10ms 唤醒一次（≈2% 单核空转），
        // 真正的释放一直发生在 worker 线程里。那个任务已删除。
        let _ = now_ns;
    }

    pub fn metrics(&self) -> codev_capture::FrameBusMetrics {
        self.sender.metrics()
    }
}

impl Default for TapHandle {
    fn default() -> Self {
        Self::new(NoopFrameTap)
    }
}

struct NoopFrameTap;

impl FrameTap for NoopFrameTap {
    fn observe(&mut self, _frame: &FrameEnvelope) {}

    /// 没有协议状态要释放 → 允许执行器空闲低频等待（不设期限）。
    fn next_deadline_ns(&self) -> Option<u64> {
        None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyEvent {
    AuthenticationRejected {
        peer: SocketAddr,
    },
    TargetRejected {
        peer: SocketAddr,
        transport: Transport,
        target: TargetAddr,
        reason: String,
    },
    UdpFragmentRejected {
        peer: SocketAddr,
        fragment: u8,
    },
    MalformedUdpPacket {
        peer: SocketAddr,
        reason: String,
    },
    UdpDuplicateObserved {
        peer: SocketAddr,
        flow_id: u64,
    },
    UnauthorizedUdpSource {
        peer: SocketAddr,
        source: SocketAddr,
    },
    QuicBlocked {
        peer: SocketAddr,
        target: TargetAddr,
    },
    QuotaExceeded {
        peer: SocketAddr,
        quota: &'static str,
    },
    UdpIdleTimeout {
        peer: SocketAddr,
    },
    UdpAssociationClosed {
        peer: SocketAddr,
        reason: UdpAssociationCloseReason,
    },
    /// A SOCKS TCP CONNECT relay ended.  The flow identifier is opaque to
    /// callers and lets the session broker discard stale MNA material when a
    /// control channel is actually closed; ordinary HTTPS/game TCP flows are
    /// ignored unless they own the active MNA session.
    TcpConnectionClosed {
        peer: SocketAddr,
        flow_id: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpAssociationCloseReason {
    ControlClosed,
    ControlError,
    IdleTimeout,
}

pub trait ProxyEventSink: Send + Sync {
    fn emit(&self, event: ProxyEvent);
}

#[derive(Default)]
struct NoopEventSink;

impl ProxyEventSink for NoopEventSink {
    fn emit(&self, _event: ProxyEvent) {}
}

#[derive(Clone, Default)]
pub struct ProxyMetrics {
    inner: Arc<ProxyMetricCounters>,
}

#[derive(Default)]
struct ProxyMetricCounters {
    accepted_connections: AtomicU64,
    tcp_connects: AtomicU64,
    udp_associations: AtomicU64,
    rejected_authentication: AtomicU64,
    rejected_targets: AtomicU64,
    tcp_frames: AtomicU64,
    udp_frames: AtomicU64,
    udp_fragments_rejected: AtomicU64,
    udp_duplicates_observed: AtomicU64,
    quic_blocked: AtomicU64,
    quota_rejections: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxyMetricsSnapshot {
    pub accepted_connections: u64,
    pub tcp_connects: u64,
    pub udp_associations: u64,
    pub rejected_authentication: u64,
    pub rejected_targets: u64,
    pub tcp_frames: u64,
    pub udp_frames: u64,
    pub udp_fragments_rejected: u64,
    pub udp_duplicates_observed: u64,
    pub quic_blocked: u64,
    pub quota_rejections: u64,
}

impl ProxyMetrics {
    pub fn snapshot(&self) -> ProxyMetricsSnapshot {
        ProxyMetricsSnapshot {
            accepted_connections: self.inner.accepted_connections.load(Ordering::Relaxed),
            tcp_connects: self.inner.tcp_connects.load(Ordering::Relaxed),
            udp_associations: self.inner.udp_associations.load(Ordering::Relaxed),
            rejected_authentication: self.inner.rejected_authentication.load(Ordering::Relaxed),
            rejected_targets: self.inner.rejected_targets.load(Ordering::Relaxed),
            tcp_frames: self.inner.tcp_frames.load(Ordering::Relaxed),
            udp_frames: self.inner.udp_frames.load(Ordering::Relaxed),
            udp_fragments_rejected: self.inner.udp_fragments_rejected.load(Ordering::Relaxed),
            udp_duplicates_observed: self.inner.udp_duplicates_observed.load(Ordering::Relaxed),
            quic_blocked: self.inner.quic_blocked.load(Ordering::Relaxed),
            quota_rejections: self.inner.quota_rejections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
pub struct ConnectContext {
    pub target: TargetAddr,
    pub resolved: Vec<SocketAddr>,
    pub peer: SocketAddr,
    pub flow_id: u64,
    pub token_username: String,
    tap: TapHandle,
    quota: QuotaMeter,
    metrics: ProxyMetrics,
    events: Arc<dyn ProxyEventSink>,
}

impl ConnectContext {
    pub fn observe(&self, direction: Direction, payload: &[u8]) -> Result<(), ProxyError> {
        self.observe_with_origin(direction, Transport::Tcp, FrameOrigin::SocksTcp, payload)
    }

    /// Emit a frame using an explicit origin. HTTPS interception can use this
    /// to distinguish decrypted application bytes from the outer SOCKS tunnel.
    pub fn observe_with_origin(
        &self,
        direction: Direction,
        transport: Transport,
        origin: FrameOrigin,
        payload: &[u8],
    ) -> Result<(), ProxyError> {
        if let Err(error) = self.quota.charge_bytes(payload.len()) {
            self.metrics
                .inner
                .quota_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.events.emit(ProxyEvent::QuotaExceeded {
                peer: self.peer,
                quota: "bandwidth",
            });
            return Err(error.into());
        }
        let remote = self
            .resolved
            .first()
            .copied()
            .unwrap_or_else(|| SocketAddr::new(self.peer.ip(), self.target.port()));
        let route = match direction {
            Direction::ClientToServer => FrameRoute {
                source: self.peer,
                destination: remote,
            },
            Direction::ServerToClient => FrameRoute {
                source: remote,
                destination: self.peer,
            },
        };
        let frame = FrameEnvelope::new_with_route(
            capture_time_ns(),
            direction,
            transport,
            self.flow_id,
            origin,
            route,
            payload.to_vec(),
        )?;
        self.tap.observe(&frame);
        self.metrics
            .inner
            .tcp_frames
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// Handles an already-authorized and already-connected SOCKS5 TCP tunnel.
///
/// A future HTTPS interceptor receives both sides after the SOCKS success
/// response and can terminate TLS selectively. The default implementation is
/// a transparent byte relay and emits each chunk through the frame tap.
pub trait TcpConnectHandler: Send + Sync {
    fn handle(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        context: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send>>;
}

pub use TcpConnectHandler as ConnectInterceptor;

#[derive(Default)]
pub struct DirectTcpConnectHandler;

impl TcpConnectHandler for DirectTcpConnectHandler {
    fn handle(
        &self,
        client: TcpStream,
        upstream: TcpStream,
        context: ConnectContext,
    ) -> Pin<Box<dyn Future<Output = Result<(), ProxyError>> + Send>> {
        Box::pin(async move {
            let (client_read, client_write) = client.into_split();
            let (upstream_read, upstream_write) = upstream.into_split();
            let outbound = relay_half(
                client_read,
                upstream_write,
                context.clone(),
                Direction::ClientToServer,
            );
            let inbound = relay_half(
                upstream_read,
                client_write,
                context,
                Direction::ServerToClient,
            );
            tokio::try_join!(outbound, inbound)?;
            Ok(())
        })
    }
}

async fn relay_half<R, W>(
    mut reader: R,
    mut writer: W,
    context: ConnectContext,
    direction: Direction,
) -> Result<(), ProxyError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; RELAY_BUFFER];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        context.observe(direction, &buffer[..count])?;
        writer.write_all(&buffer[..count]).await?;
    }
}

async fn read_mna_probation_prefix(
    client: &mut TcpStream,
    wait: Duration,
) -> io::Result<Option<Vec<u8>>> {
    let read = async {
        let mut prefix = Vec::with_capacity(MNA_CONTROL_MAGIC.len());
        while prefix.len() < MNA_CONTROL_MAGIC.len() {
            let mut buffer = [0_u8; MNA_CONTROL_MAGIC.len()];
            let count = client
                .read(&mut buffer[..MNA_CONTROL_MAGIC.len() - prefix.len()])
                .await?;
            if count == 0 {
                return Ok(None);
            }
            prefix.extend_from_slice(&buffer[..count]);
            if !MNA_CONTROL_MAGIC.starts_with(&prefix) {
                return Ok(None);
            }
        }
        Ok(Some(prefix))
    };
    match timeout(wait, read).await {
        Ok(result) => result,
        Err(_) => Ok(None),
    }
}

pub trait TcpConnector: Send + Sync {
    fn connect(
        &self,
        addresses: Vec<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;
}

#[derive(Default)]
pub struct SystemTcpConnector;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TcpPreparation {
    Bound,
    Unbound,
}

fn should_retry_unbound(preparation: TcpPreparation, connect_failed: bool) -> bool {
    preparation == TcpPreparation::Bound && connect_failed
}

impl TcpConnector for SystemTcpConnector {
    fn connect(
        &self,
        addresses: Vec<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>> {
        Box::pin(async move {
            let mut last_error = None;
            for address in addresses {
                // 先建 socket、再绑定物理出口，最后才 connect —— 连接建立后再设置
                // 接口对已经出去的首包无效。iOS 单机场景靠这一步绕开系统 VPN 隧道。
                let attempt = match address {
                    SocketAddr::V4(_) => TcpSocket::new_v4(),
                    SocketAddr::V6(_) => TcpSocket::new_v6(),
                }
                .map(|socket| {
                    let preparation = if crate::netbind::prepare_tcp(&socket).is_ok() {
                        TcpPreparation::Bound
                    } else {
                        TcpPreparation::Unbound
                    };
                    (socket, preparation)
                });
                let result = match attempt {
                    Ok((socket, preparation)) => {
                        let result = socket.connect(address).await;
                        if should_retry_unbound(preparation, result.is_err()) {
                            let fallback = match address {
                                SocketAddr::V4(_) => TcpSocket::new_v4(),
                                SocketAddr::V6(_) => TcpSocket::new_v6(),
                            };
                            match fallback {
                                Ok(socket) => socket.connect(address).await,
                                Err(error) => Err(error),
                            }
                        } else {
                            result
                        }
                    }
                    Err(error) => Err(error),
                };
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some(error),
                }
            }
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "target resolved to no addresses")
            }))
        })
    }
}

pub struct Socks5Server {
    config: RuntimeProxyConfig,
    tokens: TokenStore,
    policy: StrictTargetPolicy,
    tap: TapHandle,
    events: Arc<dyn ProxyEventSink>,
    handler: Arc<dyn TcpConnectHandler>,
    resolver: Arc<dyn TargetResolver>,
    connector: Arc<dyn TcpConnector>,
    flow_ids: AtomicU64,
    udp_relay_cursor: AtomicU64,
    metrics: ProxyMetrics,
}

impl Socks5Server {
    pub fn new(
        config: impl Into<RuntimeProxyConfig>,
        tokens: TokenStore,
    ) -> Result<Self, ConfigError> {
        let config = config.into();
        config.validate()?;
        Ok(Self {
            policy: StrictTargetPolicy::new_with_public_target_override(
                &config.proxy.allow_hosts,
                &config.proxy.allow_ports,
                config.proxy.allow_any_public_target,
            )
            .with_dns_proxying(config.proxy.allow_dns_proxying),
            config,
            tokens,
            tap: TapHandle::default(),
            events: Arc::new(NoopEventSink),
            handler: Arc::new(DirectTcpConnectHandler),
            resolver: Arc::new(SystemTargetResolver),
            connector: Arc::new(SystemTcpConnector),
            flow_ids: AtomicU64::new(1),
            udp_relay_cursor: AtomicU64::new(0),
            metrics: ProxyMetrics::default(),
        })
    }

    pub fn with_frame_tap(mut self, tap: TapHandle) -> Self {
        self.tap = tap;
        self
    }

    /// Bind a session-scoped IP/port store. Entries are installed only after
    /// authenticated session material is recovered by the embedding runtime.
    pub fn with_dynamic_targets(mut self, targets: DynamicTargetStore) -> Self {
        self.policy = self.policy.clone().with_dynamic_targets(targets);
        self
    }

    pub fn with_event_sink(mut self, events: Arc<dyn ProxyEventSink>) -> Self {
        self.events = events;
        self
    }

    pub fn with_connect_handler(mut self, handler: Arc<dyn TcpConnectHandler>) -> Self {
        self.handler = handler;
        self
    }

    /// Override name resolution for a controlled embedding or deterministic
    /// integration test. The default resolver enforces public-only DNS answers.
    pub fn with_target_resolver(mut self, resolver: Arc<dyn TargetResolver>) -> Self {
        self.resolver = resolver;
        self
    }

    pub fn with_tcp_connector(mut self, connector: Arc<dyn TcpConnector>) -> Self {
        self.connector = connector;
        self
    }

    pub fn metrics(&self) -> ProxyMetrics {
        self.metrics.clone()
    }

    pub async fn bind(&self) -> Result<TcpListener, ProxyError> {
        Ok(TcpListener::bind(self.config.proxy.listen).await?)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<(), ProxyError> {
        let (_shutdown_sender, shutdown) = watch::channel(false);
        self.serve_until(listener, shutdown).await
    }

    /// Stop accepting when `shutdown` becomes true or its sender is dropped.
    /// Existing bounded connection tasks are allowed to drain normally.
    pub async fn serve_until(
        self,
        listener: TcpListener,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<(), ProxyError> {
        let connection_limit = Arc::new(Semaphore::new(self.config.proxy.max_total_connections));
        let server = Arc::new(self);
        loop {
            if *shutdown.borrow() {
                return Ok(());
            }
            let permit = tokio::select! {
                permit = connection_limit.clone().acquire_owned() => {
                    permit.map_err(|_| ProxyError::ShuttingDown)?
                }
                changed = shutdown.changed() => {
                    let _ = changed;
                    return Ok(());
                }
            };
            let accepted = tokio::select! {
                accepted = listener.accept() => accepted,
                changed = shutdown.changed() => {
                    let _ = changed;
                    drop(permit);
                    return Ok(());
                }
            }?;
            let (stream, peer) = accepted;
            // TCP_NODELAY：MNA 这类小控制包不能被 Nagle + 延迟 ACK 拖到 ~40ms。
            // 代理是"小包转发"场景，禁用 Nagle 是标准做法（客户端侧）。
            let _ = stream.set_nodelay(true);
            server
                .metrics
                .inner
                .accepted_connections
                .fetch_add(1, Ordering::Relaxed);
            let server = server.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let _ = server.handle_client(stream, peer).await;
            });
        }
    }

    async fn handle_client(
        self: &Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<(), ProxyError> {
        let local_ip = stream.local_addr()?.ip();
        let handshake = timeout(
            Duration::from_secs(self.config.proxy.handshake_timeout_secs),
            self.negotiate_and_read_request(stream, peer),
        )
        .await
        .map_err(|_| ProxyError::HandshakeTimeout)?;
        let (protocol, connection_permit, command, target) = handshake?;
        match command {
            Socks5Command::TCPConnect => {
                self.handle_connect(protocol, peer, target, connection_permit)
                    .await
            }
            Socks5Command::UDPAssociate => {
                self.handle_udp_associate(protocol, peer, local_ip, target, connection_permit)
                    .await
            }
            _ => {
                protocol
                    .reply_error(&OpenReplyError::CommandNotSupported)
                    .await?;
                Err(ProxyError::Protocol(format!(
                    "unsupported SOCKS command {command:?}"
                )))
            }
        }
    }

    /// 免鉴权（C 方案）：**不消费字节**地看一眼客户端提供的 SOCKS5 方法列表。
    ///
    /// 只有客户端确实提供了 no-auth(0x00) 才返回 `true`。为什么不用
    /// `accept_no_auth` 去"试"：它一旦失败 socket 就已经被消耗掉了，无法回退到
    /// 密码分支。`peek` 不动接收队列，随后库自己会再读一遍同一个问候。
    ///
    /// 问候被拆成多个 TCP 段时循环等待；没有新字节时让出执行权（避免空转），
    /// 整个握手仍由 `handshake_timeout_secs` 兜底。
    async fn client_offers_no_auth(stream: &TcpStream) -> bool {
        const SOCKS5_VERSION: u8 = 0x05;
        const METHOD_NO_AUTH: u8 = 0x00;
        let mut buffer = [0_u8; 2 + 255];
        let mut previous = 0_usize;
        loop {
            let available = match stream.peek(&mut buffer).await {
                Ok(available) => available,
                Err(_) => return false,
            };
            if available == 0 {
                return false; // 对端关闭
            }
            if available >= 2 {
                if buffer[0] != SOCKS5_VERSION {
                    return false;
                }
                let method_count = usize::from(buffer[1]);
                if method_count == 0 {
                    return false;
                }
                if available >= 2 + method_count {
                    return buffer[2..2 + method_count].contains(&METHOD_NO_AUTH);
                }
            }
            if available >= buffer.len() {
                return false;
            }
            if available == previous {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            previous = available;
        }
    }

    async fn negotiate_and_read_request(
        &self,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<
        (
            OpenSocksCommand,
            ConnectionPermit,
            Socks5Command,
            TargetAddr,
        ),
        ProxyError,
    > {
        // C 方案（节点免鉴权）：打开开关后，客户端只要提供 no-auth 就免密码放行；
        // 仍然保留密码分支，所以老客户端已下发的账号密码配置不会失效。
        // 两条分支返回同一个协议状态（`accept_no_auth` 与 `accept_password_auth`
        // 都是 `finish_auth()` 之后的状态），因此这里只是分支调用。
        let anonymous =
            self.config.proxy.allow_anonymous && Self::client_offers_no_auth(&stream).await;
        let authentication = if anonymous {
            Socks5ServerProtocol::accept_no_auth(stream)
                .await
                .map(|protocol| (protocol, self.tokens.anonymous_permit()))
        } else {
            Socks5ServerProtocol::accept_password_auth(stream, |mut username, mut secret| {
                let result = self.tokens.authenticate(&username, secret.as_bytes());
                username.zeroize();
                secret.zeroize();
                result
            })
            .await
        };
        let (protocol, connection_permit) = match authentication {
            Ok(value) => value,
            Err(error) => {
                self.authentication_rejected(peer);
                return Err(error.into());
            }
        };
        let connection_permit = connection_permit.map_err(ProxyError::Token)?;
        let (protocol, command, target) = protocol.read_command().await?;
        Ok((
            protocol,
            connection_permit,
            command,
            convert_open_target(target),
        ))
    }

    fn authentication_rejected(&self, peer: SocketAddr) {
        self.metrics
            .inner
            .rejected_authentication
            .fetch_add(1, Ordering::Relaxed);
        self.events
            .emit(ProxyEvent::AuthenticationRejected { peer });
    }

    async fn handle_connect(
        &self,
        client: OpenSocksCommand,
        peer: SocketAddr,
        target: TargetAddr,
        connection_permit: ConnectionPermit,
    ) -> Result<(), ProxyError> {
        if is_mirror_target(&target) {
            return self
                .handle_mirror_ingest(client, peer, connection_permit)
                .await;
        }
        let probation_error = match self.policy.authorize(&target) {
            Ok(()) => None,
            Err(error) => {
                if self.policy.authorize_mna_probation(&target).is_err() {
                    self.reject_target(peer, Transport::Tcp, &target, &error);
                    client
                        .reply_error(&OpenReplyError::ConnectionNotAllowed)
                        .await?;
                    return Err(error.into());
                }
                Some(error)
            }
        };
        let addresses = match timeout(
            Duration::from_secs(self.config.proxy.handshake_timeout_secs),
            self.resolver.resolve(&target),
        )
        .await
        {
            Err(_) => {
                client.reply_error(&OpenReplyError::HostUnreachable).await?;
                return Err(ProxyError::HandshakeTimeout);
            }
            Ok(result) => match result {
                Ok(addresses) => addresses,
                Err(error) => {
                    self.reject_target(peer, Transport::Tcp, &target, &error);
                    client.reply_error(&OpenReplyError::HostUnreachable).await?;
                    return Err(error.into());
                }
            },
        };
        let mut upstream = match timeout(
            Duration::from_secs(self.config.proxy.handshake_timeout_secs),
            self.connector.connect(addresses.clone()),
        )
        .await
        {
            Err(_) => {
                client
                    .reply_error(&OpenReplyError::ConnectionRefused)
                    .await?;
                return Err(ProxyError::HandshakeTimeout);
            }
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                client
                    .reply_error(&OpenReplyError::ConnectionRefused)
                    .await?;
                return Err(error.into());
            }
        };
        // TCP_NODELAY（上游侧）：与客户端侧同理，避免回包被 Nagle 攒着。
        let _ = upstream.set_nodelay(true);
        let bound = upstream
            .local_addr()
            .unwrap_or_else(|_| zero_bound(peer.is_ipv4()));
        let mut client = client.reply_success(bound).await?;
        let context = ConnectContext {
            target,
            resolved: addresses,
            peer,
            flow_id: self.next_flow_id(),
            token_username: connection_permit.username().to_owned(),
            tap: self.tap.clone(),
            quota: connection_permit.meter(),
            metrics: self.metrics.clone(),
            events: self.events.clone(),
        };
        if let Some(error) = probation_error {
            let prefix = read_mna_probation_prefix(
                &mut client,
                Duration::from_secs(self.config.proxy.handshake_timeout_secs),
            )
            .await?;
            let Some(prefix) = prefix else {
                self.reject_target(peer, Transport::Tcp, &context.target, &error);
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Err(error.into());
            };
            context.observe(Direction::ClientToServer, &prefix)?;
            upstream.write_all(&prefix).await?;
        }
        self.metrics
            .inner
            .tcp_connects
            .fetch_add(1, Ordering::Relaxed);
        let flow_id = context.flow_id;
        let result = self.handler.handle(client, upstream, context).await;
        self.events
            .emit(ProxyEvent::TcpConnectionClosed { peer, flow_id });
        result
    }

    /// Accept an authenticated, parser-only copy of traffic that already
    /// reached the real game server through the Mac's residential connection.
    /// The sentinel target is intercepted before DNS/policy resolution and is
    /// never opened as an outbound socket, so mirrored bytes cannot create a
    /// second game session or a second public egress identity.
    async fn handle_mirror_ingest(
        &self,
        client: OpenSocksCommand,
        peer: SocketAddr,
        connection_permit: ConnectionPermit,
    ) -> Result<(), ProxyError> {
        let mut stream = client.reply_success(zero_bound(peer.is_ipv4())).await?;
        let meter = connection_permit.meter();
        let mut flows = HashMap::<(u8, u64), u64>::new();
        let mut header = [0_u8; MIRROR_RECORD_HEADER_LEN];

        loop {
            match stream.read_exact(&mut header).await {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }
            if header[..4] != codev_conceal::record_magic() {
                return Err(ProxyError::Protocol("invalid mirror record magic".into()));
            }
            let direction = Direction::try_from(header[4]).map_err(ProxyError::Capture)?;
            let transport = Transport::try_from(header[5]).map_err(ProxyError::Capture)?;
            let flags = header[6];
            let family = header[7];
            if flags & !MIRROR_FLAG_CLOSE != 0 {
                return Err(ProxyError::Protocol("invalid mirror record flags".into()));
            }
            let client_flow_id = u64::from_be_bytes(header[8..16].try_into().unwrap());
            let capture_ns = u64::from_be_bytes(header[16..24].try_into().unwrap());
            let remote_port = u16::from_be_bytes(header[24..26].try_into().unwrap());
            let remote_ip = match family {
                4 => IpAddr::V4(Ipv4Addr::new(
                    header[26], header[27], header[28], header[29],
                )),
                6 => {
                    let mut octets = [0_u8; 16];
                    octets.copy_from_slice(&header[26..42]);
                    IpAddr::V6(Ipv6Addr::from(octets))
                }
                _ => return Err(ProxyError::Protocol("invalid mirror address family".into())),
            };
            let payload_len = u32::from_be_bytes(header[42..46].try_into().unwrap()) as usize;
            if payload_len > MAX_MIRROR_PAYLOAD {
                return Err(ProxyError::Protocol("mirror payload exceeds limit".into()));
            }
            let key = (header[5], client_flow_id);
            if flags & MIRROR_FLAG_CLOSE != 0 {
                if payload_len != 0 || transport != Transport::Tcp {
                    return Err(ProxyError::Protocol("invalid mirror close record".into()));
                }
                if let Some(flow_id) = flows.remove(&key) {
                    self.events
                        .emit(ProxyEvent::TcpConnectionClosed { peer, flow_id });
                }
                continue;
            }

            meter.charge_bytes(payload_len)?;
            let mut payload = vec![0_u8; payload_len];
            stream.read_exact(&mut payload).await?;
            let flow_id = *flows.entry(key).or_insert_with(|| self.next_flow_id());
            let remote = SocketAddr::new(remote_ip, remote_port);
            let route = match direction {
                Direction::ClientToServer => FrameRoute {
                    source: peer,
                    destination: remote,
                },
                Direction::ServerToClient => FrameRoute {
                    source: remote,
                    destination: peer,
                },
            };
            let frame = FrameEnvelope::new_with_route(
                capture_ns,
                direction,
                transport,
                flow_id,
                FrameOrigin::MacHostAgent,
                route,
                payload,
            )?;
            self.tap.observe(&frame);
            match transport {
                Transport::Tcp => self
                    .metrics
                    .inner
                    .tcp_frames
                    .fetch_add(1, Ordering::Relaxed),
                Transport::Udp => self
                    .metrics
                    .inner
                    .udp_frames
                    .fetch_add(1, Ordering::Relaxed),
            };
        }

        for ((transport, _), flow_id) in flows {
            if transport == Transport::Tcp as u8 {
                self.events
                    .emit(ProxyEvent::TcpConnectionClosed { peer, flow_id });
            }
        }
        Ok(())
    }

    async fn handle_udp_associate(
        &self,
        control: OpenSocksCommand,
        peer: SocketAddr,
        tcp_local_ip: IpAddr,
        requested_client: TargetAddr,
        connection_permit: ConnectionPermit,
    ) -> Result<(), ProxyError> {
        // Mobile VPN/TUN clients such as Shadowrocket can place their virtual
        // interface address in UDP ASSOCIATE even though the relay observes the
        // phone's LAN address as the TCP peer. RFC 1928 permits the request to
        // describe the endpoint the client expects to use, but that endpoint is
        // not trustworthy across a VPN boundary. Only retain the requested port
        // when its address is unspecified or agrees with the authenticated TCP
        // peer; otherwise learn the concrete UDP endpoint from the first packet.
        // The receive loop still pins the source IP to `peer.ip()`, so accepting
        // a virtual address does not allow a third party to inject datagrams.
        let expected_client_port = match requested_client {
            TargetAddr::Ip(address)
                if address.ip().is_unspecified() || address.ip() == peer.ip() =>
            {
                address.port()
            }
            _ => 0,
        };
        let socket = match self.bind_udp_relay(peer.is_ipv4()).await {
            Ok(socket) => socket,
            Err(error) => {
                control.reply_error(&OpenReplyError::GeneralFailure).await?;
                return Err(error);
            }
        };
        let udp_port = socket.local_addr()?.port();
        let advertised_bound = self
            .udp_advertised_bound(tcp_local_ip, udp_port, peer.is_ipv4())
            .await?;
        let mut control = control.reply_success(advertised_bound).await?;
        self.metrics
            .inner
            .udp_associations
            .fetch_add(1, Ordering::Relaxed);
        let meter = connection_permit.meter();
        let mut client_endpoint =
            (expected_client_port != 0).then(|| SocketAddr::new(peer.ip(), expected_client_port));
        let mut remotes: HashMap<SocketAddr, UdpRemote> = HashMap::new();
        let mut resolved_cache: HashMap<TargetAddr, Vec<SocketAddr>> = HashMap::new();
        let mut udp_buffer = vec![0_u8; UDP_BUFFER];
        let mut control_buffer = [0_u8; 1];
        let idle_duration = meter.udp_idle_timeout()?;
        let idle: Sleep = tokio::time::sleep(idle_duration);
        tokio::pin!(idle);

        loop {
            tokio::select! {
                received = socket.recv_from(&mut udp_buffer) => {
                    let (count, source) = received?;
                    let is_client = match client_endpoint {
                        Some(endpoint) => source == endpoint,
                        None => source.ip() == peer.ip(),
                    };
                    let accepted = if is_client {
                        if client_endpoint.is_none() {
                            client_endpoint = Some(source);
                        }
                        self.handle_udp_from_client(
                            &socket,
                            peer,
                            client_endpoint.unwrap_or(source),
                            &udp_buffer[..count],
                            &meter,
                            &mut remotes,
                            &mut resolved_cache,
                        ).await?
                    } else if let Some(endpoint) = client_endpoint {
                        self.handle_udp_from_remote(
                            &socket,
                            peer,
                            endpoint,
                            source,
                            &udp_buffer[..count],
                            &meter,
                            &remotes,
                        ).await?
                    } else {
                        self.events.emit(ProxyEvent::UnauthorizedUdpSource { peer, source });
                        false
                    };
                    if accepted {
                        idle.as_mut().reset(tokio::time::Instant::now() + idle_duration);
                    }
                }
                control_read = control.read(&mut control_buffer) => {
                    match control_read {
                        Ok(0) => {
                            self.events.emit(ProxyEvent::UdpAssociationClosed {
                                peer,
                                reason: UdpAssociationCloseReason::ControlClosed,
                            });
                            return Ok(());
                        }
                        Ok(_) => {}
                        Err(error) => {
                            self.events.emit(ProxyEvent::UdpAssociationClosed {
                                peer,
                                reason: UdpAssociationCloseReason::ControlError,
                            });
                            return Err(error.into());
                        }
                    }
                }
                _ = &mut idle => {
                    self.events.emit(ProxyEvent::UdpIdleTimeout { peer });
                    self.events.emit(ProxyEvent::UdpAssociationClosed {
                        peer,
                        reason: UdpAssociationCloseReason::IdleTimeout,
                    });
                    return Ok(());
                }
            }
        }
    }

    async fn bind_udp_relay(&self, ipv4: bool) -> Result<UdpSocket, ProxyError> {
        let Some(range) = self.config.proxy.udp_relay_ports else {
            let socket = UdpSocket::bind(zero_bound(ipv4)).await?;
            return Ok(socket);
        };
        let port_count = u64::from(range.len());
        let first_offset = self.udp_relay_cursor.fetch_add(1, Ordering::Relaxed) % port_count;
        for attempt in 0..port_count {
            let offset = (first_offset + attempt) % port_count;
            let port = u64::from(range.start) + offset;
            let address = SocketAddr::new(
                if ipv4 {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                },
                port as u16,
            );
            match UdpSocket::bind(address).await {
                Ok(socket) => {
                    return Ok(socket);
                }
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(ProxyError::UdpRelayPortsExhausted {
            start: range.start,
            end: range.end,
        })
    }

    async fn udp_advertised_bound(
        &self,
        fallback_ip: IpAddr,
        port: u16,
        ipv4: bool,
    ) -> Result<SocketAddr, ProxyError> {
        let Some(host) = self.config.proxy.advertised_host.as_deref() else {
            return Ok(SocketAddr::new(fallback_ip, port));
        };
        let bare_host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        match bare_host.parse::<IpAddr>() {
            Ok(ip) => {
                // A mobile listener serves both the local VPN client and LAN
                // clients. Local UDP must stay on loopback even if the profile
                // advertises a LAN address for the second phone.
                let address = if fallback_ip.is_loopback() && is_local_only_ip(ip) {
                    fallback_ip
                } else {
                    ip
                };
                Ok(SocketAddr::new(address, port))
            }
            Err(_) => {
                let addresses = timeout(
                    Duration::from_secs(self.config.proxy.handshake_timeout_secs),
                    tokio::net::lookup_host((bare_host, port)),
                )
                .await
                .map_err(|_| ProxyError::HandshakeTimeout)??;
                addresses
                    .into_iter()
                    .find(|address| address.is_ipv4() == ipv4)
                    .ok_or_else(|| {
                        ProxyError::Protocol(format!(
                            "advertised host {bare_host} has no compatible address"
                        ))
                    })
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_udp_from_client(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        client_endpoint: SocketAddr,
        packet: &[u8],
        meter: &QuotaMeter,
        remotes: &mut HashMap<SocketAddr, UdpRemote>,
        resolved_cache: &mut HashMap<TargetAddr, Vec<SocketAddr>>,
    ) -> Result<bool, ProxyError> {
        let (fragment, open_target, payload) = match parse_udp_request(packet).await {
            Ok(request) => request,
            Err(error) => {
                self.events.emit(ProxyEvent::MalformedUdpPacket {
                    peer,
                    reason: error.to_string(),
                });
                return Ok(false);
            }
        };
        if fragment != 0 {
            self.metrics
                .inner
                .udp_fragments_rejected
                .fetch_add(1, Ordering::Relaxed);
            self.events
                .emit(ProxyEvent::UdpFragmentRejected { peer, fragment });
            return Ok(false);
        }
        let target = convert_open_target(open_target);
        if let Err(error) = self.policy.authorize(&target) {
            self.reject_target(peer, Transport::Udp, &target, &error);
            return Ok(false);
        }
        if self.config.block_quic && target.port() == 443 {
            self.metrics
                .inner
                .quic_blocked
                .fetch_add(1, Ordering::Relaxed);
            self.events.emit(ProxyEvent::QuicBlocked { peer, target });
            return Ok(false);
        }
        let addresses = if let Some(addresses) = resolved_cache.get(&target) {
            addresses.clone()
        } else {
            match timeout(
                Duration::from_secs(self.config.proxy.handshake_timeout_secs),
                self.resolver.resolve(&target),
            )
            .await
            {
                Err(_) => {
                    self.events.emit(ProxyEvent::TargetRejected {
                        peer,
                        transport: Transport::Udp,
                        target: target.clone(),
                        reason: "target resolution timed out".into(),
                    });
                    self.metrics
                        .inner
                        .rejected_targets
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(false);
                }
                Ok(Ok(addresses)) => addresses,
                Ok(Err(error)) => {
                    self.reject_target(peer, Transport::Udp, &target, &error);
                    return Ok(false);
                }
            }
        };
        let relay_is_ipv4 = socket.local_addr()?.is_ipv4();
        let Some(destination) = addresses
            .iter()
            .copied()
            .find(|address| address.is_ipv4() == relay_is_ipv4)
        else {
            self.events.emit(ProxyEvent::TargetRejected {
                peer,
                transport: Transport::Udp,
                target,
                reason: "target has no address compatible with the UDP relay family".into(),
            });
            return Ok(false);
        };
        if let std::collections::hash_map::Entry::Vacant(entry) = remotes.entry(destination) {
            let permit = match meter.acquire_udp_flow() {
                Ok(permit) => permit,
                Err(TokenError::UdpFlowLimit) => {
                    self.metrics
                        .inner
                        .quota_rejections
                        .fetch_add(1, Ordering::Relaxed);
                    self.events.emit(ProxyEvent::QuotaExceeded {
                        peer,
                        quota: "udp_flows",
                    });
                    return Ok(false);
                }
                Err(error) => return Err(error.into()),
            };
            entry.insert(UdpRemote {
                _permit: permit,
                flow_id: self.next_flow_id(),
                client: client_endpoint,
            });
            // Keep wildcard-host associations bounded by the token's UDP
            // flow quota; a client cannot grow an unbounded DNS cache.
            insert_bounded_resolution(
                resolved_cache,
                target,
                addresses.clone(),
                self.config.proxy.max_udp_flows_per_token as usize,
            );
        }
        let flow_id = remotes[&destination].flow_id;
        if let Err(error) = meter.charge_bytes(payload.len()) {
            self.metrics
                .inner
                .quota_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.events.emit(ProxyEvent::QuotaExceeded {
                peer,
                quota: "bandwidth",
            });
            if matches!(error, TokenError::BandwidthLimit) {
                return Ok(false);
            }
            return Err(error.into());
        }
        self.observe_udp(
            Direction::ClientToServer,
            flow_id,
            client_endpoint,
            destination,
            payload,
        )?;
        crate::netbind::prepare_udp_destination(socket, destination)?;
        socket.send_to(payload, destination).await?;
        Ok(true)
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_udp_from_remote(
        &self,
        socket: &UdpSocket,
        peer: SocketAddr,
        client: SocketAddr,
        source: SocketAddr,
        payload: &[u8],
        meter: &QuotaMeter,
        remotes: &HashMap<SocketAddr, UdpRemote>,
    ) -> Result<bool, ProxyError> {
        let Some(remote) = remotes.get(&source) else {
            self.events
                .emit(ProxyEvent::UnauthorizedUdpSource { peer, source });
            return Ok(false);
        };
        if let Err(error) = meter.charge_bytes(payload.len()) {
            self.metrics
                .inner
                .quota_rejections
                .fetch_add(1, Ordering::Relaxed);
            self.events.emit(ProxyEvent::QuotaExceeded {
                peer,
                quota: "bandwidth",
            });
            if matches!(error, TokenError::BandwidthLimit) {
                return Ok(false);
            }
            return Err(error.into());
        }
        self.observe_udp(
            Direction::ServerToClient,
            remote.flow_id,
            source,
            remote.client,
            payload,
        )?;
        let mut response = new_udp_header(source)?;
        response.extend_from_slice(payload);
        crate::netbind::prepare_udp_destination(socket, client)?;
        socket.send_to(&response, client).await?;
        Ok(true)
    }

    fn observe_udp(
        &self,
        direction: Direction,
        flow_id: u64,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
    ) -> Result<(), ProxyError> {
        let frame = FrameEnvelope::new_with_route(
            capture_time_ns(),
            direction,
            Transport::Udp,
            flow_id,
            FrameOrigin::SocksUdp,
            FrameRoute {
                source,
                destination,
            },
            payload.to_vec(),
        )?;
        self.tap.observe(&frame);
        self.metrics
            .inner
            .udp_frames
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn reject_target(
        &self,
        peer: SocketAddr,
        transport: Transport,
        target: &TargetAddr,
        error: &PolicyError,
    ) {
        self.metrics
            .inner
            .rejected_targets
            .fetch_add(1, Ordering::Relaxed);
        self.events.emit(ProxyEvent::TargetRejected {
            peer,
            transport,
            target: target.clone(),
            reason: error.to_string(),
        });
    }

    fn next_flow_id(&self) -> u64 {
        self.flow_ids.fetch_add(1, Ordering::Relaxed)
    }
}

fn is_local_only_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_unspecified() || ip.is_loopback() || ip.is_private() || ip.is_link_local()
        }
        IpAddr::V6(ip) => {
            ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
        }
    }
}

struct UdpRemote {
    _permit: UdpFlowPermit,
    flow_id: u64,
    client: SocketAddr,
}

fn zero_bound(ipv4: bool) -> SocketAddr {
    if ipv4 {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    }
}

fn capture_time_ns() -> u64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    u64::try_from(nanos).unwrap_or(u64::MAX)
}

fn is_mirror_target(target: &TargetAddr) -> bool {
    matches!(
        target,
        TargetAddr::Domain { host, port }
            if host.eq_ignore_ascii_case(codev_conceal::mirror_host()) && *port == MIRROR_TARGET_PORT
    )
}

fn convert_open_target(target: OpenTargetAddr) -> TargetAddr {
    match target {
        OpenTargetAddr::Ip(address) => TargetAddr::Ip(address),
        OpenTargetAddr::Domain(host, port) => TargetAddr::Domain {
            host: host.trim_end_matches('.').to_ascii_lowercase(),
            port,
        },
    }
}

fn insert_bounded_resolution(
    cache: &mut HashMap<TargetAddr, Vec<SocketAddr>>,
    target: TargetAddr,
    addresses: Vec<SocketAddr>,
    capacity: usize,
) {
    if capacity != 0 && cache.len() < capacity {
        cache.insert(target, addresses);
    }
}

#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("proxy I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("proxy protocol error: {0}")]
    Protocol(String),
    #[error("open-source SOCKS5 server error: {0}")]
    OpenSourceSocks(#[from] SocksServerError),
    #[error("open-source SOCKS5 UDP header error: {0}")]
    OpenSourceUdp(#[from] UdpHeaderError),
    #[error("target policy error: {0}")]
    Policy(#[from] PolicyError),
    #[error("token error: {0}")]
    Token(#[from] TokenError),
    #[error("capture error: {0}")]
    Capture(#[from] codev_capture::CaptureError),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("unsupported SOCKS command {0}")]
    UnsupportedCommand(u8),
    #[error("SOCKS handshake timed out")]
    HandshakeTimeout,
    #[error("proxy is shutting down")]
    ShuttingDown,
    #[error("all configured UDP relay ports {start}-{end} are in use")]
    UdpRelayPortsExhausted { start: u16, end: u16 },
}

#[cfg(test)]
mod tests {

    #[test]
    fn stale_physical_binding_requests_an_unbound_retry() {
        assert!(should_retry_unbound(TcpPreparation::Bound, true));
        assert!(!should_retry_unbound(TcpPreparation::Unbound, true));
        assert!(!should_retry_unbound(TcpPreparation::Bound, false));
    }

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
    use std::time::Duration;

    use super::*;
    use crate::{ProxyConfig, TokenLimits, UdpRelayPortRange};

    const COMMAND_CONNECT: u8 = fast_socks5::consts::SOCKS5_CMD_TCP_CONNECT;
    const COMMAND_UDP_ASSOCIATE: u8 = fast_socks5::consts::SOCKS5_CMD_UDP_ASSOCIATE;
    const REPLY_SUCCEEDED: u8 = fast_socks5::consts::SOCKS5_REPLY_SUCCEEDED;
    const REPLY_GENERAL_FAILURE: u8 = fast_socks5::consts::SOCKS5_REPLY_GENERAL_FAILURE;

    #[derive(Clone)]
    struct RecordingTap(Arc<Mutex<Vec<FrameEnvelope>>>);

    impl FrameTap for RecordingTap {
        fn observe(&mut self, frame: &FrameEnvelope) {
            self.0.lock().unwrap().push(frame.clone());
        }
    }

    struct SlowTap {
        observed: Arc<AtomicU64>,
    }

    impl FrameTap for SlowTap {
        fn observe(&mut self, _frame: &FrameEnvelope) {
            std::thread::sleep(Duration::from_millis(20));
            self.observed.fetch_add(1, AtomicOrdering::Relaxed);
        }
    }

    /// 验证"有期限就按期限醒来、没期限就空闲低频"的 tap。
    struct DeadlineTap {
        active: Arc<AtomicBool>,
        polls: Arc<Mutex<Vec<u64>>>,
    }

    impl FrameTap for DeadlineTap {
        fn observe(&mut self, _frame: &FrameEnvelope) {}

        fn next_deadline_ns(&self) -> Option<u64> {
            if self.active.load(AtomicOrdering::Relaxed) {
                Some(capture_time_ns() + 10_000_000) // 保持原来的 ~10ms 节奏
            } else {
                None // 没有待释放状态 → 允许空闲等待
            }
        }

        fn poll(&mut self, now_ns: u64) {
            self.polls.lock().unwrap().push(now_ns);
        }
    }

    #[test]
    fn frame_parser_wakes_on_the_deadline_and_idles_when_there_is_none() {
        // 改动前：worker 无条件 10ms 轮询（100Hz），空闲槽位也一直醒 —— 就是那个 3.7% 空转。
        // 改动后：有期限才按期限醒；没期限就 250ms 一次（1 秒 4 次）。
        let active = Arc::new(AtomicBool::new(true));
        let polls = Arc::new(Mutex::new(Vec::new()));
        let tap = TapHandle::new(DeadlineTap {
            active: Arc::clone(&active),
            polls: Arc::clone(&polls),
        });

        std::thread::sleep(Duration::from_millis(250));
        let active_polls = polls.lock().unwrap().len();
        assert!(
            active_polls >= 15,
            "有期限时应保持 ~10ms 节奏（实测 250ms 内 {active_polls} 次）"
        );

        active.store(false, AtomicOrdering::Relaxed);
        std::thread::sleep(Duration::from_millis(600)); // 排掉上一次定时唤醒的遗留
        let before = polls.lock().unwrap().len();
        std::thread::sleep(Duration::from_millis(250));
        let idle_polls = polls.lock().unwrap().len() - before;
        assert!(
            idle_polls <= 2,
            "空闲时不应再 100Hz 空转（实测 250ms 内 {idle_polls} 次）"
        );
    }

    #[test]
    fn frame_tap_default_deadline_keeps_legacy_polling() {
        // 默认实现返回 Some(0)：没实现新接口的 tap 行为保持与改动前一致（仍短周期轮询）。
        struct LegacyTap;
        impl FrameTap for LegacyTap {
            fn observe(&mut self, _frame: &FrameEnvelope) {}
        }
        assert_eq!(LegacyTap.next_deadline_ns(), Some(0));
        assert_eq!(NoopFrameTap.next_deadline_ns(), None);
    }

    #[test]
    fn tcp_relay_sets_nodelay_on_both_sides() {
        // MNA 小控制包不能被 Nagle + 延迟 ACK 拖到 ~40ms。
        assert!(INDEX_SERVER_SRC.contains("stream.set_nodelay(true)"));
        assert!(INDEX_SERVER_SRC.contains("upstream.set_nodelay(true)"));
    }

    #[test]
    fn tap_enqueue_never_waits_for_a_slow_parser_and_reports_drop_epoch() {
        let observed = Arc::new(AtomicU64::new(0));
        let tap = TapHandle::new(SlowTap {
            observed: Arc::clone(&observed),
        });
        let frame = FrameEnvelope::new(
            capture_time_ns(),
            Direction::ClientToServer,
            Transport::Udp,
            1,
            FrameOrigin::SocksUdp,
            vec![0_u8; 64],
        )
        .unwrap();
        let started = std::time::Instant::now();
        for _ in 0..2_048 {
            tap.observe(&frame);
        }
        assert!(started.elapsed() < Duration::from_millis(250));
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while (tap.metrics().dropped_frames == 0 || observed.load(AtomicOrdering::Relaxed) == 0)
            && std::time::Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(tap.metrics().dropped_frames > 0);
        assert!(tap.metrics().drop_epoch > 0);
        assert!(observed.load(AtomicOrdering::Relaxed) > 0);
    }

    struct RecordingEvents(Arc<Mutex<Vec<ProxyEvent>>>);

    impl ProxyEventSink for RecordingEvents {
        fn emit(&self, event: ProxyEvent) {
            self.0.lock().unwrap().push(event);
        }
    }

    struct TestResolver(SocketAddr);

    impl TargetResolver for TestResolver {
        fn resolve<'a>(
            &'a self,
            _target: &'a TargetAddr,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, PolicyError>> + Send + 'a>>
        {
            Box::pin(async move { Ok(vec![self.0]) })
        }
    }

    fn test_config(port: u16, block_quic: bool) -> RuntimeProxyConfig {
        RuntimeProxyConfig {
            proxy: ProxyConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                token_ttl_secs: 60,
                udp_idle_secs: 2,
                handshake_timeout_secs: 2,
                max_total_connections: 8,
                max_connections_per_token: 4,
                max_udp_flows_per_token: 4,
                bytes_per_second_per_token: 1024 * 1024,
                allow_hosts: vec!["game.example.com".into()],
                allow_ports: vec![port],
                ..ProxyConfig::default()
            },
            block_quic,
        }
    }

    fn token(tokens: &TokenStore) -> crate::TokenCredential {
        tokens
            .create_token(
                Some("phone"),
                60,
                TokenLimits {
                    max_connections: 4,
                    max_udp_flows: 4,
                    bytes_per_second: 1024 * 1024,
                    udp_idle_secs: 2,
                },
            )
            .unwrap()
    }

    async fn authenticate(client: &mut TcpStream, credential: &crate::TokenCredential) {
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0_u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        let mut auth = vec![1, credential.username.len() as u8];
        auth.extend_from_slice(credential.username.as_bytes());
        auth.push(credential.secret.len() as u8);
        auth.extend_from_slice(credential.secret.as_bytes());
        client.write_all(&auth).await.unwrap();
        let mut result = [0_u8; 2];
        client.read_exact(&mut result).await.unwrap();
        assert_eq!(result, [1, 0]);
    }

    async fn read_reply_target(client: &mut TcpStream) -> (u8, TargetAddr) {
        let mut header = [0_u8; 4];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 5);
        assert_eq!(header[2], 0);
        let target = match header[3] {
            fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV4 => {
                let mut bytes = [0_u8; 6];
                client.read_exact(&mut bytes).await.unwrap();
                TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                    u16::from_be_bytes([bytes[4], bytes[5]]),
                ))
            }
            fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV6 => {
                let mut bytes = [0_u8; 18];
                client.read_exact(&mut bytes).await.unwrap();
                let mut ip = [0_u8; 16];
                ip.copy_from_slice(&bytes[..16]);
                TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(ip)),
                    u16::from_be_bytes([bytes[16], bytes[17]]),
                ))
            }
            fast_socks5::consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME => {
                let mut length = [0_u8; 1];
                client.read_exact(&mut length).await.unwrap();
                let mut host = vec![0_u8; usize::from(length[0])];
                client.read_exact(&mut host).await.unwrap();
                let mut port = [0_u8; 2];
                client.read_exact(&mut port).await.unwrap();
                TargetAddr::Domain {
                    host: String::from_utf8(host).unwrap(),
                    port: u16::from_be_bytes(port),
                }
            }
            atyp => panic!("unsupported reply address type {atyp}"),
        };
        (header[1], target)
    }

    async fn read_reply(client: &mut TcpStream) -> SocketAddr {
        let (reply, target) = read_reply_target(client).await;
        assert_eq!(reply, REPLY_SUCCEEDED);
        match target {
            TargetAddr::Ip(address) => address,
            TargetAddr::Domain { host, port } => {
                panic!("unexpected domain reply {host}:{port}")
            }
        }
    }

    fn available_udp_range(width: u16) -> UdpRelayPortRange {
        static NEXT_TEST_RANGE: AtomicU64 = AtomicU64::new(30_000);
        assert!(width != 0);
        let segment_start = NEXT_TEST_RANGE.fetch_add(512, Ordering::Relaxed) as u16;
        let segment_end = segment_start.saturating_add(500).min(60_000);
        for start in (segment_start..segment_end - width).step_by(17) {
            let mut sockets = Vec::with_capacity(usize::from(width));
            let mut available = true;
            for port in start..start + width {
                match std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)) {
                    Ok(socket) => sockets.push(socket),
                    Err(_) => {
                        available = false;
                        break;
                    }
                }
            }
            if available {
                drop(sockets);
                return UdpRelayPortRange {
                    start,
                    end: start + width - 1,
                };
            }
        }
        panic!("could not find {width} consecutive UDP test ports");
    }

    fn domain_request(command: u8, port: u16) -> Vec<u8> {
        let host = b"game.example.com";
        let mut request = vec![5, command, 0, 3, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    fn ipv4_request(command: u8, address: SocketAddr) -> Vec<u8> {
        let IpAddr::V4(ip) = address.ip() else {
            panic!("test request requires IPv4");
        };
        let mut request = vec![5, command, 0, fast_socks5::consts::SOCKS5_ADDR_TYPE_IPV4];
        request.extend_from_slice(&ip.octets());
        request.extend_from_slice(&address.port().to_be_bytes());
        request
    }

    /// C 方案：免鉴权握手 —— 客户端只提供 no-auth(0x00)，不带任何凭据。
    async fn handshake_no_auth(client: &mut TcpStream) {
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0_u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
    }

    /// 老客户端：问候里**只有** password(0x02)，没有 no-auth。
    async fn authenticate_password_only(
        client: &mut TcpStream,
        credential: &crate::TokenCredential,
    ) {
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0_u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        let mut auth = vec![1, credential.username.len() as u8];
        auth.extend_from_slice(credential.username.as_bytes());
        auth.push(credential.secret.len() as u8);
        auth.extend_from_slice(credential.secret.as_bytes());
        client.write_all(&auth).await.unwrap();
        let mut result = [0_u8; 2];
        client.read_exact(&mut result).await.unwrap();
        assert_eq!(result, [1, 0]);
    }

    async fn echo_upstream() -> SocketAddr {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let count = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..count]).await.unwrap();
        });
        upstream_addr
    }

    fn anonymous_test_config(port: u16) -> RuntimeProxyConfig {
        let mut config = test_config(port, false);
        config.proxy.allow_anonymous = true;
        config
    }

    #[tokio::test]
    async fn anonymous_client_connects_without_credentials_and_is_metered() {
        let upstream_addr = echo_upstream().await;
        let tokens = TokenStore::new();
        let limits = test_config(0, false).proxy.token_limits();
        assert!(tokens.ensure_anonymous_token(60, limits).unwrap());
        // 客户端只提供 no-auth(0x00)，完全没有凭据。
        let server = Socks5Server::new(anonymous_test_config(upstream_addr.port()), tokens.clone())
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        handshake_no_auth(&mut client).await;
        client
            .write_all(&domain_request(COMMAND_CONNECT, upstream_addr.port()))
            .await
            .unwrap();
        read_reply(&mut client).await;
        client.write_all(b"position").await.unwrap();
        let mut echoed = [0_u8; 8];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"position");
        // 匿名连接确实计入了内置匿名令牌（不是"免鉴权 = 免限流"）。
        let active = |tokens: &TokenStore| {
            tokens
                .list()
                .into_iter()
                .find(|status| status.username == crate::ANONYMOUS_USERNAME)
                .expect("anonymous token must exist")
                .active_connections
        };
        assert_eq!(active(&tokens), 1, "anonymous connection must be counted");
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(active(&tokens), 0, "permit must be released");
        task.abort();
    }

    #[tokio::test]
    async fn password_only_client_authenticates_when_anonymous_is_enabled() {
        let upstream_addr = echo_upstream().await;
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        tokens
            .ensure_anonymous_token(60, test_config(0, false).proxy.token_limits())
            .unwrap();
        let server = Socks5Server::new(anonymous_test_config(upstream_addr.port()), tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate_password_only(&mut client, &credential).await;
        client
            .write_all(&domain_request(COMMAND_CONNECT, upstream_addr.port()))
            .await
            .unwrap();
        read_reply(&mut client).await;
        client.write_all(b"position").await.unwrap();
        let mut echoed = [0_u8; 8];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"position");
        task.abort();
    }

    #[tokio::test]
    async fn anonymous_flag_off_keeps_rejecting_no_auth_clients() {
        let tokens = TokenStore::new();
        let _credential = token(&tokens);
        let server = Socks5Server::new(test_config(443, false), tokens).unwrap();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0_u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0xff], "no-auth must be refused when disabled");
        task.abort();
    }

    #[tokio::test]
    async fn anonymous_without_the_builtin_token_is_refused() {
        // 开关打开但令牌库没有匿名令牌：必须拒绝，而不是放行一条无计量的连接。
        let tokens = TokenStore::new();
        let _credential = token(&tokens);
        let server = Socks5Server::new(anonymous_test_config(443), tokens).unwrap();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        handshake_no_auth(&mut client).await;
        client
            .write_all(&domain_request(COMMAND_CONNECT, 443))
            .await
            .unwrap();
        let mut header = [0_u8; 4];
        if client.read_exact(&mut header).await.is_ok() {
            assert_ne!(header[1], 0, "must not report success");
        }
        task.abort();
    }

    #[tokio::test]
    async fn tcp_connect_relays_and_taps_both_directions() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let count = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..count]).await.unwrap();
        });

        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let frames = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Socks5Server::new(test_config(upstream_addr.port(), false), tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)))
            .with_frame_tap(TapHandle::new(RecordingTap(frames.clone())))
            .with_event_sink(Arc::new(RecordingEvents(events.clone())));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut client, &credential).await;
        client
            .write_all(&domain_request(COMMAND_CONNECT, upstream_addr.port()))
            .await
            .unwrap();
        read_reply(&mut client).await;
        client.write_all(b"position").await.unwrap();
        let mut echoed = [0_u8; 8];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"position");
        drop(client);

        tokio::time::sleep(Duration::from_millis(50)).await;
        let frames = frames.lock().unwrap();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].direction, Direction::ClientToServer);
        assert_eq!(frames[1].direction, Direction::ServerToClient);
        assert_eq!(frames[0].flow_id, frames[1].flow_id);
        let flow_id = frames[0].flow_id;
        assert!(events.lock().unwrap().iter().any(|event| matches!(
            event,
            ProxyEvent::TcpConnectionClosed {
                flow_id: observed,
                ..
            } if *observed == flow_id
        )));
        task.abort();
    }

    #[tokio::test]
    async fn rotated_public_mna_target_is_relayed_only_after_magic_proof() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let payload = [MNA_CONTROL_MAGIC.as_slice(), b"session"].concat();
        let expected = payload.clone();
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut received = vec![0_u8; expected.len()];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(received, expected);
            stream.write_all(&received).await.unwrap();
        });

        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let server = Socks5Server::new(test_config(upstream_addr.port(), false), tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut client, &credential).await;
        let rotated_target: SocketAddr =
            format!("8.8.8.8:{}", upstream_addr.port()).parse().unwrap();
        client
            .write_all(&ipv4_request(COMMAND_CONNECT, rotated_target))
            .await
            .unwrap();
        read_reply(&mut client).await;
        client.write_all(&payload).await.unwrap();
        let mut echoed = vec![0_u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);
        task.abort();
    }

    #[tokio::test]
    async fn udp_associate_relays_and_taps_both_directions() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            let (count, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            upstream.send_to(&buffer[..count], peer).await.unwrap();
            upstream.send_to(&buffer[..count], peer).await.unwrap();
        });

        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let frames = Arc::new(Mutex::new(Vec::new()));
        let relay_range = available_udp_range(4);
        let mut config = test_config(upstream_addr.port(), false);
        config.proxy.udp_relay_ports = Some(relay_range);
        let server = Socks5Server::new(config, tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)))
            .with_frame_tap(TapHandle::new(RecordingTap(frames.clone())));
        let metrics = server.metrics();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut control, &credential).await;
        control
            .write_all(&[5, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let relay_addr = read_reply(&mut control).await;
        assert!((relay_range.start..=relay_range.end).contains(&relay_addr.port()));
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&domain_request(0, upstream_addr.port())[3..]);
        packet.extend_from_slice(b"udp-position");
        client_udp.send_to(&packet, relay_addr).await.unwrap();
        // Identical datagrams are valid UDP traffic and must be forwarded
        // transparently; SOCKS has no sequence semantics at this layer.
        client_udp.send_to(&packet, relay_addr).await.unwrap();
        let mut response = [0_u8; 128];
        let (count, _) = timeout(Duration::from_secs(1), client_udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, _, payload) = parse_udp_request(&response[..count]).await.unwrap();
        assert_eq!(payload, b"udp-position");
        let (count, _) = timeout(Duration::from_secs(1), client_udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, _, payload) = parse_udp_request(&response[..count]).await.unwrap();
        assert_eq!(payload, b"udp-position");
        tokio::time::sleep(Duration::from_millis(20)).await;
        let frames = frames.lock().unwrap();
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].transport, Transport::Udp);
        assert_eq!(frames[0].direction, Direction::ClientToServer);
        assert_eq!(frames[1].direction, Direction::ClientToServer);
        assert_eq!(frames[2].direction, Direction::ServerToClient);
        assert_eq!(frames[3].direction, Direction::ServerToClient);
        assert_eq!(frames[0].flow_id, frames[2].flow_id);
        assert_eq!(frames[1].flow_id, frames[3].flow_id);
        assert_eq!(metrics.snapshot().udp_duplicates_observed, 0);
        task.abort();
    }

    #[tokio::test]
    async fn udp_associate_accepts_tun_virtual_address_and_learns_real_peer_endpoint() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            let (count, peer) = upstream.recv_from(&mut buffer).await.unwrap();
            upstream.send_to(&buffer[..count], peer).await.unwrap();
        });

        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let server = Socks5Server::new(test_config(upstream_addr.port(), false), tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(upstream_addr)));
        let metrics = server.metrics();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut control, &credential).await;
        let tun_client: SocketAddr = "198.18.0.1:5353".parse().unwrap();
        control
            .write_all(&ipv4_request(COMMAND_UDP_ASSOCIATE, tun_client))
            .await
            .unwrap();
        let relay_addr = read_reply(&mut control).await;

        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&domain_request(0, upstream_addr.port())[3..]);
        packet.extend_from_slice(b"shadowrocket-tun");
        client_udp.send_to(&packet, relay_addr).await.unwrap();

        let mut response = [0_u8; 128];
        let (count, _) = timeout(Duration::from_secs(1), client_udp.recv_from(&mut response))
            .await
            .unwrap()
            .unwrap();
        let (_, _, payload) = parse_udp_request(&response[..count]).await.unwrap();
        assert_eq!(payload, b"shadowrocket-tun");
        assert_eq!(metrics.snapshot().udp_associations, 1);
        assert_eq!(metrics.snapshot().udp_frames, 2);
        task.abort();
    }

    #[tokio::test]
    async fn fixed_udp_pool_never_reuses_an_active_port_and_reports_exhaustion() {
        let relay_range = available_udp_range(2);
        let tokens = TokenStore::new();
        let mut config = test_config(443, false);
        config.proxy.udp_relay_ports = Some(relay_range);
        let server = Socks5Server::new(config, tokens).unwrap();

        let (first, second) =
            tokio::join!(server.bind_udp_relay(true), server.bind_udp_relay(true));
        let first = first.unwrap();
        let second = second.unwrap();
        let first_port = first.local_addr().unwrap().port();
        let second_port = second.local_addr().unwrap().port();
        assert_ne!(first_port, second_port);
        assert!((relay_range.start..=relay_range.end).contains(&first_port));
        assert!((relay_range.start..=relay_range.end).contains(&second_port));
        assert!(matches!(
            server.bind_udp_relay(true).await,
            Err(ProxyError::UdpRelayPortsExhausted { start, end })
                if start == relay_range.start && end == relay_range.end
        ));

        drop(first);
        let reused = server.bind_udp_relay(true).await.unwrap();
        assert_eq!(reused.local_addr().unwrap().port(), first_port);
    }

    #[tokio::test]
    async fn loopback_udp_client_receives_loopback_relay_not_the_lan_advertisement() {
        let mut config = test_config(443, false);
        config.proxy.advertised_host = Some("192.168.1.2".into());
        let server = Socks5Server::new(config, TokenStore::new()).unwrap();
        let bound = server
            .udp_advertised_bound("127.0.0.1".parse().unwrap(), 22000, true)
            .await
            .unwrap();
        assert_eq!(bound, "127.0.0.1:22000".parse().unwrap());
        let lan_bound = server
            .udp_advertised_bound("192.168.1.2".parse().unwrap(), 22000, true)
            .await
            .unwrap();
        assert_eq!(lan_bound, "192.168.1.2:22000".parse().unwrap());
    }

    #[tokio::test]
    async fn udp_associate_advertises_configured_public_host_and_relay_port() {
        let relay_range = available_udp_range(1);
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let mut config = test_config(443, false);
        config.proxy.udp_relay_ports = Some(relay_range);
        config.proxy.advertised_host = Some("203.0.113.10".into());
        // `advertised_port` belongs to the TCP profile endpoint. A UDP
        // ASSOCIATE reply must advertise the selected relay-pool port instead.
        config.proxy.advertised_port = Some(1080);
        let server = Socks5Server::new(config, tokens).unwrap();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut control, &credential).await;
        control
            .write_all(&[5, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (reply, bound) = read_reply_target(&mut control).await;
        assert_eq!(reply, REPLY_SUCCEEDED);
        assert_eq!(
            bound,
            TargetAddr::Ip(SocketAddr::new(
                "203.0.113.10".parse().unwrap(),
                relay_range.start,
            ))
        );
        task.abort();
    }

    #[tokio::test]
    async fn exhausted_udp_pool_returns_a_socks_failure() {
        let relay_range = available_udp_range(1);
        let blocker =
            std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, relay_range.start)).unwrap();
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let mut config = test_config(443, false);
        config.proxy.udp_relay_ports = Some(relay_range);
        let server = Socks5Server::new(config, tokens).unwrap();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut control, &credential).await;
        control
            .write_all(&[5, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let (reply, bound) = read_reply_target(&mut control).await;
        assert_eq!(reply, REPLY_GENERAL_FAILURE);
        assert_eq!(bound, TargetAddr::Ip("0.0.0.0:0".parse().unwrap()));

        drop(blocker);
        task.abort();
    }

    #[tokio::test]
    async fn quic_is_blocked_with_an_explicit_event() {
        let unused: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Socks5Server::new(test_config(443, true), tokens)
            .unwrap()
            .with_target_resolver(Arc::new(TestResolver(unused)))
            .with_event_sink(Arc::new(RecordingEvents(events.clone())));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut control = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut control, &credential).await;
        control
            .write_all(&[5, COMMAND_UDP_ASSOCIATE, 0, 1, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let relay_addr = read_reply(&mut control).await;
        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut packet = vec![0, 0, 0];
        packet.extend_from_slice(&domain_request(0, 443)[3..]);
        packet.extend_from_slice(b"quic");
        client_udp.send_to(&packet, relay_addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, ProxyEvent::QuicBlocked { .. }))
        );
        task.abort();
    }

    #[tokio::test]
    async fn authenticated_mirror_ingest_taps_frames_without_opening_target() {
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let events = Arc::new(Mutex::new(Vec::new()));
        let server = Socks5Server::new(test_config(443, false), tokens)
            .unwrap()
            .with_frame_tap(TapHandle::new(RecordingTap(observed.clone())))
            .with_event_sink(Arc::new(RecordingEvents(events.clone())));
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let task = tokio::spawn(server.serve(listener));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        authenticate(&mut client, &credential).await;
        let mut request = vec![
            5,
            COMMAND_CONNECT,
            0,
            fast_socks5::consts::SOCKS5_ADDR_TYPE_DOMAIN_NAME,
            codev_conceal::mirror_host().len() as u8,
        ];
        request.extend_from_slice(codev_conceal::mirror_host().as_bytes());
        request.extend_from_slice(&MIRROR_TARGET_PORT.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let _ = read_reply(&mut client).await;

        async fn send_record(
            client: &mut TcpStream,
            direction: Direction,
            transport: Transport,
            flags: u8,
            flow_id: u64,
            remote: SocketAddr,
            payload: &[u8],
        ) {
            let mut header = Vec::with_capacity(MIRROR_RECORD_HEADER_LEN);
            header.extend_from_slice(&codev_conceal::record_magic());
            header.extend_from_slice(&[
                direction as u8,
                transport as u8,
                flags,
                if remote.is_ipv4() { 4 } else { 6 },
            ]);
            header.extend_from_slice(&flow_id.to_be_bytes());
            header.extend_from_slice(&capture_time_ns().to_be_bytes());
            header.extend_from_slice(&remote.port().to_be_bytes());
            match remote.ip() {
                IpAddr::V4(ip) => {
                    header.extend_from_slice(&ip.octets());
                    header.extend_from_slice(&[0_u8; 12]);
                }
                IpAddr::V6(ip) => header.extend_from_slice(&ip.octets()),
            }
            header.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            assert_eq!(header.len(), MIRROR_RECORD_HEADER_LEN);
            client.write_all(&header).await.unwrap();
            client.write_all(payload).await.unwrap();
        }

        let tcp_remote: SocketAddr = "203.0.113.20:17500".parse().unwrap();
        let udp_remote: SocketAddr = "203.0.113.21:18680".parse().unwrap();
        send_record(
            &mut client,
            Direction::ClientToServer,
            Transport::Tcp,
            0,
            7,
            tcp_remote,
            &MNA_CONTROL_MAGIC,
        )
        .await;
        send_record(
            &mut client,
            Direction::ServerToClient,
            Transport::Udp,
            0,
            8,
            udp_remote,
            b"position",
        )
        .await;
        send_record(
            &mut client,
            Direction::ClientToServer,
            Transport::Tcp,
            MIRROR_FLAG_CLOSE,
            7,
            tcp_remote,
            &[],
        )
        .await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while observed.lock().unwrap().len() < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let frames = observed.lock().unwrap().clone();
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].source, FrameOrigin::MacHostAgent);
        assert_eq!(frames[0].direction, Direction::ClientToServer);
        assert_eq!(frames[0].transport, Transport::Tcp);
        assert_eq!(frames[0].payload, MNA_CONTROL_MAGIC);
        assert_eq!(frames[0].route.unwrap().destination, tcp_remote);
        assert_eq!(frames[1].source, FrameOrigin::MacHostAgent);
        assert_eq!(frames[1].direction, Direction::ServerToClient);
        assert_eq!(frames[1].transport, Transport::Udp);
        assert_eq!(frames[1].payload, b"position");
        assert_eq!(frames[1].route.unwrap().source, udp_remote);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        while !events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, ProxyEvent::TcpConnectionClosed { .. }))
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            events
                .lock()
                .unwrap()
                .iter()
                .any(|event| matches!(event, ProxyEvent::TcpConnectionClosed { .. }))
        );
        task.abort();
    }

    #[tokio::test]
    async fn rfc1929_rejects_wrong_secret_without_accepting_a_command() {
        let tokens = TokenStore::new();
        let credential = token(&tokens);
        let server = Socks5Server::new(test_config(443, false), tokens).unwrap();
        let listener = server.bind().await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let metrics = server.metrics();
        let task = tokio::spawn(server.serve(listener));
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0_u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        let mut auth = vec![1, credential.username.len() as u8];
        auth.extend_from_slice(credential.username.as_bytes());
        auth.push(5);
        auth.extend_from_slice(b"wrong");
        client.write_all(&auth).await.unwrap();
        let mut rejected = [0_u8; 2];
        client.read_exact(&mut rejected).await.unwrap();
        assert_eq!(rejected[0], 1);
        assert_ne!(rejected[1], 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(metrics.snapshot().rejected_authentication, 1);
        task.abort();
    }

    #[test]
    fn resolution_cache_is_bounded_before_new_flow_admission() {
        let mut cache = HashMap::new();
        for index in 0..64_u16 {
            insert_bounded_resolution(
                &mut cache,
                TargetAddr::Domain {
                    host: format!("{index}.game.example.com"),
                    port: 10000,
                },
                vec!["8.8.8.8:10000".parse().unwrap()],
                4,
            );
        }
        assert_eq!(cache.len(), 4);
        insert_bounded_resolution(
            &mut cache,
            TargetAddr::Domain {
                host: "new.game.example.com".into(),
                port: 10000,
            },
            vec!["8.8.8.8:10000".parse().unwrap()],
            0,
        );
        assert_eq!(cache.len(), 4);
    }
}
