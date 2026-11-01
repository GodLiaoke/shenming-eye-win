use std::collections::{BTreeMap, HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use codev_assets::MapCatalog;
use codev_capture::{Direction, FrameEnvelope, FrameTap, Transport};
use codev_https::{
    MitmAuthority, MitmPolicy, PlaintextRecorder, PlaintextSink, ProxyMitmHandler, RecordingLimits,
    SessionExtractionSink, TlsMitmRelay,
};
use codev_proxy::{
    DynamicTargetStore, MitmRoutingConfig, ProfileStore, ProxyConfig, ProxyError, ProxyEvent,
    ProxyEventSink, RuntimeProxyConfig, Socks5Server, TapHandle, TokenStore, ensure_public_ip,
};
use codev_session::{AcceptDisposition, SessionBroker, SessionId, SessionMaterial};
use codev_stream::{
    ENTER_GAME_NOTIFY_COMMAND, Endpoint, EnterGameSession, IpAddress, MNA_DATA, MNA_MAGIC,
    MNA_SERVER_HELLO, P0Pipeline, PipelineGap, PipelineStats, REENTER_GAME_NOTIFY_COMMAND,
    TransportKind, W0Framer, decrypt_mna_frame, parse_enter_game_session, parse_mna_application,
    recover_embedded_enter_game_session_with_evidence, recover_mna_session_key,
    strip_mna_random_padding,
};
use codev_web::{
    CaPanelService, ComponentStatus, EventHub, MetricsPayload, OperationalState, PanelServices,
    PipelineHealth, ProxyPanelService, ProxyPipelineMetrics, SessionStatus, SessionView,
};
use rand::RngCore;
use serde::Deserialize;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};
use zeroize::Zeroizing;

use super::{SUPPORTED_BUILD, actor_positions};
use crate::proxy_pcap::{ProxyPcapConfig, ProxyPcapRecorder};

const MAX_CONFIG_BYTES: u64 = 512 * 1024;
const MAX_SECRET_BYTES: u64 = 512;
const PANEL_SECRET_PREFIX: &str = "codev-panel-v1";
const PROXY_EVENT_QUEUE: usize = 256;
const PROXY_ACTOR_QUEUE: usize = 256;
const MAX_PROXY_MNA_FLOWS: usize = 512;
const MAX_MNA_COMMAND_IDS: usize = 128;
const TCP_CLOSE_STATE_GRACE_NS: u64 = 1_000_000_000;
const TOKEN_RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const UDP_CANDIDATE_MAX_DATAGRAMS: u64 = 64;
const UDP_CANDIDATE_MAX_AGE_NS: u64 = 2_000_000_000;
const MAX_UDP_CANDIDATE_FLOWS: usize = 64;

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct PanelConfig {
    pub listen: SocketAddr,
    pub token_file: Option<PathBuf>,
    pub token_ttl_secs: u64,
    pub public_base_url: Option<String>,
    pub profile_store: Option<PathBuf>,
    pub staging: bool,
    /// 局域网共享：允许面板接受私网地址的 Host（A 起引擎，B/C 用局域网地址访问）。
    /// 默认关闭，仅本地引擎配置显式打开；公网/网关部署必须保持关闭。
    #[serde(default)]
    pub allow_lan_hosts: bool,
    /// 异地观看写入端（`/api/v1/mirror/positions`）的房间令牌自校验：
    /// 网关 env 文件（读 `BATTLE_COOKIE_KEY`）。
    /// **两项都配置**才生效；只配置其中一项 = 不生效（路由保持原鉴权）。
    #[serde(default)]
    pub room_access_key_file: Option<PathBuf>,
    /// 异地观看写入端：网关 `rooms.json`（读活跃房间号）。
    #[serde(default)]
    pub room_access_state_file: Option<PathBuf>,
}

impl Default for PanelConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:3000"
                .parse()
                .expect("valid default panel address"),
            token_file: None,
            token_ttl_secs: 3600,
            public_base_url: None,
            profile_store: None,
            staging: false,
            allow_lan_hosts: false,
            room_access_key_file: None,
            room_access_state_file: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct RecordConfig {
    pub directory: PathBuf,
    pub plaintext: bool,
    pub proxy_pcap: bool,
    pub max_bytes: u64,
    pub max_duration_secs: u64,
    pub max_files: usize,
}

impl Default for RecordConfig {
    fn default() -> Self {
        Self {
            directory: PathBuf::from("record"),
            plaintext: false,
            proxy_pcap: false,
            max_bytes: 512 * 1024 * 1024,
            max_duration_secs: 30 * 60,
            max_files: 5,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct ProxyAppConfig {
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub mitm: MitmRoutingConfig,
    #[serde(default)]
    pub panel: PanelConfig,
    #[serde(default)]
    pub record: RecordConfig,
}

impl ProxyAppConfig {
    pub fn load(path: &Path) -> Result<Self, ProxyRuntimeError> {
        let metadata = path.symlink_metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(ProxyRuntimeError::InvalidConfig(
                "config must be a regular file under the size limit".into(),
            ));
        }
        let text = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&text)?;
        config
            .proxy
            .validate()
            .map_err(ProxyRuntimeError::ProxyConfig)?;
        if config.panel.token_ttl_secs == 0 {
            return Err(ProxyRuntimeError::InvalidConfig(
                "panel.token_ttl_secs must be non-zero".into(),
            ));
        }
        if config
            .panel
            .public_base_url
            .as_deref()
            .is_some_and(|value| {
                value.is_empty()
                    || value.chars().any(char::is_control)
                    || !value.starts_with("http://") && !value.starts_with("https://")
            })
        {
            return Err(ProxyRuntimeError::InvalidConfig(
                "panel.public_base_url must be an absolute http(s) URL".into(),
            ));
        }
        if let Some(base_url) = config.panel.public_base_url.as_deref() {
            let (scheme, host) = parse_public_base_url(base_url).ok_or_else(|| {
                ProxyRuntimeError::InvalidConfig(
                    "panel.public_base_url must contain a valid host authority".into(),
                )
            })?;
            let is_ip = host.parse::<std::net::IpAddr>().is_ok();
            if !config.panel.staging && (scheme == "http" || is_ip) {
                return Err(ProxyRuntimeError::InvalidConfig(
                    "IP or plaintext panel.public_base_url requires panel.staging=true".into(),
                ));
            }
            if !matches!(scheme, "http" | "https") {
                return Err(ProxyRuntimeError::InvalidConfig(
                    "panel.public_base_url must use http or https".into(),
                ));
            }
        }
        if !config.panel.listen.ip().is_loopback() && config.panel.token_file.is_none() {
            return Err(ProxyRuntimeError::InvalidConfig(
                "a non-loopback panel listener requires panel.token_file".into(),
            ));
        }
        if config.record.max_bytes == 0
            || config.record.max_duration_secs == 0
            || !(1..=100).contains(&config.record.max_files)
        {
            return Err(ProxyRuntimeError::InvalidConfig(
                "record limits or max_files are invalid".into(),
            ));
        }
        Ok(config)
    }
}

/// Parse the small origin-shaped URL accepted for generated profile links.
/// The panel base is deliberately restricted to a scheme + authority, with no
/// path/query/fragment, so concatenating API paths cannot produce an ambiguous
/// or attacker-controlled URL.  Bracketed IPv6 authorities are normalized to
/// their bare address for the staging/IP policy check.
fn parse_public_base_url(value: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") || rest.is_empty() {
        return None;
    }
    if rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    let authority = rest;
    let host = if let Some(after_open) = authority.strip_prefix('[') {
        let end = after_open.find(']')?;
        let host = &after_open[..end];
        let suffix = &after_open[end + 1..];
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix[1..].is_empty()
                || !suffix[1..].chars().all(|ch| ch.is_ascii_digit()))
        {
            return None;
        }
        host
    } else {
        match authority.matches(':').count() {
            0 => authority,
            1 => {
                let (host, port) = authority.rsplit_once(':')?;
                if host.is_empty()
                    || port.is_empty()
                    || !port.chars().all(|ch| ch.is_ascii_digit())
                    || port.parse::<u16>().ok().is_none()
                {
                    return None;
                }
                host
            }
            _ => return None,
        }
    };
    if host.is_empty()
        || host.len() > 253
        || host
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace() || matches!(ch, ',' | ';' | '='))
    {
        return None;
    }
    Some((scheme, host))
}

pub struct ProxyCommandOptions {
    pub config_path: PathBuf,
    pub record_plaintext: bool,
    pub private_session: Option<EnterGameSession>,
    pub panel_listen_override: Option<SocketAddr>,
}

pub async fn run_proxy(options: ProxyCommandOptions) -> Result<i32, ProxyRuntimeError> {
    let config = ProxyAppConfig::load(&options.config_path)?;
    let proxy_pcap = if config.record.proxy_pcap {
        Some(ProxyPcapRecorder::start(ProxyPcapConfig {
            directory: config.record.directory.clone(),
            max_bytes: config.record.max_bytes,
            max_duration_secs: config.record.max_duration_secs,
            max_files: config.record.max_files,
        })?)
    } else {
        None
    };
    let panel_listen = options.panel_listen_override.unwrap_or(config.panel.listen);
    if options.panel_listen_override.is_some() && !panel_listen.ip().is_loopback() {
        return Err(ProxyRuntimeError::InvalidConfig(
            "live proxy panel override must be loopback".into(),
        ));
    }
    let allow_anonymous = config.proxy.allow_anonymous;
    let token_path =
        config
            .proxy
            .token_store
            .as_deref()
            .ok_or(ProxyRuntimeError::InvalidConfig(
                "proxy.token_store is required; unauthenticated mode is disabled".into(),
            ))?;
    let tokens = TokenStore::load(token_path).map_err(ProxyRuntimeError::Token)?;
    if allow_anonymous {
        // C 方案（节点免鉴权）：免鉴权连接要复用内置匿名令牌做计量/限流，所以
        // **空令牌库也要能启动**（老行为：空库直接拒绝启动）。
        // 新建后立刻落盘 —— 令牌库的热重载是"整表替换"，不落盘的话下一次
        // 文件变动就会把内存里的匿名令牌冲掉，免鉴权会莫名其妙失效。
        let created = tokens
            .ensure_anonymous_token(config.proxy.token_ttl_secs, config.proxy.token_limits())
            .map_err(ProxyRuntimeError::Token)?;
        if created && let Err(error) = tokens.save(token_path) {
            eprintln!("warning: anonymous proxy token could not be persisted: {error}");
        }
    } else if tokens.list().is_empty() {
        return Err(ProxyRuntimeError::InvalidConfig(
            "proxy token store is empty; run `codev-net token create` first".into(),
        ));
    }
    let panel_token = match config.panel.token_file.as_deref() {
        Some(path) => read_secret(path, config.panel.token_ttl_secs)?,
        None => random_secret(),
    };
    let session_id = format!(
        "proxy-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let private_session = options.private_session.clone();
    let hub = EventHub::new_public(&session_id, &panel_token, config.panel.token_ttl_secs)?;
    hub.set_session(SessionView {
        build_id: SUPPORTED_BUILD.into(),
        status: if private_session.is_some() {
            SessionStatus::Degraded
        } else {
            SessionStatus::AwaitingSession
        },
        status_detail: if private_session.is_some() {
            "私有 session 已校验；等待代理 UDP tuple 锁定".into()
        } else {
            "等待 HTTPS/MNA 会话材料和 SOCKS5 UDP 对局流".into()
        },
        ..SessionView::default()
    })
    .await?;
    let initial_operations = codev_web::OperationalStatus {
        tls_mitm: if config.mitm.enabled {
            ComponentStatus::new(OperationalState::Ready, "白名单 TLS MITM 已加载")
        } else {
            ComponentStatus::new(OperationalState::Disabled, "HTTPS MITM 默认关闭")
        },
        recording: if options.record_plaintext && config.record.proxy_pcap {
            ComponentStatus::new(
                OperationalState::Ready,
                "本地代理 PCAP 与授权 HTTPS 明文录制已启用并受限",
            )
        } else if config.record.proxy_pcap {
            ComponentStatus::new(
                OperationalState::Ready,
                "本地代理 TCP/UDP PCAP 自动录制已启用并受限",
            )
        } else if options.record_plaintext {
            ComponentStatus::new(OperationalState::Ready, "授权 HTTPS 明文录制已启用并受限")
        } else {
            ComponentStatus::new(OperationalState::Disabled, "录制默认关闭")
        },
        ..Default::default()
    };
    hub.set_operational_status(initial_operations.clone())
        .await?;

    let (session_tx, mut session_rx) = mpsc::channel::<ProxySessionUpdate>(PROXY_EVENT_QUEUE);
    let (material_tx, mut material_rx) = mpsc::channel::<SessionMaterial>(PROXY_EVENT_QUEUE);
    let (actor_tx, mut actor_rx) = mpsc::channel::<ProxyActorBatch>(PROXY_ACTOR_QUEUE);
    let dynamic_targets = DynamicTargetStore::default();
    let decoder_state = Arc::new(Mutex::new(ProxyDecodeState {
        dynamic_targets: dynamic_targets.clone(),
        ..ProxyDecodeState::default()
    }));
    let runtime_counters = Arc::new(ProxyRuntimeCounters::default());
    let (tcp_closed_sender, tcp_closed_receiver) = std_mpsc::channel();
    let tap = TapHandle::new(ProxyFrameTap::new_with_tcp_close_receiver(
        session_tx.clone(),
        actor_tx,
        Arc::clone(&decoder_state),
        Arc::clone(&runtime_counters),
        tcp_closed_receiver,
        proxy_pcap.clone(),
    ));
    let token_store_for_reload = tokens.clone();
    let token_path_for_reload = token_path.to_path_buf();

    // Install an explicitly supplied private session before accepting proxy
    // traffic. It remains sensitive inside the broker/decoder only; the
    // public roster is projected to unresolved batch slots.
    let private_material = private_session
        .map(|session| {
            let id = SessionId::parse(format!("private-{session_id}"))
                .map_err(ProxyRuntimeError::Broker)?;
            codev_session::SessionMaterial::from_mna(id, session, super::now_ns())
                .map_err(ProxyRuntimeError::Broker)
        })
        .transpose()?;
    if let Some(material) = private_material.as_ref()
        && install_material(&decoder_state, material)
    {
        runtime_counters
            .materials_installed
            .fetch_add(1, Ordering::Relaxed);
    }
    if let Some(material) = private_material {
        session_tx
            .try_send(ProxySessionUpdate::Material(material))
            .map_err(|_| {
                ProxyRuntimeError::InvalidConfig(
                    "private session material queue is unexpectedly full".into(),
                )
            })?;
    }

    let authority = if config.mitm.enabled {
        let directory = config
            .mitm
            .ca_dir
            .clone()
            .ok_or(ProxyRuntimeError::InvalidConfig(
                "mitm.ca_dir is required when MITM is enabled".into(),
            ))?;
        Some(Arc::new(MitmAuthority::load_or_generate(directory)?))
    } else {
        None
    };
    let profile_path = config.panel.profile_store.clone().or_else(|| {
        config
            .proxy
            .profile_store
            .clone()
            .or_else(|| Some(token_path.with_file_name("shadowrocket-profiles.toml")))
    });
    let profiles =
        ProfileStore::load(profile_path.as_deref().ok_or_else(|| {
            ProxyRuntimeError::InvalidConfig("profile store path missing".into())
        })?)
        .map_err(ProxyRuntimeError::Profile)?;
    let proxy_service = ProxyPanelService::new(
        config.proxy.clone(),
        tokens.clone(),
        token_path,
        profiles,
        config.panel.public_base_url.clone(),
        config.panel.allow_lan_hosts,
    );
    // 异地观看写入端：只有两个只读文件都配置了才开启房间令牌自校验。
    // 配置错误**直接拒绝启动** —— 否则表现是"手机端一切正常、异地永远黑屏"。
    let mirror_access = match (
        config.panel.room_access_key_file.as_deref(),
        config.panel.room_access_state_file.as_deref(),
    ) {
        (Some(key_file), Some(state_file)) => Some(Arc::new(
            codev_web::MirrorAccess::load(key_file, state_file)
                .map_err(ProxyRuntimeError::InvalidConfig)?,
        )),
        _ => None,
    };
    hub.set_panel_services(PanelServices {
        proxy: Some(Arc::new(proxy_service.with_mirror_access(mirror_access))),
        ca: authority
            .as_ref()
            .map(|authority| Arc::new(CaPanelService::new(Arc::clone(authority)))),
    })
    .await;
    let mitm_policy = MitmPolicy {
        enabled: config.mitm.enabled,
        domains: config.mitm.domains.clone(),
        ports: vec![443],
        block_quic: config.mitm.block_quic,
    }
    .validate()?;

    let recorder: Option<Arc<PlaintextRecorder>> = if options.record_plaintext {
        if !config.record.plaintext {
            return Err(ProxyRuntimeError::InvalidConfig(
                "--record-plaintext requires record.plaintext=true in config".into(),
            ));
        }
        Some(Arc::new(PlaintextRecorder::create(
            &config.record.directory,
            RecordingLimits {
                max_bytes: config.record.max_bytes,
                max_duration_ns: config
                    .record
                    .max_duration_secs
                    .saturating_mul(1_000_000_000),
                max_record_bytes: 8 * 1024 * 1024,
            },
            true,
        )?))
    } else {
        None
    };
    let extractor = Arc::new(SessionExtractionSink::new(material_tx));
    let sink: Arc<dyn PlaintextSink> = Arc::new(CompositePlaintextSink {
        recorder: recorder.clone(),
        extractor,
        status_sender: session_tx.clone(),
        recording_notified: Arc::new(AtomicBool::new(false)),
    });

    let server = if let Some(authority) = authority {
        let relay = Arc::new(TlsMitmRelay::new(authority));
        Socks5Server::new(
            RuntimeProxyConfig {
                proxy: config.proxy.clone(),
                block_quic: config.mitm.block_quic,
            },
            tokens,
        )?
        .with_dynamic_targets(dynamic_targets.clone())
        .with_frame_tap(tap.clone())
        .with_event_sink(Arc::new(ProxyEventForwarder {
            sender: session_tx.clone(),
            tcp_closed_sender: tcp_closed_sender.clone(),
            pcap_recorder: proxy_pcap.clone(),
        }))
        .with_connect_handler(Arc::new(
            ProxyMitmHandler::new(relay, mitm_policy.clone()).with_plaintext_sink(sink),
        ))
    } else {
        Socks5Server::new(
            RuntimeProxyConfig {
                proxy: config.proxy.clone(),
                block_quic: config.mitm.block_quic,
            },
            tokens,
        )?
        .with_dynamic_targets(dynamic_targets.clone())
        .with_frame_tap(tap.clone())
        .with_event_sink(Arc::new(ProxyEventForwarder {
            sender: session_tx.clone(),
            tcp_closed_sender,
            pcap_recorder: proxy_pcap.clone(),
        }))
    };
    let proxy_metrics = server.metrics();
    let proxy_listener = server.bind().await?;
    let panel_listener = TcpListener::bind(panel_listen).await?;
    println!("SOCKS5 listening on {}", proxy_listener.local_addr()?);
    println!(
        "panel listening on {} (Caddy may terminate public TLS)",
        panel_listener.local_addr()?
    );
    if config.panel.token_file.is_none() {
        println!("panel bootstrap token (write to a 0600 file for persistent use): {panel_token}");
    }

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let material_forward_sender = session_tx.clone();
    let material_forward_task = tokio::spawn(async move {
        while let Some(material) = material_rx.recv().await {
            if material_forward_sender
                .send(ProxySessionUpdate::Material(material))
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let token_reload_sender = session_tx.clone();
    let token_reload_task = tokio::spawn(async move {
        let mut previous = token_store_fingerprint(&token_path_for_reload);
        let mut ticker = tokio::time::interval(TOKEN_RELOAD_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let current = token_store_fingerprint(&token_path_for_reload);
            if current == previous {
                continue;
            }
            previous = current;
            match TokenStore::load(&token_path_for_reload) {
                Ok(replacement) => {
                    token_store_for_reload.reload_from(replacement);
                    let _ = token_reload_sender.try_send(ProxySessionUpdate::TokenStoreReloaded);
                }
                Err(_error) => {
                    let _ = token_reload_sender.try_send(ProxySessionUpdate::TokenStoreError {
                        // Do not reflect parser diagnostics into the public
                        // panel; malformed TOML may contain operator input.
                        detail: "token store reload failed; previous credentials remain active"
                            .into(),
                    });
                }
            }
        }
    });
    let proxy_task = tokio::spawn(server.serve_until(proxy_listener, shutdown_rx));
    // Reorder 释放（UDP 50ms 序号窗口）不再由这里的 100Hz 定时任务驱动。
    //
    //   · 这个任务原来每 10ms 调一次 `TapHandle::poll`，而那个函数是
    //     `let _ = now_ns;`——空实现，什么都没释放；真正干活的是
    //     `codev-frame-parser` worker 线程里的 `ProxyFrameTap::poll`。
    //     所以它只是把 tokio 运行时每 10ms 唤醒一次，纯空转（实测 ≈2% 单核）。
    //   · 现在 worker 按 `FrameTap::next_deadline_ns()` 的期限醒：
    //     `ProxyFrameTap::next_deadline_ns` 已把两条方向的 reorder gap 死线
    //     （`gap_started_ns + 50ms`）算进去，到点就 poll，释放时序与原来一致。
    //     见 codev-proxy/src/server.rs 的 worker 循环与 codev-stream 的
    //     `SequenceReorderBuffer::next_deadline_ns`。
    let metrics_hub = hub.clone();
    let metrics_counters = Arc::clone(&runtime_counters);
    let tap_metrics = tap.clone();
    let pcap_metrics = proxy_pcap.clone();
    let metrics_task = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            let snapshot = proxy_metrics.snapshot();
            let actor_messages = metrics_counters.actor_messages.load(Ordering::Relaxed);
            let coordinate_updates = metrics_counters.coordinate_updates.load(Ordering::Relaxed);
            let parse_failures = metrics_counters.parse_failures.load(Ordering::Relaxed);
            let parser_bus = tap_metrics.metrics();
            let mna_command_counts = {
                let counts = metrics_counters
                    .mna_command_counts
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                counts
                    .iter()
                    .map(|(command, count)| (command.to_string(), *count))
                    .collect()
            };
            let _ = metrics_hub
                .publish_metrics(
                    super::now_ns(),
                    MetricsPayload {
                        packets: snapshot.tcp_frames.saturating_add(snapshot.udp_frames),
                        actor_messages,
                        coordinate_updates,
                        parse_failures,
                        pcap_drops: pcap_metrics
                            .as_ref()
                            .map_or(0, ProxyPcapRecorder::dropped_items),
                        proxy_pipeline: Some(ProxyPipelineMetrics {
                            accepted_connections: snapshot.accepted_connections,
                            tcp_connects: snapshot.tcp_connects,
                            udp_associations: snapshot.udp_associations,
                            rejected_authentication: snapshot.rejected_authentication,
                            rejected_targets: snapshot.rejected_targets,
                            tcp_frames: snapshot.tcp_frames,
                            udp_frames: snapshot.udp_frames,
                            udp_fragments_rejected: snapshot.udp_fragments_rejected,
                            udp_duplicates_observed: snapshot.udp_duplicates_observed,
                            quic_blocked: snapshot.quic_blocked,
                            quota_rejections: snapshot.quota_rejections,
                            mna_magic_observed: metrics_counters
                                .mna_magic_observed
                                .load(Ordering::Relaxed),
                            mna_server_hello_observed: metrics_counters
                                .mna_server_hello_observed
                                .load(Ordering::Relaxed),
                            mna_keys_recovered: metrics_counters
                                .mna_keys_recovered
                                .load(Ordering::Relaxed),
                            mna_data_without_key: metrics_counters
                                .mna_data_without_key
                                .load(Ordering::Relaxed),
                            mna_failures: metrics_counters.mna_failures.load(Ordering::Relaxed),
                            mna_data_decrypted: metrics_counters
                                .mna_data_decrypted
                                .load(Ordering::Relaxed),
                            mna_application_messages: metrics_counters
                                .mna_application_messages
                                .load(Ordering::Relaxed),
                            mna_session_parse_failures: metrics_counters
                                .mna_session_parse_failures
                                .load(Ordering::Relaxed),
                            mna_ordinary_flows_evicted: metrics_counters
                                .mna_ordinary_flows_evicted
                                .load(Ordering::Relaxed),
                            mna_control_flows_evicted: metrics_counters
                                .mna_control_flows_evicted
                                .load(Ordering::Relaxed),
                            mna_authenticated_layout_sessions: metrics_counters
                                .mna_authenticated_layout_sessions
                                .load(Ordering::Relaxed),
                            mna_command_counts,
                            mna_sessions_observed: metrics_counters
                                .mna_sessions_observed
                                .load(Ordering::Relaxed),
                            materials_installed: metrics_counters
                                .materials_installed
                                .load(Ordering::Relaxed),
                            udp_without_material: metrics_counters
                                .udp_without_material
                                .load(Ordering::Relaxed),
                            udp_candidates_observed: metrics_counters
                                .udp_candidates_observed
                                .load(Ordering::Relaxed),
                            udp_candidates_rejected: metrics_counters
                                .udp_candidates_rejected
                                .load(Ordering::Relaxed),
                            udp_flows_locked: metrics_counters
                                .udp_flows_locked
                                .load(Ordering::Relaxed),
                            udp_association_migrations: metrics_counters
                                .udp_association_migrations
                                .load(Ordering::Relaxed),
                            actor_updates_decoded: metrics_counters
                                .actor_updates_decoded
                                .load(Ordering::Relaxed),
                            actor_updates_invalid: metrics_counters
                                .actor_updates_invalid
                                .load(Ordering::Relaxed),
                            parser_queue_capacity: parser_bus.capacity as u64,
                            parser_queue_max_bytes: parser_bus.max_bytes,
                            parser_queue_depth: parser_bus.queue_depth as u64,
                            parser_queue_bytes: parser_bus.queued_bytes,
                            parser_processed_frames: parser_bus.processed_frames,
                            parser_dropped_frames: parser_bus.dropped_frames,
                            parser_dropped_bytes: parser_bus.dropped_bytes,
                            parser_drop_epoch: parser_bus.drop_epoch,
                        }),
                        parse_to_ws_p99_ms: None,
                        capture_to_ws_p99_ms: None,
                    },
                )
                .await;
        }
    });
    let panel_task = tokio::spawn(codev_web::serve(panel_listener, hub.clone()));
    let broker_hub = hub.clone();
    let broker_state = Arc::clone(&decoder_state);
    let initial_operations_for_broker = initial_operations;
    let counters_for_broker = Arc::clone(&runtime_counters);
    let broker_task = tokio::spawn(async move {
        let mut broker = SessionBroker::default();
        let mut operations = initial_operations_for_broker;
        while let Some(update) = session_rx.recv().await {
            match update {
                ProxySessionUpdate::Mna {
                    flow_id,
                    capture_ns,
                    session,
                } => {
                    let id = SessionId::parse(format!("mna-{flow_id}"));
                    if let Ok(id) = id
                        && let Ok(material) =
                            codev_session::SessionMaterial::from_mna(id, session, capture_ns)
                        && let Ok(outcome) = broker.accept_with_outcome(material.clone())
                    {
                        if outcome.disposition == AcceptDisposition::Installed
                            && install_material_at_generation(
                                &broker_state,
                                &material,
                                outcome.channel_generation,
                            )
                        {
                            counters_for_broker
                                .materials_installed
                                .fetch_add(1, Ordering::Relaxed);
                            emit_stage_log(ProxyPipelineStage::MaterialInstalled);
                        }
                        if outcome.disposition == AcceptDisposition::Installed {
                            operations.proxy = ComponentStatus::new(
                                OperationalState::Active,
                                "MNA 会话材料已认证；等待代理 UDP tuple",
                            );
                            let _ = broker_hub.set_operational_status(operations.clone()).await;
                            let _ = broker_hub
                                .set_session(SessionView {
                                    build_id: SUPPORTED_BUILD.into(),
                                    map_id: material.map_id,
                                    status: SessionStatus::Degraded,
                                    status_detail: "MNA 会话已认证；等待代理 UDP tuple 锁定".into(),
                                    capture_start_ns: Some(capture_ns),
                                    latest_capture_ns: Some(capture_ns),
                                    channel_generation: outcome.channel_generation,
                                })
                                .await;
                            let _ = broker_hub.set_roster(roster_from_material(&material)).await;
                        }
                    }
                }
                ProxySessionUpdate::Material(material) => {
                    if let Ok(outcome) = broker.accept_with_outcome(material.clone()) {
                        if outcome.disposition == AcceptDisposition::Installed
                            && install_material_at_generation(
                                &broker_state,
                                &material,
                                outcome.channel_generation,
                            )
                        {
                            counters_for_broker
                                .materials_installed
                                .fetch_add(1, Ordering::Relaxed);
                            emit_stage_log(ProxyPipelineStage::MaterialInstalled);
                        }
                        if outcome.disposition == AcceptDisposition::Installed {
                            operations.proxy = ComponentStatus::new(
                                OperationalState::Active,
                                "会话材料已认证；等待代理 UDP tuple",
                            );
                            let _ = broker_hub.set_operational_status(operations.clone()).await;
                            let _ = broker_hub
                                .set_session(SessionView {
                                    build_id: SUPPORTED_BUILD.into(),
                                    map_id: material.map_id,
                                    status: SessionStatus::Degraded,
                                    status_detail: "HTTPS MITM 会话材料已认证；等待 UDP tuple 锁定"
                                        .into(),
                                    latest_capture_ns: Some(material.observed_ns),
                                    capture_start_ns: Some(material.observed_ns),
                                    channel_generation: outcome.channel_generation,
                                })
                                .await;
                            let _ = broker_hub.set_roster(roster_from_material(&material)).await;
                        }
                    }
                }
                ProxySessionUpdate::TcpClosed {
                    flow_id,
                    capture_ns,
                } => {
                    let flow_name = format!("mna-{flow_id}");
                    let owns_active_mna = broker.active().is_some_and(|active| {
                        active.source == codev_session::SessionMaterialSource::Mna
                            && active.session_id.as_str() == flow_name
                    });
                    if owns_active_mna {
                        // MNA is the authenticated control plane, not the UDP
                        // data-plane lifetime. The reference capture closes
                        // this TCP flow while Channel 32 still emits 83 valid
                        // actor blocks. Keep the installed material and UDP
                        // decoder until a new Enter/ReEnter atomically
                        // replaces them; stale material cannot validate a
                        // tuple encrypted with a different session key.
                        let udp_locked = broker_state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .locked_flow_id
                            .is_some();
                        operations.proxy = ComponentStatus::new(
                            if udp_locked {
                                OperationalState::Active
                            } else {
                                OperationalState::Awaiting
                            },
                            if udp_locked {
                                "MNA 控制连接已关闭；已锁定 UDP 继续解析"
                            } else {
                                "MNA 控制连接已关闭；保留已认证材料等待 UDP 或新会话"
                            },
                        );
                        let _ = broker_hub.set_operational_status(operations.clone()).await;
                        let _ = broker_hub
                            .set_pipeline_stage(
                                capture_ns,
                                if udp_locked {
                                    "tcp_control_closed_udp_retained"
                                } else {
                                    "tcp_control_closed_material_retained"
                                },
                                if udp_locked {
                                    PipelineHealth::Healthy
                                } else {
                                    PipelineHealth::Awaiting
                                },
                                if udp_locked {
                                    "MNA 控制连接已关闭；UDP 数据面与解析状态继续保留"
                                } else {
                                    "MNA 控制连接已关闭；已认证材料保留到新会话替换"
                                },
                            )
                            .await;
                    }
                }
                ProxySessionUpdate::Event(event) => {
                    let mut changed = false;
                    if let Some((state, detail)) = event_status(&event) {
                        operations.proxy = ComponentStatus::new(state, detail);
                        changed = true;
                    }
                    if matches!(event, ProxyEvent::QuicBlocked { .. }) {
                        operations.quic = ComponentStatus::new(
                            OperationalState::Blocked,
                            "白名单 UDP/443 已阻断，等待 TCP 回落",
                        );
                        changed = true;
                    }
                    if changed {
                        let _ = broker_hub.set_operational_status(operations.clone()).await;
                    }
                }
                ProxySessionUpdate::Stage { capture_ns, stage } => {
                    emit_stage_log(stage);
                    let (state, detail) = stage_component_status(stage);
                    operations.proxy = ComponentStatus::new(state, detail);
                    let _ = broker_hub.set_operational_status(operations.clone()).await;
                    let broker_is_live = matches!(
                        broker.snapshot().state,
                        codev_session::BrokerState::UdpLocked | codev_session::BrokerState::Live
                    );
                    if !(stage == ProxyPipelineStage::MnaSessionObserved && broker_is_live) {
                        let _ = broker_hub
                            .set_pipeline_stage(
                                capture_ns,
                                stage.as_str(),
                                stage_pipeline_health(stage),
                                detail,
                            )
                            .await;
                    }
                    if let Some((status, status_detail)) = stage_session_status(stage) {
                        let snapshot = broker.snapshot();
                        let _ = broker_hub
                            .set_session(SessionView {
                                build_id: SUPPORTED_BUILD.into(),
                                map_id: snapshot.map_id,
                                status,
                                status_detail: status_detail.into(),
                                capture_start_ns: None,
                                latest_capture_ns: Some(capture_ns),
                                channel_generation: snapshot.channel_generation,
                            })
                            .await;
                    }
                }
                ProxySessionUpdate::UdpLocked { capture_ns } => {
                    let transition = broker.lock_udp().and_then(|()| broker.mark_live());
                    if transition.is_ok() {
                        emit_stage_log(ProxyPipelineStage::UdpLocked);
                        let _ = broker_hub
                            .set_pipeline_stage(
                                capture_ns,
                                ProxyPipelineStage::UdpLocked.as_str(),
                                PipelineHealth::Healthy,
                                codev_obf::s("252ed4e5817503b52421dd2c54abbb2a46b63c829a5427ba91f70caeb1451bf4aff203a0a61e06d0e17fc5493c9ed2707820865155d4fd0f"),
                            )
                            .await;
                        operations.proxy = ComponentStatus::new(
                            OperationalState::Active,
                            codev_obf::s("252ed4e5817503b52421dd2c54abbb2a46b63c829a5427ba91f70caeb1451bf4aff203a0a61e06d0e17fc5493c9ed2707820865155d4fd0f"),
                        );
                        let _ = broker_hub.set_operational_status(operations.clone()).await;
                        let snapshot = broker.snapshot();
                        let calibration_available = snapshot.map_id.is_some_and(|id| {
                            MapCatalog::embedded().ok().is_some_and(|catalog| {
                                catalog.calibration(SUPPORTED_BUILD, id).is_ok()
                            })
                        });
                        let _ = broker_hub
                            .set_session(SessionView {
                                build_id: SUPPORTED_BUILD.into(),
                                map_id: snapshot.map_id,
                                status: if calibration_available {
                                    SessionStatus::Live
                                } else {
                                    SessionStatus::Degraded
                                },
                                status_detail: if calibration_available {
                                    codev_obf::s("8f7577bb898df0658e7a7e72764548eaea28752d355d21a0c5572327472e0dcc8e7349bb9ea8d426039eb5f5bfe945d8fb2b6c1c3a5214a3fd7d").into()
                                } else {
                                    "主 UDP 已验证并锁定；地图标定未 proven".into()
                                },
                                capture_start_ns: Some(capture_ns),
                                latest_capture_ns: Some(capture_ns),
                                channel_generation: snapshot.channel_generation,
                            })
                            .await;
                    }
                }
                ProxySessionUpdate::PipelineError { capture_ns, detail } => {
                    counters_for_broker
                        .parse_failures
                        .fetch_add(1, Ordering::Relaxed);
                    operations.proxy = ComponentStatus::new(
                        OperationalState::Error,
                        format!("UDP 坐标解析失败：{detail}"),
                    );
                    let _ = broker.mark_degraded("proxy UDP pipeline failed");
                    let _ = broker_hub.set_operational_status(operations.clone()).await;
                    let _ = broker_hub
                        .set_session(SessionView {
                            build_id: SUPPORTED_BUILD.into(),
                            status: SessionStatus::Degraded,
                            status_detail: "代理 UDP 解析进入 degraded；等待独立 fresh 坐标恢复"
                                .into(),
                            latest_capture_ns: Some(capture_ns),
                            ..SessionView::default()
                        })
                        .await;
                }
                ProxySessionUpdate::RecordingStopped { detail } => {
                    operations.recording = ComponentStatus::new(
                        OperationalState::Incomplete,
                        format!("录制不完整：{detail}"),
                    );
                    let _ = broker_hub.set_operational_status(operations.clone()).await;
                }
                ProxySessionUpdate::TokenStoreReloaded => {
                    // Credential control-plane reloads do not prove that game
                    // traffic is active. Preserve the current data-plane state.
                    eprintln!("[codev-stage] credential_store_reloaded");
                }
                ProxySessionUpdate::TokenStoreError { detail } => {
                    operations.proxy = ComponentStatus::new(OperationalState::Error, detail);
                    let _ = broker_hub.set_operational_status(operations.clone()).await;
                }
            }
        }
    });
    let actor_hub = hub.clone();
    let actor_state = Arc::clone(&decoder_state);
    let actor_counters = Arc::clone(&runtime_counters);
    let actor_task = tokio::spawn(async move {
        let mut stale_tick = tokio::time::interval(Duration::from_millis(250));
        stale_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut stream_live = false;
        let mut last_session_generation = 0_u64;
        let mut published_actor_generation = None;
        // 贴槽状态：本机五人槽位（state_index==0）/ 自己那个角色的出生点与槽位 /
        // 上一次已经下发的映射（变了才重发）。
        let mut local_state_counts: std::collections::BTreeMap<u8, u64> =
            std::collections::BTreeMap::new();
        let mut local_slots: Vec<u8> = Vec::new();
        let mut anchor_spawn: Option<[f64; 3]> = None;
        let mut anchor_slot: Option<u8> = None;
        let mut published_seat_plan: Option<Vec<Option<u8>>> = None;
        let mut published_self_slot: Option<Option<u8>> = None;
        let mut roster_plan_stabilizer = codev_stream::RosterPlanStabilizer::default();
        loop {
            tokio::select! {
                maybe_batch = actor_rx.recv() => {
                    let Some(batch) = maybe_batch else { break; };
                    let (current_session_generation, map_id) = {
                        let state = actor_state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        (state.channel_generation, state.map_id)
                    };
                    // Actor delivery is asynchronous. A new Enter/ReEnter may
                    // replace the private decoder while an older batch is
                    // queued; never publish that stale batch into the new
                    // session generation.
                    if batch.session_generation != current_session_generation {
                        continue;
                    }
                    if current_session_generation != last_session_generation {
                        last_session_generation = current_session_generation;
                        published_actor_generation = None;
                        stream_live = false;
                        reset_round_binding_state(
                            &mut local_state_counts,
                            &mut local_slots,
                            &mut anchor_spawn,
                            &mut anchor_slot,
                            &mut published_seat_plan,
                            &mut published_self_slot,
                            &mut roster_plan_stabilizer,
                        );
                        // 先主动撤回上一局的可视映射，不能在新局收集到
                        // 5/10 个槽位前让面板继续显示旧阵营和旧的“自己”。
                        let _ = actor_hub.set_roster(Vec::new()).await;
                        let _ = actor_hub.set_self_slot(None).await;
                    }
                    for gap in batch.gaps {
                        let _ = actor_hub
                            .publish_gap(gap.detected_ns, super::pipeline_gap_payload(&gap))
                            .await;
                        stream_live = false;
                        let _ = actor_hub
                            .set_session(SessionView {
                                build_id: SUPPORTED_BUILD.into(),
                                map_id,
                                status: SessionStatus::Degraded,
                                status_detail: "代理 UDP 出现 gap；等待不依赖旧 baseline 的 fresh 坐标恢复"
                                    .into(),
                                latest_capture_ns: Some(gap.detected_ns),
                                channel_generation: published_actor_generation
                                    .unwrap_or(current_session_generation),
                                ..SessionView::default()
                            })
                            .await;
                    }
                    for actor in batch.actors {
                        if !actor_belongs_to_session(
                            actor.channel_generation,
                            current_session_generation,
                        ) {
                            continue;
                        }
                        if published_actor_generation != Some(actor.channel_generation) {
                            published_actor_generation = Some(actor.channel_generation);
                            stream_live = false;
                        }
                        if !stream_live {
                            let calibration_available = map_id.is_some_and(|id| {
                                MapCatalog::embedded()
                                    .ok()
                                    .is_some_and(|catalog| {
                                        catalog.calibration(SUPPORTED_BUILD, id).is_ok()
                                    })
                            });
                            let status = if calibration_available {
                                SessionStatus::Live
                            } else {
                                SessionStatus::Degraded
                            };
                            let detail = if calibration_available {
                                codev_obf::s("a7280f163e63c0c607c38c85db958cf663761b4347716176ed09434d35b6a7dd26e783a4ebcaa2f237f0c4a2d78b83b3a63d32173953050ed3750c7646424375dd03444e3e0d411fa72b01")
                            } else {
                                "代理 UDP tuple 已锁定；地图标定未 proven，坐标仍保持 degraded".to_string()
                            };
                            let _ = actor_hub
                                .set_session(SessionView {
                                    build_id: SUPPORTED_BUILD.into(),
                                    map_id,
                                    status,
                                    status_detail: detail.into(),
                                    latest_capture_ns: Some(actor.timestamp_ns),
                                    channel_generation: actor.channel_generation,
                                    ..SessionView::default()
                                })
                                .await;
                            stream_live = true;
                        }
                        actor_counters
                            .actor_messages
                            .fetch_add(1, Ordering::Relaxed);
                        actor_counters
                            .actor_updates_decoded
                            .fetch_add(actor.updates.len() as u64, Ordering::Relaxed);
                        actor_counters
                            .actor_updates_invalid
                            .fetch_add(
                                actor
                                    .updates
                                    .iter()
                                    .filter(|update| !update.position_valid)
                                    .count() as u64,
                                Ordering::Relaxed,
                            );
                        let calibration = map_id.and_then(|id| {
                            MapCatalog::embedded()
                                .ok()
                                .and_then(|catalog| catalog.calibration(SUPPORTED_BUILD, id).ok().cloned())
                        });
                        // ---- 贴槽：先把本机五人（state_index==0）和自己（第一个
                        // open 的玩家角色出生点）认出来，再把 roster 的英雄编号按
                        // 阵营贴到具体槽位，下发给面板。----
                        if anchor_spawn.is_none() {
                            anchor_spawn = actor.local_anchor_spawn;
                        }
                        for update in &actor.updates {
                            if update.state_index == 0 {
                                *local_state_counts.entry(update.slot).or_insert(0) += 1;
                            }
                            // 兜底锚点（没有身份证据时才用）：**必须落在本机五人名单里**。
                            // 以前不管名单，谁先上报就认谁 —— 回合准备阶段全队挤在出生点 5 米内，
                            // 于是认成队友，而且 `is_none()` 只认一次，认错就永不再改。
                            if anchor_slot.is_none()
                                && update.position_valid
                                && (local_slots.is_empty() || local_slots.contains(&update.slot))
                                && let Some(spawn) = anchor_spawn
                            {
                                let state = update.state;
                                if (state.position.x - spawn[0]).abs() <= 5.0
                                    && (state.position.y - spawn[1]).abs() <= 5.0
                                {
                                    anchor_slot = Some(update.slot);
                                }
                            }
                        }
                        local_slots = codev_stream::pick_local_team_slots(&local_state_counts);
                        if local_slots.len() == 5 {
                            let _ = local_slots.len();
                            let roster_seats = {
                                let state = actor_state
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                state.roster_seats.clone()
                            };
                            if roster_seats.len() == 10 {
                let self_key = known_self_key();
                                let mut player_slots: Vec<u8> = local_slots.clone();
                                for slot in actor.updates.iter().map(|update| update.slot) {
                                    if !player_slots.contains(&slot) {
                                        player_slots.push(slot);
                                    }
                                }
                                player_slots.sort_unstable();
                                player_slots.truncate(10);
                                let plan = codev_stream::assign_roster_slots(
                                    &roster_seats,
                                    &local_slots,
                                    &player_slots,
                                    anchor_slot,
                                    self_key,
                                );
                                if let Some(stable_plan) = roster_plan_stabilizer.observe(&plan) {
                                    // "自己"优先用**身份/设备证据**（self-identity.json 的 uid 匹配，
                                    // 或全队只有一个带真人设备字段的座位），出生点兜底。
                                    // 出生点那条只是几何相似，准备阶段不可靠。
                                    let identity_seat_index =
                                        codev_stream::self_seat_index(&roster_seats, self_key);
                                    let identity_self_slot = identity_seat_index
                                        .and_then(|index| stable_plan.slots.get(index).copied().flatten());
                                    let effective_self_slot = identity_self_slot.or(anchor_slot);
                                    let changed = published_seat_plan.as_ref() != Some(&stable_plan.slots)
                                        || published_self_slot != Some(effective_self_slot);
                                    if changed && stable_plan.slots.iter().any(Option::is_some) {
                                    published_seat_plan = Some(stable_plan.slots.clone());
                                    published_self_slot = Some(effective_self_slot);
                                    let anchor_seat = codev_stream::self_seat_index(
                                        &roster_seats,
                                        self_key,
                                    )
                                    .map(|index| roster_seats[index]);
                                    let entries = roster_seats
                                        .iter()
                                        .zip(stable_plan.slots.iter())
                                        .map(|(seat, slot)| codev_web::RosterEntry {
                                            slot: *slot,
                                            display_name: slot.map_or_else(
                                                || "unbound".to_owned(),
                                                |slot| format!("batch_slot_{slot}"),
                                            ),
                                            agent_id: seat.agent_id,
                                            camp_id: if stable_plan.local_camp_id == Some(seat.camp_id) {
                                                codev_stream::LOCAL_CAMP_ID
                                            } else {
                                                codev_stream::REMOTE_CAMP_ID
                                            },
                                            position_slot: Some(seat.position_slot),
                                            // 只有"自己"这个槽位是出生点锚点证明出来的
                                            // （加上真人设备字段），算确定；其余 9 个是
                                            // 阵营+位次推出来的，明确标成未确认，面板会打问号。
                                            identity_confidence: if Some(*seat) == anchor_seat {
                                                codev_stream::IdentityConfidence::Proven
                                            } else {
                                                codev_stream::IdentityConfidence::Unresolved
                                            },
                                            device_tag: seat.device_tag,
                                        })
                                        .collect::<Vec<_>>();
                                    let _ = actor_hub.set_roster(entries).await;
                                    let _ = actor_hub.set_self_slot(effective_self_slot).await;
                                    }
                                }
                            }
                        }
                        let positions = actor_positions(&actor, calibration.as_ref());
                        actor_counters
                            .coordinate_updates
                            .fetch_add(positions.len() as u64, Ordering::Relaxed);
                        if !positions.is_empty() {
                            let _ = actor_hub
                                .publish_positions(actor.timestamp_ns, positions)
                                .await;
                        }
                    }
                }
                _ = stale_tick.tick() => {
                    let _ = actor_hub
                        .mark_positions_stale(super::now_ns(), super::LIVE_POSITION_STALE_AFTER_NS)
                        .await;
                }
            }
        }
    });

    // Desktop waits for Ctrl-C. iOS never delivers SIGINT and tokio's
    // signal hook can fail immediately, which would tear the in-process
    // engine down right after start. Stay parked until the embedding
    // runtime is shut down instead.
    #[cfg(target_os = "ios")]
    std::future::pending::<()>().await;
    #[cfg(not(target_os = "ios"))]
    tokio::signal::ctrl_c().await?;
    let _ = shutdown_tx.send(true);
    let _ = proxy_task.await;
    metrics_task.abort();
    panel_task.abort();
    broker_task.abort();
    actor_task.abort();
    material_forward_task.abort();
    token_reload_task.abort();
    if let Some(recorder) = recorder {
        let _ = recorder.finish();
    }
    for _ in 0..100 {
        if tap.metrics().queue_depth == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if let Some(recorder) = proxy_pcap {
        let _ = recorder.finish();
    }
    Ok(0)
}

fn event_status(event: &ProxyEvent) -> Option<(OperationalState, String)> {
    match event {
        // These are bounded per-client policy outcomes, not listener health.
        // Internet scans, a stale client profile, a denied target, or a normal
        // idle timeout must not overwrite the global proxy-ready state.
        ProxyEvent::AuthenticationRejected { .. }
        | ProxyEvent::TargetRejected { .. }
        | ProxyEvent::QuotaExceeded { .. }
        | ProxyEvent::UdpIdleTimeout { .. }
        | ProxyEvent::QuicBlocked { .. } => None,
        _ => Some((
            OperationalState::Active,
            "SOCKS5 代理正在转发授权流量".into(),
        )),
    }
}

fn emit_stage_log(stage: ProxyPipelineStage) {
    eprintln!("[codev-stage] {}", stage.as_str());
}

impl ProxyPipelineStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::TcpObserved => "tcp_observed",
            Self::MnaMagicObserved => "mna_magic_observed",
            Self::MnaServerHelloObserved => "mna_server_hello_observed",
            Self::MnaKeyRecovered => "mna_key_recovered",
            Self::MnaDataWithoutKey => "mna_data_without_key",
            Self::MnaFramingFailed => "mna_framing_failed",
            Self::MnaKeyRecoveryFailed => "mna_key_recovery_failed",
            Self::MnaDecryptFailed => "mna_decrypt_failed",
            Self::MnaPaddingFailed => "mna_padding_failed",
            Self::MnaApplicationFailed => "mna_application_failed",
            Self::MnaSessionObserved => "mna_session_observed",
            Self::MaterialInstalled => "session_material_installed",
            Self::UdpWithoutMaterial => "udp_without_session_material",
            Self::UdpCandidateObserved => "udp_candidate_observed",
            Self::UdpOodleBlocked => "udp_oodle_blocked",
            Self::UdpLocked => "udp_flow_locked",
        }
    }
}

fn stage_component_status(stage: ProxyPipelineStage) -> (OperationalState, &'static str) {
    match stage {
        ProxyPipelineStage::TcpObserved => (
            OperationalState::Active,
            "已观察到代理 TCP；等待 MNA 控制连接",
        ),
        ProxyPipelineStage::MnaMagicObserved => (
            OperationalState::Active,
            "已识别 MNA 控制流；等待 ServerHello",
        ),
        ProxyPipelineStage::MnaServerHelloObserved => (
            OperationalState::Active,
            "已捕获 MNA ServerHello；正在恢复会话密钥",
        ),
        ProxyPipelineStage::MnaKeyRecovered => {
            (OperationalState::Active, "MNA 会话密钥已恢复；等待进局通知")
        }
        ProxyPipelineStage::MnaSessionObserved | ProxyPipelineStage::MaterialInstalled => {
            (OperationalState::Active, "会话材料已逐字段验证；等待主 UDP")
        }
        ProxyPipelineStage::UdpCandidateObserved => (
            OperationalState::Active,
            codev_obf::s_static("e589fc142d0cecb9b0d7ce685e25acd6ab91a970005d93b5206b0aa2560692d7ad9dab6e1153a3bde891cfd2eafd475474111e93dad16c45485f2096d5df7b1e557b"),
        ),
        ProxyPipelineStage::UdpLocked => (OperationalState::Active, "主 UDP 已验证并锁定"),
        ProxyPipelineStage::MnaDataWithoutKey => (
            OperationalState::Awaiting,
            "看到了 MNA DATA，但未捕获 ServerHello；请在启用代理后彻底结束并冷启动游戏",
        ),
        ProxyPipelineStage::UdpWithoutMaterial => (
            OperationalState::Awaiting,
            "UDP 已到达但没有会话材料；保持 UDP 转发开启并冷启动游戏以捕获控制连接",
        ),
        ProxyPipelineStage::UdpOodleBlocked => (
            OperationalState::Blocked,
            "主 UDP 命中 Oodle 压缩边界，当前构建没有获授权解码器",
        ),
        ProxyPipelineStage::MnaFramingFailed
        | ProxyPipelineStage::MnaKeyRecoveryFailed
        | ProxyPipelineStage::MnaDecryptFailed
        | ProxyPipelineStage::MnaPaddingFailed
        | ProxyPipelineStage::MnaApplicationFailed => (
            OperationalState::Opaque,
            "MNA 控制流未通过当前构建的严格验证；等待新的冷启动控制连接",
        ),
    }
}

fn stage_pipeline_health(stage: ProxyPipelineStage) -> PipelineHealth {
    match stage {
        ProxyPipelineStage::UdpLocked => PipelineHealth::Healthy,
        ProxyPipelineStage::UdpOodleBlocked => PipelineHealth::Unrecoverable,
        ProxyPipelineStage::MnaFramingFailed
        | ProxyPipelineStage::MnaKeyRecoveryFailed
        | ProxyPipelineStage::MnaDecryptFailed
        | ProxyPipelineStage::MnaPaddingFailed
        | ProxyPipelineStage::MnaApplicationFailed => PipelineHealth::Degraded,
        ProxyPipelineStage::UdpWithoutMaterial
        | ProxyPipelineStage::MnaDataWithoutKey
        | ProxyPipelineStage::TcpObserved
        | ProxyPipelineStage::MnaMagicObserved
        | ProxyPipelineStage::MnaServerHelloObserved
        | ProxyPipelineStage::MnaKeyRecovered
        | ProxyPipelineStage::MnaSessionObserved
        | ProxyPipelineStage::MaterialInstalled
        | ProxyPipelineStage::UdpCandidateObserved => PipelineHealth::Awaiting,
    }
}

fn stage_session_status(stage: ProxyPipelineStage) -> Option<(SessionStatus, &'static str)> {
    match stage {
        ProxyPipelineStage::MnaDataWithoutKey => Some((
            SessionStatus::AwaitingSession,
            "已看到 MNA DATA，但缺少同一连接的 ServerHello；代理需在游戏启动前启用",
        )),
        ProxyPipelineStage::UdpWithoutMaterial => Some((
            SessionStatus::AwaitingSession,
            "UDP 已进入代理，但未捕获完整 MNA 控制连接；保持 UDP 转发开启并冷启动游戏",
        )),
        ProxyPipelineStage::UdpOodleBlocked => Some((
            SessionStatus::Degraded,
            "UDP 已认证到 Oodle 压缩边界；缺少获授权解码器",
        )),
        ProxyPipelineStage::MnaFramingFailed
        | ProxyPipelineStage::MnaKeyRecoveryFailed
        | ProxyPipelineStage::MnaDecryptFailed
        | ProxyPipelineStage::MnaPaddingFailed
        | ProxyPipelineStage::MnaApplicationFailed => Some((
            SessionStatus::AwaitingSession,
            "MNA 严格验证失败；等待新的完整控制连接",
        )),
        _ => None,
    }
}

/// 本机身份的哈希（uid 的 FNV-1a），存在引擎目录的 `self-identity.json`：
/// `{ "uid_fnv1a_64": "0x...." }`。只读，不写。没有文件就退回"唯一带设备字段的那条"。
/// 原始 uid / 账号串永不落盘、永不下发。
fn known_self_key() -> Option<u64> {
    use std::sync::OnceLock;
    static KEY: OnceLock<Option<u64>> = OnceLock::new();
    *KEY.get_or_init(|| {
        let path = std::env::var_os("CODEV_SELF_IDENTITY")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                Some(dirs_support_dir()?.join("Phoenix CodeV/LocalEngine/self-identity.json"))
            });
        let path = path?;
        let text = std::fs::read_to_string(path).ok()?;
        let value: serde_json::Value = serde_json::from_str(&text).ok()?;
        let raw = value.get("uid_fnv1a_64")?.as_str()?;
        let raw = raw.trim_start_matches("0x");
        u64::from_str_radix(raw, 16).ok()
    })
}

fn dirs_support_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(|home| std::path::PathBuf::from(home).join("Library/Application Support"))
}

fn roster_from_material(material: &SessionMaterial) -> Vec<codev_web::RosterEntry> {
    material
        .roster
        .iter()
        .map(|entry| codev_web::RosterEntry {
            // MNA roster 数组序号不是 BatchData.slot；在引擎完成稳定贴槽前
            // 必须保持未绑定，避免首帧把英雄头像贴到错误玩家。
            slot: None,
            display_name: if entry.display_name.is_empty() {
                "unbound".to_owned()
            } else {
                entry.display_name.clone()
            },
            agent_id: entry.agent_id,
            camp_id: entry.camp_id,
            // 只保留 MNA 的阵营/位次元数据；具体 BatchData.slot 由稳定贴槽阶段填写。
            position_slot: Some(entry.position_slot),
            device_tag: entry.device_tag,
            identity_confidence: codev_stream::IdentityConfidence::Unresolved,
        })
        .collect()
}

fn install_material(state: &Arc<Mutex<ProxyDecodeState>>, material: &SessionMaterial) -> bool {
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let generation = state.channel_generation.saturating_add(1_u64 << 32);
    install_material_locked(&mut state, material, generation)
}

fn install_material_at_generation(
    state: &Arc<Mutex<ProxyDecodeState>>,
    material: &SessionMaterial,
    generation: u64,
) -> bool {
    let mut state = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    install_material_locked(&mut state, material, generation)
}

fn install_material_locked(
    state: &mut ProxyDecodeState,
    material: &SessionMaterial,
    generation: u64,
) -> bool {
    if state
        .installed_material
        .as_ref()
        .is_some_and(|(session_id, observed_ns)| {
            session_id == &material.session_id && *observed_ns == material.observed_ns
        })
        && state.channel_generation == generation
    {
        return false;
    }
    state.cipher = Some(material.cipher());
    state.map_id = material.map_id;
    state.roster_seats = material
        .roster
        .iter()
        .map(|entry| codev_stream::RosterSeat {
            camp_id: u64::from(entry.camp_id),
            agent_id: entry.agent_id,
            position_slot: entry.position_slot,
            device_tag: entry.device_tag,
            self_key: entry.self_key,
        })
        .collect();
    let mut expected_servers = Vec::new();
    for host in [
        Some(material.server_host.as_str()),
        material.server_vip.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(endpoint) = endpoint_from_host(host, material.server_port)
            && !expected_servers.contains(&endpoint)
        {
            expected_servers.push(endpoint);
        }
    }
    state.expected_server = expected_servers.first().copied();
    state.expected_servers = expected_servers.clone();
    state.expected_server_port = material.server_port;
    state.allow_public_server_port_candidate =
        material.server_host.parse::<std::net::IpAddr>().is_err();
    let dynamic_targets: Vec<_> = expected_servers
        .iter()
        .filter_map(|endpoint| socket_addr_from_endpoint(*endpoint))
        .collect();
    state
        .dynamic_targets
        .replace_session_targets(&dynamic_targets, material.server_port);
    state.channel_generation = generation;
    state.pipelines.clear();
    state.candidate_started_ns.clear();
    state.migrated_flow_ids.clear();
    state.locked_flow_id = None;
    state.installed_material = Some((material.session_id.clone(), material.observed_ns));
    true
}

struct CompositePlaintextSink {
    recorder: Option<Arc<PlaintextRecorder>>,
    extractor: Arc<SessionExtractionSink>,
    status_sender: mpsc::Sender<ProxySessionUpdate>,
    recording_notified: Arc<AtomicBool>,
}

impl PlaintextSink for CompositePlaintextSink {
    fn observe(&self, record: codev_https::PlaintextRecord<'_>) -> io::Result<()> {
        if let Some(recorder) = self.recorder.as_ref() {
            match recorder.record(record) {
                Ok(true) => {}
                Ok(false) => self.notify_recording_stop(recorder),
                Err(error) => {
                    self.notify_recording_stop(recorder);
                    return Err(error);
                }
            }
        }
        self.extractor.observe(record)
    }
}

impl CompositePlaintextSink {
    fn notify_recording_stop(&self, recorder: &PlaintextRecorder) {
        if self.recording_notified.swap(true, Ordering::AcqRel) {
            return;
        }
        let detail = recorder
            .status()
            .stop_reason
            .unwrap_or_else(|| "录制 sink 停止".into());
        let _ = self
            .status_sender
            .try_send(ProxySessionUpdate::RecordingStopped { detail });
    }
}

struct ProxyEventForwarder {
    sender: mpsc::Sender<ProxySessionUpdate>,
    tcp_closed_sender: std_mpsc::Sender<(u64, u64)>,
    pcap_recorder: Option<ProxyPcapRecorder>,
}

impl ProxyEventSink for ProxyEventForwarder {
    fn emit(&self, event: ProxyEvent) {
        match event {
            ProxyEvent::TcpConnectionClosed { flow_id, .. } => {
                // The parser worker owns the MNA flow map. Forward closure on
                // a separate non-blocking channel so ordinary global-proxy
                // TCP traffic does not occupy historical MNA probe slots.
                let capture_ns = super::now_ns();
                if let Some(recorder) = self.pcap_recorder.as_ref() {
                    recorder.tcp_closed(flow_id, capture_ns);
                }
                let _ = self.tcp_closed_sender.send((flow_id, capture_ns));
                let _ = self.sender.try_send(ProxySessionUpdate::TcpClosed {
                    flow_id,
                    capture_ns,
                });
            }
            event => {
                let _ = self.sender.try_send(ProxySessionUpdate::Event(event));
            }
        }
    }
}

#[derive(Debug)]
enum ProxySessionUpdate {
    Mna {
        flow_id: u64,
        capture_ns: u64,
        session: EnterGameSession,
    },
    Material(SessionMaterial),
    Event(ProxyEvent),
    TcpClosed {
        flow_id: u64,
        capture_ns: u64,
    },
    Stage {
        capture_ns: u64,
        stage: ProxyPipelineStage,
    },
    UdpLocked {
        capture_ns: u64,
    },
    PipelineError {
        capture_ns: u64,
        detail: String,
    },
    RecordingStopped {
        detail: String,
    },
    TokenStoreReloaded,
    TokenStoreError {
        detail: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyPipelineStage {
    TcpObserved,
    MnaMagicObserved,
    MnaServerHelloObserved,
    MnaKeyRecovered,
    MnaDataWithoutKey,
    MnaFramingFailed,
    MnaKeyRecoveryFailed,
    MnaDecryptFailed,
    MnaPaddingFailed,
    MnaApplicationFailed,
    MnaSessionObserved,
    MaterialInstalled,
    UdpWithoutMaterial,
    UdpCandidateObserved,
    UdpOodleBlocked,
    UdpLocked,
}

struct ProxyActorBatch {
    session_generation: u64,
    actors: Vec<codev_stream::A0Payload>,
    gaps: Vec<PipelineGap>,
}

#[derive(Default)]
struct ProxyDecodeState {
    cipher: Option<codev_stream::C0Cipher>,
    map_id: Option<u32>,
    dynamic_targets: DynamicTargetStore,
    expected_server: Option<Endpoint>,
    expected_servers: Vec<Endpoint>,
    expected_server_port: u16,
    allow_public_server_port_candidate: bool,
    channel_generation: u64,
    pipelines: HashMap<u64, P0Pipeline>,
    candidate_started_ns: HashMap<u64, u64>,
    /// SOCKS5 UDP association flow IDs already joined to the selected game
    /// stream. Shadowrocket may recreate an association while the UE session
    /// and remote game endpoint remain unchanged.
    migrated_flow_ids: HashSet<u64>,
    locked_flow_id: Option<u64>,
    installed_material: Option<(SessionId, u64)>,
    /// 当前会话的 MNA roster（英雄编号 / 阵营 / 阵营内位次 / 是否真人）。
    /// 贴槽要用它跟 BatchData 槽位对齐，所以必须跟着 material 一起换。
    roster_seats: Vec<codev_stream::RosterSeat>,
}

#[derive(Default)]
struct ProxyRuntimeCounters {
    actor_messages: AtomicU64,
    coordinate_updates: AtomicU64,
    parse_failures: AtomicU64,
    tcp_observed: AtomicU64,
    mna_magic_observed: AtomicU64,
    mna_server_hello_observed: AtomicU64,
    mna_keys_recovered: AtomicU64,
    mna_data_without_key: AtomicU64,
    mna_failures: AtomicU64,
    mna_data_decrypted: AtomicU64,
    mna_application_messages: AtomicU64,
    mna_session_parse_failures: AtomicU64,
    mna_ordinary_flows_evicted: AtomicU64,
    mna_control_flows_evicted: AtomicU64,
    mna_authenticated_layout_sessions: AtomicU64,
    mna_command_counts: Mutex<BTreeMap<u64, u64>>,
    mna_sessions_observed: AtomicU64,
    materials_installed: AtomicU64,
    udp_without_material: AtomicU64,
    udp_candidates_observed: AtomicU64,
    udp_candidates_rejected: AtomicU64,
    udp_flows_locked: AtomicU64,
    udp_association_migrations: AtomicU64,
    actor_updates_decoded: AtomicU64,
    actor_updates_invalid: AtomicU64,
}

struct ProxyFrameTap {
    mna: HashMap<u64, ProxyMnaFlow>,
    pcap_recorder: Option<ProxyPcapRecorder>,
    tcp_closed_receiver: std_mpsc::Receiver<(u64, u64)>,
    pending_tcp_closures: HashMap<u64, u64>,
    session_sender: mpsc::Sender<ProxySessionUpdate>,
    actor_sender: mpsc::Sender<ProxyActorBatch>,
    state: Arc<Mutex<ProxyDecodeState>>,
    counters: Arc<ProxyRuntimeCounters>,
    next_capture_index: u64,
    announced_tcp: bool,
    announced_udp_without_material: bool,
    announced_udp_candidate: bool,
    observed_generation: u64,
}

impl ProxyFrameTap {
    #[cfg(test)]
    fn new(
        session_sender: mpsc::Sender<ProxySessionUpdate>,
        actor_sender: mpsc::Sender<ProxyActorBatch>,
        state: Arc<Mutex<ProxyDecodeState>>,
        counters: Arc<ProxyRuntimeCounters>,
    ) -> Self {
        let (_tcp_closed_sender, tcp_closed_receiver) = std_mpsc::channel();
        Self::new_with_tcp_close_receiver(
            session_sender,
            actor_sender,
            state,
            counters,
            tcp_closed_receiver,
            None,
        )
    }

    fn new_with_tcp_close_receiver(
        session_sender: mpsc::Sender<ProxySessionUpdate>,
        actor_sender: mpsc::Sender<ProxyActorBatch>,
        state: Arc<Mutex<ProxyDecodeState>>,
        counters: Arc<ProxyRuntimeCounters>,
        tcp_closed_receiver: std_mpsc::Receiver<(u64, u64)>,
        pcap_recorder: Option<ProxyPcapRecorder>,
    ) -> Self {
        Self {
            mna: HashMap::new(),
            pcap_recorder,
            tcp_closed_receiver,
            pending_tcp_closures: HashMap::new(),
            session_sender,
            actor_sender,
            state,
            counters,
            next_capture_index: 0,
            announced_tcp: false,
            announced_udp_without_material: false,
            announced_udp_candidate: false,
            observed_generation: 0,
        }
    }
}

impl FrameTap for ProxyFrameTap {
    fn observe(&mut self, frame: &FrameEnvelope) {
        if let Some(recorder) = self.pcap_recorder.as_ref() {
            recorder.record(frame);
        }
        match frame.transport {
            Transport::Tcp => self.observe_tcp(frame),
            Transport::Udp => self.observe_udp(frame),
        }
    }

    /// 告诉 frame-parser worker 下一次必须醒来 `poll` 的时刻：
    ///   * 有 TCP 流在关闭宽限期内 → 宽限到期那一刻（原来是每 10ms 醒一次来查）；
    ///   * 有 reorder gap 待释放（UDP 50ms 序号窗口）→ 死线那一刻；
    ///     这条以前是靠 proxy_runtime 里另起一个 100Hz 定时任务"兜底"的，
    ///     但那个任务调用的 `TapHandle::poll` 是空实现，实际上一直是本 worker
    ///     在按 10ms 无条件轮询时顺手释放的。把死线并进来之后，释放时机
    ///     与原来一致（误差仍在 10ms 以内），而空闲时不必再空轮询；
    ///   * 有锁定中的管线（正在解析的 UDP/TCP 流）→ 保持原来的 10ms 节奏；
    ///   * 什么都没有 → `None`，worker 进入低频空闲等待（这就是空转 CPU 的来源）。
    fn next_deadline_ns(&self) -> Option<u64> {
        let now = epoch_ns();
        let mut deadline: Option<u64> = None;
        for closed_ns in self.pending_tcp_closures.values() {
            let due = closed_ns.saturating_add(TCP_CLOSE_STATE_GRACE_NS);
            deadline = Some(deadline.map_or(due, |current: u64| current.min(due)));
        }
        let (locked, reorder_due) = {
            let state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (
                state.locked_flow_id.is_some(),
                state
                    .pipelines
                    .values()
                    .filter_map(P0Pipeline::next_reorder_deadline_ns)
                    .min(),
            )
        };
        if let Some(due) = reorder_due {
            deadline = Some(deadline.map_or(due, |current: u64| current.min(due)));
        }
        if locked {
            let soon = now.saturating_add(10_000_000);
            deadline = Some(deadline.map_or(soon, |current: u64| current.min(soon)));
        }
        deadline
    }

    fn poll(&mut self, now_ns: u64) {
        while let Ok((flow_id, closed_ns)) = self.tcp_closed_receiver.try_recv() {
            self.pending_tcp_closures.insert(flow_id, closed_ns);
        }
        let closed_flows: Vec<u64> = self
            .pending_tcp_closures
            .iter()
            .filter(|(_, closed_ns)| now_ns.saturating_sub(**closed_ns) >= TCP_CLOSE_STATE_GRACE_NS)
            .map(|(flow_id, _)| *flow_id)
            .collect();
        for flow_id in closed_flows {
            self.pending_tcp_closures.remove(&flow_id);
            self.mna.remove(&flow_id);
        }
        let mut actors = Vec::new();
        let mut gaps = Vec::new();
        let generation_base;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            generation_base = state.channel_generation;
            let locked_flow_id = state.locked_flow_id;
            let flow_ids: Vec<u64> = locked_flow_id.into_iter().collect();
            for flow_id in flow_ids {
                let Some(pipeline) = state.pipelines.get_mut(&flow_id) else {
                    continue;
                };
                match pipeline.poll_timeout(now_ns) {
                    Ok(mut released) => actors.append(&mut released),
                    Err(error) => {
                        pipeline.mark_capture_gap(now_ns);
                        gaps.extend(pipeline.drain_gaps());
                        let _ = self
                            .session_sender
                            .try_send(ProxySessionUpdate::PipelineError {
                                capture_ns: now_ns,
                                detail: error.to_string(),
                            });
                    }
                }
                gaps.extend(pipeline.drain_gaps());
            }
        }
        for actor in &mut actors {
            actor.channel_generation = generation_base.saturating_add(actor.channel_generation);
        }
        if (!actors.is_empty() || !gaps.is_empty())
            && self
                .actor_sender
                .try_send(ProxyActorBatch {
                    session_generation: generation_base,
                    actors,
                    gaps,
                })
                .is_err()
        {
            let _ = self
                .session_sender
                .try_send(ProxySessionUpdate::PipelineError {
                    capture_ns: now_ns,
                    detail: "proxy actor queue overflow or closed".into(),
                });
        }
    }

    fn on_capture_gap(&mut self, now_ns: u64) {
        // A full tee queue means the parser has an unknown hole in the wire
        // stream. Invalidate every stateful branch before accepting the next
        // frame; this prevents a stale baseline from being presented as a
        // continuous coordinate sample.
        self.mna.clear();
        let mut gaps = Vec::new();
        let generation;
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            generation = state.channel_generation;
            state.candidate_started_ns.clear();
            for pipeline in state.pipelines.values_mut() {
                pipeline.mark_capture_gap(now_ns);
                gaps.extend(pipeline.drain_gaps());
            }
        }
        self.counters.parse_failures.fetch_add(1, Ordering::Relaxed);
        let _ = self
            .session_sender
            .try_send(ProxySessionUpdate::PipelineError {
                capture_ns: now_ns,
                detail: "capture parser queue overflow; baselines invalidated".into(),
            });
        if !gaps.is_empty()
            && self
                .actor_sender
                .try_send(ProxyActorBatch {
                    session_generation: generation,
                    actors: Vec::new(),
                    gaps,
                })
                .is_err()
        {
            let _ = self
                .session_sender
                .try_send(ProxySessionUpdate::PipelineError {
                    capture_ns: now_ns,
                    detail: "capture gap notification queue overflow".into(),
                });
        }
    }
}

#[derive(Default)]
struct ProxyMnaFlow {
    client: W0Framer,
    server: W0Framer,
    client_candidate: Option<bool>,
    server_candidate: Option<bool>,
    /// Bytes used to classify a SOCKS TCP flow as MNA.  The proxy tap sees
    /// already-ordered relay chunks, but a read boundary may split the six
    /// byte magic.  Keep only that bounded prefix until it is decisive; do
    /// not scan arbitrary application bytes for a magic sequence.
    client_probe: Vec<u8>,
    server_probe: Vec<u8>,
    key: Option<Zeroizing<[u8; 16]>>,
    last_capture_ns: u64,
}

impl ProxyMnaFlow {
    fn should_preserve_under_pressure(&self) -> bool {
        self.key.is_some()
            || self.client_candidate == Some(true)
            || (self.client_candidate.is_none() && !self.client_probe.is_empty())
    }
}

impl ProxyFrameTap {
    fn observe_tcp(&mut self, frame: &FrameEnvelope) {
        self.counters.tcp_observed.fetch_add(1, Ordering::Relaxed);
        if !self.announced_tcp {
            self.announced_tcp = true;
            let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                capture_ns: frame.capture_ns,
                stage: ProxyPipelineStage::TcpObserved,
            });
        }
        if !self.mna.contains_key(&frame.flow_id)
            && self.mna.len() >= MAX_PROXY_MNA_FLOWS
            && let Some((evicted, preserved_mna)) = self
                .mna
                .iter()
                .filter(|(_, flow)| !flow.should_preserve_under_pressure())
                .min_by_key(|(_, flow)| flow.last_capture_ns)
                .map(|(flow_id, _)| (*flow_id, false))
                .or_else(|| {
                    self.mna
                        .iter()
                        .min_by_key(|(_, flow)| flow.last_capture_ns)
                        .map(|(flow_id, _)| (*flow_id, true))
                })
        {
            // Closed flows are normally removed through the event channel.
            // Under concurrent pressure, discard an old ordinary/non-MNA
            // probe before touching a confirmed or partially matched MNA
            // control flow. Only loss of preserved MNA state is a parser
            // failure that requires a fresh authenticated session.
            self.mna.remove(&evicted);
            if preserved_mna {
                self.counters
                    .mna_control_flows_evicted
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self
                    .session_sender
                    .try_send(ProxySessionUpdate::PipelineError {
                        capture_ns: frame.capture_ns,
                        detail: "confirmed MNA flow state evicted under exceptional capacity pressure; awaiting a fresh authenticated session"
                            .into(),
                    });
            } else {
                self.counters
                    .mna_ordinary_flows_evicted
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let flow = self.mna.entry(frame.flow_id).or_default();
        flow.last_capture_ns = frame.capture_ns;
        let (framer, candidate, probe) = match frame.direction {
            Direction::ClientToServer => (
                &mut flow.client,
                &mut flow.client_candidate,
                &mut flow.client_probe,
            ),
            Direction::ServerToClient => (
                &mut flow.server,
                &mut flow.server_candidate,
                &mut flow.server_probe,
            ),
        };
        let bytes = if candidate.is_none() {
            if frame.payload.is_empty() {
                return;
            }
            let needed = MNA_MAGIC.len().saturating_sub(probe.len());
            let take = needed.min(frame.payload.len());
            probe.extend_from_slice(&frame.payload[..take]);
            if !MNA_MAGIC.starts_with(probe) {
                *candidate = Some(false);
                return;
            }
            if probe.len() < MNA_MAGIC.len() {
                // The next relay chunk may contain the rest of the magic.
                return;
            }
            *candidate = Some(true);
            if self
                .counters
                .mna_magic_observed
                .fetch_add(1, Ordering::Relaxed)
                == 0
            {
                let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                    capture_ns: frame.capture_ns,
                    stage: ProxyPipelineStage::MnaMagicObserved,
                });
            }
            let mut combined = Vec::with_capacity(probe.len() + frame.payload.len() - take);
            combined.extend_from_slice(probe);
            combined.extend_from_slice(&frame.payload[take..]);
            std::borrow::Cow::Owned(combined)
        } else {
            std::borrow::Cow::Borrowed(frame.payload.as_slice())
        };
        if *candidate != Some(true) {
            return;
        }
        let frames = match framer.feed(bytes.as_ref()) {
            Ok(frames) => frames,
            Err(_) => {
                if self.counters.mna_failures.fetch_add(1, Ordering::Relaxed) == 0 {
                    let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                        capture_ns: frame.capture_ns,
                        stage: ProxyPipelineStage::MnaFramingFailed,
                    });
                }
                *candidate = Some(false);
                return;
            }
        };
        for message in frames {
            if message.message_type == MNA_SERVER_HELLO {
                if self
                    .counters
                    .mna_server_hello_observed
                    .fetch_add(1, Ordering::Relaxed)
                    == 0
                {
                    let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                        capture_ns: frame.capture_ns,
                        stage: ProxyPipelineStage::MnaServerHelloObserved,
                    });
                }
                match recover_mna_session_key(std::slice::from_ref(&message)) {
                    Ok(key) => {
                        flow.key = Some(key);
                        if self
                            .counters
                            .mna_keys_recovered
                            .fetch_add(1, Ordering::Relaxed)
                            == 0
                        {
                            let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                                capture_ns: frame.capture_ns,
                                stage: ProxyPipelineStage::MnaKeyRecovered,
                            });
                        }
                    }
                    Err(_) => {
                        if self.counters.mna_failures.fetch_add(1, Ordering::Relaxed) == 0 {
                            let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                                capture_ns: frame.capture_ns,
                                stage: ProxyPipelineStage::MnaKeyRecoveryFailed,
                            });
                        }
                    }
                }
                continue;
            }
            if message.message_type != MNA_DATA {
                continue;
            }
            let Some(key) = flow.key.as_deref() else {
                if self
                    .counters
                    .mna_data_without_key
                    .fetch_add(1, Ordering::Relaxed)
                    == 0
                {
                    let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                        capture_ns: frame.capture_ns,
                        stage: ProxyPipelineStage::MnaDataWithoutKey,
                    });
                }
                continue;
            };
            let mut plaintext = match decrypt_mna_frame(&message, key) {
                Ok(plaintext) => plaintext,
                Err(_) => {
                    if self.counters.mna_failures.fetch_add(1, Ordering::Relaxed) == 0 {
                        let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                            capture_ns: frame.capture_ns,
                            stage: ProxyPipelineStage::MnaDecryptFailed,
                        });
                    }
                    continue;
                }
            };
            self.counters
                .mna_data_decrypted
                .fetch_add(1, Ordering::Relaxed);
            if strip_mna_random_padding(&mut plaintext).is_err() {
                if self.counters.mna_failures.fetch_add(1, Ordering::Relaxed) == 0 {
                    let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                        capture_ns: frame.capture_ns,
                        stage: ProxyPipelineStage::MnaPaddingFailed,
                    });
                }
                continue;
            }
            let mut recovered_session = None;
            let mut authenticated_layout = false;
            let application = match parse_mna_application(
                &plaintext,
                message.direction_marker,
                message.sequence,
            ) {
                Ok(application) => Some(application),
                Err(error) => {
                    if self.counters.mna_failures.fetch_add(1, Ordering::Relaxed) == 0 {
                        eprintln!(
                            "[codev-mna] application_parse_failed error={error} direction={} sequence={} plaintext_len={}",
                            message.direction_marker,
                            message.sequence,
                            plaintext.len()
                        );
                        let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                            capture_ns: frame.capture_ns,
                            stage: ProxyPipelineStage::MnaApplicationFailed,
                        });
                    }
                    None
                }
            };
            if let Some(application) = application.as_ref() {
                self.counters
                    .mna_application_messages
                    .fetch_add(1, Ordering::Relaxed);
                {
                    let mut command_counts = self
                        .counters
                        .mna_command_counts
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if command_counts.contains_key(&application.head.command_id)
                        || command_counts.len() < MAX_MNA_COMMAND_IDS
                    {
                        let count = command_counts
                            .entry(application.head.command_id)
                            .or_default();
                        *count = count.saturating_add(1);
                    }
                }
                match parse_enter_game_session(application) {
                    Ok(Some(session)) => {
                        authenticated_layout = !matches!(
                            application.head.command_id,
                            ENTER_GAME_NOTIFY_COMMAND | REENTER_GAME_NOTIFY_COMMAND
                        );
                        recovered_session = Some(session);
                    }
                    Ok(None) => {}
                    Err(_) => {
                        self.counters
                            .mna_session_parse_failures
                            .fetch_add(1, Ordering::Relaxed);
                        // Non-session MNA application messages are expected. Only
                        // a descriptor claiming Enter/ReEnter can reach an error
                        // here, and the parser keeps that distinction private.
                    }
                }
            }
            if recovered_session.is_none()
                && let Some(parsed) = recover_embedded_enter_game_session_with_evidence(
                    &plaintext,
                    message.direction_marker,
                    message.sequence,
                )
            {
                authenticated_layout = true;
                recovered_session = Some(parsed.session);
            }
            let Some(session) = recovered_session else {
                continue;
            };
            if authenticated_layout {
                self.counters
                    .mna_authenticated_layout_sessions
                    .fetch_add(1, Ordering::Relaxed);
            }
            self.counters
                .mna_sessions_observed
                .fetch_add(1, Ordering::Relaxed);
            let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                capture_ns: frame.capture_ns,
                stage: ProxyPipelineStage::MnaSessionObserved,
            });
            let _ = self.session_sender.try_send(ProxySessionUpdate::Mna {
                flow_id: frame.flow_id,
                capture_ns: frame.capture_ns,
                session,
            });
        }
    }

    fn observe_udp(&mut self, frame: &FrameEnvelope) {
        let Some(route) = frame.route else {
            return;
        };
        self.next_capture_index = self.next_capture_index.saturating_add(1);
        let capture_index = self.next_capture_index;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.observed_generation != state.channel_generation {
            self.observed_generation = state.channel_generation;
            self.announced_udp_without_material = false;
            self.announced_udp_candidate = false;
        }
        let generation_base = state.channel_generation;
        let Some(cipher) = state.cipher.clone() else {
            self.counters
                .udp_without_material
                .fetch_add(1, Ordering::Relaxed);
            if !self.announced_udp_without_material {
                self.announced_udp_without_material = true;
                let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                    capture_ns: frame.capture_ns,
                    stage: ProxyPipelineStage::UdpWithoutMaterial,
                });
            }
            return;
        };
        let (client, server) = match frame.direction {
            Direction::ClientToServer => (route.source, route.destination),
            Direction::ServerToClient => (route.destination, route.source),
        };
        let client = socket_endpoint(client);
        let server = socket_endpoint(server);
        if !udp_server_matches_any(
            &state.expected_servers,
            state.expected_server_port,
            state.allow_public_server_port_candidate,
            server,
        ) {
            return;
        }
        let transport = codev_stream::TransportPacket {
            capture_index,
            timestamp_ns: frame.capture_ns,
            source: if frame.direction == Direction::ClientToServer {
                client
            } else {
                server
            },
            destination: if frame.direction == Direction::ClientToServer {
                server
            } else {
                client
            },
            kind: TransportKind::Udp,
            tcp_sequence: None,
            tcp_flags: 0,
            payload: &frame.payload,
        };
        let mut locked_now = false;
        let (mut actors, gaps) = if let Some(locked_flow_id) = state.locked_flow_id {
            let is_original_flow = locked_flow_id == frame.flow_id;
            let same_game_session = state
                .pipelines
                .get(&locked_flow_id)
                .is_some_and(|pipeline| {
                    pipeline.server() == server && pipeline.client().ip == client.ip
                });
            if !is_original_flow && !same_game_session {
                return;
            }
            // codev-proxy assigns a new flow_id for every SOCKS5 UDP
            // association. Shadowrocket can recreate that association during
            // a match, changing the client UDP port while retaining the same
            // authenticated phone IP and exact game server endpoint. Keep the
            // proven SGNet/UE decoder and its baselines instead of silently
            // abandoning all packets on the replacement association.
            if !is_original_flow && state.migrated_flow_ids.insert(frame.flow_id) {
                self.counters
                    .udp_association_migrations
                    .fetch_add(1, Ordering::Relaxed);
            }
            let pipeline = state
                .pipelines
                .entry(locked_flow_id)
                .or_insert_with(|| P0Pipeline::new(cipher, client, server));
            match pipeline.push_datagram(
                match frame.direction {
                    Direction::ClientToServer => codev_stream::Direction::ClientToServer,
                    Direction::ServerToClient => codev_stream::Direction::ServerToClient,
                },
                capture_index,
                frame.capture_ns,
                &frame.payload,
            ) {
                Ok(actors) => (actors, pipeline.drain_gaps()),
                Err(error) => {
                    pipeline.mark_capture_gap(frame.capture_ns);
                    let gaps = pipeline.drain_gaps();
                    let _ = self
                        .session_sender
                        .try_send(ProxySessionUpdate::PipelineError {
                            capture_ns: frame.capture_ns,
                            detail: error.to_string(),
                        });
                    (Vec::new(), gaps)
                }
            }
        } else {
            self.counters
                .udp_candidates_observed
                .fetch_add(1, Ordering::Relaxed);
            if !self.announced_udp_candidate {
                self.announced_udp_candidate = true;
                let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                    capture_ns: frame.capture_ns,
                    stage: ProxyPipelineStage::UdpCandidateObserved,
                });
            }
            // Keep one bounded trial pipeline per tuple.  The first datagram
            // is often a reliable/ack packet without an actor bunch; creating
            // a fresh decoder for every datagram used to reject the real game
            // stream before its first UE payload arrived.
            if !state.candidate_started_ns.contains_key(&frame.flow_id)
                && state.candidate_started_ns.len() >= MAX_UDP_CANDIDATE_FLOWS
                && let Some((evicted_flow, _)) = state
                    .candidate_started_ns
                    .iter()
                    .min_by_key(|(_, started)| **started)
                    .map(|(flow_id, started)| (*flow_id, *started))
            {
                state.candidate_started_ns.remove(&evicted_flow);
                state.pipelines.remove(&evicted_flow);
                self.counters
                    .udp_candidates_rejected
                    .fetch_add(1, Ordering::Relaxed);
            }
            let started_ns = *state
                .candidate_started_ns
                .entry(frame.flow_id)
                .or_insert(frame.capture_ns);
            let mut trial = state
                .pipelines
                .remove(&frame.flow_id)
                .unwrap_or_else(|| P0Pipeline::new(cipher, client, server));
            let actors = match trial.push_transport(&transport) {
                Ok(actors) => actors,
                Err(_) => {
                    state.candidate_started_ns.remove(&frame.flow_id);
                    self.counters
                        .udp_candidates_rejected
                        .fetch_add(1, Ordering::Relaxed);
                    return;
                }
            };
            let stats = trial.stats();
            if stats.oodle_compressed > 0 {
                let _ = self.session_sender.try_send(ProxySessionUpdate::Stage {
                    capture_ns: frame.capture_ns,
                    stage: ProxyPipelineStage::UdpOodleBlocked,
                });
            }
            if !udp_trial_is_valid(stats)
                && (stats.datagrams >= UDP_CANDIDATE_MAX_DATAGRAMS
                    || frame.capture_ns.saturating_sub(started_ns) >= UDP_CANDIDATE_MAX_AGE_NS)
            {
                state.candidate_started_ns.remove(&frame.flow_id);
                self.counters
                    .udp_candidates_rejected
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let gaps = trial.drain_gaps();
            if udp_trial_is_valid(stats) {
                // A proven tuple is the only point at which the temporary
                // session-port fallback is narrowed.  Other candidate flows
                // and their baselines are discarded atomically.
                state.pipelines.clear();
                state.candidate_started_ns.clear();
                state.migrated_flow_ids.clear();
                state.pipelines.insert(frame.flow_id, trial);
                state.locked_flow_id = Some(frame.flow_id);
                if let Some(address) = socket_addr_from_endpoint(server) {
                    state.dynamic_targets.lock_exact(address);
                }
                self.counters
                    .udp_flows_locked
                    .fetch_add(1, Ordering::Relaxed);
                locked_now = true;
                (actors, gaps)
            } else {
                state.pipelines.insert(frame.flow_id, trial);
                (Vec::new(), gaps)
            }
        };
        for actor in &mut actors {
            actor.channel_generation = generation_base.saturating_add(actor.channel_generation);
        }
        drop(state);
        if locked_now {
            let _ = self.session_sender.try_send(ProxySessionUpdate::UdpLocked {
                capture_ns: frame.capture_ns,
            });
        }
        if (!actors.is_empty() || !gaps.is_empty())
            && self
                .actor_sender
                .try_send(ProxyActorBatch {
                    session_generation: generation_base,
                    actors,
                    gaps,
                })
                .is_err()
        {
            let _ = self
                .session_sender
                .try_send(ProxySessionUpdate::PipelineError {
                    capture_ns: frame.capture_ns,
                    detail: "proxy actor queue overflow or closed".into(),
                });
        }
    }
}

fn socket_endpoint(address: SocketAddr) -> Endpoint {
    Endpoint {
        ip: match address.ip() {
            std::net::IpAddr::V4(value) => IpAddress::V4(value.octets()),
            std::net::IpAddr::V6(value) => IpAddress::V6(value.octets()),
        },
        port: address.port(),
    }
}

fn endpoint_from_host(host: &str, port: u16) -> Option<Endpoint> {
    let ip = host.parse::<std::net::IpAddr>().ok()?;
    Some(socket_endpoint(SocketAddr::new(ip, port)))
}

fn socket_addr_from_endpoint(endpoint: Endpoint) -> Option<SocketAddr> {
    let ip = match endpoint.ip {
        IpAddress::V4(value) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(value)),
        IpAddress::V6(value) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(value)),
    };
    Some(SocketAddr::new(ip, endpoint.port))
}

#[cfg(test)]
fn udp_server_matches(expected: Option<Endpoint>, expected_port: u16, actual: Endpoint) -> bool {
    if expected_port == 0 || actual.port != expected_port {
        return false;
    }
    expected.is_none_or(|expected| expected.ip == actual.ip)
}

fn udp_server_matches_any(
    expected: &[Endpoint],
    expected_port: u16,
    allow_public_port_candidate: bool,
    actual: Endpoint,
) -> bool {
    if expected_port == 0 || actual.port != expected_port {
        return false;
    }
    if expected.iter().any(|candidate| candidate.ip == actual.ip) {
        return true;
    }
    // A DNS session can legitimately resolve to an address different from
    // its separately advertised VIP. Admit only a public address on the
    // authenticated port until SGNet/PacketHandler/UE proves the tuple; the
    // policy and decoder both narrow to that exact address on lock.
    allow_public_port_candidate
        && socket_addr_from_endpoint(actual)
            .is_some_and(|address| ensure_public_ip(address.ip()).is_ok())
}

fn udp_trial_is_valid(stats: PipelineStats) -> bool {
    // The build-pinned reference capture starts with four authenticated
    // PacketHandler flag-one control/Oodle boundaries before its first
    // pass-through UE packet. Those boundaries invalidate continuity, but
    // they do not make a later independently proven UE packet ambiguous.
    // Require exact accounting for every accumulated datagram and at least
    // one fully decoded UE packet before locking the tuple.
    stats.datagrams > 0
        && stats.sgnet_decrypted > 0
        && stats.sgnet_wire_reencode_exact == stats.sgnet_decrypted
        && stats.packet_handler_envelopes_exact == stats.sgnet_decrypted
        && stats.packet_handler_pass_through > 0
        && stats.unreal_packets > 0
        && stats.unreal_packets == stats.packet_handler_pass_through
        && stats
            .packet_handler_pass_through
            .saturating_add(stats.oodle_compressed)
            == stats.sgnet_decrypted
}

fn actor_belongs_to_session(actor_generation: u64, session_generation: u64) -> bool {
    const LOCAL_CHANNEL_GENERATION_MAX: u64 = u32::MAX as u64;
    actor_generation >= session_generation
        && actor_generation - session_generation <= LOCAL_CHANNEL_GENERATION_MAX
}

#[allow(clippy::too_many_arguments)]
fn reset_round_binding_state(
    local_state_counts: &mut BTreeMap<u8, u64>,
    local_slots: &mut Vec<u8>,
    anchor_spawn: &mut Option<[f64; 3]>,
    anchor_slot: &mut Option<u8>,
    published_seat_plan: &mut Option<Vec<Option<u8>>>,
    published_self_slot: &mut Option<Option<u8>>,
    roster_plan_stabilizer: &mut codev_stream::RosterPlanStabilizer,
) {
    local_state_counts.clear();
    local_slots.clear();
    *anchor_spawn = None;
    *anchor_slot = None;
    *published_seat_plan = None;
    *published_self_slot = None;
    roster_plan_stabilizer.reset();
}

fn read_secret(path: &Path, ttl_secs: u64) -> Result<String, ProxyRuntimeError> {
    if let Some(parent) = path.parent() {
        let parent_metadata = parent.symlink_metadata()?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(ProxyRuntimeError::InvalidConfig(
                "secret parent must be a regular directory".into(),
            ));
        }
    }
    let metadata = path.symlink_metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_SECRET_BYTES {
        return Err(ProxyRuntimeError::InvalidConfig(
            "secret file must be a regular file under the size limit".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(ProxyRuntimeError::InvalidConfig(
                "secret file must be mode 0600".into(),
            ));
        }
    }
    let raw = std::fs::read_to_string(path)?.trim().to_owned();
    let (secret, embedded_expiry) = if let Some(rest) = raw.strip_prefix(PANEL_SECRET_PREFIX) {
        let rest = rest.strip_prefix(':').ok_or_else(|| {
            ProxyRuntimeError::InvalidConfig("panel secret has an invalid version prefix".into())
        })?;
        let (expiry, secret) = rest.split_once(':').ok_or_else(|| {
            ProxyRuntimeError::InvalidConfig("panel secret is missing its expiry".into())
        })?;
        let expiry = expiry.parse::<u64>().map_err(|_| {
            ProxyRuntimeError::InvalidConfig("panel secret expiry is not a uint64".into())
        })?;
        (secret.to_owned(), Some(expiry))
    } else {
        // Older installations stored only the secret. Keep a narrow
        // migration path, but bind its lifetime to the protected file mtime.
        let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default()
            .as_secs();
        if age > ttl_secs {
            return Err(ProxyRuntimeError::InvalidConfig(
                "legacy panel secret has expired; rotate it with `token create --scope panel`"
                    .into(),
            ));
        }
        (raw, None)
    };
    if embedded_expiry.is_some_and(|expires_at| expires_at <= epoch_secs()) {
        return Err(ProxyRuntimeError::InvalidConfig(
            "panel secret has expired; rotate it before starting the service".into(),
        ));
    }
    if secret.is_empty()
        || secret.len() > 256
        || secret.bytes().any(|byte| byte.is_ascii_whitespace())
        || (embedded_expiry.is_some() && secret.contains(':'))
    {
        return Err(ProxyRuntimeError::InvalidConfig(
            "secret file contains an invalid token".into(),
        ));
    }
    Ok(secret)
}

fn token_store_fingerprint(path: &Path) -> Option<(u64, SystemTime)> {
    let metadata = path.symlink_metadata().ok()?;
    Some((
        metadata.len(),
        metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
    ))
}

pub fn format_panel_secret(secret: &str, ttl_secs: u64) -> Result<String, ProxyRuntimeError> {
    if secret.is_empty()
        || secret.len() > 256
        || secret.bytes().any(|byte| byte.is_ascii_whitespace())
        || secret.contains(':')
        || ttl_secs == 0
    {
        return Err(ProxyRuntimeError::InvalidConfig(
            "panel secret or TTL is invalid".into(),
        ));
    }
    let expires_at = epoch_secs()
        .checked_add(ttl_secs)
        .ok_or_else(|| ProxyRuntimeError::InvalidConfig("panel secret TTL overflows".into()))?;
    Ok(format!("{PANEL_SECRET_PREFIX}:{expires_at}:{secret}\n"))
}

/// 与 `codev_proxy::capture_time_ns` 同一时钟（epoch 纳秒），供 frame-parser 期限计算用。
fn epoch_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn random_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_capture::{FrameOrigin, FrameRoute, Transport};
    use codev_protocol::Lsb0Writer;

    /// 守卫：UDP reorder 的释放不许再靠"每 10ms 醒一次"的定时任务驱动。
    ///
    /// 那个任务（原来叫 reorder_task）每 10ms 调一次 `TapHandle::poll`，
    /// 而被调的函数是 `let _ = now_ns;` —— 空实现。它既不释放状态，
    /// 又把 tokio 运行时按 100Hz 唤醒，实测每个空闲槽位 ≈2% 单核。
    /// 释放必须由 frame-parser worker 按 `FrameTap::next_deadline_ns()` 完成。
    #[test]
    fn udp_reorder_release_is_deadline_driven_not_a_100hz_ticker() {
        const SRC: &str = include_str!("proxy_runtime.rs");
        // 用 concat! 拼出名字：否则这条断言自己就把关键字写进了被检查的源码里。
        const FORBIDDEN: &str = concat!("UDP_REORDER", "_POLL_INTERVAL");
        assert!(
            !SRC.contains(FORBIDDEN),
            "100Hz reorder 定时任务又回来了：它调的是空实现，只会白烧 CPU"
        );
        assert!(
            SRC.contains("next_reorder_deadline_ns"),
            "worker 的死线必须把 reorder gap 算进去，否则缺口释放会拖到空闲等待结束（最长 250ms）"
        );
    }

    #[test]
    fn policy_rejections_do_not_downgrade_global_proxy_health() {
        let peer = "192.0.2.10:40000".parse().unwrap();
        assert!(event_status(&ProxyEvent::AuthenticationRejected { peer }).is_none());
        assert!(
            event_status(&ProxyEvent::TargetRejected {
                peer,
                transport: Transport::Tcp,
                target: codev_proxy::TargetAddr::Domain {
                    host: "not-allowlisted.example".into(),
                    port: 443,
                },
                reason: "host not allowed".into(),
            })
            .is_none()
        );
        assert!(
            event_status(&ProxyEvent::QuotaExceeded {
                peer,
                quota: "connections",
            })
            .is_none()
        );
        assert!(event_status(&ProxyEvent::UdpIdleTimeout { peer }).is_none());
        assert!(event_status(&ProxyEvent::UdpDuplicateObserved { peer, flow_id: 7 }).is_some());
    }

    #[test]
    fn mna_magic_split_across_proxy_relay_chunks_is_retained() {
        let (session_sender, _session_receiver) = mpsc::channel(2);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            state,
            Arc::new(ProxyRuntimeCounters::default()),
        );
        let split = 3;
        let first = FrameEnvelope::new(
            1,
            Direction::ClientToServer,
            Transport::Tcp,
            7,
            FrameOrigin::SocksTcp,
            MNA_MAGIC[..split].to_vec(),
        )
        .unwrap();
        tap.observe(&first);
        assert_eq!(
            tap.mna.get(&7).unwrap().client_candidate,
            None,
            "a partial magic must remain undecided"
        );

        let second = FrameEnvelope::new(
            2,
            Direction::ClientToServer,
            Transport::Tcp,
            7,
            FrameOrigin::SocksTcp,
            MNA_MAGIC[split..].to_vec(),
        )
        .unwrap();
        tap.observe(&second);
        assert_eq!(tap.mna.get(&7).unwrap().client_candidate, Some(true));
    }

    #[test]
    fn non_mna_prefix_is_rejected_without_unbounded_scanning() {
        let (session_sender, _session_receiver) = mpsc::channel(2);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            state,
            Arc::new(ProxyRuntimeCounters::default()),
        );
        let frame = FrameEnvelope::new(
            1,
            Direction::ClientToServer,
            Transport::Tcp,
            8,
            FrameOrigin::SocksTcp,
            b"TLS".to_vec(),
        )
        .unwrap();
        tap.observe(&frame);
        assert_eq!(tap.mna.get(&8).unwrap().client_candidate, Some(false));
    }

    #[test]
    fn mna_capacity_pressure_preserves_confirmed_control_flow() {
        let (session_sender, mut session_receiver) = mpsc::channel(4);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            state,
            Arc::new(ProxyRuntimeCounters::default()),
        );
        tap.announced_tcp = true;
        tap.mna.insert(
            7,
            ProxyMnaFlow {
                client_candidate: Some(true),
                last_capture_ns: 1,
                ..ProxyMnaFlow::default()
            },
        );
        for offset in 0..MAX_PROXY_MNA_FLOWS - 1 {
            tap.mna.insert(
                1_000 + offset as u64,
                ProxyMnaFlow {
                    client_candidate: Some(false),
                    last_capture_ns: 2 + offset as u64,
                    ..ProxyMnaFlow::default()
                },
            );
        }

        let ordinary = FrameEnvelope::new(
            10_000,
            Direction::ClientToServer,
            Transport::Tcp,
            99_999,
            FrameOrigin::SocksTcp,
            b"TLS".to_vec(),
        )
        .unwrap();
        tap.observe(&ordinary);

        assert_eq!(tap.mna.len(), MAX_PROXY_MNA_FLOWS);
        assert!(tap.mna.contains_key(&7));
        assert_eq!(
            tap.mna.get(&7).unwrap().client_candidate,
            Some(true),
            "a confirmed MNA control flow must outlive ordinary global traffic"
        );
        assert!(session_receiver.try_recv().is_err());
    }

    #[test]
    fn closed_tcp_flow_state_is_removed_after_parser_grace_period() {
        let (session_sender, _session_receiver) = mpsc::channel(2);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let (closed_sender, closed_receiver) = std_mpsc::channel();
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let mut tap = ProxyFrameTap::new_with_tcp_close_receiver(
            session_sender,
            actor_sender,
            state,
            Arc::new(ProxyRuntimeCounters::default()),
            closed_receiver,
            None,
        );
        tap.mna.insert(41, ProxyMnaFlow::default());
        closed_sender.send((41, 100)).unwrap();

        tap.poll(100 + TCP_CLOSE_STATE_GRACE_NS - 1);
        assert!(tap.mna.contains_key(&41));
        tap.poll(100 + TCP_CLOSE_STATE_GRACE_NS);
        assert!(!tap.mna.contains_key(&41));
    }

    #[test]
    fn udp_before_material_is_reported_once_without_creating_a_pipeline() {
        let (session_sender, mut session_receiver) = mpsc::channel(8);
        let (actor_sender, mut actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let counters = Arc::new(ProxyRuntimeCounters::default());
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            Arc::clone(&state),
            Arc::clone(&counters),
        );
        for capture_ns in [1, 2] {
            tap.observe(&udp_frame(
                capture_ns,
                9,
                Direction::ClientToServer,
                "192.0.2.10:40000".parse().unwrap(),
                "203.0.113.8:15806".parse().unwrap(),
                vec![0; 16],
            ));
        }

        assert_eq!(counters.udp_without_material.load(Ordering::Relaxed), 2);
        assert!(
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pipelines
                .is_empty()
        );
        assert!(matches!(
            session_receiver.try_recv().unwrap(),
            ProxySessionUpdate::Stage {
                stage: ProxyPipelineStage::UdpWithoutMaterial,
                ..
            }
        ));
        assert!(session_receiver.try_recv().is_err());
        assert!(actor_receiver.try_recv().is_err());
    }

    #[test]
    fn material_endpoint_filters_trials_and_rejoins_replacement_udp_association() {
        let (session_sender, mut session_receiver) = mpsc::channel(16);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let counters = Arc::new(ProxyRuntimeCounters::default());
        let material = test_material("203.0.113.8", 15_806);
        let cipher = material.cipher();
        assert!(install_material(&state, &material));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            Arc::clone(&state),
            Arc::clone(&counters),
        );
        let encrypted = valid_server_datagram(&cipher);

        tap.observe(&udp_frame(
            1,
            10,
            Direction::ServerToClient,
            "203.0.113.9:15806".parse().unwrap(),
            "192.0.2.10:40000".parse().unwrap(),
            encrypted.clone(),
        ));
        tap.observe(&udp_frame(
            2,
            10,
            Direction::ServerToClient,
            "203.0.113.8:15807".parse().unwrap(),
            "192.0.2.10:40000".parse().unwrap(),
            encrypted.clone(),
        ));
        assert_eq!(counters.udp_candidates_observed.load(Ordering::Relaxed), 0);
        {
            let filtered = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(filtered.locked_flow_id, None);
            assert!(filtered.pipelines.is_empty());
        }

        tap.observe(&udp_frame(
            3,
            11,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.10:40000".parse().unwrap(),
            encrypted.clone(),
        ));
        {
            let locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(locked.locked_flow_id, Some(11));
            assert_eq!(locked.pipelines.len(), 1);
            assert!(locked.pipelines.contains_key(&11));
        }
        assert_eq!(counters.udp_flows_locked.load(Ordering::Relaxed), 1);
        assert!(matches!(
            session_receiver.try_recv().unwrap(),
            ProxySessionUpdate::Stage {
                stage: ProxyPipelineStage::UdpCandidateObserved,
                ..
            }
        ));
        assert!(matches!(
            session_receiver.try_recv().unwrap(),
            ProxySessionUpdate::UdpLocked { .. }
        ));

        let locked_stats_before = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pipelines
            .get(&11)
            .expect("the validated flow must be retained")
            .stats();
        tap.observe(&udp_frame(
            4,
            12,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.10:40001".parse().unwrap(),
            encrypted.clone(),
        ));
        {
            let locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(locked.locked_flow_id, Some(11));
            assert_eq!(locked.pipelines.len(), 1);
            assert!(locked.pipelines.contains_key(&11));
            assert!(locked.migrated_flow_ids.contains(&12));
            assert_eq!(
                locked.pipelines.get(&11).unwrap().stats().datagrams,
                locked_stats_before.datagrams + 1
            );
        }
        assert_eq!(
            counters.udp_association_migrations.load(Ordering::Relaxed),
            1
        );

        // More datagrams on the same replacement association continue to use
        // the canonical decoder without inflating the migration counter.
        tap.observe(&udp_frame(
            5,
            12,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.10:40001".parse().unwrap(),
            encrypted.clone(),
        ));
        assert_eq!(
            counters.udp_association_migrations.load(Ordering::Relaxed),
            1
        );
        let datagrams_after_migration = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pipelines
            .get(&11)
            .unwrap()
            .stats()
            .datagrams;

        // An unrelated LAN client cannot join the selected stream even when
        // it targets the same game server address.
        tap.observe(&udp_frame(
            6,
            13,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.11:40001".parse().unwrap(),
            encrypted,
        ));
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            locked.pipelines.get(&11).unwrap().stats().datagrams,
            datagrams_after_migration
        );
        assert!(!locked.migrated_flow_ids.contains(&13));
    }

    #[test]
    fn oodle_boundary_before_first_ue_packet_does_not_permanently_reject_flow() {
        let (session_sender, _session_receiver) = mpsc::channel(16);
        let (actor_sender, _actor_receiver) = mpsc::channel(2);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let counters = Arc::new(ProxyRuntimeCounters::default());
        let material = test_material("203.0.113.8", 15_806);
        let cipher = material.cipher();
        assert!(install_material(&state, &material));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            Arc::clone(&state),
            Arc::clone(&counters),
        );

        // [0x01, 0x08] is a bit-exact raw-size-one PacketHandler flag-one
        // boundary. It is authenticated by SGNet but deliberately not
        // decoded as UE without an authorized Oodle implementation.
        let oodle = cipher.crypt_server_datagram(&[0x01, 0x08]);
        tap.observe(&udp_frame(
            1,
            21,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.10:40000".parse().unwrap(),
            oodle,
        ));
        {
            let candidate = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(candidate.locked_flow_id, None);
            let stats = candidate.pipelines.get(&21).unwrap().stats();
            assert_eq!(stats.oodle_compressed, 1);
            assert!(!udp_trial_is_valid(stats));
        }

        tap.observe(&udp_frame(
            2,
            21,
            Direction::ServerToClient,
            "203.0.113.8:15806".parse().unwrap(),
            "192.0.2.10:40000".parse().unwrap(),
            valid_server_datagram(&cipher),
        ));
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(locked.locked_flow_id, Some(21));
        let stats = locked.pipelines.get(&21).unwrap().stats();
        assert_eq!(stats.datagrams, 2);
        assert_eq!(stats.oodle_compressed, 1);
        assert_eq!(stats.packet_handler_pass_through, 1);
        assert_eq!(stats.unreal_packets, 1);
        assert!(udp_trial_is_valid(stats));
        assert_eq!(counters.udp_flows_locked.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn reference_pcap_candidate_locks_after_initial_oodle_boundaries() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !fixture.is_file() {
            return;
        }
        let recovery = codev_stream::recover_enter_game_session_from_classic_pcap(&fixture)
            .expect("reference MNA session must recover");
        let cipher = codev_stream::C0Cipher::from_packet_key(
            &recovery.session.packet_key,
            recovery.session.g0_id,
        );
        let mut discovery = codev_stream::S0PcapSource::open(&fixture).unwrap();
        let flow = codev_stream::discover_primary_udp_flow(&mut discovery).unwrap();
        let mut pipeline = P0Pipeline::new(cipher, flow.client, flow.server);
        let mut source = codev_stream::S0PcapSource::open(&fixture).unwrap();
        let locked_stats = loop {
            let Some(packet) = codev_stream::PacketSource::next_packet(&mut source).unwrap() else {
                panic!("reference flow ended before candidate validation");
            };
            let Ok(transport) = codev_stream::parse_transport(&packet) else {
                continue;
            };
            if !flow.key.contains(transport.source, transport.destination) {
                continue;
            }
            pipeline.push_transport(&transport).unwrap();
            let stats = pipeline.stats();
            if udp_trial_is_valid(stats) {
                break stats;
            }
            assert!(
                stats.datagrams < UDP_CANDIDATE_MAX_DATAGRAMS,
                "reference candidate exceeded the live lock window"
            );
        };
        assert_eq!(locked_stats.oodle_compressed, 4);
        assert!(locked_stats.packet_handler_pass_through > 0);
        assert!(locked_stats.unreal_packets > 0);
        assert!(locked_stats.datagrams <= UDP_CANDIDATE_MAX_DATAGRAMS);
    }

    #[test]
    fn reference_pcap_through_proxy_tap_preserves_all_actor_coordinates() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !fixture.is_file() {
            return;
        }
        let recovery = codev_stream::recover_enter_game_session_from_classic_pcap(&fixture)
            .expect("reference MNA session must recover");
        let material = SessionMaterial::from_mna(
            SessionId::parse("proxy-reference-pcap").unwrap(),
            recovery.session,
            recovery.notification.timestamp_ns,
        )
        .unwrap();
        let mut discovery = codev_stream::S0PcapSource::open(&fixture).unwrap();
        let flow = codev_stream::discover_primary_udp_flow(&mut discovery).unwrap();
        let (session_sender, _session_receiver) = mpsc::channel(128);
        let (actor_sender, mut actor_receiver) = mpsc::channel(20_000);
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let counters = Arc::new(ProxyRuntimeCounters::default());
        assert!(install_material(&state, &material));
        let mut tap = ProxyFrameTap::new(
            session_sender,
            actor_sender,
            Arc::clone(&state),
            Arc::clone(&counters),
        );

        let mut source = codev_stream::S0PcapSource::open(&fixture).unwrap();
        while let Some(packet) = codev_stream::PacketSource::next_packet(&mut source).unwrap() {
            let Ok(transport) = codev_stream::parse_transport(&packet) else {
                continue;
            };
            if !flow.key.contains(transport.source, transport.destination) {
                continue;
            }
            let direction = if transport.source == flow.client {
                Direction::ClientToServer
            } else {
                Direction::ServerToClient
            };
            let source = socket_addr_from_endpoint(transport.source).unwrap();
            let destination = socket_addr_from_endpoint(transport.destination).unwrap();
            tap.observe(&udp_frame(
                packet.timestamp_ns,
                900,
                direction,
                source,
                destination,
                transport.payload.to_vec(),
            ));
        }
        tap.poll(u64::MAX);

        let mut actor_messages = 0_u64;
        let mut coordinate_updates = 0_u64;
        while let Ok(batch) = actor_receiver.try_recv() {
            assert_eq!(batch.session_generation, 1_u64 << 32);
            actor_messages += batch.actors.len() as u64;
            coordinate_updates += batch
                .actors
                .iter()
                .flat_map(|actor| &actor.updates)
                .filter(|update| update.position_valid)
                .count() as u64;
        }
        assert_eq!(actor_messages, 4_444);
        assert_eq!(coordinate_updates, 17_031);
        assert_eq!(counters.udp_flows_locked.load(Ordering::Relaxed), 1);
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(locked.locked_flow_id, Some(900));
        let stats = locked.pipelines.get(&900).unwrap().stats();
        assert_eq!(stats.datagrams, 12_414);
        assert_eq!(stats.actor_messages, 4_444);
        assert_eq!(stats.character_updates, 17_031);
    }

    #[test]
    fn actor_generation_filter_rejects_queued_batches_from_adjacent_sessions() {
        let current = 3_u64 << 32;
        assert!(actor_belongs_to_session(current, current));
        assert!(actor_belongs_to_session(current + 7, current));
        assert!(!actor_belongs_to_session(current - 1, current));
        assert!(!actor_belongs_to_session(2_u64 << 32 | 19, current));
        assert!(!actor_belongs_to_session(4_u64 << 32, current));
    }

    #[test]
    fn new_session_generation_clears_every_round_binding_anchor() {
        let mut counts = BTreeMap::from([(3, 12), (8, 9)]);
        let mut slots = vec![3, 8];
        let mut spawn = Some([100.0, 200.0, 300.0]);
        let mut self_slot = Some(3);
        let mut plan = Some(vec![Some(3), Some(8)]);
        let mut published_self = Some(Some(3));
        let mut stabilizer = codev_stream::RosterPlanStabilizer::default();
        let _ = stabilizer.observe(&codev_stream::RosterPlan {
            slots: vec![Some(3), Some(8)],
            local_camp_id: Some(1),
        });
        reset_round_binding_state(
            &mut counts,
            &mut slots,
            &mut spawn,
            &mut self_slot,
            &mut plan,
            &mut published_self,
            &mut stabilizer,
        );
        assert!(counts.is_empty());
        assert!(slots.is_empty());
        assert_eq!(spawn, None);
        assert_eq!(self_slot, None);
        assert_eq!(plan, None);
        assert_eq!(published_self, None);
        assert!(stabilizer.committed().is_none());
    }

    #[test]
    fn mna_control_close_policy_retains_locked_udp_decoder_until_replacement() {
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let material = test_material("203.0.113.8", 15_806);
        assert!(install_material(&state, &material));
        {
            let mut locked = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            locked.locked_flow_id = Some(11);
            locked.pipelines.insert(
                11,
                P0Pipeline::new(
                    material.cipher(),
                    socket_endpoint("192.0.2.10:40000".parse().unwrap()),
                    socket_endpoint("203.0.113.8:15806".parse().unwrap()),
                ),
            );
        }
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(locked.cipher.is_some());
        assert_eq!(locked.map_id, Some(1003));
        assert_eq!(locked.expected_server_port, 15_806);
        assert_eq!(locked.pipelines.len(), 1);
        assert_eq!(locked.locked_flow_id, Some(11));
        assert!(locked.installed_material.is_some());
    }

    #[test]
    fn broker_reserved_reopen_generation_is_used_without_a_second_increment() {
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let first = test_material("203.0.113.8", 15_806);
        let mut second = test_material("203.0.113.9", 15_806);
        second.session_id = SessionId::parse("proxy-runtime-test-2").unwrap();
        let mut broker = SessionBroker::default();
        let first_outcome = broker.accept_with_outcome(first.clone()).unwrap();
        assert!(install_material_at_generation(
            &state,
            &first,
            first_outcome.channel_generation
        ));
        broker.close_channel("test close");
        let reserved = broker.reopen_channel("test reopen").unwrap();
        let second_outcome = broker.accept_with_outcome(second.clone()).unwrap();
        assert_eq!(second_outcome.channel_generation, reserved);
        assert!(install_material_at_generation(
            &state,
            &second,
            second_outcome.channel_generation
        ));
        assert_eq!(
            state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .channel_generation,
            reserved
        );
    }

    #[test]
    fn dns_material_matches_notified_port_while_literal_material_matches_ip_and_port() {
        let literal = endpoint_from_host("203.0.113.8", 15_806);
        let actual = socket_endpoint("203.0.113.8:15806".parse().unwrap());
        let other = socket_endpoint("203.0.113.9:15806".parse().unwrap());
        assert!(udp_server_matches(literal, 15_806, actual));
        assert!(!udp_server_matches(literal, 15_806, other));
        assert!(udp_server_matches(None, 15_806, other));
        assert!(!udp_server_matches(None, 15_807, other));
    }

    #[test]
    fn mna_vip_is_retained_as_an_additional_udp_endpoint() {
        let state = Arc::new(Mutex::new(ProxyDecodeState::default()));
        let material = SessionMaterial::new_with_vip(
            SessionId::parse("proxy-runtime-vip").unwrap(),
            codev_session::SessionMaterialSource::Mna,
            Zeroizing::new("test-packet-key".to_owned()),
            7,
            Some(1003),
            "game.example.invalid".into(),
            Some("203.0.113.8".into()),
            15_806,
            Vec::new(),
            1,
            false,
        )
        .unwrap();
        assert!(install_material(&state, &material));
        let locked = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(locked.expected_servers.len(), 1);
        assert!(udp_server_matches_any(
            &locked.expected_servers,
            locked.expected_server_port,
            locked.allow_public_server_port_candidate,
            socket_endpoint("203.0.113.8:15806".parse().unwrap())
        ));
        assert!(udp_server_matches_any(
            &locked.expected_servers,
            locked.expected_server_port,
            locked.allow_public_server_port_candidate,
            socket_endpoint("8.8.8.8:15806".parse().unwrap())
        ));
        assert!(!udp_server_matches_any(
            &locked.expected_servers,
            locked.expected_server_port,
            locked.allow_public_server_port_candidate,
            socket_endpoint("10.0.0.8:15806".parse().unwrap())
        ));
    }

    fn test_material(host: &str, port: u16) -> SessionMaterial {
        SessionMaterial::new(
            SessionId::parse("proxy-runtime-test").unwrap(),
            codev_session::SessionMaterialSource::PrivateSession,
            Zeroizing::new("test-packet-key".to_owned()),
            7,
            Some(1003),
            host.to_owned(),
            port,
            Vec::new(),
            1,
            false,
        )
        .unwrap()
    }

    fn udp_frame(
        capture_ns: u64,
        flow_id: u64,
        direction: Direction,
        source: SocketAddr,
        destination: SocketAddr,
        payload: Vec<u8>,
    ) -> FrameEnvelope {
        FrameEnvelope::new_with_route(
            capture_ns,
            direction,
            Transport::Udp,
            flow_id,
            FrameOrigin::SocksUdp,
            FrameRoute {
                source,
                destination,
            },
            payload,
        )
        .unwrap()
    }

    fn valid_server_datagram(cipher: &codev_stream::C0Cipher) -> Vec<u8> {
        let mut ue = Lsb0Writer::default();
        ue.write_bits(0, 32).unwrap();
        ue.write_bits(0, 8).unwrap();
        ue.write_bit(false);
        ue.write_bit(true);
        let ue = ue.into_bytes();

        let mut handler = Lsb0Writer::default();
        handler.write_bit(false);
        handler.write_bit_slice(&ue, 0, 42).unwrap();
        handler.write_bit(true);
        cipher.crypt_server_datagram(&handler.into_bytes())
    }

    #[test]
    fn public_base_url_parser_handles_ipv6_and_rejects_non_origin_urls() {
        assert_eq!(
            parse_public_base_url("https://[2001:db8::10]:443"),
            Some(("https", "2001:db8::10"))
        );
        assert_eq!(
            parse_public_base_url("https://panel.example.com"),
            Some(("https", "panel.example.com"))
        );
        for value in [
            "https://[2001:db8::10]oops",
            "https://panel.example.com/path",
            "https://user:pass@panel.example.com",
            "https://panel.example.com:99999",
            "ftp://panel.example.com",
        ] {
            assert_eq!(parse_public_base_url(value), None, "accepted {value}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn panel_secret_format_enforces_expiry_and_keeps_legacy_migration_bounded() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "codev-panel-secret-runtime-test-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("panel.secret");
        let encoded = format_panel_secret("secret-value", 60).unwrap();
        std::fs::write(&path, encoded).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_secret(&path, 60).unwrap(), "secret-value");

        std::fs::write(&path, "codev-panel-v1:1:secret-value\n").unwrap();
        assert!(read_secret(&path, 60).is_err());

        std::fs::write(&path, "legacy-secret\n").unwrap();
        assert_eq!(read_secret(&path, 60).unwrap(), "legacy-secret");
        let _ = std::fs::remove_dir_all(&directory);
    }
}

#[derive(Debug, Error)]
pub enum ProxyRuntimeError {
    #[error("proxy I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("proxy TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid proxy configuration: {0}")]
    InvalidConfig(String),
    #[error("proxy configuration error: {0}")]
    ProxyConfig(#[from] codev_proxy::ConfigError),
    #[error("proxy token store error: {0}")]
    Token(#[from] codev_proxy::TokenError),
    #[error("proxy profile store error: {0}")]
    Profile(#[from] codev_proxy::ProfileError),
    #[error("proxy server error: {0}")]
    Proxy(#[from] ProxyError),
    #[error("HTTPS authority error: {0}")]
    Authority(#[from] codev_https::AuthorityError),
    #[error("HTTPS policy error: {0}")]
    Policy(#[from] codev_https::PolicyError),
    #[error("web error: {0}")]
    Web(#[from] codev_web::WebError),
    #[error("session broker error: {0}")]
    Broker(#[from] codev_session::BrokerError),
    #[error("tokio task error: {0}")]
    Join(#[from] tokio::task::JoinError),
}
