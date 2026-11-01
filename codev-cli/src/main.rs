use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use codev_assets::{MapCatalog, Vec2 as AssetVec2};
use codev_protocol::{D0Decoder, DecodeScratch, SlotContinuity};
#[cfg(feature = "live-capture")]
use codev_stream::S0LiveSource;
use codev_stream::{
    A0Payload, C0Cipher, Continuity, Endpoint, EnterGameSession, IdentityConfidence, IpAddress,
    MNA_DATA, MNA_MAGIC, MNA_SERVER_HELLO, P0Pipeline, PacketSource, PipelineGap, PipelineStats,
    S0PcapSource, TcpReassembler, TransportKind, W0Framer, decrypt_mna_frame,
    parse_enter_game_session, parse_mna_application, parse_transport,
    recover_enter_game_session_from_classic_pcap_open_ended, recover_mna_session_key,
    strip_mna_random_padding,
};
use codev_web::{
    EndPayload, EventHub, GapPayload, MapPoint, MetricsPayload, PositionView, RosterEntry,
    SessionStatus, SessionView, Vec3 as WebVec3,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

mod artifacts;
mod compat_auxiliary;
mod compat_batch;
mod compat_documents;
mod compat_gate;
mod compat_netguid;
mod compat_network;
mod compat_packets;
mod compat_report;
mod compat_session;
mod dump_coordinates;
mod proxy_pcap;
mod proxy_runtime;
mod record;
use artifacts::write_native_events;
use record::BoundedPrivateRecorder;

const SUPPORTED_BUILD: &str = "1.24.0.2911";
const TCP_FIN: u16 = 0x001;
const TCP_SYN: u16 = 0x002;
const TCP_RST: u16 = 0x004;
const LIVE_MNA_GAP_TIMEOUT_NS: u64 = 5_000_000_000;
// Actor batches are sparse deltas rather than a ten-player heartbeat.  Give a
// quiet slot enough time to receive its next update before treating it as a
// despawn; the previous one-second window made stationary actors flicker.
const LIVE_POSITION_STALE_AFTER_NS: u64 = 4_000_000_000;
const RECORD_QUEUE_CAPACITY: usize = 2_048;
const MAX_LIVE_TCP_FLOWS: usize = 512;
const MAX_RECORDING_SUMMARY_BYTES: u64 = 64 * 1024;
const MAX_REPLAY_JSON_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLAY_DATA_HEX_CHARS: usize = 16 * 1024 * 1024;
const MAX_REPLAY_GAP_REASON_BYTES: usize = 2 * 1024;

#[derive(Parser)]
#[command(name = "codev-net", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Rust-native compatibility decode producing all eleven historical artifacts.
    Decode {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        schema: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        /// Legacy alias for the default Rust-native compatibility decoder.
        #[arg(long)]
        rust_events: bool,
    },
    /// Capture live traffic and expose loopback-only session diagnostics.
    Live {
        #[arg(long, default_value = "auto")]
        interface: String,
        #[arg(long)]
        session: Option<PathBuf>,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
        #[arg(long)]
        record: Option<PathBuf>,
        #[arg(long, default_value = "pcap")]
        source: String,
        /// Proxy configuration used when `--source proxy` is selected.
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        record_plaintext: bool,
    },
    /// Run an authenticated Shadowrocket-compatible SOCKS5 proxy and panel.
    Proxy {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        record_plaintext: bool,
    },
    /// Manage hashed SOCKS5 token credentials.
    Token {
        #[command(subcommand)]
        action: TokenAction,
        #[arg(long, global = true)]
        store: Option<PathBuf>,
        #[arg(long, global = true)]
        config: Option<PathBuf>,
        #[arg(long, default_value = "proxy", global = true)]
        scope: String,
    },
    /// Generate/export the installation HTTPS inspection CA.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Build a compact timeline from v2 coordinates or Unreal message JSONL.
    Replay {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        session: Option<PathBuf>,
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: SocketAddr,
    },
    /// List capture devices visible to libpcap/Npcap.
    Interfaces,
    /// Export decoded per-slot world coordinates for map calibration.
    ///
    /// Unlike `decode` this bypasses the fail-closed recovery gate, so a
    /// lossy or mid-session capture still yields coordinates. The output is a
    /// calibration aid and is not a compatibility evidence artifact.
    DumpCoordinates {
        #[arg(long)]
        pcap: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// 打开宽容句柄普查：记录当前解码器不认识的属性句柄（诊断用）。
        #[arg(long, default_value_t = false)]
        handle_census: bool,
    },
}

#[derive(Subcommand)]
enum TokenAction {
    Create {
        #[arg(long)]
        username: Option<String>,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    Revoke {
        #[arg(long)]
        username: String,
    },
    Rotate {
        #[arg(long)]
        username: String,
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
    },
    List,
}

#[derive(Subcommand)]
enum CaAction {
    Export {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Error)]
enum CliError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("capture error: {0}")]
    Capture(#[from] codev_stream::SourceError),
    #[error("web error: {0}")]
    Web(#[from] codev_web::WebError),
    #[error("map error: {0}")]
    Map(#[from] codev_assets::MapError),
    #[error("session pipeline error: {0}")]
    Session(#[from] codev_stream::SessionError),
    #[error("M0 session error: {0}")]
    Mna(#[from] codev_stream::W0Error),
    #[error("M0 capture recovery error: {0}")]
    MnaCapture(#[from] codev_stream::W0CaptureError),
    #[error("capture task failed: {0}")]
    CaptureTask(#[from] tokio::task::JoinError),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("native event artifact error: {0}")]
    NativeEvents(#[from] artifacts::NativeEventsError),
    #[error("private compatibility session error: {0}")]
    CompatibilitySession(#[from] compat_session::CompatibilitySessionError),
    #[error("proxy runtime error: {0}")]
    ProxyRuntime(#[from] proxy_runtime::ProxyRuntimeError),
    #[error("HTTPS authority error: {0}")]
    HttpsAuthority(#[from] codev_https::AuthorityError),
}

#[derive(Debug, Deserialize)]
struct UnrealRow {
    #[serde(default)]
    direction: Option<String>,
    channel_index: u32,
    #[serde(default)]
    open: bool,
    #[serde(default)]
    close: bool,
    #[serde(default)]
    partial: bool,
    timestamp_ns: u64,
    data_bit_length: usize,
    data_hex: String,
}

#[derive(Debug, Deserialize)]
struct CoordinateRow {
    record_type: String,
    timestamp_ns: u64,
    batch_slot: u8,
    #[serde(default, rename = "player_binding")]
    _player_binding: Option<String>,
    #[serde(default, rename = "player_binding_confidence")]
    _player_binding_confidence: Option<String>,
    position: CoordinatePosition,
    #[serde(default)]
    state: Option<CoordinateState>,
    #[serde(default)]
    movement: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct CoordinatePosition {
    x: f64,
    y: f64,
    z: f64,
}

#[derive(Debug, Deserialize)]
struct CoordinateState {
    #[serde(default)]
    rotation_degrees: Option<[f64; 3]>,
}

#[derive(Clone, Default)]
struct SessionMetadata {
    map_id: Option<u32>,
    roster: Vec<RosterEntry>,
    server: Option<Endpoint>,
    server_port: Option<u16>,
    cipher: Option<C0Cipher>,
}

#[tokio::main]
async fn main() {
    // S2：把字段字典交给 web 层，供 /api/v1/session/key 按会话加密下发。
    // 只能在这里注入：artifacts 模块属于二进制，lib（proxy_runtime）够不到它。
    codev_web::session_key::set_dictionary(artifacts::embedded_fields_json_bytes());

    let code = match run(Cli::parse()).await {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            1
        }
    };
    std::process::exit(code);
}

async fn run(cli: Cli) -> Result<i32, CliError> {
    match cli.command {
        Commands::Decode {
            pcap,
            schema,
            out,
            rust_events: _,
        } => {
            let report = write_native_events(&pcap, schema.as_deref(), &out)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(report.exit_code())
        }
        Commands::Interfaces => {
            #[cfg(feature = "live-capture")]
            {
                for device in S0LiveSource::devices()? {
                    println!("{device}");
                }
                return Ok(0);
            }
            #[cfg(not(feature = "live-capture"))]
            {
                eprintln!(
                    "本次构建未包含实时抓包（Live capture）能力：本机版走 SOCKS5/WinDivert 通道，无需 libpcap"
                );
                Ok(1)
            }
        }
        Commands::Proxy {
            config,
            record_plaintext,
        } => proxy_runtime::run_proxy(proxy_runtime::ProxyCommandOptions {
            config_path: config,
            record_plaintext,
            private_session: None,
            panel_listen_override: None,
        })
        .await
        .map_err(CliError::ProxyRuntime),
        Commands::Token {
            action,
            store,
            config,
            scope,
        } => run_token_command(action, store.as_deref(), config.as_deref(), &scope),
        Commands::Ca { action } => run_ca_command(action),
        Commands::Replay {
            input,
            session,
            speed,
            listen,
        } => {
            if !matches!(speed, 0.25 | 0.5 | 1.0 | 2.0 | 4.0) {
                return Err(CliError::InvalidInput(
                    "--speed must be 0.25, 0.5, 1, 2, or 4".into(),
                ));
            }
            ensure_loopback(listen)?;
            let metadata = session
                .as_deref()
                .map(load_session_metadata)
                .transpose()?
                .unwrap_or_default();
            let session_id = session_id_for_path(&input)?;
            let hub = EventHub::new(session_id)?;
            hub.set_initial_replay_speed(speed)?;
            let mut session_view = SessionView {
                build_id: SUPPORTED_BUILD.into(),
                map_id: metadata.map_id,
                status: SessionStatus::Replay,
                status_detail: format!("已载入 {}；初始速度 {speed}×", input.display()),
                ..SessionView::default()
            };
            hub.set_session(session_view.clone()).await?;
            hub.set_roster(metadata.roster.clone()).await?;
            let replay_session = session.as_ref().map(|_| metadata.clone());
            let stats = load_replay(&input, replay_session, &hub, metadata.map_id).await?;
            session_view.latest_capture_ns = stats.last_timestamp_ns;
            session_view.capture_start_ns = stats.first_timestamp_ns;
            session_view.map_id = stats.map_id.or(metadata.map_id);
            session_view.channel_generation = stats.channel_generation;
            session_view.status_detail = format!(
                "已载入 {} 条坐标更新；使用 Rust v2 多-property 状态机",
                stats.coordinate_updates
            );
            hub.set_session(session_view).await?;
            hub.publish_metrics(
                stats.last_timestamp_ns.unwrap_or_default(),
                MetricsPayload {
                    packets: stats.packets,
                    actor_messages: stats.actor_messages,
                    coordinate_updates: stats.coordinate_updates,
                    parse_failures: stats.parse_failures,
                    pcap_drops: 0,
                    proxy_pipeline: None,
                    parse_to_ws_p99_ms: None,
                    capture_to_ws_p99_ms: None,
                },
            )
            .await?;
            serve_until_signal(listen, hub).await?;
            Ok(0)
        }
        Commands::Live {
            interface,
            session,
            listen,
            record,
            source,
            config,
            record_plaintext,
        } => {
            if source == "proxy" {
                let config = config.ok_or_else(|| {
                    CliError::InvalidInput(
                        "live --source proxy requires --config PATH (or use `codev-net proxy`)"
                            .into(),
                    )
                })?;
                let private_session = session
                    .as_deref()
                    .map(compat_session::load_compatibility_enter_session)
                    .transpose()?;
                if record.is_some() {
                    return Err(CliError::InvalidInput(
                        "live --source proxy does not accept --record yet; use proxy HTTPS plaintext recording explicitly with --record-plaintext"
                            .into(),
                    ));
                }
                return proxy_runtime::run_proxy(proxy_runtime::ProxyCommandOptions {
                    config_path: config,
                    record_plaintext,
                    private_session,
                    panel_listen_override: Some(listen),
                })
                .await
                .map_err(CliError::ProxyRuntime);
            }
            if source != "pcap" {
                return Err(CliError::InvalidInput(
                    "live --source must be pcap or proxy".into(),
                ));
            }
            ensure_loopback(listen)?;
            let has_private_session = session.is_some();
            let metadata = session
                .as_deref()
                .map(load_session_metadata)
                .transpose()?
                .unwrap_or_default();
            let hub = EventHub::new(format!(
                "live-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ))?;
            hub.set_session(SessionView {
                build_id: SUPPORTED_BUILD.into(),
                map_id: metadata.map_id,
                status: SessionStatus::AwaitingSession,
                status_detail: if has_private_session {
                    "私有 session 已提供；正在验证版本、权限和主 UDP endpoint".into()
                } else {
                    "正在寻找合法 MNA server hello".into()
                },
                ..SessionView::default()
            })
            .await?;
            hub.set_roster(metadata.roster.clone()).await?;
            let capture_result = start_live_capture(
                interface,
                has_private_session,
                metadata,
                hub.clone(),
                record,
            )
            .await;
            let (capture, capture_failed) = match capture_result {
                Ok(capture) => (Some(capture), false),
                Err(CliError::Capture(error)) => {
                    hub.set_session(SessionView {
                        build_id: SUPPORTED_BUILD.into(),
                        status: SessionStatus::Unrecoverable,
                        status_detail: format!("无法启动被动抓包：{error}"),
                        ..SessionView::default()
                    })
                    .await?;
                    (None, true)
                }
                Err(error) => return Err(error),
            };
            let serve_result = serve_until_signal(listen, hub).await;
            if let Some(capture) = capture {
                capture.shutdown().await?;
            }
            serve_result?;
            Ok(i32::from(capture_failed))
        }
        Commands::DumpCoordinates {
            pcap,
            out,
            handle_census,
        } => {
            let summary = dump_coordinates::dump_coordinates(&pcap, &out, handle_census)?;
            if let Some(parent) = out.parent() {
                let meta = parent.join(format!(
                    "{}.meta.json",
                    out.file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_else(|| "coordinates.jsonl".into())
                ));
                dump_coordinates::write_meta(&meta, &summary)?;
                println!("meta        {}", meta.display());
            }
            println!("pcap        {}", summary.pcap);
            println!(
                "map         map_id={} mode={} sub_mode={} path={}",
                summary.map_id,
                summary.g1_mode,
                summary.s0_mode,
                summary.map_object_path.as_deref().unwrap_or("<unknown>")
            );
            println!(
                "coordinates {} 记录 / {} 个 slot / {} 个数据包 / 序列缺口 {}",
                summary.coordinate_records,
                summary.slots.len(),
                summary.pipeline_datagrams,
                summary.sequence_gaps
            );
            if let (Some(minimum), Some(maximum)) = (summary.coordinate_min, summary.coordinate_max)
            {
                println!(
                    "world bounds x {:.1}..{:.1}  y {:.1}..{:.1}  z {:.1}..{:.1}",
                    minimum[0], maximum[0], minimum[1], maximum[1], minimum[2], maximum[2]
                );
            }
            if !summary.handle_census.is_empty() {
                println!(
                    "未支持句柄   {} 种（诊断普查）",
                    summary.handle_census.len()
                );
            }
            println!("输出        {}", out.display());
            // Coordinates are a calibration aid: the evidence gate was skipped,
            // so this is never reported as a clean decode.
            Ok(0)
        }
    }
}

fn run_token_command(
    action: TokenAction,
    explicit_store: Option<&Path>,
    config_path: Option<&Path>,
    scope: &str,
) -> Result<i32, CliError> {
    if scope == "panel" {
        return run_panel_token_command(action, explicit_store, config_path);
    }
    if scope != "proxy" {
        return Err(CliError::InvalidInput(
            "--scope must be proxy or panel".into(),
        ));
    }
    let loaded_config = config_path
        .map(proxy_runtime::ProxyAppConfig::load)
        .transpose()?;
    let store_path = explicit_store
        .map(Path::to_path_buf)
        .or_else(|| {
            loaded_config
                .as_ref()
                .and_then(|config| config.proxy.token_store.clone())
        })
        .ok_or_else(|| {
            CliError::InvalidInput(
                "proxy token command requires --store or --config with proxy.token_store".into(),
            )
        })?;
    let token_limits = loaded_config
        .as_ref()
        .map(|config| config.proxy.token_limits())
        .unwrap_or(codev_proxy::TokenLimits {
            max_connections: 8,
            max_udp_flows: 16,
            bytes_per_second: 16 * 1024 * 1024,
            udp_idle_secs: 30,
        });
    let store = if store_path.is_file() {
        codev_proxy::TokenStore::load(&store_path)
            .map_err(|error| CliError::InvalidInput(format!("token store: {error}")))?
    } else {
        codev_proxy::TokenStore::new()
    };
    match action {
        TokenAction::Create { username, ttl_secs } => {
            let credential = store
                .create_token(username.as_deref(), ttl_secs, token_limits)
                .map_err(|error| CliError::InvalidInput(format!("token create: {error}")))?;
            store
                .save(&store_path)
                .map_err(|error| CliError::InvalidInput(format!("token save: {error}")))?;
            println!(
                "{}",
                serde_json::json!({
                    "username": credential.username,
                    "secret": credential.secret,
                    "expires_at": credential.expires_at,
                    "warning": "secret is shown once; configure it in Shadowrocket and do not log it"
                })
            );
        }
        TokenAction::Revoke { username } => {
            if !store.revoke_token(&username) {
                return Err(CliError::InvalidInput(format!(
                    "token username not found: {username}"
                )));
            }
            store
                .save(&store_path)
                .map_err(|error| CliError::InvalidInput(format!("token save: {error}")))?;
            println!("revoked {username}");
        }
        TokenAction::Rotate { username, ttl_secs } => {
            let credential = store
                .rotate_token(&username, ttl_secs)
                .map_err(|error| CliError::InvalidInput(format!("token rotate: {error}")))?;
            store
                .save(&store_path)
                .map_err(|error| CliError::InvalidInput(format!("token save: {error}")))?;
            println!(
                "{}",
                serde_json::json!({
                    "username": credential.username,
                    "secret": credential.secret,
                    "expires_at": credential.expires_at,
                    "warning": "old secret is revoked; secret is shown once"
                })
            );
        }
        TokenAction::List => {
            println!("{}", serde_json::to_string_pretty(&store.list())?);
        }
    }
    Ok(0)
}

fn run_panel_token_command(
    action: TokenAction,
    explicit_store: Option<&Path>,
    config_path: Option<&Path>,
) -> Result<i32, CliError> {
    let token_path = explicit_store
        .map(Path::to_path_buf)
        .or_else(|| {
            config_path.and_then(|path| {
                proxy_runtime::ProxyAppConfig::load(path)
                    .ok()
                    .and_then(|config| config.panel.token_file)
            })
        })
        .ok_or_else(|| {
            CliError::InvalidInput(
                "panel token command requires --store or --config with panel.token_file".into(),
            )
        })?;
    match action {
        TokenAction::Create { ttl_secs, .. } | TokenAction::Rotate { ttl_secs, .. } => {
            if ttl_secs == 0 {
                return Err(CliError::InvalidInput(
                    "panel token TTL must be non-zero".into(),
                ));
            }
            let token = random_cli_secret();
            let encoded = proxy_runtime::format_panel_secret(&token, ttl_secs)
                .map_err(|error| CliError::InvalidInput(error.to_string()))?;
            write_secret_file(&token_path, &encoded)?;
            println!(
                "{}",
                serde_json::json!({
                    "scope": "panel",
                    "secret": token,
                    "expires_in_secs": ttl_secs,
                    "warning": "secret is shown once; keep the 0600 token file private"
                })
            );
        }
        TokenAction::Revoke { .. } => {
            if token_path.exists() {
                std::fs::remove_file(&token_path)?;
            }
            println!("revoked panel token");
        }
        TokenAction::List => {
            println!(
                "{}",
                serde_json::json!({"scope":"panel","configured":token_path.is_file()})
            );
        }
    }
    Ok(0)
}

fn random_cli_secret() -> String {
    use rand::RngCore;
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_secret_file(path: &Path, secret: &str) -> Result<(), CliError> {
    if let Some(parent) = path.parent() {
        let parent_created = match std::fs::symlink_metadata(parent) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(CliError::InvalidInput(
                        "secret parent must be a regular directory".into(),
                    ));
                }
                false
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::create_dir_all(parent)?;
                true
            }
            Err(error) => return Err(error.into()),
        };
        if parent_created {
            #[cfg(unix)]
            use std::os::unix::fs::PermissionsExt;
            #[cfg(unix)]
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(CliError::InvalidInput(
                "secret path must be a regular, non-symlink file".into(),
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(0o600);
    }
    use std::io::Write;
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` only applies when a file is created; rotation must also
        // repair permissions on an existing token file before writing it.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(secret.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn run_ca_command(action: CaAction) -> Result<i32, CliError> {
    match action {
        CaAction::Export { dir, config, out } => {
            let dir = dir
                .or_else(|| {
                    config.as_deref().and_then(|path| {
                        proxy_runtime::ProxyAppConfig::load(path)
                            .ok()
                            .and_then(|value| value.mitm.ca_dir)
                    })
                })
                .ok_or_else(|| {
                    CliError::InvalidInput(
                        "ca export requires --dir or --config with mitm.ca_dir".into(),
                    )
                })?;
            let authority = codev_https::MitmAuthority::load_or_generate(dir)?;
            authority.export_public(out)?;
            println!(
                "CA exported; SHA-256 fingerprint {}",
                authority.fingerprint_sha256()
            );
            Ok(0)
        }
    }
}

fn ensure_loopback(address: SocketAddr) -> Result<(), CliError> {
    if !address.ip().is_loopback() {
        return Err(CliError::InvalidInput(format!(
            "refusing non-loopback --listen {address}"
        )));
    }
    Ok(())
}

async fn serve_until_signal(address: SocketAddr, hub: EventHub) -> Result<(), CliError> {
    let listener = TcpListener::bind(address).await?;
    let actual = listener.local_addr()?;
    println!("http://{actual}/");
    tokio::select! {
        result = codev_web::serve(listener, hub) => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[derive(Default)]
struct ReplayStats {
    packets: u64,
    actor_messages: u64,
    coordinate_updates: u64,
    parse_failures: u64,
    first_timestamp_ns: Option<u64>,
    last_timestamp_ns: Option<u64>,
    map_id: Option<u32>,
    channel_generation: u64,
}

async fn load_replay(
    input: &Path,
    session: Option<SessionMetadata>,
    hub: &EventHub,
    map_id: Option<u32>,
) -> Result<ReplayStats, CliError> {
    let is_finalized_record_directory = input.is_dir();
    let input = resolve_replay_input(input)?;
    if is_classic_pcap(&input)? {
        return load_pcap_replay(&input, session, hub, map_id).await;
    }
    let mut file = BufReader::with_capacity(1024 * 1024, File::open(&input)?);
    let catalog = MapCatalog::embedded()?;
    let calibration = map_id.and_then(|map_id| catalog.calibration(SUPPORTED_BUILD, map_id).ok());
    let preserve_recorded_continuity = is_finalized_record_directory
        && input
            .file_name()
            .is_some_and(|name| name == "events-v1.jsonl");
    let mut decoder = D0Decoder::new();
    let mut scratch = DecodeScratch::with_capacity(2, 16);
    let mut bytes = Vec::with_capacity(256);
    let mut stats = ReplayStats {
        map_id,
        ..ReplayStats::default()
    };
    let mut line_bytes = Vec::with_capacity(16 * 1024);
    while read_bounded_json_line(&mut file, &mut line_bytes)? {
        let line = std::str::from_utf8(&line_bytes)
            .map_err(|_| CliError::InvalidInput("replay JSONL is not valid UTF-8".into()))?;
        if line.trim().is_empty() {
            continue;
        }
        let probe: ReplayProbe = serde_json::from_str(line)?;
        if probe.record_type.as_deref() == Some("channel_generation") {
            let row: RecordedChannelGenerationRow = serde_json::from_str(line)?;
            publish_recorded_generation(hub, &mut stats, row.channel_generation, row.capture_ns)
                .await?;
            stats.first_timestamp_ns.get_or_insert(row.capture_ns);
            stats.last_timestamp_ns = Some(row.capture_ns);
            continue;
        }
        if probe.record_type.as_deref() == Some("gap") {
            let row: RecordedGapRow = serde_json::from_str(line)?;
            if row.gap.reason.len() > MAX_REPLAY_GAP_REASON_BYTES {
                return Err(CliError::InvalidInput(format!(
                    "recorded gap reason exceeds the {MAX_REPLAY_GAP_REASON_BYTES}-byte limit"
                )));
            }
            publish_recorded_generation(hub, &mut stats, row.channel_generation, row.capture_ns)
                .await?;
            stats.first_timestamp_ns.get_or_insert(row.capture_ns);
            stats.last_timestamp_ns = Some(row.capture_ns);
            hub.publish_gap(row.capture_ns, row.gap).await?;
            continue;
        }
        let (timestamp_ns, positions) = if probe.record_type.as_deref() == Some("position_update") {
            let row: RecordedPositionRow = serde_json::from_str(line)?;
            publish_recorded_generation(hub, &mut stats, row.channel_generation, row.capture_ns)
                .await?;
            let position = sanitized_replay_position(
                row.capture_ns,
                row.position,
                calibration,
                preserve_recorded_continuity,
            );
            (row.capture_ns, vec![position])
        } else if probe.data_hex.is_some() {
            let row: UnrealRow = serde_json::from_str(line)?;
            if row.channel_index == 32 && (row.open || row.close) {
                decoder = D0Decoder::new();
                stats.channel_generation = stats.channel_generation.saturating_add(1);
                hub.set_session(SessionView {
                    build_id: SUPPORTED_BUILD.into(),
                    map_id: stats.map_id,
                    status: SessionStatus::Replay,
                    status_detail: format!(
                        "Channel 32 generation {} replay boundary",
                        stats.channel_generation
                    ),
                    capture_start_ns: stats.first_timestamp_ns.or(Some(row.timestamp_ns)),
                    latest_capture_ns: Some(row.timestamp_ns),
                    channel_generation: stats.channel_generation,
                })
                .await?;
            }
            if row.channel_index != 32
                || row.open
                || row.close
                || row.partial
                || row
                    .direction
                    .as_deref()
                    .is_some_and(|value| value != "server_to_client")
            {
                continue;
            }
            stats.actor_messages += 1;
            decode_hex(&row.data_hex, &mut bytes)?;
            if decoder
                .decode_actor_message_into(&bytes, row.data_bit_length, &mut scratch)
                .is_err()
            {
                stats.parse_failures += 1;
                continue;
            }
            let positions = scratch
                .updates
                .iter()
                .filter(|update| update.position_valid)
                .map(|update| {
                    let state = update.state;
                    let mut position = PositionView::unresolved(
                        update.slot,
                        row.timestamp_ns,
                        WebVec3 {
                            x: state.position.x,
                            y: state.position.y,
                            z: state.position.z,
                        },
                        state.rotation_degrees.z,
                    );
                    position.pitch = state.rotation_degrees.x;
                    position.fresh = update.fresh_movement();
                    position.continuity = match update.continuity {
                        SlotContinuity::Continuous => Continuity::Proven,
                        SlotContinuity::Discontinuous => Continuity::Degraded,
                        SlotContinuity::Unknown => Continuity::Resyncing,
                    };
                    apply_map(calibration, &mut position);
                    position
                })
                .collect();
            (row.timestamp_ns, positions)
        } else {
            let row: CoordinateRow = serde_json::from_str(line)?;
            if !matches!(
                row.record_type.as_str(),
                "batch_character_update" | "coordinate_update"
            ) {
                continue;
            }
            let mut position = PositionView::unresolved(
                row.batch_slot,
                row.timestamp_ns,
                WebVec3 {
                    x: row.position.x,
                    y: row.position.y,
                    z: row.position.z,
                },
                row.state
                    .as_ref()
                    .and_then(|state| state.rotation_degrees)
                    .map_or(0.0, |rotation| rotation[2]),
            );
            position.pitch = row
                .state
                .as_ref()
                .and_then(|state| state.rotation_degrees)
                .map_or(0.0, |rotation| rotation[0]);
            // Compatibility coordinates are useful as a movement oracle, but
            // they do not carry the bit-level identity proof chain.  Never
            // promote caller-controlled labels or confidence into the public
            // identity graph.
            position.fresh = row.movement.is_some();
            position.continuity = Continuity::Resyncing;
            apply_map(calibration, &mut position);
            (row.timestamp_ns, vec![position])
        };
        if positions.is_empty() {
            continue;
        }
        stats.first_timestamp_ns.get_or_insert(timestamp_ns);
        stats.last_timestamp_ns = Some(timestamp_ns);
        stats.coordinate_updates += positions.len() as u64;
        hub.publish_positions(timestamp_ns, positions).await?;
    }
    Ok(stats)
}

async fn publish_recorded_generation(
    hub: &EventHub,
    stats: &mut ReplayStats,
    generation: u64,
    capture_ns: u64,
) -> Result<(), CliError> {
    // Generation zero is the explicit legacy/unknown value used by older
    // events-v1 files.  It may not roll a proven newer boundary backwards.
    if generation == 0 || generation == stats.channel_generation {
        return Ok(());
    }
    if generation < stats.channel_generation {
        return Err(CliError::InvalidInput(format!(
            "recorded channel generation rolled back from {} to {generation}",
            stats.channel_generation
        )));
    }
    stats.channel_generation = generation;
    hub.set_session(SessionView {
        build_id: SUPPORTED_BUILD.into(),
        map_id: stats.map_id,
        status: SessionStatus::Replay,
        status_detail: format!("recorded Channel 32 generation {generation}"),
        capture_start_ns: stats.first_timestamp_ns.or(Some(capture_ns)),
        latest_capture_ns: Some(capture_ns),
        channel_generation: generation,
    })
    .await?;
    Ok(())
}

#[derive(Deserialize)]
struct ReplayProbe {
    #[serde(default)]
    data_hex: Option<String>,
    #[serde(default)]
    record_type: Option<String>,
}

#[derive(Deserialize)]
struct RecordedPositionRow {
    #[serde(rename = "record_type")]
    _record_type: String,
    capture_ns: u64,
    #[serde(default)]
    channel_generation: u64,
    position: PositionView,
}

#[derive(Deserialize)]
struct RecordedGapRow {
    #[serde(rename = "record_type")]
    _record_type: String,
    capture_ns: u64,
    #[serde(default)]
    channel_generation: u64,
    gap: GapPayload,
}

#[derive(Deserialize)]
struct RecordedChannelGenerationRow {
    #[serde(rename = "record_type")]
    _record_type: String,
    capture_ns: u64,
    channel_generation: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayRecordingSummary {
    schema_version: u32,
    status: String,
    #[serde(rename = "packets")]
    _packets: u64,
    #[serde(rename = "coordinate_events")]
    _coordinate_events: u64,
    #[serde(default, rename = "gap_events")]
    _gap_events: u64,
    #[serde(default, rename = "generation_events")]
    _generation_events: u64,
    incomplete_reasons: Vec<String>,
    contains_private_session_material: bool,
}

async fn load_pcap_replay(
    input: &Path,
    session: Option<SessionMetadata>,
    hub: &EventHub,
    map_id: Option<u32>,
) -> Result<ReplayStats, CliError> {
    let input = input.to_owned();
    let hub = hub.clone();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let (cipher, server, server_port, effective_map_id, recovered_roster) =
            if let Some(mut metadata) = session {
                let server_port = metadata.server_port.ok_or_else(|| {
                    CliError::InvalidInput(
                        "--session must include the descriptor-proven UDP server port".into(),
                    )
                })?;
                (
                    metadata.cipher.take().ok_or_else(|| {
                        CliError::InvalidInput(
                            "--session did not yield descriptor-proven cipher material".into(),
                        )
                    })?,
                    metadata.server,
                    server_port,
                    map_id.or(metadata.map_id),
                    None,
                )
            } else {
                let enter = recover_enter_session_from_pcap(&input)?;
                let server = endpoint_from_text(&enter.server_ip, enter.server_port);
                let roster = roster_from_mna(&enter)?;
                (
                    C0Cipher::from_packet_key(&enter.packet_key, enter.g0_id),
                    server,
                    enter.server_port,
                    Some(enter.map_id),
                    Some(roster),
                )
            };

        if let Some(roster) = recovered_roster {
            runtime.block_on(hub.set_roster(roster))?;
        }
        let catalog = MapCatalog::embedded()?;
        let calibration = effective_map_id
            .and_then(|map_id| catalog.calibration(SUPPORTED_BUILD, map_id).ok())
            .cloned();
        let mut stats = ReplayStats {
            map_id: effective_map_id,
            ..ReplayStats::default()
        };
        let mut pending_cipher = Some(cipher);
        let mut pipeline = None;
        let mut source = S0PcapSource::open(&input)?;
        while let Some(packet) = source.next_packet()? {
            let transport = match parse_transport(&packet) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if transport.kind != TransportKind::Udp {
                continue;
            }
            if pipeline.is_none()
                && let Some((client, concrete_server)) =
                    client_and_server_for_target(&transport, server, server_port)
            {
                pipeline = Some(P0Pipeline::new(
                    pending_cipher
                        .take()
                        .expect("the selected PCAP flow consumes the cipher once"),
                    client,
                    concrete_server,
                ));
            }
            let Some(pipeline) = pipeline.as_mut() else {
                continue;
            };
            let actors = pipeline.push_transport(&transport)?;
            publish_replay_pipeline_output(
                &runtime,
                &hub,
                pipeline,
                actors,
                calibration.as_ref(),
                &mut stats,
            )?;
        }
        let pipeline = pipeline.as_mut().ok_or_else(|| {
            CliError::InvalidInput(
                "PCAP contains no UDP tuple matching the authenticated game endpoint".into(),
            )
        })?;
        let actors = pipeline.finish()?;
        publish_replay_pipeline_output(
            &runtime,
            &hub,
            pipeline,
            actors,
            calibration.as_ref(),
            &mut stats,
        )?;
        let pipeline_stats = pipeline.stats();
        stats.packets = pipeline_stats.datagrams;
        debug_assert_eq!(stats.actor_messages, pipeline_stats.actor_messages);
        Ok(stats)
    })
    .await?
}

fn publish_replay_pipeline_output(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    pipeline: &mut P0Pipeline,
    actors: Vec<A0Payload>,
    calibration: Option<&codev_assets::MapCalibration>,
    stats: &mut ReplayStats,
) -> Result<(), CliError> {
    // A reorder release may contain both the gap that invalidated baselines
    // and fresh absolute updates that immediately recover individual slots.
    // The gap must be visible first so it cannot degrade those recovered
    // samples after the fact.
    publish_pipeline_gaps(runtime, hub, pipeline)?;
    for actor in actors {
        publish_replay_actor(runtime, hub, &actor, calibration, stats)?;
    }
    Ok(())
}

fn publish_replay_actor(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    actor: &A0Payload,
    calibration: Option<&codev_assets::MapCalibration>,
    stats: &mut ReplayStats,
) -> Result<(), CliError> {
    stats.actor_messages = stats.actor_messages.saturating_add(1);
    if actor.channel_generation != stats.channel_generation {
        stats.channel_generation = actor.channel_generation;
        runtime.block_on(hub.set_session(SessionView {
            build_id: SUPPORTED_BUILD.into(),
            map_id: stats.map_id,
            status: SessionStatus::Replay,
            status_detail: format!(
                "Channel 32 generation {} replay boundary",
                stats.channel_generation
            ),
            capture_start_ns: stats.first_timestamp_ns.or(Some(actor.timestamp_ns)),
            latest_capture_ns: Some(actor.timestamp_ns),
            channel_generation: stats.channel_generation,
        }))?;
    }
    let positions = actor_positions(actor, calibration);
    if positions.is_empty() {
        return Ok(());
    }
    stats.first_timestamp_ns.get_or_insert(actor.timestamp_ns);
    stats.last_timestamp_ns = Some(actor.timestamp_ns);
    stats.coordinate_updates = stats
        .coordinate_updates
        .saturating_add(positions.len() as u64);
    runtime.block_on(hub.publish_positions(actor.timestamp_ns, positions))?;
    Ok(())
}

fn recover_enter_session_from_pcap(input: &Path) -> Result<EnterGameSession, CliError> {
    Ok(recover_enter_game_session_from_classic_pcap_open_ended(input)?.into_session())
}

fn actor_positions(
    actor: &A0Payload,
    calibration: Option<&codev_assets::MapCalibration>,
) -> Vec<PositionView> {
    actor
        .updates
        .iter()
        // A position reconstructed from an invalid baseline is not a stale
        // sample; its numeric value is unknown. Keep the last independently
        // valid point in EventHub and let gap/staleness state degrade that
        // point instead of replacing it with a guessed coordinate.
        .filter(|update| update.position_valid)
        .map(|update| {
            let state = update.state;
            let mut position = PositionView::unresolved(
                update.slot,
                actor.timestamp_ns,
                WebVec3 {
                    x: state.position.x,
                    y: state.position.y,
                    z: state.position.z,
                },
                state.rotation_degrees.z,
            );
            position.pitch = state.rotation_degrees.x;
            position.fresh = update.fresh_movement();
            position.continuity = match update.continuity {
                SlotContinuity::Continuous => Continuity::Proven,
                SlotContinuity::Discontinuous => Continuity::Degraded,
                SlotContinuity::Unknown => Continuity::Resyncing,
            };
            // 阵营优先级：BatchData 的 2 bit state_index（实测本机五人恒为 0，
            // 敌人为 1/2/3；三局真实抓包 100% 吻合，而且第一帧就有）> 出生点几何
            // 判定（RoundCampClassifier，需要开局几个包才 commit）。
            if update.state_index == 0 {
                position.camp_id = Some(codev_stream::LOCAL_CAMP_ID);
                position.identity_confidence = IdentityConfidence::Proven;
            } else if let Some(assignment) = actor
                .camp_assignments
                .iter()
                .find(|assignment| assignment.slot == update.slot)
            {
                position.camp_id = Some(assignment.camp_id);
                position.identity_confidence = IdentityConfidence::Proven;
            }
            apply_map(calibration, &mut position);
            position
        })
        .collect()
}

/// Convert a caller-controlled JSONL position into a public replay sample.
///
/// `events-v1.jsonl` contains no cryptographic/protocol identity provenance.
/// Identity-bearing fields and caller-provided map coordinates are therefore
/// always discarded. Continuity is retained only for a finalized private
/// record directory whose event stream also carries ordered generation/gap
/// records; standalone caller-controlled JSONL remains resyncing.
fn sanitized_replay_position(
    capture_ns: u64,
    source: PositionView,
    calibration: Option<&codev_assets::MapCalibration>,
    preserve_continuity: bool,
) -> PositionView {
    let mut position = PositionView::unresolved(source.slot, capture_ns, source.world, source.yaw);
    position.pitch = source.pitch;
    position.fresh = source.fresh;
    position.continuity = if preserve_continuity {
        source.continuity
    } else {
        Continuity::Resyncing
    };
    apply_map(calibration, &mut position);
    position
}

fn apply_map(calibration: Option<&codev_assets::MapCalibration>, position: &mut PositionView) {
    let Some(calibration) = calibration else {
        return;
    };
    if let Ok(map) =
        calibration.world_to_normalized(AssetVec2::new(position.world.x, position.world.y))
    {
        position.map = Some(MapPoint { u: map.x, v: map.y });
    }
}

fn resolve_replay_input(input: &Path) -> Result<PathBuf, CliError> {
    if input.is_file() {
        return Ok(input.to_owned());
    }
    if input.is_dir() {
        validate_recording_directory(input)?;
        for name in [
            "events-v1.jsonl",
            "coordinates.jsonl",
            "unreal-messages.jsonl",
            "capture.pcap",
        ] {
            let candidate = input.join(name);
            if is_nonempty_replay_artifact(&candidate)? {
                return Ok(candidate);
            }
        }
    }
    Err(CliError::InvalidInput(format!(
        "{} is not a supported replay file or record directory",
        input.display()
    )))
}

fn validate_recording_directory(directory: &Path) -> Result<(), CliError> {
    let summary_path = directory.join("summary.json");
    let metadata = std::fs::symlink_metadata(&summary_path).map_err(|_| {
        CliError::InvalidInput(format!(
            "record directory {} has no finalized summary.json",
            directory.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CliError::InvalidInput(format!(
            "record directory {} has a non-regular summary.json",
            directory.display()
        )));
    }
    if metadata.len() > MAX_RECORDING_SUMMARY_BYTES {
        return Err(CliError::InvalidInput(format!(
            "record directory {} has an oversized summary.json",
            directory.display()
        )));
    }
    let summary: ReplayRecordingSummary = serde_json::from_reader(File::open(&summary_path)?)
        .map_err(|_| {
            CliError::InvalidInput(format!(
                "record directory {} has an invalid summary.json",
                directory.display()
            ))
        })?;
    if summary.schema_version != 1 {
        return Err(CliError::InvalidInput(format!(
            "record directory {} uses an unsupported summary schema",
            directory.display()
        )));
    }
    if summary.status != "complete" || !summary.incomplete_reasons.is_empty() {
        return Err(CliError::InvalidInput(format!(
            "record directory {} is incomplete and cannot be replayed as authoritative",
            directory.display()
        )));
    }
    if !summary.contains_private_session_material {
        return Err(CliError::InvalidInput(format!(
            "record directory {} has an inconsistent privacy declaration",
            directory.display()
        )));
    }
    Ok(())
}

fn is_nonempty_replay_artifact(path: &Path) -> Result<bool, CliError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CliError::InvalidInput(format!(
            "record artifact {} must not be a symbolic link",
            path.display()
        ))),
        Ok(metadata) if !metadata.is_file() => Err(CliError::InvalidInput(format!(
            "record artifact {} is not a regular file",
            path.display()
        ))),
        Ok(metadata) => Ok(metadata.len() != 0),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn is_classic_pcap(path: &Path) -> Result<bool, CliError> {
    use std::io::Read;

    let mut magic = [0_u8; 4];
    let mut file = File::open(path)?;
    if file.read(&mut magic)? != magic.len() {
        return Ok(false);
    }
    Ok(matches!(
        magic,
        [0xd4, 0xc3, 0xb2, 0xa1]
            | [0x4d, 0x3c, 0xb2, 0xa1]
            | [0xa1, 0xb2, 0xc3, 0xd4]
            | [0xa1, 0xb2, 0x3c, 0x4d]
    ))
}

fn decode_hex(value: &str, output: &mut Vec<u8>) -> Result<(), CliError> {
    if value.len() > MAX_REPLAY_DATA_HEX_CHARS {
        return Err(CliError::InvalidInput(format!(
            "data_hex exceeds the {MAX_REPLAY_DATA_HEX_CHARS}-character replay limit"
        )));
    }
    if !value.len().is_multiple_of(2) {
        return Err(CliError::InvalidInput("odd data_hex length".into()));
    }
    output.clear();
    output.reserve(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high =
            hex_nibble(pair[0]).ok_or_else(|| CliError::InvalidInput("invalid data_hex".into()))?;
        let low =
            hex_nibble(pair[1]).ok_or_else(|| CliError::InvalidInput("invalid data_hex".into()))?;
        output.push((high << 4) | low);
    }
    Ok(())
}

fn read_bounded_json_line<R: BufRead>(
    reader: &mut R,
    output: &mut Vec<u8>,
) -> Result<bool, CliError> {
    read_bounded_json_line_with_limit(reader, output, MAX_REPLAY_JSON_LINE_BYTES)
}

fn read_bounded_json_line_with_limit<R: BufRead>(
    reader: &mut R,
    output: &mut Vec<u8>,
    limit: usize,
) -> Result<bool, CliError> {
    output.clear();
    loop {
        let (consumed, ended) = {
            let available = reader.fill_buf()?;
            if available.is_empty() {
                return Ok(!output.is_empty());
            }
            if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
                if output.len().saturating_add(newline) > limit {
                    return Err(CliError::InvalidInput(format!(
                        "replay JSONL line exceeds the {limit}-byte limit"
                    )));
                }
                output.extend_from_slice(&available[..newline]);
                (newline + 1, true)
            } else {
                if output.len().saturating_add(available.len()) > limit {
                    return Err(CliError::InvalidInput(format!(
                        "replay JSONL line exceeds the {limit}-byte limit"
                    )));
                }
                output.extend_from_slice(available);
                (available.len(), false)
            }
        };
        reader.consume(consumed);
        if ended {
            return Ok(true);
        }
    }
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn session_id_for_path(path: &Path) -> Result<String, CliError> {
    let mut hasher = Sha256::new();
    hasher.update(path.as_os_str().as_encoded_bytes());
    if let Ok(metadata) = path.metadata() {
        hasher.update(metadata.len().to_le_bytes());
    }
    Ok(format!("replay-{:x}", hasher.finalize())[..31].to_owned())
}

fn load_session_metadata(path: &Path) -> Result<SessionMetadata, CliError> {
    let session = compat_session::load_compatibility_enter_session(path)?;
    session_metadata_from_enter_session(&session)
}

fn session_metadata_from_enter_session(
    session: &EnterGameSession,
) -> Result<SessionMetadata, CliError> {
    let roster = roster_from_mna(session)?;
    let server_port = session.server_port;
    // EnterGameNotify.IP can be a DNS name. VIP is not necessarily the
    // datagram source address (the authenticated fixture demonstrates that it
    // is a distinct virtual address), so only accept an IP literal here. When
    // IP is a name, the exact notified port selects the first observed UDP
    // tuple and its concrete endpoint becomes the locked BPF target.
    let server = endpoint_from_text(&session.server_ip, server_port);
    Ok(SessionMetadata {
        map_id: Some(session.map_id),
        roster,
        server,
        server_port: Some(server_port),
        cipher: Some(C0Cipher::from_packet_key(
            &session.packet_key,
            session.g0_id,
        )),
    })
}

fn endpoint_from_text(ip: &str, port: u16) -> Option<Endpoint> {
    let ip = match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(value) => IpAddress::V4(value.octets()),
        IpAddr::V6(value) => IpAddress::V6(value.octets()),
    };
    Some(Endpoint { ip, port })
}

struct LiveCaptureTask {
    stop: Arc<AtomicBool>,
    join: JoinHandle<()>,
}

impl LiveCaptureTask {
    async fn shutdown(self) -> Result<(), CliError> {
        self.stop.store(true, Ordering::Release);
        self.join.await?;
        Ok(())
    }
}

struct PendingUdpSession {
    cipher: C0Cipher,
    server: Option<Endpoint>,
    server_port: u16,
    map_id: Option<u32>,
    generation_base: u64,
    control_flow: Option<(Endpoint, Endpoint)>,
    unsupported_oodle: bool,
}

struct ActiveUdpSession {
    pipeline: P0Pipeline,
    calibration: Option<codev_assets::MapCalibration>,
    map_id: Option<u32>,
    capture_start_ns: u64,
    channel_generation: u64,
    generation_base: u64,
    unsupported_oodle: bool,
    parse_to_ws: LatencyWindow,
    capture_to_ws: LatencyWindow,
}

fn active_session_view(
    active: Option<&ActiveUdpSession>,
    status: SessionStatus,
    status_detail: String,
    latest_capture_ns: u64,
) -> SessionView {
    SessionView {
        build_id: SUPPORTED_BUILD.into(),
        map_id: active.and_then(|value| value.map_id),
        status,
        status_detail,
        capture_start_ns: active.map(|value| value.capture_start_ns),
        latest_capture_ns: Some(latest_capture_ns),
        channel_generation: active.map_or(0, |value| value.channel_generation),
    }
}

#[derive(Default)]
struct LatencyWindow {
    samples_ns: VecDeque<u64>,
}

impl LatencyWindow {
    const CAPACITY: usize = 4096;

    fn observe(&mut self, duration: Duration) {
        if self.samples_ns.len() == Self::CAPACITY {
            self.samples_ns.pop_front();
        }
        self.samples_ns
            .push_back(duration.as_nanos().try_into().unwrap_or(u64::MAX));
    }

    fn p99_ms(&self) -> Option<f64> {
        if self.samples_ns.is_empty() {
            return None;
        }
        let mut ordered: Vec<_> = self.samples_ns.iter().copied().collect();
        ordered.sort_unstable();
        let index = ordered.len().saturating_mul(99).div_ceil(100) - 1;
        Some(ordered[index] as f64 / 1_000_000.0)
    }
}

struct MnaFlowState {
    tcp: TcpReassembler,
    framer: W0Framer,
    key: Option<Zeroizing<[u8; 16]>>,
    saw_syn: bool,
    mna_candidate: Option<bool>,
    gap_since_ns: Option<u64>,
    last_seen_ns: u64,
}

impl Default for MnaFlowState {
    fn default() -> Self {
        Self {
            tcp: TcpReassembler::new(8 * 1024 * 1024),
            framer: W0Framer::default(),
            key: None,
            saw_syn: false,
            mna_candidate: None,
            gap_since_ns: None,
            last_seen_ns: 0,
        }
    }
}

#[cfg(not(feature = "live-capture"))]
async fn start_live_capture(
    _interface: String,
    _has_private_session: bool,
    _metadata: SessionMetadata,
    _hub: EventHub,
    _record: Option<PathBuf>,
) -> Result<LiveCaptureTask, CliError> {
    Err(CliError::InvalidInput(
        "本次构建未包含实时抓包能力（Windows 客户端走代理/WinDivert 通道）".into(),
    ))
}

#[cfg(feature = "live-capture")]
async fn start_live_capture(
    interface: String,
    has_private_session: bool,
    mut metadata: SessionMetadata,
    hub: EventHub,
    record: Option<PathBuf>,
) -> Result<LiveCaptureTask, CliError> {
    let recover_from_capture = !has_private_session;
    let device = if interface == "auto" {
        S0LiveSource::auto_device()?
            .ok_or_else(|| CliError::InvalidInput("libpcap reports no active interfaces".into()))?
    } else {
        interface
    };
    let mut source = S0LiveSource::open(&device, "tcp or udp")?;
    let mut pending = if has_private_session {
        let server_port = metadata.server_port.ok_or_else(|| {
            CliError::InvalidInput(
                "--session must include the descriptor-proven UDP server port".into(),
            )
        })?;
        source.set_filter(&tight_capture_filter(metadata.server, server_port, None))?;
        Some(PendingUdpSession {
            cipher: metadata.cipher.take().ok_or_else(|| {
                CliError::InvalidInput(
                    "--session did not yield descriptor-proven cipher material".into(),
                )
            })?,
            server: metadata.server,
            server_port,
            map_id: metadata.map_id,
            generation_base: 1_u64 << 32,
            control_flow: None,
            unsupported_oodle: false,
        })
    } else {
        None
    };
    let recorder = record
        .map(|path| BoundedPrivateRecorder::create(path, RECORD_QUEUE_CAPACITY))
        .transpose()?;
    let catalog = MapCatalog::embedded()?;
    let runtime = tokio::runtime::Handle::current();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let join = tokio::task::spawn_blocking(move || {
        let mut recorder = recorder;
        let mut flows: HashMap<(Endpoint, Endpoint), MnaFlowState> = HashMap::new();
        let mut active: Option<ActiveUdpSession> = None;
        let mut session_epoch = u64::from(pending.is_some());
        let mut packets = 0_u64;
        let mut parse_failures = 0_u64;
        let mut last_pcap_drops = 0_u64;
        let mut complete = true;
        let mut end_reason = "capture stopped by user".to_owned();
        while !thread_stop.load(Ordering::Acquire) {
            let packet = match source.next_packet() {
                Ok(Some(packet)) => packet,
                Ok(None) => {
                    let idle_ns = now_ns();
                    if let Some(active) = active.as_mut() {
                        match active.pipeline.poll_timeout(idle_ns) {
                            Ok(actors) => {
                                let released_at = Instant::now();
                                if !publish_live_actors(
                                    &runtime,
                                    &hub,
                                    &mut recorder,
                                    active,
                                    actors,
                                    released_at,
                                    None,
                                ) {
                                    complete = false;
                                    end_reason = "web or recording sink failed".into();
                                    break;
                                }
                                if runtime
                                    .block_on(hub.mark_positions_stale(
                                        idle_ns,
                                        LIVE_POSITION_STALE_AFTER_NS,
                                    ))
                                    .is_err()
                                {
                                    complete = false;
                                    end_reason = "web stale-state publication failed".into();
                                    break;
                                }
                            }
                            Err(error) => {
                                complete = false;
                                end_reason = format!("UDP reorder timeout failed: {error}");
                                break;
                            }
                        }
                    }
                    if recover_from_capture && has_expired_mna_gap(&flows, idle_ns) {
                        complete = false;
                        end_reason = "MNA TCP byte gap remained unresolved for five seconds".into();
                        if let Some(recorder) = recorder.as_mut() {
                            recorder.mark_incomplete(end_reason.clone());
                        }
                        let _ = runtime.block_on(hub.set_session(active_session_view(
                            active.as_ref(),
                            SessionStatus::Unrecoverable,
                            "MNA TCP 出现永久缺口；会话恢复已 fail closed".into(),
                            idle_ns,
                        )));
                        break;
                    }
                    continue;
                }
                Err(error) => {
                    complete = false;
                    end_reason = format!("capture failed: {error}");
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.mark_incomplete(end_reason.clone());
                    }
                    let _ = runtime.block_on(hub.set_session(active_session_view(
                        active.as_ref(),
                        SessionStatus::Unrecoverable,
                        format!("抓包失败：{error}"),
                        now_ns(),
                    )));
                    break;
                }
            };
            let capture_callback_at = Instant::now();
            if let Some(recorder) = recorder.as_mut()
                && let Err(error) = recorder.try_record_packet(&packet)
            {
                complete = false;
                end_reason = format!("PCAP recording failed: {error}");
                recorder.mark_incomplete(end_reason.clone());
                let _ = runtime.block_on(hub.set_session(active_session_view(
                    active.as_ref(),
                    SessionStatus::Degraded,
                    format!("录制不完整：{error}"),
                    packet.timestamp_ns,
                )));
            }
            packets += 1;
            let Ok(transport) = parse_transport(&packet) else {
                continue;
            };

            if transport.kind == TransportKind::Tcp && recover_from_capture {
                match recover_live_enter_session(&transport, packet.timestamp_ns, &mut flows) {
                    Ok(Some(session)) => {
                        let server = endpoint_from_text(&session.server_ip, session.server_port);
                        let roster = match roster_from_mna(&session) {
                            Ok(roster) => roster,
                            Err(error) => {
                                complete = false;
                                end_reason = error.to_string();
                                break;
                            }
                        };
                        let map_id = session.map_id;
                        let cipher = C0Cipher::from_packet_key(&session.packet_key, session.g0_id);
                        session_epoch = session_epoch.saturating_add(1);
                        let generation_base = session_epoch << 32;
                        pending = Some(PendingUdpSession {
                            cipher,
                            server,
                            server_port: session.server_port,
                            map_id: Some(map_id),
                            generation_base,
                            control_flow: Some((transport.source, transport.destination)),
                            unsupported_oodle: false,
                        });
                        if let Some(active_session) = active.as_ref()
                            && !publish_live_gap(
                                &runtime,
                                &hub,
                                &mut recorder,
                                packet.timestamp_ns,
                                active_session.channel_generation,
                                GapPayload {
                                    first_missing: 0,
                                    last_missing: 0,
                                    reason: if session.reenter {
                                        "descriptor-proven re-enter notification reset the UDP session"
                                            .into()
                                    } else {
                                        "a new descriptor-proven enter notification reset the UDP session"
                                            .into()
                                    },
                                },
                            )
                        {
                            complete = false;
                            end_reason = "session-reset gap publication failed".into();
                            break;
                        }
                        active = None;
                        if let Err(error) = source.set_filter(&tight_capture_filter(
                            server,
                            session.server_port,
                            Some((transport.source, transport.destination)),
                        )) {
                            complete = false;
                            end_reason = format!("failed to tighten BPF: {error}");
                            break;
                        }
                        let calibrated = catalog.calibration(SUPPORTED_BUILD, map_id).is_ok();
                        let _ = runtime.block_on(hub.set_roster(roster));
                        let _ = runtime.block_on(hub.set_session(SessionView {
                            build_id: SUPPORTED_BUILD.into(),
                            map_id: Some(map_id),
                            status: if calibrated {
                                SessionStatus::Live
                            } else {
                                SessionStatus::Degraded
                            },
                            status_detail: if calibrated {
                                "MNA 进局通知已逐字段验证；等待主 UDP".into()
                            } else {
                                "MNA 会话有效，但当前地图缺少 proven 标定；地图坐标 fail closed"
                                    .into()
                            },
                            capture_start_ns: Some(packet.timestamp_ns),
                            latest_capture_ns: Some(packet.timestamp_ns),
                            channel_generation: generation_base,
                        }));
                    }
                    Ok(None) => {}
                    Err(error) => {
                        complete = false;
                        end_reason = format!("MNA session recovery failed: {error}");
                        let _ = runtime.block_on(hub.set_session(SessionView {
                            status: SessionStatus::Unrecoverable,
                            status_detail: format!("MNA 会话不可恢复：{error}"),
                            ..SessionView::default()
                        }));
                        break;
                    }
                }
            }

            if recover_from_capture && has_expired_mna_gap(&flows, packet.timestamp_ns) {
                complete = false;
                end_reason = "MNA TCP byte gap remained unresolved for five seconds".into();
                if let Some(recorder) = recorder.as_mut() {
                    recorder.mark_incomplete(end_reason.clone());
                }
                let _ = runtime.block_on(hub.set_session(active_session_view(
                    active.as_ref(),
                    SessionStatus::Unrecoverable,
                    "MNA TCP 出现永久缺口；会话恢复已 fail closed".into(),
                    packet.timestamp_ns,
                )));
                break;
            }

            if transport.kind == TransportKind::Udp {
                let mut activation_actors = None;
                if active.is_none()
                    && let Some(candidate) = pending.as_ref()
                    && let Some((client, server)) = client_and_server_for_target(
                        &transport,
                        candidate.server,
                        candidate.server_port,
                    )
                {
                    // A notified port can be shared or receive unrelated UDP.
                    // Keep the broad port filter until this concrete tuple has
                    // passed the authenticated SGNet -> PacketHandler -> UE
                    // path. Oodle-only packets do not establish the tuple
                    // because they stop before a UE packet is validated.
                    let mut trial = P0Pipeline::new(candidate.cipher.clone(), client, server);
                    if let Ok(actors) = trial.push_transport(&transport) {
                        let stats = trial.stats();
                        if stats.datagrams == 1 && stats.oodle_compressed == 1 {
                            complete = false;
                            end_reason =
                                "unsupported Oodle payload observed before UDP activation".into();
                            if let Some(candidate) = pending.as_mut() {
                                candidate.unsupported_oodle = true;
                                let _ = runtime.block_on(hub.set_session(SessionView {
                                    build_id: SUPPORTED_BUILD.into(),
                                    map_id: candidate.map_id,
                                    status: SessionStatus::Degraded,
                                    status_detail: codev_obf::s("9ecc1163b1ed2bd7fa5bf0cd5504b7572b1ac0e17e158b19151fcfef69418c171f17c6aaf3df7a9feef74c3697857efe9dc9026c87e82bf6cc9d2d02fdfc4090dcd8442a9a845ad094c7386da0c624c3d69c0e03fedf469df4d44a2097896cf95b2ee6aafeed46").into(),
                                    capture_start_ns: Some(packet.timestamp_ns),
                                    latest_capture_ns: Some(packet.timestamp_ns),
                                    channel_generation: candidate.generation_base,
                                }));
                            }
                            if let Some(recorder) = recorder.as_mut() {
                                recorder.mark_incomplete(end_reason.clone());
                            }
                            if !publish_live_gap(
                                &runtime,
                                &hub,
                                &mut recorder,
                                packet.timestamp_ns,
                                pending
                                    .as_ref()
                                    .map_or(0, |candidate| candidate.generation_base),
                                GapPayload {
                                    first_missing: 0,
                                    last_missing: 0,
                                    reason: codev_obf::s("c4ff473398aaf129c6eb473e99e4d521c6e1562fb5a5eb24c9ef417bb2abe12cc0aa433a84a8ea21c1aa402f92b4f525c1aa522fddb0ed2585e95c368db6e033d6e35c35dda6ea35cbee522984").into(),
                                },
                            ) {
                                end_reason = "Oodle boundary gap publication failed".into();
                                break;
                            }
                        }
                        let tuple_is_valid = stats.datagrams == 1
                            && stats.sgnet_decrypted == 1
                            && stats.packet_handler_pass_through == 1
                            && stats.unreal_packets == 1;
                        if tuple_is_valid {
                            let candidate = pending.take().unwrap();
                            let calibration = candidate
                                .map_id
                                .and_then(|map_id| {
                                    catalog.calibration(SUPPORTED_BUILD, map_id).ok()
                                })
                                .cloned();
                            active = Some(ActiveUdpSession {
                                pipeline: trial,
                                calibration,
                                map_id: candidate.map_id,
                                capture_start_ns: packet.timestamp_ns,
                                channel_generation: candidate.generation_base,
                                generation_base: candidate.generation_base,
                                unsupported_oodle: candidate.unsupported_oodle,
                                parse_to_ws: LatencyWindow::default(),
                                capture_to_ws: LatencyWindow::default(),
                            });
                            activation_actors = Some(actors);
                            if let Err(error) = source.set_filter(&locked_capture_filter(
                                client,
                                server,
                                candidate.control_flow,
                            )) {
                                complete = false;
                                end_reason =
                                    format!("failed to lock the concrete UDP BPF tuple: {error}");
                                break;
                            }
                            let calibrated = active
                                .as_ref()
                                .is_some_and(|value| value.calibration.is_some());
                            let oodle_blocked =
                                active.as_ref().is_some_and(|value| value.unsupported_oodle);
                            let _ = runtime.block_on(hub.set_session(SessionView {
                                build_id: SUPPORTED_BUILD.into(),
                                map_id: active.as_ref().and_then(|value| value.map_id),
                                status: if calibrated && !oodle_blocked {
                                    SessionStatus::Live
                                } else {
                                    SessionStatus::Degraded
                                },
                                status_detail: if oodle_blocked {
                                    "主 UDP 已锁定，但此前出现未授权 Oodle 边界；会话保持 degraded"
                                        .into()
                                } else if calibrated {
                                    codev_obf::s("d78134a0ae389adbd68e3d697be62244b419dcc7b519bed4667caf6951f02254b2dc363612e84b1e9da3603c60996465d5ae396566ec2c5bb4d128231de25a138ca9672177987256")
                                        .into()
                                } else {
                                    codev_obf::s("46fd1c640166600247f215add4b8d89d2565f4031a47440df70087adfeaed88d23a01ef2bdb6b1c70cdf48f8cfc7ac9247de19a2f4a5d58c38a33bee7452424dd420c9abe8ae65748da01dd1b1b98ec61dd841c8d5025643cb298727384d4347c6")
                                        .into()
                                },
                                capture_start_ns: Some(packet.timestamp_ns),
                                latest_capture_ns: Some(packet.timestamp_ns),
                                channel_generation: active
                                    .as_ref()
                                    .map_or(0, |value| value.generation_base),
                            }));
                        }
                    }
                }
                if let Some(active) = active.as_mut() {
                    let oodle_before = active.pipeline.stats().oodle_compressed;
                    let decoded = activation_actors
                        .map_or_else(|| active.pipeline.push_transport(&transport), Ok);
                    match decoded {
                        Ok(actors) => {
                            let released_at = Instant::now();
                            if !publish_live_actors(
                                &runtime,
                                &hub,
                                &mut recorder,
                                active,
                                actors,
                                released_at,
                                Some(capture_callback_at),
                            ) {
                                complete = false;
                                end_reason = "web or recording sink failed".into();
                                break;
                            }
                            if active.pipeline.stats().oodle_compressed > oodle_before
                                && transport.source == active.pipeline.server()
                            {
                                active.unsupported_oodle = true;
                                complete = false;
                                end_reason =
                                    "unsupported server Oodle payload observed after UDP activation"
                                        .into();
                                if let Some(recorder) = recorder.as_mut() {
                                    recorder.mark_incomplete(end_reason.clone());
                                }
                                if !publish_live_gap(
                                    &runtime,
                                    &hub,
                                    &mut recorder,
                                    packet.timestamp_ns,
                                    active.channel_generation,
                                    GapPayload {
                                        first_missing: 0,
                                        last_missing: 0,
                                        reason: codev_obf::s("1d3d9031b0cc73cf0f3b8922a1f632f10a348735f5f13cfb023dc237b4c73ff00f3cc22ea69e26f11d2d9237bacc27fa0a63c224bad027f6002d8b33ac9e3af118398e2eb1df27fa0a").into(),
                                    },
                                ) {
                                    end_reason = "Oodle gap publication failed".into();
                                    break;
                                }
                                let _ = runtime.block_on(hub.set_session(SessionView {
                                    build_id: SUPPORTED_BUILD.into(),
                                    map_id: active.map_id,
                                    status: SessionStatus::Degraded,
                                    status_detail:
                                        "服务端出现未授权 Oodle 压缩边界；未尝试猜解".into(),
                                    capture_start_ns: Some(active.capture_start_ns),
                                    latest_capture_ns: Some(packet.timestamp_ns),
                                    channel_generation: active.channel_generation,
                                }));
                            }
                        }
                        Err(error) => {
                            parse_failures = parse_failures.saturating_add(1);
                            complete = false;
                            end_reason = format!(
                                "strict UDP decode failed after {parse_failures} parse failure(s): {error}"
                            );
                            if let Some(recorder) = recorder.as_mut() {
                                recorder.mark_incomplete(end_reason.clone());
                            }
                            let _ = runtime.block_on(hub.set_session(SessionView {
                                status: SessionStatus::Unrecoverable,
                                status_detail: format!("协议解析已 fail closed：{error}"),
                                ..SessionView::default()
                            }));
                            break;
                        }
                    }
                }
            }

            if packets.is_multiple_of(128) {
                let pcap_drops = match source.capture_stats() {
                    Ok(stats) => stats.dropped.saturating_add(stats.interface_dropped),
                    Err(error) => {
                        complete = false;
                        end_reason = format!("libpcap statistics failed: {error}");
                        if let Some(recorder) = recorder.as_mut() {
                            recorder.mark_incomplete(end_reason.clone());
                        }
                        let _ = runtime.block_on(hub.set_session(active_session_view(
                            active.as_ref(),
                            SessionStatus::Unrecoverable,
                            "无法读取 libpcap/Npcap 丢包计数；完整性已 fail closed".into(),
                            packet.timestamp_ns,
                        )));
                        break;
                    }
                };
                if pcap_drops > last_pcap_drops {
                    complete = false;
                    let drop_count = pcap_drops - last_pcap_drops;
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.mark_incomplete(format!(
                            "libpcap reported {} new dropped packets",
                            drop_count
                        ));
                    }
                    let gap_published = if let Some(active) = active.as_mut() {
                        active.pipeline.mark_capture_gap(packet.timestamp_ns);
                        let _ = runtime.block_on(hub.set_session(SessionView {
                            build_id: SUPPORTED_BUILD.into(),
                            map_id: active.map_id,
                            status: SessionStatus::Degraded,
                            status_detail: "libpcap/Npcap 报告丢包；等待独立绝对坐标重同步".into(),
                            capture_start_ns: Some(active.capture_start_ns),
                            latest_capture_ns: Some(packet.timestamp_ns),
                            channel_generation: active.channel_generation,
                        }));
                        publish_live_pipeline_gaps(&runtime, &hub, &mut recorder, active)
                    } else {
                        publish_live_gap(
                            &runtime,
                            &hub,
                            &mut recorder,
                            packet.timestamp_ns,
                            0,
                            GapPayload {
                                first_missing: 0,
                                last_missing: 0,
                                reason: format!("libpcap drop counter increased by {drop_count}"),
                            },
                        )
                    };
                    if !gap_published {
                        end_reason = "web capture-gap publication failed".into();
                        break;
                    }
                }
                last_pcap_drops = pcap_drops;
                let (pipeline_stats, parse_to_ws_p99_ms, capture_to_ws_p99_ms) =
                    active.as_ref().map_or_else(
                        || (PipelineStats::default(), None, None),
                        |value| {
                            (
                                value.pipeline.stats(),
                                value.parse_to_ws.p99_ms(),
                                value.capture_to_ws.p99_ms(),
                            )
                        },
                    );
                let _ = runtime.block_on(hub.publish_metrics(
                    packet.timestamp_ns,
                    MetricsPayload {
                        packets,
                        actor_messages: pipeline_stats.actor_messages,
                        coordinate_updates: pipeline_stats.character_updates,
                        parse_failures,
                        pcap_drops,
                        proxy_pipeline: None,
                        parse_to_ws_p99_ms,
                        capture_to_ws_p99_ms,
                    },
                ));
            }
        }

        let final_capture_ns = now_ns();
        match source.capture_stats() {
            Ok(stats) => {
                let pcap_drops = stats.dropped.saturating_add(stats.interface_dropped);
                if pcap_drops > last_pcap_drops {
                    complete = false;
                    end_reason = format!(
                        "libpcap reported {} additional dropped packet(s) during finalization",
                        pcap_drops - last_pcap_drops
                    );
                    if let Some(recorder) = recorder.as_mut() {
                        recorder.mark_incomplete(end_reason.clone());
                    }
                    let gap_published = if let Some(active) = active.as_mut() {
                        active.pipeline.mark_capture_gap(final_capture_ns);
                        publish_live_pipeline_gaps(&runtime, &hub, &mut recorder, active)
                    } else {
                        publish_live_gap(
                            &runtime,
                            &hub,
                            &mut recorder,
                            final_capture_ns,
                            0,
                            GapPayload {
                                first_missing: 0,
                                last_missing: 0,
                                reason: end_reason.clone(),
                            },
                        )
                    };
                    if !gap_published {
                        end_reason = "final web capture-gap publication failed".into();
                    }
                }
            }
            Err(error) => {
                complete = false;
                end_reason = format!("final libpcap statistics failed: {error}");
                if let Some(recorder) = recorder.as_mut() {
                    recorder.mark_incomplete(end_reason.clone());
                }
            }
        }
        if active.is_none() && complete {
            complete = false;
            end_reason = if pending.is_some() {
                "capture stopped before an authenticated UE packet activated the main UDP tuple"
                    .into()
            } else {
                "capture stopped before a descriptor-valid MNA session was recovered".into()
            };
        }
        if recover_from_capture
            && pending.is_none()
            && flows.values().any(|flow| {
                flow.mna_candidate == Some(true) && (flow.tcp.has_gap() || !flow.framer.is_empty())
            })
        {
            complete = false;
            end_reason = "capture ended with an incomplete MNA TCP byte/frame stream".into();
        }
        if let Some(active) = active.as_mut() {
            match active.pipeline.finish() {
                Ok(actors) => {
                    let released_at = Instant::now();
                    if !publish_live_actors(
                        &runtime,
                        &hub,
                        &mut recorder,
                        active,
                        actors,
                        released_at,
                        None,
                    ) {
                        complete = false;
                        end_reason = "final web or recording sink failed".into();
                    }
                }
                Err(error) => {
                    complete = false;
                    end_reason = format!("capture ended with incomplete UDP state: {error}");
                }
            }
        }
        if let Some(recorder) = recorder.as_mut() {
            if !complete {
                recorder.mark_incomplete(end_reason.clone());
            }
            if let Err(error) = recorder.finish() {
                complete = false;
                end_reason = format!("recording finalization failed: {error}");
            }
        }
        let capture_ns = now_ns();
        let _ = runtime.block_on(hub.publish_end(
            capture_ns,
            EndPayload {
                complete,
                reason: end_reason.clone(),
            },
        ));
        let _ = runtime.block_on(hub.set_session(active_session_view(
            active.as_ref(),
            if complete {
                SessionStatus::Ended
            } else {
                SessionStatus::Unrecoverable
            },
            end_reason,
            capture_ns,
        )));
    });
    Ok(LiveCaptureTask { stop, join })
}

fn recover_live_enter_session(
    transport: &codev_stream::TransportPacket<'_>,
    capture_ns: u64,
    flows: &mut HashMap<(Endpoint, Endpoint), MnaFlowState>,
) -> Result<Option<EnterGameSession>, codev_stream::W0Error> {
    let key = (transport.source, transport.destination);
    let raw_sequence = transport
        .tcp_sequence
        .ok_or(codev_stream::W0Error::InvalidEnvelope("TCP sequence"))?;
    if transport.tcp_flags & TCP_RST != 0
        && flows
            .get(&key)
            .is_some_and(|flow| flow.mna_candidate == Some(true))
    {
        return Err(codev_stream::W0Error::InvalidEnvelope("MNA TCP reset"));
    }
    let has_syn = transport.tcp_flags & TCP_SYN != 0;
    if transport.tcp_flags & TCP_RST != 0 {
        flows.remove(&key);
        return Ok(None);
    }
    if !flows.contains_key(&key) && has_syn && flows.len() >= MAX_LIVE_TCP_FLOWS {
        let eviction = flows
            .iter()
            .filter(|(_, flow)| flow.mna_candidate != Some(true))
            .min_by_key(|(_, flow)| flow.last_seen_ns)
            .map(|(key, _)| *key);
        let Some(eviction) = eviction else {
            return Ok(None);
        };
        flows.remove(&eviction);
    }
    if let std::collections::hash_map::Entry::Vacant(entry) = flows.entry(key) {
        let looks_like_mna = !transport.payload.is_empty()
            && (transport.payload.starts_with(&MNA_MAGIC)
                || MNA_MAGIC.starts_with(transport.payload));
        if !has_syn {
            if looks_like_mna {
                return Err(codev_stream::W0Error::InvalidEnvelope(
                    "MNA TCP data observed before SYN",
                ));
            }
            return Ok(None);
        }
        let mut flow = MnaFlowState::default();
        flow.tcp.initialize(raw_sequence.wrapping_add(1))?;
        flow.saw_syn = true;
        flow.last_seen_ns = capture_ns;
        entry.insert(flow);
    }
    let flow = flows
        .get_mut(&key)
        .expect("the TCP flow was inserted or already existed");
    flow.last_seen_ns = capture_ns;
    if has_syn && !flow.saw_syn {
        flow.tcp.initialize(raw_sequence.wrapping_add(1))?;
        flow.saw_syn = true;
    }
    if flow.mna_candidate == Some(false) {
        return Ok(None);
    }
    let data_sequence = raw_sequence.wrapping_add(u32::from(has_syn));
    let bytes = if transport.payload.is_empty() {
        Vec::new()
    } else {
        flow.tcp.push(data_sequence, transport.payload)?
    };
    if flow.tcp.has_gap() {
        flow.gap_since_ns.get_or_insert(capture_ns);
    } else {
        flow.gap_since_ns = None;
    }
    if flow.mna_candidate.is_none() && !bytes.is_empty() {
        let looks_like_mna = bytes.starts_with(&MNA_MAGIC) || MNA_MAGIC.starts_with(&bytes);
        flow.mna_candidate = Some(looks_like_mna);
    }
    if flow.mna_candidate != Some(true) {
        if flow.mna_candidate == Some(false) || transport.tcp_flags & TCP_FIN != 0 {
            flows.remove(&key);
        }
        return Ok(None);
    }
    for frame in flow.framer.feed(&bytes)? {
        if frame.message_type == MNA_SERVER_HELLO {
            flow.key = Some(recover_mna_session_key(std::slice::from_ref(&frame))?);
            continue;
        }
        if frame.message_type != MNA_DATA {
            continue;
        }
        let Some(session_key) = flow.key.as_deref() else {
            // The client direction never carries ServerHello, so it cannot own
            // the AES key. Client MNA_DATA is irrelevant to the server-side
            // Enter/ReEnterGameNotify. A server DATA frame without a preceding
            // hello, however, proves capture started too late and must fail
            // closed.
            if frame.direction_marker == 0 {
                continue;
            }
            return Err(codev_stream::W0Error::SessionKeyCount(0));
        };
        let mut plaintext = decrypt_mna_frame(&frame, session_key)?;
        strip_mna_random_padding(&mut plaintext)?;
        let application =
            parse_mna_application(&plaintext, frame.direction_marker, frame.sequence)?;
        if let Some(session) = parse_enter_game_session(&application)? {
            return Ok(Some(session));
        }
    }
    if transport.tcp_flags & TCP_FIN != 0 {
        let end_sequence = data_sequence.wrapping_add(transport.payload.len() as u32);
        if flow.tcp.has_gap() || !flow.tcp.is_complete_at(end_sequence) || !flow.framer.is_empty() {
            return Err(codev_stream::W0Error::InvalidEnvelope(
                "MNA TCP closed with an incomplete byte/frame stream",
            ));
        }
        flows.remove(&key);
    }
    Ok(None)
}

fn has_expired_mna_gap(
    flows: &HashMap<(Endpoint, Endpoint), MnaFlowState>,
    capture_ns: u64,
) -> bool {
    flows.values().any(|flow| {
        flow.mna_candidate == Some(true)
            && flow.tcp.has_gap()
            && flow
                .gap_since_ns
                .is_some_and(|since| capture_ns.saturating_sub(since) >= LIVE_MNA_GAP_TIMEOUT_NS)
    })
}

fn roster_from_mna(session: &EnterGameSession) -> Result<Vec<RosterEntry>, CliError> {
    session
        .roster
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let camp_id = u32::try_from(entry.camp_id).map_err(|_| {
                CliError::InvalidInput("MNA CampId does not fit the public schema".into())
            })?;
            Ok(RosterEntry {
                // roster 顺序经实测与 BatchData 槽位顺序一致 → 直接用序号当槽位
                slot: Some(u8::try_from(index).unwrap_or(63)),
                display_name: format!("batch_slot_{}", entry.position_slot),
                agent_id: entry.agent_id,
                camp_id,
                position_slot: u32::try_from(entry.position_slot).ok(),
                device_tag: entry.device_tag,
                identity_confidence: IdentityConfidence::Unresolved,
            })
        })
        .collect()
}

fn client_for_server_flow(
    transport: &codev_stream::TransportPacket<'_>,
    server: Endpoint,
) -> Option<Endpoint> {
    if transport.destination == server {
        Some(transport.source)
    } else if transport.source == server {
        Some(transport.destination)
    } else {
        None
    }
}

fn client_and_server_for_target(
    transport: &codev_stream::TransportPacket<'_>,
    server: Option<Endpoint>,
    server_port: u16,
) -> Option<(Endpoint, Endpoint)> {
    if let Some(server) = server
        && let Some(client) = client_for_server_flow(transport, server)
    {
        return Some((client, server));
    }
    if transport.destination.port == server_port && transport.source.port != server_port {
        Some((transport.source, transport.destination))
    } else if transport.source.port == server_port && transport.destination.port != server_port {
        Some((transport.destination, transport.source))
    } else {
        None
    }
}

fn tight_capture_filter(
    server: Option<Endpoint>,
    server_port: u16,
    control_flow: Option<(Endpoint, Endpoint)>,
) -> String {
    let udp = server.map_or_else(
        || format!("udp and port {server_port}"),
        |server| format!("udp and host {} and port {}", server.ip, server.port),
    );
    let Some((source, destination)) = control_flow else {
        return udp;
    };
    format!(
        "({udp}) or ({})",
        bidirectional_flow_filter("tcp", source, destination)
    )
}

fn locked_capture_filter(
    client: Endpoint,
    server: Endpoint,
    control_flow: Option<(Endpoint, Endpoint)>,
) -> String {
    let udp = bidirectional_flow_filter("udp", client, server);
    let Some((source, destination)) = control_flow else {
        return udp;
    };
    format!(
        "({udp}) or ({})",
        bidirectional_flow_filter("tcp", source, destination)
    )
}

fn bidirectional_flow_filter(protocol: &str, left: Endpoint, right: Endpoint) -> String {
    format!(
        "{protocol} and (((src host {} and src port {}) and (dst host {} and dst port {})) or ((src host {} and src port {}) and (dst host {} and dst port {})))",
        left.ip, left.port, right.ip, right.port, right.ip, right.port, left.ip, left.port,
    )
}

fn publish_channel_generation(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    recorder: &mut Option<BoundedPrivateRecorder>,
    active: &mut ActiveUdpSession,
    actor: &A0Payload,
) -> bool {
    let generation = active
        .generation_base
        .saturating_add(actor.channel_generation);
    if generation == active.channel_generation {
        return true;
    }
    active.channel_generation = generation;
    let healthy = active.calibration.is_some() && !active.unsupported_oodle;
    if runtime
        .block_on(hub.set_session(SessionView {
            build_id: SUPPORTED_BUILD.into(),
            map_id: active.map_id,
            status: if healthy {
                SessionStatus::Live
            } else {
                SessionStatus::Degraded
            },
            status_detail: if active.unsupported_oodle {
                format!(
                    "Channel 32 generation {generation}；存在未授权 Oodle 边界，会话保持 degraded"
                )
            } else {
                codev_obf::s("43562f9cd7df6511330c6e95dcd46c43614a279dd79a725665502b80d8ce605e6e43a14e225eb3bae5b4ef1705352973614a2d9aeac3675220d6e9515f2499d5b893")
            },
            capture_start_ns: Some(active.capture_start_ns),
            latest_capture_ns: Some(actor.timestamp_ns),
            channel_generation: generation,
        }))
        .is_err()
    {
        return false;
    }
    if let Some(recorder) = recorder.as_mut()
        && let Err(error) = recorder.try_record_channel_generation(actor.timestamp_ns, generation)
    {
        recorder.mark_incomplete(format!("generation event recording failed: {error}"));
        return false;
    }
    true
}

fn publish_live_actors(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    recorder: &mut Option<BoundedPrivateRecorder>,
    active: &mut ActiveUdpSession,
    actors: Vec<A0Payload>,
    released_at: Instant,
    capture_callback_at: Option<Instant>,
) -> bool {
    // See `publish_replay_pipeline_output`: recovery deltas from this release
    // must follow the invalidating gap in the public event order.
    if !publish_live_pipeline_gaps(runtime, hub, recorder, active) {
        return false;
    }
    for actor in actors {
        if !publish_channel_generation(runtime, hub, recorder, active, &actor) {
            return false;
        }
        let positions = actor_positions(&actor, active.calibration.as_ref());
        if positions.is_empty() {
            continue;
        }
        if runtime
            .block_on(hub.publish_positions(actor.timestamp_ns, positions.clone()))
            .is_err()
        {
            return false;
        }
        active.parse_to_ws.observe(released_at.elapsed());
        if let Some(capture_callback_at) = capture_callback_at {
            active.capture_to_ws.observe(capture_callback_at.elapsed());
        }
        if let Some(recorder) = recorder.as_mut()
            && let Err(error) = recorder.try_record_positions_with_generation(
                actor.timestamp_ns,
                active.channel_generation,
                &positions,
            )
        {
            recorder.mark_incomplete(format!("event recording failed: {error}"));
            return false;
        }
    }
    true
}

fn publish_pipeline_gaps(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    pipeline: &mut P0Pipeline,
) -> Result<(), CliError> {
    for gap in pipeline.drain_gaps() {
        runtime.block_on(hub.publish_gap(gap.detected_ns, pipeline_gap_payload(&gap)))?;
    }
    Ok(())
}

fn publish_live_pipeline_gaps(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    recorder: &mut Option<BoundedPrivateRecorder>,
    active: &mut ActiveUdpSession,
) -> bool {
    for gap in active.pipeline.drain_gaps() {
        let payload = pipeline_gap_payload(&gap);
        if !publish_live_gap(
            runtime,
            hub,
            recorder,
            gap.detected_ns,
            active.channel_generation,
            payload,
        ) {
            return false;
        }
    }
    true
}

fn publish_live_gap(
    runtime: &tokio::runtime::Handle,
    hub: &EventHub,
    recorder: &mut Option<BoundedPrivateRecorder>,
    capture_ns: u64,
    channel_generation: u64,
    payload: GapPayload,
) -> bool {
    if runtime
        .block_on(hub.publish_gap(capture_ns, payload.clone()))
        .is_err()
    {
        return false;
    }
    if let Some(recorder) = recorder.as_mut()
        && let Err(error) = recorder.try_record_gap(capture_ns, channel_generation, &payload)
    {
        recorder.mark_incomplete(format!("gap event recording failed: {error}"));
        return false;
    }
    true
}

fn pipeline_gap_payload(gap: &PipelineGap) -> GapPayload {
    let first_missing = gap.first_missing.unwrap_or_default();
    GapPayload {
        first_missing,
        last_missing: gap.last_missing.unwrap_or(first_missing),
        reason: format!(
            "{:?} gap ({:?}); resumed at {:?}",
            gap.reason, gap.direction, gap.resumed_at
        ),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_position_stale_grace_covers_sparse_delta_updates() {
        assert_eq!(LIVE_POSITION_STALE_AFTER_NS, 4_000_000_000);
        assert!(LIVE_POSITION_STALE_AFTER_NS > 1_500_000_000);
    }

    #[test]
    fn token_options_are_accepted_after_or_before_action() {
        let after = Cli::try_parse_from([
            "codev-net",
            "token",
            "create",
            "--store",
            "/tmp/proxy-tokens.toml",
            "--scope",
            "proxy",
        ])
        .expect("token options after action should parse");
        assert!(matches!(after.command, Commands::Token { .. }));

        let before = Cli::try_parse_from([
            "codev-net",
            "token",
            "--store",
            "/tmp/proxy-tokens.toml",
            "--scope",
            "proxy",
            "create",
        ])
        .expect("token options before action should parse");
        assert!(matches!(before.command, Commands::Token { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn proxy_token_created_from_config_uses_configured_runtime_limits() {
        let directory = tempfile::tempdir().unwrap();
        let token_path = directory.path().join("tokens.toml");
        let config_path = directory.path().join("config.toml");
        let config = format!(
            r#"
[proxy]
listen = "127.0.0.1:1080"
token_store = "{}"
token_ttl_secs = 3600
max_connections_per_token = 73
max_udp_flows_per_token = 41
bytes_per_second_per_token = 33554432
udp_idle_secs = 47
allow_hosts = ["*.qq.com"]
allow_ports = [443]

[panel]
listen = "127.0.0.1:3000"

[record]
directory = "{}"
"#,
            token_path.display(),
            directory.path().join("record").display()
        );
        std::fs::write(&config_path, config).unwrap();

        run_token_command(
            TokenAction::Create {
                username: Some("configured-limits".into()),
                ttl_secs: 3600,
            },
            None,
            Some(&config_path),
            "proxy",
        )
        .unwrap();

        let store = codev_proxy::TokenStore::load(&token_path).unwrap();
        let status = store.list().into_iter().next().unwrap();
        assert_eq!(status.limits.max_connections, 73);
        assert_eq!(status.limits.max_udp_flows, 41);
        assert_eq!(status.limits.bytes_per_second, 33_554_432);
        assert_eq!(status.limits.udp_idle_secs, 47);
    }

    #[cfg(unix)]
    #[test]
    fn panel_secret_rotation_repairs_permissions_and_rejects_parent_symlink() {
        use std::os::unix::fs::PermissionsExt;

        let directory = std::env::temp_dir().join(format!(
            "codev-panel-secret-test-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("panel.secret");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_secret_file(&path, "new-secret").unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new-secret\n");

        let link_parent = directory.join("link-parent");
        std::os::unix::fs::symlink(&directory, &link_parent).unwrap();
        let linked_path = link_parent.join("should-not-exist");
        assert!(write_secret_file(&linked_path, "secret").is_err());
        assert!(!directory.join("should-not-exist").exists());
        let _ = std::fs::remove_dir_all(&directory);
    }

    #[test]
    fn hex_decoder_is_strict() {
        let mut output = Vec::new();
        decode_hex("00aF", &mut output).unwrap();
        assert_eq!(output, [0, 0xaf]);
        assert!(decode_hex("0", &mut output).is_err());
        assert!(decode_hex("zz", &mut output).is_err());
    }

    #[test]
    fn replay_jsonl_reader_rejects_a_line_before_unbounded_growth() {
        let mut reader = std::io::BufReader::with_capacity(2, &b"12345\nnext\n"[..]);
        let mut output = Vec::new();
        let error = read_bounded_json_line_with_limit(&mut reader, &mut output, 4).unwrap_err();
        assert!(error.to_string().contains("4-byte limit"));

        let mut reader = std::io::BufReader::with_capacity(2, &b"1234\n"[..]);
        assert!(read_bounded_json_line_with_limit(&mut reader, &mut output, 4).unwrap());
        assert_eq!(output, b"1234");
        assert!(!read_bounded_json_line_with_limit(&mut reader, &mut output, 4).unwrap());
    }

    #[test]
    fn record_directory_requires_a_valid_complete_summary() {
        let directory = std::env::temp_dir().join(format!(
            "codev-replay-summary-test-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("events-v1.jsonl"), "{}\n").unwrap();

        let missing = resolve_replay_input(&directory).unwrap_err();
        assert!(missing.to_string().contains("no finalized summary.json"));

        std::fs::write(
            directory.join("summary.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "status": "incomplete",
                "packets": 1,
                "coordinate_events": 1,
                "incomplete_reasons": ["test loss"],
                "contains_private_session_material": true
            }))
            .unwrap(),
        )
        .unwrap();
        let incomplete = resolve_replay_input(&directory).unwrap_err();
        assert!(incomplete.to_string().contains("is incomplete"));

        std::fs::write(
            directory.join("summary.json"),
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "status": "complete",
                "packets": 1,
                "coordinate_events": 1,
                "incomplete_reasons": [],
                "contains_private_session_material": true
            }))
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            resolve_replay_input(&directory).unwrap(),
            directory.join("events-v1.jsonl")
        );

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn latency_window_is_bounded_and_reports_nearest_rank_p99() {
        let mut window = LatencyWindow::default();
        for milliseconds in 1..=100 {
            window.observe(Duration::from_millis(milliseconds));
        }
        assert_eq!(window.p99_ms(), Some(99.0));
        for _ in 0..LatencyWindow::CAPACITY {
            window.observe(Duration::from_millis(7));
        }
        assert_eq!(window.samples_ns.len(), LatencyWindow::CAPACITY);
        assert_eq!(window.p99_ms(), Some(7.0));
    }

    #[test]
    fn private_session_exposes_only_redacted_roster_fields() {
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../work/session-20260806/session.json");
        if !fixture.is_file() {
            return;
        }
        let metadata = load_session_metadata(&fixture).unwrap();
        assert_eq!(metadata.map_id, Some(1003));
        assert_eq!(metadata.roster.len(), 10);
        let encoded = serde_json::to_string(&metadata.roster).unwrap();
        assert!(!encoded.contains("OpenId"));
        assert!(!encoded.contains("open_id"));
        assert!(!encoded.contains("Uid"));
        assert!(!encoded.contains("PacketKey"));
        let private: Value = serde_json::from_reader(File::open(&fixture).unwrap()).unwrap();
        let notify = &private["control_plane"]["e0_notify"];
        let mut forbidden = vec![
            notify["PacketKey"].as_str().unwrap().to_owned(),
            notify["GameId"].as_str().unwrap().to_owned(),
        ];
        for player in notify["CampInfo"].as_array().unwrap() {
            forbidden.push(player["Uid"].as_str().unwrap().to_owned());
            forbidden.push(player["OpenId"].as_str().unwrap().to_owned());
            if let Some(name) = player["Name"].as_str() {
                forbidden.push(name.to_owned());
            }
            if let Some(display_name) = player["DisplayName"].as_str() {
                forbidden.push(display_name.to_owned());
            }
        }
        for value in forbidden {
            assert!(
                !encoded.contains(&value),
                "public roster leaked a private value"
            );
        }
    }

    #[tokio::test]
    async fn real_unreal_message_replay_matches_v2_counts() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../work/session-20260806/unreal-messages.jsonl");
        if !fixture.is_file() {
            return;
        }
        let hub = EventHub::new("test-replay").unwrap();
        let stats = load_replay(&fixture, None, &hub, None).await.unwrap();
        assert_eq!(stats.actor_messages, 4_444);
        assert_eq!(stats.coordinate_updates, 17_031);
        assert_eq!(stats.parse_failures, 0);
        assert_eq!(hub.snapshot().await.len(), 10);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn real_pcap_replay_uses_the_bounded_rust_pipeline() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixture = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        let session = root.join("work/session-20260806/session.json");
        if !fixture.is_file() || !session.is_file() {
            return;
        }
        let hub = EventHub::new("test-pcap-replay").unwrap();
        let metadata = load_session_metadata(&session).unwrap();
        let stats = load_replay(&fixture, Some(metadata), &hub, None)
            .await
            .unwrap();
        assert_eq!(stats.packets, 12_414);
        assert_eq!(stats.actor_messages, 4_444);
        assert_eq!(stats.coordinate_updates, 17_031);
        assert_eq!(stats.parse_failures, 0);
        assert_eq!(hub.snapshot().await.len(), 10);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn full_pcap_replay_recovers_mna_without_a_session_file() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !fixture.is_file() {
            return;
        }
        let hub = EventHub::new("test-auto-mna-pcap-replay").unwrap();
        let stats = load_replay(&fixture, None, &hub, None).await.unwrap();
        assert_eq!(stats.map_id, Some(1003));
        assert_eq!(stats.packets, 12_414);
        assert_eq!(stats.actor_messages, 4_444);
        assert_eq!(stats.coordinate_updates, 17_031);
        assert_eq!(stats.parse_failures, 0);
        assert_eq!(hub.snapshot().await.len(), 10);
    }

    #[test]
    fn authenticated_endpoint_filter_drops_tcp_after_session_lock() {
        let server = Endpoint {
            ip: IpAddress::V4([203, 0, 113, 7]),
            port: 15_806,
        };
        assert_eq!(
            tight_capture_filter(Some(server), server.port, None),
            "udp and host 203.0.113.7 and port 15806"
        );
    }

    #[test]
    fn validated_udp_filter_locks_the_exact_bidirectional_tuple() {
        let client = Endpoint {
            ip: IpAddress::V4([192, 0, 2, 10]),
            port: 51_234,
        };
        let server = Endpoint {
            ip: IpAddress::V4([203, 0, 113, 7]),
            port: 15_806,
        };
        assert_eq!(
            locked_capture_filter(client, server, None),
            "udp and (((src host 192.0.2.10 and src port 51234) and (dst host 203.0.113.7 and dst port 15806)) or ((src host 203.0.113.7 and src port 15806) and (dst host 192.0.2.10 and dst port 51234)))"
        );
    }

    fn test_tcp<'a>(
        sequence: u32,
        flags: u16,
        payload: &'a [u8],
    ) -> codev_stream::TransportPacket<'a> {
        codev_stream::TransportPacket {
            capture_index: 0,
            timestamp_ns: 0,
            source: Endpoint {
                ip: IpAddress::V4([192, 0, 2, 10]),
                port: 50_000,
            },
            destination: Endpoint {
                ip: IpAddress::V4([203, 0, 113, 20]),
                port: 443,
            },
            kind: TransportKind::Tcp,
            tcp_sequence: Some(sequence),
            tcp_flags: flags,
            payload,
        }
    }

    #[test]
    fn live_mna_requires_syn_and_ignores_non_mna_tcp() {
        let mut flows = HashMap::new();
        let error =
            recover_live_enter_session(&test_tcp(100, 0, &MNA_MAGIC), 1, &mut flows).unwrap_err();
        assert!(error.to_string().contains("before SYN"));

        let mut flows = HashMap::new();
        recover_live_enter_session(&test_tcp(100, TCP_SYN, &[]), 1, &mut flows).unwrap();
        recover_live_enter_session(&test_tcp(101, 0, b"TLS"), 2, &mut flows).unwrap();
        assert!(flows.values().all(|flow| flow.mna_candidate == Some(false)));
    }

    #[test]
    fn undecided_syn_flood_cannot_permanently_exclude_a_later_mna_flow() {
        let mut flows = HashMap::new();
        for index in 0..MAX_LIVE_TCP_FLOWS {
            let mut packet = test_tcp(100, TCP_SYN, &[]);
            packet.source.port = 1_000 + u16::try_from(index).unwrap();
            recover_live_enter_session(&packet, index as u64, &mut flows).unwrap();
        }
        assert_eq!(flows.len(), MAX_LIVE_TCP_FLOWS);

        let mut syn = test_tcp(500, TCP_SYN, &[]);
        syn.source.port = 60_000;
        recover_live_enter_session(&syn, 10_000, &mut flows).unwrap();
        assert_eq!(flows.len(), MAX_LIVE_TCP_FLOWS);
        assert!(flows.contains_key(&(syn.source, syn.destination)));

        let mut hello_prefix = test_tcp(501, 0, &MNA_MAGIC);
        hello_prefix.source.port = 60_000;
        recover_live_enter_session(&hello_prefix, 10_001, &mut flows).unwrap();
        assert_eq!(
            flows
                .get(&(hello_prefix.source, hello_prefix.destination))
                .and_then(|flow| flow.mna_candidate),
            Some(true)
        );
    }

    #[test]
    fn live_mna_gap_times_out_and_partial_fin_fails_closed() {
        let mut flows = HashMap::new();
        recover_live_enter_session(&test_tcp(100, TCP_SYN, &[]), 1, &mut flows).unwrap();
        recover_live_enter_session(&test_tcp(101, 0, &MNA_MAGIC), 2, &mut flows).unwrap();
        recover_live_enter_session(&test_tcp(200, 0, &[0]), 3, &mut flows).unwrap();
        assert!(!has_expired_mna_gap(
            &flows,
            3 + LIVE_MNA_GAP_TIMEOUT_NS - 1
        ));
        assert!(has_expired_mna_gap(&flows, 3 + LIVE_MNA_GAP_TIMEOUT_NS));

        let mut partial = HashMap::new();
        recover_live_enter_session(&test_tcp(100, TCP_SYN, &[]), 1, &mut partial).unwrap();
        recover_live_enter_session(&test_tcp(101, 0, &MNA_MAGIC), 2, &mut partial).unwrap();
        let error =
            recover_live_enter_session(&test_tcp(107, TCP_FIN, &[]), 3, &mut partial).unwrap_err();
        assert!(error.to_string().contains("incomplete byte/frame stream"));
    }

    #[tokio::test]
    async fn private_record_event_replays_without_exposing_identity() {
        let path = std::env::temp_dir().join(format!(
            "codev-event-replay-test-{:032x}.jsonl",
            rand::random::<u128>()
        ));
        let position = PositionView::unresolved(
            7,
            123,
            WebVec3 {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            45.0,
        );
        std::fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"record_type\":\"position_update\",\"capture_ns\":123,\"position\":{}}}\n",
                serde_json::to_string(&position).unwrap()
            ),
        )
        .unwrap();
        let hub = EventHub::new("test-record-replay").unwrap();
        let stats = load_replay(&path, None, &hub, None).await.unwrap();
        assert_eq!(stats.coordinate_updates, 1);
        assert_eq!(hub.snapshot().await[0].track_id, "batch_slot_7");
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn external_event_cannot_forge_proven_identity_or_map_coordinates() {
        let path = std::env::temp_dir().join(format!(
            "codev-untrusted-event-test-{:032x}.jsonl",
            rand::random::<u128>()
        ));
        let mut forged = PositionView::unresolved(
            7,
            999,
            WebVec3 {
                x: 1.0,
                y: 2.0,
                z: 3.0,
            },
            45.0,
        );
        forged.track_id = "forged_player".into();
        forged.actor_guid = Some(11);
        forged.player_state_guid = Some(12);
        forged.display_name = Some("private player name".into());
        forged.agent_id = Some(13);
        forged.camp_id = Some(14);
        forged.map = Some(MapPoint { u: 0.1, v: 0.2 });
        forged.identity_confidence = IdentityConfidence::Proven;
        forged.continuity = Continuity::Proven;
        std::fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"record_type\":\"position_update\",\"capture_ns\":123,\"position\":{}}}\n",
                serde_json::to_string(&forged).unwrap()
            ),
        )
        .unwrap();

        let hub = EventHub::new("test-untrusted-event").unwrap();
        load_replay(&path, None, &hub, None).await.unwrap();
        let snapshot = hub.snapshot().await;
        let position = &snapshot[0];
        assert_eq!(position.slot, 7);
        assert_eq!(position.track_id, "batch_slot_7");
        assert_eq!(position.actor_guid, None);
        assert_eq!(position.player_state_guid, None);
        assert_eq!(position.display_name, None);
        assert_eq!(position.agent_id, None);
        assert_eq!(position.camp_id, None);
        assert_eq!(position.map, None);
        assert_eq!(position.identity_confidence, IdentityConfidence::Unresolved);
        assert_eq!(position.continuity, Continuity::Resyncing);
        assert_eq!(position.updated_ns, 123);
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn complete_record_directory_replays_gap_before_later_position() {
        let directory = std::env::temp_dir().join(format!(
            "codev-record-gap-replay-test-{:032x}",
            rand::random::<u128>()
        ));
        let mut recorder = BoundedPrivateRecorder::create(&directory, 4).unwrap();
        recorder.try_record_channel_generation(99, 7).unwrap();
        recorder
            .try_record_gap(
                100,
                7,
                &GapPayload {
                    first_missing: 11,
                    last_missing: 13,
                    reason: "test sequence gap".into(),
                },
            )
            .unwrap();
        recorder
            .try_record_positions_with_generation(
                101,
                7,
                &[PositionView::unresolved(
                    2,
                    101,
                    WebVec3 {
                        x: 10.0,
                        y: 20.0,
                        z: 30.0,
                    },
                    90.0,
                )],
            )
            .unwrap();
        recorder.finish().unwrap();

        let hub = EventHub::new("test-record-gap-replay").unwrap();
        let stats = load_replay(&directory, None, &hub, None).await.unwrap();
        assert_eq!(stats.channel_generation, 7);
        assert_eq!(stats.first_timestamp_ns, Some(99));
        assert_eq!(stats.last_timestamp_ns, Some(101));
        assert_eq!(stats.coordinate_updates, 1);
        let snapshot = hub.snapshot().await;
        assert_eq!(snapshot[0].slot, 2);
        assert_eq!(snapshot[0].continuity, Continuity::Proven);

        drop(recorder);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn actor_positions_never_publishes_coordinates_from_an_invalid_baseline() {
        let actor = A0Payload {
            direction: codev_stream::Direction::ServerToClient,
            capture_index: 7,
            timestamp_ns: 123,
            packet_sequence: 9,
            channel_index: 32,
            channel_generation: 0,
            source_capture_indices: vec![7],
            bunch_index: Some(0),
            wire_data_bit_offset: Some(0),
            data: Vec::new(),
            bit_length: 0,
            summary: codev_protocol::A0Summary {
                has_rep_layout: true,
                is_actor: true,
                content_payload_bit_offset: 0,
                content_payload_bit_length: 0,
                checksum_present: false,
                property_count: 1,
                batch_property_count: 1,
                raw_two_bit_property_count: 0,
                property_terminator_bit_offset: 0,
                property_terminator_bit_length: 1,
                consumed_bits: 0,
            },
            properties: Vec::new(),
            updates: vec![codev_protocol::D0Update {
                slot: 9,
                state_index: 0,
                bit_offset: 0,
                bit_length: 0,
                use_baseline: true,
                source_baseline: Some(0),
                source_baseline_position_valid: Some(false),
                store_baseline: false,
                destination_baseline: None,
                change_mask: 2,
                movement: Some(codev_protocol::MovementUpdate {
                    kind: codev_protocol::MovementKind::Minimal,
                    bit_offset: 0,
                    bit_length: 0,
                    state: codev_protocol::MovementState {
                        position: codev_protocol::Vec3::new(11.0, 22.0, 33.0),
                        rotation_degrees: codev_protocol::Vec3::new(0.0, 0.0, 180.0),
                        ..codev_protocol::MovementState::default()
                    },
                    position: codev_protocol::VectorField {
                        value: codev_protocol::Vec3::new(11.0, 22.0, 33.0),
                        bit_offset: 0,
                        bit_length: 0,
                        quantization_decimals: 1,
                        absolute_xy: false,
                        xy_width: 0,
                        z_width: 0,
                    },
                    velocity: codev_protocol::VectorField {
                        value: codev_protocol::Vec3::ZERO,
                        bit_offset: 0,
                        bit_length: 0,
                        quantization_decimals: 1,
                        absolute_xy: false,
                        xy_width: 0,
                        z_width: 0,
                    },
                    acceleration: None,
                    rotation: None,
                }),
                extra_state: None,
                state: codev_protocol::MovementState {
                    position: codev_protocol::Vec3::new(11.0, 22.0, 33.0),
                    rotation_degrees: codev_protocol::Vec3::new(0.0, 0.0, 180.0),
                    ..codev_protocol::MovementState::default()
                },
                position_valid: false,
                continuity: SlotContinuity::Discontinuous,
            }],
            camp_assignments: Vec::new(),
            local_anchor_spawn: None,
        };
        let calibration = None;
        let positions = actor_positions(&actor, calibration);
        assert!(positions.is_empty());
    }

    #[test]
    fn pipeline_gap_is_published_before_same_release_recovery_delta() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let hub = EventHub::new("test-gap-before-recovery").unwrap();
        let client = Endpoint {
            ip: IpAddress::V4([192, 0, 2, 10]),
            port: 50_000,
        };
        let server = Endpoint {
            ip: IpAddress::V4([203, 0, 113, 20]),
            port: 15_806,
        };
        let mut pipeline = P0Pipeline::new(
            C0Cipher::from_packet_key("test-packet-key", 1),
            client,
            server,
        );
        pipeline.mark_capture_gap(100);
        let actor = A0Payload {
            direction: codev_stream::Direction::ServerToClient,
            capture_index: 1,
            timestamp_ns: 100,
            packet_sequence: 2,
            channel_index: 32,
            channel_generation: 0,
            source_capture_indices: vec![1],
            bunch_index: Some(0),
            wire_data_bit_offset: Some(0),
            data: Vec::new(),
            bit_length: 0,
            summary: codev_protocol::A0Summary {
                has_rep_layout: true,
                is_actor: true,
                content_payload_bit_offset: 0,
                content_payload_bit_length: 0,
                checksum_present: false,
                property_count: 1,
                batch_property_count: 1,
                raw_two_bit_property_count: 0,
                property_terminator_bit_offset: 0,
                property_terminator_bit_length: 1,
                consumed_bits: 0,
            },
            properties: Vec::new(),
            updates: vec![codev_protocol::D0Update {
                slot: 4,
                state_index: 0,
                bit_offset: 0,
                bit_length: 0,
                use_baseline: false,
                source_baseline: None,
                source_baseline_position_valid: None,
                store_baseline: false,
                destination_baseline: None,
                change_mask: 1,
                movement: None,
                extra_state: None,
                state: codev_protocol::MovementState {
                    position: codev_protocol::Vec3::new(10.0, 20.0, 30.0),
                    ..codev_protocol::MovementState::default()
                },
                position_valid: true,
                continuity: SlotContinuity::Continuous,
            }],
            camp_assignments: vec![codev_stream::CampAssignment {
                slot: 4,
                camp_id: 1,
            }],
            local_anchor_spawn: None,
        };
        let mut stats = ReplayStats::default();

        publish_replay_pipeline_output(
            runtime.handle(),
            &hub,
            &mut pipeline,
            vec![actor],
            None,
            &mut stats,
        )
        .unwrap();

        let snapshot = runtime.block_on(hub.snapshot());
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].slot, 4);
        assert_eq!(snapshot[0].continuity, Continuity::Proven);
        assert_eq!(snapshot[0].camp_id, Some(1));
        assert_eq!(snapshot[0].identity_confidence, IdentityConfidence::Proven);
        assert!(pipeline.drain_gaps().is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn position_to_websocket_enqueue_release_p99_is_bounded() {
        let hub = EventHub::new("enqueue-latency-test").unwrap();
        let mut samples = Vec::with_capacity(5_000);
        for sequence in 0..5_000_u64 {
            let position = PositionView::unresolved(
                (sequence % 10) as u8,
                sequence,
                WebVec3 {
                    x: sequence as f64,
                    y: 0.0,
                    z: 0.0,
                },
                0.0,
            );
            let started = Instant::now();
            hub.publish_positions(sequence, vec![position])
                .await
                .unwrap();
            samples.push(started.elapsed());
        }
        samples.sort_unstable();
        let p99 = samples[samples.len().saturating_mul(99).div_ceil(100) - 1];
        eprintln!(
            "position_to_ws_enqueue_p99_ms={:.3}",
            p99.as_secs_f64() * 1_000.0
        );
        if !cfg!(debug_assertions) {
            assert!(p99 < Duration::from_millis(10), "p99 was {p99:?}");
        }
    }
}
