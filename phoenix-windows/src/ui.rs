use crate::app::{
    BackendRuntime, G0Grant, SavedState, acquire_single_instance, candidate_addresses, clear_state,
    data_dir, ensure_administrator, load_or_create_device_id, load_state, local_password,
    local_port, local_username, open_url, save_state,
};
use crate::authorization::{self, AttemptError, RenewFailure, RenewInfo, now_unix};
use crate::lifecycle::{Requests, Ticket};
use crate::local_engine::{LocalEngine, capture_dir};
use anyhow::Context;
use qrcode::{QrCode, render::svg};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::{Command, Stdio};
use std::time::Duration;
use tao::dpi::{LogicalPosition, LogicalSize, PhysicalSize};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon, WindowBuilder};
use wry::{Rect, WebContext, WebView, WebViewBuilder};

const SIDEBAR_WIDTH: f64 = 390.0;
const COMPACT_WIDTH: f64 = 68.0;
const SIDEBAR_HTML: &str = include_str!("sidebar.html");

#[derive(Debug)]
enum UserEvent {
    Ipc(String),
    /// 激活正在自动重试：把"卡密服务器忙，正在自动重试（第 N 次）"推给侧栏。
    ActivationProgress {
        generation: u64,
        message: String,
    },
    ActivationFinished {
        generation: u64,
        card: String,
        result: Result<G0Grant, AttemptError>,
    },
    /// 房间快到期了（或已经过了）：自动重新激活一次续上。
    RenewDue(u64),
    RenewFinished {
        generation: u64,
        result: Result<RenewInfo, RenewFailure>,
    },
    Tick,
}

#[derive(Debug, Deserialize)]
struct UiCommand {
    action: String,
    #[serde(default)]
    card: String,
}

pub(crate) fn run() -> anyhow::Result<()> {
    ensure_administrator()?;
    // 第二份实例直接给一句人话退出，别让客户看到「中继服务启动失败（-2）」。
    acquire_single_instance()?;
    let data_dir = data_dir()?;
    fs::create_dir_all(&data_dir)?;
    crate::log::init(&data_dir);
    crate::log::info(&format!(
        "启动 神明之眼 Windows build {} / 验证服务器 {}",
        crate::app::CLIENT_BUILD,
        crate::app::gateway_origin().unwrap_or_else(|| "未设置".to_string())
    ));
    let device_id = load_or_create_device_id(&data_dir)?;
    let (saved_state, _load_error) = match load_state(&data_dir) {
        Ok(state) => (state, None),
        Err(_) => (None, Some("本机授权读取失败".to_string())),
    };
    // 神明之眼 1.0：没有历史状态（首次运行 / 老状态解不开）也必须立刻起本机引擎。
    // 卡密版这里会停在「等待有效授权」等用户输卡；去掉卡密后如果还照原样走，
    // 事件循环就永远不会收到 ActivationFinished —— 界面会一直卡在
    // 「正在启动安全服务…」。所以这里直接合成一份本机授权。
    let saved_state = saved_state.or_else(|| Some(SavedState {
        card: "SHENMING-LOCAL".to_string(),
        grant: authorization::local_grant(),
        local_password: local_password(&device_id),
    }));

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();
    let window = WindowBuilder::new()
        .with_title("神明之眼 1.0 · 实时雷达")
        .with_inner_size(LogicalSize::new(1440.0, 880.0))
        .with_min_inner_size(LogicalSize::new(1050.0, 680.0))
        .with_maximized(true)
        .with_background_color((238, 242, 248, 255))
        .with_window_icon(load_window_icon())
        .build(&event_loop)
        .context("窗口创建失败")?;

    let boot = if saved_state.is_some() {
        json!({"phase":"starting","message":"正在启动本机引擎…"})
    } else {
        json!({"phase":"starting","message":"正在启动本机引擎…"})
    };
    let mut boot = boot;
    boot["build"] = json!(crate::app::CLIENT_BUILD);
    boot["version"] = json!(env!("CARGO_PKG_VERSION"));
    boot["serverMode"] = json!(crate::app::server_mode());
    let sidebar_html = SIDEBAR_HTML.replace("__BOOT__", &boot.to_string());
    let webview_dir = data_dir.join("webview2");
    fs::create_dir_all(&webview_dir)?;
    // 测试包（连裸 IP + 自签证书）专用：让 WebView2 忽略证书错误，
    // 否则雷达页在 WebView 里直接白屏报证书不受信任。
    // 必须在创建 WebContext **之前**设进进程环境；正式包不注入这个开关。
    if crate::app::INSECURE_TLS
        && std::env::var_os("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS").is_none()
    {
        // SAFETY: 单线程启动早期、还没有别的线程读环境变量。
        unsafe {
            std::env::set_var(
                "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS",
                "--ignore-certificate-errors",
            );
        }
    }
    let mut web_context = WebContext::new(Some(webview_dir));

    let initial_size = window.inner_size();
    let side_bounds = sidebar_bounds(&window, initial_size, false);
    let radar_bounds = radar_bounds(&window, initial_size, false);
    let ipc_proxy = proxy.clone();
    let sidebar = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_bounds(side_bounds)
        .with_html(&sidebar_html)
        .with_background_color((247, 250, 253, 255))
        .with_clipboard(true)
        .with_ipc_handler(move |request| {
            let _ = ipc_proxy.send_event(UserEvent::Ipc(request.body().to_owned()));
        })
        .build_as_child(&window)
        .context("控制面板启动失败")?;
    let radar = WebViewBuilder::new_with_web_context(&mut web_context)
        .with_bounds(radar_bounds)
        .with_html(radar_placeholder())
        .with_initialization_script(HERO_UNLOCK_JS)
        .with_background_color((10, 14, 20, 255))
        .with_clipboard(true)
        .build_as_child(&window)
        .context("雷达视图启动失败")?;

    let tick_proxy = proxy.clone();
    std::thread::Builder::new()
        .name("phoenix-ui-tick".to_string())
        .spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(1));
                if tick_proxy.send_event(UserEvent::Tick).is_err() {
                    break;
                }
            }
        })?;

    let mut requests = Requests::default();
    if let Some(saved) = &saved_state {
        start_activation(
            saved.card.clone(),
            device_id.clone(),
            requests.begin(),
            proxy.clone(),
        );
    }

    let mut sidebar = Some(sidebar);
    let mut radar = Some(radar);
    let mut state = saved_state;
    let mut runtime: Option<BackendRuntime> = None;
    let mut lease_deadline = i64::MAX / 2;
    let mut collapsed = false;
    let mut latest_node_uri = String::new();
    let mut pending_panel_auth: Option<String> = None;
    let web_context = web_context;

    event_loop.run(move |event, _, control_flow| {
        // Keep the shared WebView2 environment alive for both child views so
        // the private radar can retain its room cookies throughout the run.
        let _shared_web_context = &web_context;
        *control_flow = ControlFlow::Wait;
        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                requests.invalidate();
                runtime.take();
                radar.take();
                sidebar.take();
                *control_flow = ControlFlow::Exit;
            }
            Event::WindowEvent {
                event: WindowEvent::Resized(size),
                ..
            } => layout(&window, sidebar.as_ref(), radar.as_ref(), size, collapsed),
            Event::WindowEvent {
                event: WindowEvent::ScaleFactorChanged { new_inner_size, .. },
                ..
            } => layout(
                &window,
                sidebar.as_ref(),
                radar.as_ref(),
                *new_inner_size,
                collapsed,
            ),
            Event::UserEvent(UserEvent::Ipc(message)) => {
                let Ok(command) = serde_json::from_str::<UiCommand>(&message) else {
                    return;
                };
                match command.action.as_str() {
                    "activate" => {
                        if requests.busy() { return; }
                        let card = authorization::normalize_card(&command.card);
                        if card.is_empty() {
                            update_sidebar(
                                sidebar.as_ref(),
                                json!({"phase":"license","message":"卡密不能为空"}),
                            );
                        } else {
                            update_sidebar(
                                sidebar.as_ref(),
                                json!({"phase":"activating","message":"正在验证，请稍候…"}),
                            );
                            start_activation(card, device_id.clone(), requests.begin(), proxy.clone());
                        }
                    }
                    "collapse" => {
                        collapsed = true;
                        set_collapsed(sidebar.as_ref(), true);
                        layout(
                            &window,
                            sidebar.as_ref(),
                            radar.as_ref(),
                            window.inner_size(),
                            collapsed,
                        );
                    }
                    "expand" => {
                        collapsed = false;
                        set_collapsed(sidebar.as_ref(), false);
                        layout(
                            &window,
                            sidebar.as_ref(),
                            radar.as_ref(),
                            window.inner_size(),
                            collapsed,
                        );
                    }
                    "open-captures" => {
                        // 抓包目录：本机引擎每局都会写 proxy-*.pcap，这里直接打开资源管理器。
                        let dir = capture_dir(&data_dir);
                        let _ = fs::create_dir_all(&dir);
                        crate::app::open_url(&dir.to_string_lossy());
                        toast(sidebar.as_ref(), "已打开抓包文件夹");
                    }
                    "copy-captures" => {
                        let dir = capture_dir(&data_dir);
                        let text = dir.to_string_lossy().to_string();
                        if copy_to_clipboard(&text).is_ok() {
                            toast(sidebar.as_ref(), "抓包路径已复制");
                        } else {
                            toast(sidebar.as_ref(), &text);
                        }
                    }
                    "open-browser" => {
                        if let Some(saved) = state.as_ref() {
                            open_url(&radar_target(saved));
                        } else {
                            toast(sidebar.as_ref(), "引擎还没就绪，请稍候");
                        }
                    }
                    "copy-node" => {
                        if latest_node_uri.is_empty() {
                            toast(sidebar.as_ref(), "节点尚未启动");
                        } else if copy_to_clipboard(&latest_node_uri).is_ok() {
                            toast(sidebar.as_ref(), "节点已复制");
                        } else {
                            toast(sidebar.as_ref(), "复制失败，请手动复制节点地址");
                        }
                    }
                    "reconnect" => {
                        if requests.busy() { return; }
                        let Some(saved) = state.as_ref() else {
                            toast(sidebar.as_ref(), "引擎还没就绪，请稍候");
                            return;
                        };
                        // 关键改动：以前这里只重启本地中继、沿用旧 grant ——
                        // 卡/房间已经过期时，再怎么重连也连不回来。
                        // 现在先重新激活一次（顺便刷新房间与到期时间），激活成功再拉后端。
                        let card = saved.card.clone();
                        crate::log::info("用户点了「重新连接」→ 重新激活");
                        update_sidebar(
                            sidebar.as_ref(),
                            json!({"phase":"activating","message":"正在重新验证并刷新房间…"}),
                        );
                        start_activation(card, device_id.clone(), requests.begin(), proxy.clone());
                    }
                    "forget" => {
                        // 「清除本机授权」：换卡 / 填错卡的唯一出路（以前只能手工删文件）。
                        crate::log::info("用户点了「清除本机授权」");
                        requests.invalidate();
                        pending_panel_auth = None;
                        runtime.take();
                        let clear_error = clear_state(&data_dir).err();
                        state = None;
                        collapsed = false;
                        set_collapsed(sidebar.as_ref(), false);
                        layout(&window, sidebar.as_ref(), radar.as_ref(), window.inner_size(), false);
                        latest_node_uri.clear();
                        if let Some(view) = radar.as_ref() {
                            let _ = view.load_url("about:blank");
                        }
                        update_sidebar(
                            sidebar.as_ref(),
                            json!({"phase":"license","clearCard":true,"message":if clear_error.is_some() {"本次运行已清除，但磁盘授权删除失败；下次启动可能恢复旧卡，请检查数据目录权限"} else {"已清除本机授权，请输入新卡密"}}),
                        );
                    }
                    _ => {}
                }
            }
            Event::UserEvent(UserEvent::ActivationProgress {generation,message}) => {
                if requests.accepts(generation) { update_sidebar(sidebar.as_ref(),json!({"phase":"activating","message":message})); }
            }
            Event::UserEvent(UserEvent::ActivationFinished {generation,card,result}) => {
                if !requests.finish(generation) { return; }
                match result {
                    Ok(grant) => {
                        let next=SavedState {card,grant,local_password:state.as_ref().map(|s|s.local_password.clone()).filter(|p|!p.is_empty()).unwrap_or_else(||local_password(&device_id))};
                        // Storage is not the licensing authority: a valid online grant remains usable
                        // if DPAPI/disk persistence fails. Never fall back to plaintext.
                        let storage_warning=if save_state(&data_dir,&next).is_err() {crate::log::warn("授权有效，但加密凭据未能持久化");Some("本次已激活，但加密凭据保存失败；下次启动需要重新输入卡密")} else {None};
                        lease_deadline=i64::MAX/2;
                        update_sidebar(sidebar.as_ref(),json!({"phase":"starting","message":"授权通过，正在启动接收服务…"}));
                        pending_panel_auth=None;
                        runtime.take();
                        match BackendRuntime::start(&data_dir,&next,&device_id) {
                            Ok(new_runtime) => {
                                let mut page_error=false;
                                if let Some(view)=radar.as_ref() {page_error=view.load_url(&radar_target(&next)).is_err();}
                                if !crate::app::server_mode() {pending_panel_auth=Some(new_runtime.panel_token().to_string());}
                                let (mut payload,uri)=ready_payload(&next,new_runtime.capture_error(),&data_dir);
                                payload["storageWarning"]=json!(storage_warning);
                                if page_error {payload["status"]=json!("接收服务已启动，但雷达页载入失败；请重新连接");}
                                latest_node_uri=uri;runtime=Some(new_runtime);state=Some(next);
                                update_sidebar(sidebar.as_ref(),payload);
                            },
                            Err(error) => {
                                latest_node_uri.clear();state=Some(next);
                                crate::log::error(&format!("接收服务启动失败：{error:#}"));
                                update_sidebar(sidebar.as_ref(),json!({"phase":"service-error","message":format!("接收服务启动失败：{error}")}));
                            }
                        }
                    },
                    Err(error) => {
                        crate::log::warn(&format!("激活未成功（HTTP {:?}）",error.status));
                        if error.retryable() && runtime.is_some() && now_unix()<lease_deadline {
                            let saved=state.as_ref().expect("runtime requires grant");
                            let (mut payload,_)=ready_payload(saved,runtime.as_ref().and_then(|r|r.capture_error()),&data_dir);
                            payload["status"]=json!(format!("授权刷新暂未成功，当前会话仍有效；15 秒后重试：{}",error.detail));
                            update_sidebar(sidebar.as_ref(),payload);
                        } else {
                            collapsed=false;set_collapsed(sidebar.as_ref(),false);layout(&window,sidebar.as_ref(),radar.as_ref(),window.inner_size(),false);
                            requests.invalidate();runtime.take();pending_panel_auth=None;state=None;latest_node_uri.clear();
                            if let Some(view)=radar.as_ref() {let _=view.load_url("about:blank");}
                            update_sidebar(sidebar.as_ref(),json!({"phase":"license","message":error.detail}));
                        }
                    }
                }
            }
            Event::UserEvent(UserEvent::RenewDue(generation)) => {
                if !requests.accepts(generation) || requests.busy() {return;}
                if let Some(saved)=state.as_ref() {
                    let ticket=requests.begin();
                    start_renew(device_id.clone(),saved.grant.room_id.clone(),ticket,proxy.clone());
                }
            }
            Event::UserEvent(UserEvent::RenewFinished {generation,result}) => {
                if !requests.finish(generation) {return;}
                let Some(saved)=state.as_ref() else {return;};
                match result {
                    Ok(info) if runtime.is_some() && (info.node_expires_unix==0 || info.node_expires_unix>now_unix()+120) => {
                        // A healthy lease renewal MUST NOT restart relay/capture or reload the page.
                        lease_deadline=i64::MAX/2;
                    },
                    Ok(_) | Err(RenewFailure::RoomGone(_)) => {
                        let card=saved.card.clone();
                        start_activation(card,device_id.clone(),requests.begin(),proxy.clone());
                    },
                    Err(RenewFailure::Transient(message)) if runtime.is_some() && now_unix()<lease_deadline => {
                        update_sidebar(sidebar.as_ref(),json!({"status":format!("会话续期暂未成功，将自动重试：{message}")}));
                    },
                    Err(error) => {
                        collapsed=false;set_collapsed(sidebar.as_ref(),false);layout(&window,sidebar.as_ref(),radar.as_ref(),window.inner_size(),false);
                        requests.invalidate();runtime.take();state=None;latest_node_uri.clear();pending_panel_auth=None;
                        if let Some(view)=radar.as_ref() {let _=view.load_url("about:blank");}
                        update_sidebar(sidebar.as_ref(),json!({"phase":"license","message":error.to_string()}));
                    }
                }
            }
            Event::UserEvent(UserEvent::Tick) => {
                if runtime.is_some() && now_unix()>=lease_deadline {
                    runtime.take();latest_node_uri.clear();pending_panel_auth=None;
                    if let Some(view)=radar.as_ref() {let _=view.load_url("about:blank");}
                    update_sidebar(sidebar.as_ref(),json!({"phase":"starting","message":"当前会话已到期，正在重新验证…"}));
                    if !requests.busy() && let Some(saved)=state.as_ref() {
                        start_activation(saved.card.clone(),device_id.clone(),requests.begin(),proxy.clone());
                    }
                }
                if let Some(active) = &runtime {
                    update_sidebar(sidebar.as_ref(), json!({"clients":active.client_count()}));
                }
                if let Some(token) = pending_panel_auth.take()
                    && let Some(view) = radar.as_ref()
                {
                    let _ = view.evaluate_script(&panel_auth_script(&token));
                }
            }
            _ => {}
        }
    });
}

/// 雷达页的「英雄身份解锁」脚本（与 iOS 版同一条）。
///
/// 页面 `zt()` 里写死 `agent_id: "proven" === identity_confidence ? … : null`，
/// 而引擎只在阵营 commit 后才把位置标 proven —— 敌人前几秒是 unresolved，
/// 于是"有英雄编号也显示不出英雄/头像"。这里在页面脚本之前包一层 JSON.parse：
/// 只给**已带 agent_id 的位置**置 proven，并把 `map_roster` 里的昵称补进帧。
/// 坐标 / 阵营 / continuity 一律不动。
const HERO_UNLOCK_JS: &str = r#"
(function () {
  var ROSTER = Object.create(null);
  function remember(obj) {
    if (!obj || obj.kind !== "map_roster") return;
    var list = obj.payload && obj.payload.roster;
    if (!Array.isArray(list)) return;
    for (var i = 0; i < list.length; i++) {
      var e = list[i];
      if (!e) continue;
      if (Number.isInteger(e.slot) && typeof e.display_name === "string" && e.display_name) {
        ROSTER[e.slot] = e.display_name;
      }
    }
  }
  function unlock(obj) {
    if (!obj || typeof obj !== "object") return;
    if (obj.kind !== "position_delta" && obj.kind !== "snapshot") return;
    var list = obj.payload && obj.payload.positions;
    if (!Array.isArray(list)) return;
    for (var i = 0; i < list.length; i++) {
      var p = list[i];
      if (!p || typeof p !== "object") continue;
      if (typeof p.agent_id !== "number" || !(p.agent_id > 0)) continue;
      var name = ROSTER[p.slot];
      if (!p.display_name && name) p.display_name = name;
      if (p.identity_confidence !== "proven") p.identity_confidence = "proven";
    }
  }
  var original = JSON.parse;
  if (typeof original !== "function") return;
  window.JSON.parse = function (text, reviver) {
    var value = original.call(this, text, reviver);
    try { remember(value); unlock(value); } catch (ignore) {}
    return value;
  };
})();
"#;
fn panel_auth_script(token: &str) -> String {
    // The local panel runs in token-gated public mode. Exchange the bootstrap
    // token for a session cookie inside the loaded panel origin, then reload so
    // the radar connects without showing the manual gate.
    let token = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "(function(){{\
            fetch('/api/v1/session',{{credentials:'include'}}).then(function(r){{\
                if(r.ok)return;\
                return fetch('/api/v1/auth/exchange',{{method:'POST',credentials:'include',\
                    headers:{{'content-type':'application/json'}},body:JSON.stringify({{token:{token}}})}})\
                    .then(function(x){{if(x.ok)location.reload();}});\
            }}).catch(function(){{}});\
        }})();"
    )
}

fn start_activation(
    card: String,
    device_id: String,
    ticket: Ticket,
    proxy: EventLoopProxy<UserEvent>,
) {
    let generation = ticket.generation;
    let failure_proxy = proxy.clone();
    let failure_card = card.clone();
    let spawn = std::thread::Builder::new()
        .name("phoenix-activation".into())
        .spawn(move || {
            let progress_proxy = proxy.clone();
            let mut retry = move |attempt| {
                let _ = progress_proxy.send_event(UserEvent::ActivationProgress {
                    generation,
                    message: format!("卡密服务器响应慢，正在重试（第 {attempt} 次，最多 2 次）"),
                });
            };
            crate::log::info("激活开始：直连卡密平台");
            // 进度上报：把 Rust 侧的验证阶段推给侧栏，客户能看到"卡在第几段"。
            let stage_done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            {
                let done = stage_done.clone();
                let progress = proxy.clone();
                let generation = generation;
                std::thread::spawn(move || {
                    let mut last = "";
                    while !done.load(std::sync::atomic::Ordering::Relaxed) {
                        let stage = codev_verify::current_stage();
                        if stage != last {
                            last = stage;
                            let _ = progress.send_event(UserEvent::ActivationProgress {
                                generation,
                                message: format!("正在验证 · {}", codev_verify::stage_label(stage)),
                            });
                        }
                        std::thread::sleep(std::time::Duration::from_millis(300));
                    }
                });
            }
            // 任何 panic 都必须变成一条错误事件 —— 否则界面会永远停在"正在验证"。
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                authorization::activate_with_progress(&card, &device_id, &ticket.cancel, &mut retry)
            }));
            stage_done.store(true, std::sync::atomic::Ordering::Relaxed);
            let result = match outcome {
                Ok(result) => result,
                Err(panic) => {
                    let detail = panic
                        .downcast_ref::<&str>()
                        .map(|value| (*value).to_string())
                        .or_else(|| panic.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "未知内部错误".to_string());
                    crate::log::error(&format!("激活线程 panic：{detail}"));
                    Err(AttemptError {
                        status: Some(500),
                        detail: format!("验证过程异常：{detail}"),
                    })
                }
            };
            match &result {
                Ok(grant) => crate::log::info(&format!(
                    "激活成功：到期 {}",
                    grant.expires_at
                )),
                Err(error) => crate::log::error(&format!(
                    "激活失败({:?})：{}",
                    error.status, error.detail
                )),
            }
            let _ = proxy.send_event(UserEvent::ActivationFinished {
                generation,
                card,
                result,
            });
        });
    if spawn.is_err() {
        let _ = failure_proxy.send_event(UserEvent::ActivationFinished {
            generation,
            card: failure_card,
            result: Err(AttemptError {
                status: Some(503),
                detail: "验证线程未能启动，请重试".into(),
            }),
        });
    }
}
fn start_renew(
    device_id: String,
    room_id: String,
    ticket: Ticket,
    proxy: EventLoopProxy<UserEvent>,
) {
    let generation = ticket.generation;
    let failure_proxy = proxy.clone();
    let spawn = std::thread::Builder::new()
        .name("phoenix-renew".into())
        .spawn(move || {
            if ticket.cancel.is_cancelled() {
                return;
            }
            let result = authorization::renew_session(&device_id, &room_id);
            if !ticket.cancel.is_cancelled() {
                let _ = proxy.send_event(UserEvent::RenewFinished { generation, result });
            }
        });
    if spawn.is_err() {
        let _ = failure_proxy.send_event(UserEvent::RenewFinished {
            generation,
            result: Err(RenewFailure::Transient("续期线程未能启动".into())),
        });
    }
}

/// 雷达页面地址：服务端模式加载房间地址（解码在服务端），本地模式加载本机面板。
fn radar_target(state: &SavedState) -> String {
    if crate::app::server_mode() {
        state.grant.radar_url.clone()
    } else {
        LocalEngine::panel_url()
    }
}

fn ready_payload(state: &SavedState, capture_error: Option<&str>, data_dir: &std::path::Path) -> (serde_json::Value, String) {
    // Both modes run a local relay. Directing phones to the cloud node bypasses
    // its forwarding/capture path and exposes the upstream room credentials.
    let address = format!("{}:{}", primary_address(), local_port());
    let mut node = reqwest::Url::parse(&format!("socks5://{address}")).expect("IPv4 local node");
    let _ = node.set_username(local_username());
    let _ = node.set_password(Some(&state.local_password));
    let uri = node.to_string().trim_end_matches('/').to_string();
    let qr_svg = qr_svg(&uri).unwrap_or_default();
    let status = if capture_error.is_some() {
        "本机 SOCKS5 已就绪；端游/热点采集尚未启动"
    } else if crate::app::server_mode() {
        "本机采集与 SOCKS5 已就绪 · 云端解析"
    } else {
        "本机端游、Windows 热点与局域网 SOCKS5 均已就绪"
    };
    let node_meta = format!(
        "本机节点 · 用户 {} · 端口 {} · {}",
        local_username(),
        local_port(),
        if crate::app::server_mode() {
            "云端解析"
        } else {
            "本地解析"
        }
    );
    (
        json!({
            "phase":"ready",
            "status":status,
            "address":address.clone(),
            "nodeUri":uri,
            "nodeMeta":node_meta,
            "qrSvg":qr_svg,
            "clients":0,
            // 抓包驱动没起来时，侧栏要显红字 + 排查建议，而不是假装一切正常。
            "captureError":capture_error,
            "build":crate::app::CLIENT_BUILD,
            "version":env!("CARGO_PKG_VERSION"),
            "storageWarning":null,
            "captureDir":capture_dir(data_dir).to_string_lossy(),
            "expiresAt":state.grant.expires_at,
        }),
        uri,
    )
}

fn schedule_renew(wait: Duration, ticket: Ticket, proxy: EventLoopProxy<UserEvent>) {
    if let Err(error) = std::thread::Builder::new()
        .name("phoenix-renew-timer".into())
        .spawn(move || {
            if ticket.cancel.wait(wait) {
                let _ = proxy.send_event(UserEvent::RenewDue(ticket.generation));
            }
        })
    {
        crate::log::warn(&format!("续期计时线程启动失败：{error}"));
    }
}

fn primary_address() -> Ipv4Addr {
    candidate_addresses()
        .into_iter()
        .next()
        .unwrap_or(Ipv4Addr::new(192, 168, 137, 1))
}

fn qr_svg(text: &str) -> anyhow::Result<String> {
    let code = QrCode::new(text.as_bytes())?;
    let svg = code
        .render::<svg::Color>()
        .dark_color(svg::Color("#0a0508"))
        .light_color(svg::Color("#fff1ef"))
        .min_dimensions(280, 280)
        .build();
    Ok(svg)
}

fn update_sidebar(sidebar: Option<&WebView>, payload: serde_json::Value) {
    if let Some(view) = sidebar {
        let _ = view.evaluate_script(&format!("window.phoenixUpdate({payload});"));
    }
}

fn set_collapsed(sidebar: Option<&WebView>, collapsed: bool) {
    if let Some(view) = sidebar {
        let _ = view.evaluate_script(&format!("window.phoenixSetCollapsed({collapsed});"));
    }
}

fn toast(sidebar: Option<&WebView>, message: &str) {
    if let Some(view) = sidebar {
        let message = serde_json::to_string(message).unwrap_or_else(|_| "\"\"".to_string());
        let _ = view.evaluate_script(&format!("window.phoenixToast({message});"));
    }
}

fn copy_to_clipboard(value: &str) -> anyhow::Result<()> {
    let mut child = Command::new("clip.exe")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .context("剪贴板不可用")?
        .write_all(value.as_bytes())?;
    let status = child.wait()?;
    anyhow::ensure!(status.success(), "剪贴板写入失败");
    Ok(())
}

fn layout(
    window: &tao::window::Window,
    sidebar: Option<&WebView>,
    radar: Option<&WebView>,
    size: PhysicalSize<u32>,
    collapsed: bool,
) {
    if let Some(view) = sidebar {
        let _ = view.set_bounds(sidebar_bounds(window, size, collapsed));
    }
    if let Some(view) = radar {
        let _ = view.set_bounds(radar_bounds(window, size, collapsed));
    }
}

fn sidebar_bounds(window: &tao::window::Window, size: PhysicalSize<u32>, collapsed: bool) -> Rect {
    let logical = size.to_logical::<f64>(window.scale_factor());
    Rect {
        position: LogicalPosition::new(0.0, 0.0).into(),
        size: LogicalSize::new(
            if collapsed {
                COMPACT_WIDTH
            } else {
                SIDEBAR_WIDTH
            },
            logical.height,
        )
        .into(),
    }
}

fn radar_bounds(window: &tao::window::Window, size: PhysicalSize<u32>, collapsed: bool) -> Rect {
    let logical = size.to_logical::<f64>(window.scale_factor());
    let left = if collapsed {
        COMPACT_WIDTH
    } else {
        SIDEBAR_WIDTH
    };
    Rect {
        position: LogicalPosition::new(left, 0.0).into(),
        size: LogicalSize::new((logical.width - left).max(1.0), logical.height).into(),
    }
}

fn radar_placeholder() -> &'static str {
    r#"<!doctype html><html><head><meta charset="utf-8"><style>*{box-sizing:border-box}html,body{width:100%;height:100%;margin:0;background:#0a0508;color:#fff1ef;font-family:'Segoe UI','Microsoft YaHei UI',sans-serif;overflow:hidden}body{display:grid;place-items:center;background-image:linear-gradient(#2a101340 1px,transparent 1px),linear-gradient(90deg,#2a101340 1px,transparent 1px),radial-gradient(circle at center,#1a0b0e 0,#0a0508 62%);background-size:48px 48px,48px 48px,100% 100%}.box{text-align:center}.radar{width:82px;height:82px;margin:0 auto 20px;border-radius:50%;border:1px solid #ff5a4d66;position:relative;box-shadow:0 0 70px #27b8b833}.radar:before{content:'';position:absolute;inset:9px;border:1px solid #ff5a4d44;border-radius:50%}.radar:after{content:'';position:absolute;width:38px;height:1px;left:41px;top:40px;background:#ff8a3d;transform-origin:left;animation:scan 1.8s linear infinite;box-shadow:0 0 8px #ff8a3d}@keyframes scan{to{transform:rotate(360deg)}}h2{font-size:18px;margin:0 0 7px}p{font-size:12px;color:#b89a99;margin:0}</style></head><body><div class="box"><div class="radar"></div><h2>正在建立私人雷达</h2><p>完成授权后将在此处自动显示实时地图</p></div></body></html>"#
}

fn load_window_icon() -> Option<Icon> {
    // 图标改为本 crate 自带（assets/app-icon.png）：
    // 以前指到 ../../macos/... 那份，换个目录布局就把编译打断。
    const ICON: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/app-icon.png"));
    let image = image::load_from_memory(ICON).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    Icon::from_rgba(image.into_raw(), width, height).ok()
}
