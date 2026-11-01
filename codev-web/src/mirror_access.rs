//! 异地观看写入端（`POST /api/v1/mirror/positions`）的**房间令牌自校验**。
//!
//! # 为什么需要它
//!
//! 手机上的转发器手里只有"一个带令牌的 POST"：它没有房间页的 Cookie，也不会带
//! `Origin`（原生 `URLSession` 默认不发）。把镜像路由挂在统一的 `require_access`
//! 会话中间件后面，就必须先走"取房间页 → 拿面板 Cookie"那套，iOS 上 Cookie 存储
//! 不可靠 —— 这正是异地观看卡住的地方。所以这条路由改为**自己校验房间令牌**。
//!
//! # 令牌算法（必须与房间网关一致）
//!
//! ```text
//! access = hex(HMAC-SHA256(cookie_key, "viewer:" + room_id))
//! ```
//!
//! 网关在 `/api/activate` 返回的 `room_url`（`/r/<room>?access=<令牌>`）里下发它。
//! 面板用同一算法重算 + 定时比较，因此**不需要网关参与**，也不用给面板（它被链进
//! iOS App）增加 HTTP 客户端依赖。
//!
//! # 面板要读的两份只读状态
//!
//! | 配置项 | 内容 |
//! |---|---|
//! | `room_access_key_file` | 网关 env 文件，取 `BATTLE_COOKIE_KEY=<hex>` |
//! | `room_access_state_file` | 网关 `rooms.json`，取活跃房间号 |
//!
//! 两项都**不配置**时，该路由保持原来的 `require_access` 行为（默认、向后兼容）。
//! 文件读不动时**失败关闭**（拒绝写入），不会退化成"谁都能写"。
//!
//! # 已知边界（有意为之）
//!
//! nginx 把 `/api/v1/` 固定转发到槽位 1 的面板，所以这里**只校验令牌，不校验槽位**：
//! 若按槽位再卡一道，其他槽位的房间会因为转发规则而永远写不进来。代价是：槽位 2
//! 房间的令牌也会被槽位 1 的面板接受并广播到槽位 1 的房间；在当前部署下槽位 2 的
//! 面板外网不可达，实际写入只发生在槽位 1。

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::auth::{decode_hex, hex, hmac_sha256};

/// 令牌域分隔前缀 —— 必须与房间网关 `sign(cookie_key, "viewer:<room>")` 完全一致。
const VIEWER_PREFIX: &str = "viewer:";
/// 网关 env 里的键名。
const KEY_NAME: &str = "BATTLE_COOKIE_KEY";
/// 网关要求 `BATTLE_COOKIE_KEY` 至少 32 字节，这里保持一致。
const MIN_KEY_BYTES: usize = 32;
const MAX_KEY_CHARS: usize = 512;
const MAX_ROOM_ID_BYTES: usize = 64;
const MAX_ACCESS_CHARS: usize = 256;

/// 房间令牌校验器。构造即失败关闭：读写不了状态文件时**不会**注册这条免会话路由。
pub struct MirrorAccess {
    key: Vec<u8>,
    state_path: PathBuf,
    /// 最近一次成功解析出来的 `(房间号, 期望令牌)`；网关重写 `rooms.json` 的瞬间
    /// 可能读到半截文件，这时用上一次的缓存兜底（而不是把请求全拒掉）。
    cache: Mutex<Vec<(String, String)>>,
}

impl MirrorAccess {
    /// 从只读文件装载：密钥文件 + 房间状态文件。
    ///
    /// 启动时就把两份状态读一遍：配置写错要**在启动时暴露**，而不是等到转发器
    /// 上传时才发现（那会表现成"手机端一切正常、异地永远黑屏"）。
    pub fn load(key_file: &Path, state_file: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(key_file).map_err(|error| {
            format!(
                "room access key file {} is unreadable: {error}",
                key_file.display()
            )
        })?;
        let key = parse_key(&text).ok_or_else(|| {
            format!(
                "room access key file {} has no usable {KEY_NAME}",
                key_file.display()
            )
        })?;
        let access = Self {
            key,
            state_path: state_file.to_path_buf(),
            cache: Mutex::new(Vec::new()),
        };
        if access.parse_state().is_none() {
            return Err(format!(
                "room access state file {} is unreadable or malformed",
                state_file.display()
            ));
        }
        Ok(access)
    }

    /// 校验 `?access=` 令牌，命中则返回房间号（仅供日志/诊断）。
    pub fn verify(&self, access: &str) -> Option<String> {
        if access.is_empty() || access.len() > MAX_ACCESS_CHARS {
            return None;
        }
        let candidate = access.as_bytes();
        let mut hit = None;
        for (room_id, expected) in self.expected() {
            // 不提前 return：保持与房间数量无关的比较次数。
            if constant_time_eq(candidate, expected.as_bytes()) {
                hit = Some(room_id);
            }
        }
        hit
    }

    /// 期望令牌集合：优先用刚读到的状态，读不到就用上次成功的缓存（失败关闭）。
    fn expected(&self) -> Vec<(String, String)> {
        if let Some(rooms) = self.parse_state() {
            *self.cache.lock().unwrap_or_else(|error| error.into_inner()) = rooms.clone();
            return rooms;
        }
        self.cache
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn parse_state(&self) -> Option<Vec<(String, String)>> {
        let text = std::fs::read_to_string(&self.state_path).ok()?;
        let entries: Vec<serde_json::Value> = serde_json::from_str(&text).ok()?;
        let now = epoch_seconds();
        let mut rooms = Vec::new();
        for entry in entries {
            if !entry
                .get("active")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            {
                continue;
            }
            if entry
                .get("expires_unix")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0)
                <= now
            {
                continue;
            }
            let Some(room_id) = entry.get("room_id").and_then(serde_json::Value::as_str) else {
                continue;
            };
            if room_id.is_empty() || room_id.len() > MAX_ROOM_ID_BYTES {
                continue;
            }
            rooms.push((room_id.to_owned(), self.token_for(room_id)));
        }
        Some(rooms)
    }

    fn token_for(&self, room_id: &str) -> String {
        let payload = format!("{VIEWER_PREFIX}{room_id}");
        hex(&hmac_sha256(&self.key, payload.as_bytes()))
    }
}

/// 解析 `KEY=value` 形式的 env 文件，取十六进制的 `BATTLE_COOKIE_KEY`。
fn parse_key(text: &str) -> Option<Vec<u8>> {
    let raw = text.lines().find_map(|line| {
        let line = line.trim();
        let line = line.strip_prefix("export ").unwrap_or(line);
        let (name, value) = line.split_once('=')?;
        (name.trim() == KEY_NAME).then(|| value.trim().trim_matches(['"', '\'']).to_owned())
    })?;
    if raw.is_empty() || raw.len() > MAX_KEY_CHARS {
        return None;
    }
    let decoded = decode_hex(&raw)?;
    (decoded.len() >= MIN_KEY_BYTES).then_some(decoded)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn epoch_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(directory: &Path, name: &str, contents: &str) -> PathBuf {
        let path = directory.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn key_file(directory: &Path) -> PathBuf {
        write(
            directory,
            "gateway.env",
            &format!("{KEY_NAME}={}\n", "ab".repeat(32)),
        )
    }

    fn state_file(directory: &Path, room: &str, active: bool, expires_unix: i64) -> PathBuf {
        write(
            directory,
            "rooms.json",
            &format!(
                r#"[{{"room_id":"{room}","slot":1,"active":{active},"expires_unix":{expires_unix}}}]"#
            ),
        )
    }

    #[test]
    fn accepts_the_gateway_token_shape_and_rejects_everything_else() {
        let directory = tempfile::tempdir().unwrap();
        let access = MirrorAccess::load(
            &key_file(directory.path()),
            &state_file(directory.path(), "FCEACCBFCFBF", true, epoch_seconds() + 600),
        )
        .unwrap();
        // 与网关 `sign(cookie_key, "viewer:<room>")` 逐字节一致。
        let expected = access.token_for("FCEACCBFCFBF");
        assert_eq!(expected.len(), 64, "hex(HMAC-SHA256) 必须 64 个字符");
        assert_eq!(access.verify(&expected).as_deref(), Some("FCEACCBFCFBF"));
        assert!(access.verify("").is_none());
        assert!(access.verify("deadbeef").is_none());
        assert!(
            access
                .verify(&expected.to_uppercase())
                .is_none(),
            "大小写必须敏感（网关输出小写 hex）"
        );
    }

    #[test]
    fn inactive_or_expired_rooms_are_not_accepted() {
        let directory = tempfile::tempdir().unwrap();
        let key = key_file(directory.path());
        let inactive = MirrorAccess::load(
            &key,
            &state_file(directory.path(), "AAAAAAAAAAAA", false, epoch_seconds() + 600),
        )
        .unwrap();
        assert!(inactive.verify(&inactive.token_for("AAAAAAAAAAAA")).is_none());

        let expired = MirrorAccess::load(
            &key,
            &state_file(directory.path(), "BBBBBBBBBBBB", true, epoch_seconds() - 1),
        )
        .unwrap();
        assert!(expired.verify(&expired.token_for("BBBBBBBBBBBB")).is_none());
    }

    #[test]
    fn missing_state_file_fails_closed_and_a_broken_rewrite_uses_the_cache() {
        let directory = tempfile::tempdir().unwrap();
        let key = key_file(directory.path());
        let state = state_file(directory.path(), "FCEACCBFCFBF", true, epoch_seconds() + 600);
        let access = MirrorAccess::load(&key, &state).unwrap();
        let token = access.token_for("FCEACCBFCFBF");
        assert!(access.verify(&token).is_some());

        // 网关正在重写状态文件（半截文件）→ 必须沿用上一次成功的集合。
        std::fs::write(&state, "[{\"room_id\":\"FCEA").unwrap();
        assert!(access.verify(&token).is_some());

        // 状态文件消失 → 仍然用缓存，绝不"读不到就放行"。
        std::fs::remove_file(&state).unwrap();
        assert!(access.verify(&token).is_some());
        assert!(access.verify("nope").is_none());
    }

    #[test]
    fn load_rejects_bad_key_material() {
        let directory = tempfile::tempdir().unwrap();
        let state = state_file(directory.path(), "FCEACCBFCFBF", true, epoch_seconds() + 600);
        // 不是十六进制
        let not_hex = write(directory.path(), "bad-encoding.env", &format!("{KEY_NAME}=zzzz\n"));
        assert!(MirrorAccess::load(&not_hex, &state).is_err());
        // 太短（网关自己也会拒绝）
        let short = write(directory.path(), "short.env", &format!("{KEY_NAME}=aabb\n"));
        assert!(MirrorAccess::load(&short, &state).is_err());
        // 完全没有这个键
        let absent = write(directory.path(), "absent.env", "OTHER=1\n");
        assert!(MirrorAccess::load(&absent, &state).is_err());
        // 密钥文件不存在
        assert!(MirrorAccess::load(&directory.path().join("nope.env"), &state).is_err());
    }
}
