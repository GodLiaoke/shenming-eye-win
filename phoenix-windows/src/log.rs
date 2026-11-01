//! 极简文件日志。
//!
//! 为什么需要：程序是 GUI 子系统（`windows_subsystem = "windows"`），
//! `eprintln!` 没有控制台可打印，等于丢进虚空。客户报"没数据"时我们手上什么都没有。
//! 现在所有关键事件（激活、后端启动、抓包驱动失败、续期）都写到
//! `%LOCALAPPDATA%\Phoenix\logs\app.log`，超过 512KB 自动轮转一份 `.1`。
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 512 * 1024;

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

/// 在拿到 data_dir 之后调用一次；失败就退化成"不写日志"，绝不影响主流程。
pub(crate) fn init(data_dir: &Path) {
    let dir = data_dir.join("logs");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("app.log");
    if fs::metadata(&path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = fs::rename(&path, dir.join("app.log.1"));
    }
    if let Ok(mut guard) = LOG_PATH.lock() {
        *guard = Some(path);
    }
}

pub(crate) fn line(level: &str, message: &str) {
    let Ok(guard) = LOG_PATH.lock() else { return };
    let Some(path) = guard.as_ref() else { return };
    let stamp = timestamp();
    if fs::metadata(path)
        .map(|m| m.len() > MAX_BYTES)
        .unwrap_or(false)
    {
        let _ = fs::rename(path, path.with_extension("log.1"));
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "[{stamp}] {level:<5} {message}");
    }
}

pub(crate) fn info(message: &str) {
    line("INFO", message);
}

pub(crate) fn warn(message: &str) {
    line("WARN", message);
}

pub(crate) fn error(message: &str) {
    line("ERROR", message);
}

/// 日志目录（给侧栏"打开日志"用）。
pub(crate) fn directory() -> Option<PathBuf> {
    LOG_PATH.lock().ok().and_then(|guard| {
        guard
            .as_ref()
            .and_then(|p| p.parent().map(Path::to_path_buf))
    })
}

fn timestamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    // 本地时间 = UTC + 时区偏移（Windows 上取不到就按 UTC 记，够定位问题）
    let offset = local_offset_seconds();
    let secs = secs + offset;
    let days = secs.div_euclid(86_400);
    let rest = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// 用 `GetLocalTime` 拿时区偏移；拿不到就 0（按 UTC）。
fn local_offset_seconds() -> i64 {
    use windows_sys::Win32::Foundation::SYSTEMTIME;
    use windows_sys::Win32::System::SystemInformation::{GetLocalTime, GetSystemTime};
    unsafe {
        let mut local = SYSTEMTIME::default();
        let mut utc = SYSTEMTIME::default();
        GetLocalTime(&mut local);
        GetSystemTime(&mut utc);
        let to_secs = |t: &SYSTEMTIME| -> i64 {
            let days = days_from_civil(t.wYear as i64, t.wMonth as i64, t.wDay as i64);
            days * 86_400 + t.wHour as i64 * 3600 + t.wMinute as i64 * 60 + t.wSecond as i64
        };
        to_secs(&local) - to_secs(&utc)
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
