//! Replace a credential blob only after a complete write, fsync and readback.
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub(crate) fn write_verified(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("凭据目录无效"))?;
    let temporary = parent.join(format!(
        ".license-{}-{}.tmp",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        anyhow::ensure!(fs::read(&temporary)? == bytes, "凭据写入校验失败");
        replace(&temporary, path)?;
        #[cfg(unix)]
        {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}
#[cfg(not(windows))]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    fs::rename(from, to)
}
#[cfg(windows)]
fn replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let from: Vec<u16> = from.as_os_str().encode_wide().chain(Some(0)).collect();
    let to: Vec<u16> = to.as_os_str().encode_wide().chain(Some(0)).collect();
    if unsafe {
        MoveFileExW(
            from.as_ptr(),
            to.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Scratch(std::path::PathBuf);
    impl Scratch {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "phoenix-store-test-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn complete_blob_replaces_old_file() {
        let d = Scratch::new();
        let p = d.0.join("license.dpapi");
        fs::write(&p, b"old-encrypted").unwrap();
        write_verified(&p, b"new-encrypted").unwrap();
        assert_eq!(fs::read(p).unwrap(), b"new-encrypted");
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }
    #[test]
    fn failed_replace_preserves_existing_target() {
        let d = Scratch::new();
        let p = d.0.join("license.dpapi");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("sentinel"), b"old").unwrap();
        assert!(write_verified(&p, b"new").is_err());
        assert_eq!(fs::read(p.join("sentinel")).unwrap(), b"old");
        assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    }
    #[test]
    fn missing_directory_is_reported() {
        let d = Scratch::new();
        assert!(write_verified(&d.0.join("missing/file"), b"encrypted").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn temporary_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = Scratch::new();
        let p = d.0.join("license.dpapi");
        write_verified(&p, b"blob").unwrap();
        assert_eq!(fs::metadata(p).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
