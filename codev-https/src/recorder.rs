use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

const MAGIC: &[u8; 8] = b"CVHTTP\0\x01";
const MAX_HOST_BYTES: usize = 253;
const MAX_FLOW_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaintextDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Clone, Copy, Debug)]
pub struct PlaintextRecord<'a> {
    pub capture_ns: u64,
    pub direction: PlaintextDirection,
    pub flow_id: &'a str,
    pub host: &'a str,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordingLimits {
    pub max_bytes: u64,
    pub max_duration_ns: u64,
    pub max_record_bytes: usize,
}

impl Default for RecordingLimits {
    fn default() -> Self {
        Self {
            max_bytes: 512 * 1024 * 1024,
            max_duration_ns: 30 * 60 * 1_000_000_000,
            max_record_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordingStatus {
    pub enabled: bool,
    pub complete: bool,
    pub bytes_written: u64,
    pub records_written: u64,
    pub stop_reason: Option<String>,
}

struct RecorderState {
    writer: BufWriter<File>,
    limits: RecordingLimits,
    started_ns: Option<u64>,
    status: RecordingStatus,
}

pub struct PlaintextRecorder {
    state: Mutex<RecorderState>,
}

impl PlaintextRecorder {
    pub fn create(
        directory: impl AsRef<Path>,
        limits: RecordingLimits,
        explicitly_enabled: bool,
    ) -> io::Result<Self> {
        if !explicitly_enabled {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "plaintext recording requires explicit one-shot enablement",
            ));
        }
        if limits.max_bytes < MAGIC.len() as u64
            || limits.max_duration_ns == 0
            || limits.max_record_bytes == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid limits",
            ));
        }
        create_private_directory(directory.as_ref())?;
        let path = directory.as_ref().join("https-plaintext.bin");
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut writer = BufWriter::new(options.open(path)?);
        writer.write_all(MAGIC)?;
        Ok(Self {
            state: Mutex::new(RecorderState {
                writer,
                limits,
                started_ns: None,
                status: RecordingStatus {
                    enabled: true,
                    complete: true,
                    bytes_written: MAGIC.len() as u64,
                    records_written: 0,
                    stop_reason: None,
                },
            }),
        })
    }

    pub fn record(&self, record: PlaintextRecord<'_>) -> io::Result<bool> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.status.enabled {
            return Ok(false);
        }
        if record.host.is_empty()
            || record.host.len() > MAX_HOST_BYTES
            || record.flow_id.is_empty()
            || record.flow_id.len() > MAX_FLOW_ID_BYTES
            || record.payload.len() > state.limits.max_record_bytes
        {
            stop(
                &mut state,
                "record metadata or payload exceeded the configured limit",
            );
            return Ok(false);
        }
        let started = *state.started_ns.get_or_insert(record.capture_ns);
        if record.capture_ns.saturating_sub(started) > state.limits.max_duration_ns {
            stop(&mut state, "recording duration limit reached");
            return Ok(false);
        }
        let encoded_length = 8_u64
            + 1
            + 2
            + 2
            + 4
            + record.flow_id.len() as u64
            + record.host.len() as u64
            + record.payload.len() as u64;
        if state.status.bytes_written.saturating_add(encoded_length) > state.limits.max_bytes {
            stop(&mut state, "recording byte limit reached");
            return Ok(false);
        }
        let direction = match record.direction {
            PlaintextDirection::ClientToServer => 0_u8,
            PlaintextDirection::ServerToClient => 1_u8,
        };
        state.writer.write_all(&record.capture_ns.to_le_bytes())?;
        state.writer.write_all(&[direction])?;
        state
            .writer
            .write_all(&(record.flow_id.len() as u16).to_le_bytes())?;
        state
            .writer
            .write_all(&(record.host.len() as u16).to_le_bytes())?;
        state
            .writer
            .write_all(&(record.payload.len() as u32).to_le_bytes())?;
        state.writer.write_all(record.flow_id.as_bytes())?;
        state.writer.write_all(record.host.as_bytes())?;
        state.writer.write_all(record.payload)?;
        state.status.bytes_written += encoded_length;
        state.status.records_written += 1;
        Ok(true)
    }

    pub fn finish(&self) -> io::Result<RecordingStatus> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.writer.flush()?;
        state.status.enabled = false;
        Ok(state.status.clone())
    }

    pub fn status(&self) -> RecordingStatus {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .status
            .clone()
    }
}

fn stop(state: &mut RecorderState, reason: &str) {
    state.status.enabled = false;
    state.status.complete = false;
    state.status.stop_reason = Some(reason.into());
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "record directory is a symlink",
        ));
    }
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recorder_is_explicit_private_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            PlaintextRecorder::create(directory.path(), RecordingLimits::default(), false).is_err()
        );
        let recorder = PlaintextRecorder::create(
            directory.path(),
            RecordingLimits {
                max_bytes: 64,
                max_duration_ns: 100,
                max_record_bytes: 16,
            },
            true,
        )
        .unwrap();
        assert!(
            recorder
                .record(PlaintextRecord {
                    capture_ns: 1,
                    direction: PlaintextDirection::ClientToServer,
                    flow_id: "f",
                    host: "a.example",
                    payload: b"hello",
                })
                .unwrap()
        );
        assert!(
            !recorder
                .record(PlaintextRecord {
                    capture_ns: 2,
                    direction: PlaintextDirection::ServerToClient,
                    flow_id: "f",
                    host: "a.example",
                    payload: b"this payload exceeds",
                })
                .unwrap()
        );
        let status = recorder.finish().unwrap();
        assert!(!status.complete);
        assert_eq!(status.records_written, 1);
    }
}
