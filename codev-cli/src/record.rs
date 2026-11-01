use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use codev_stream::CapturedPacket;
use codev_web::{GapPayload, PositionView};
use serde::Serialize;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

pub struct PrivateRecorder {
    directory: PathBuf,
    pcap: Option<BufWriter<File>>,
    events: BufWriter<File>,
    link_type: Option<u32>,
    packets: u64,
    events_written: u64,
    gap_events_written: u64,
    generation_events_written: u64,
    incomplete_reasons: Vec<String>,
    finished: bool,
}

const QUEUE_OVERFLOW_REASON: &str = "recording queue overflowed; queued data was dropped";
const QUEUE_ITEM_REJECTED_REASON: &str =
    "recording item exceeded bounded queue limits; data was dropped";
const WORKER_UNAVAILABLE_REASON: &str =
    "recording worker became unavailable; queued data may be incomplete";
#[allow(dead_code)]
const UNORDERLY_DROP_REASON: &str = "bounded recorder dropped before an orderly finish";
const MAX_QUEUED_PACKET_BYTES: usize = 65_535;
const MAX_QUEUED_POSITIONS: usize = 64;
const MAX_QUEUED_TRACK_ID_BYTES: usize = 128;
const MAX_QUEUED_DISPLAY_NAME_BYTES: usize = 256;
const MAX_QUEUED_GAP_REASON_BYTES: usize = 2 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordingWorkerError {
    kind: io::ErrorKind,
    detail: String,
}

#[allow(dead_code)]
impl RecordingWorkerError {
    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: error.kind(),
            detail: sanitize_incomplete_reason(error.to_string()),
        }
    }

    fn worker_panicked() -> Self {
        Self {
            kind: io::ErrorKind::Other,
            detail: "recording worker thread panicked".into(),
        }
    }

    pub fn kind(&self) -> io::ErrorKind {
        self.kind
    }

    pub fn detail(&self) -> &str {
        &self.detail
    }

    fn to_io_error(&self) -> io::Error {
        io::Error::new(self.kind, self.detail.clone())
    }
}

impl std::fmt::Display for RecordingWorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for RecordingWorkerError {}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RecordingQueueError {
    #[error("recording queue is full; recording was marked incomplete")]
    Full,
    #[error("recording worker is unavailable; recording was marked incomplete")]
    WorkerUnavailable,
    #[error("recording worker failed: {0}")]
    WorkerFailed(RecordingWorkerError),
    #[error("recording item exceeds the bounded {0} limit; recording was marked incomplete")]
    ItemTooLarge(&'static str),
    #[error("recorder is already finished")]
    Finished,
}

#[derive(Default)]
struct RecordingWorkerState {
    incomplete_reasons: Mutex<Vec<String>>,
    error: Mutex<Option<RecordingWorkerError>>,
    stopped: AtomicBool,
}

impl RecordingWorkerState {
    fn mark_incomplete(&self, reason: String) {
        let reason = sanitize_incomplete_reason(reason);
        let mut reasons = self
            .incomplete_reasons
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }

    fn incomplete_reasons(&self) -> Vec<String> {
        self.incomplete_reasons
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn record_error(&self, error: &io::Error) {
        self.record_worker_error(RecordingWorkerError::from_io(error));
    }

    fn record_worker_error(&self, error: RecordingWorkerError) {
        let mut current = self
            .error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if current.is_none() {
            self.mark_incomplete(format!("recording worker I/O failed: {error}"));
            *current = Some(error);
        }
    }

    fn error(&self) -> Option<RecordingWorkerError> {
        self.error
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

struct QueuedPacket {
    timestamp_ns: u64,
    original_length: u32,
    link_type: u32,
    data: Vec<u8>,
}

enum RecordingItem {
    Packet(QueuedPacket),
    Positions {
        capture_ns: u64,
        channel_generation: u64,
        positions: Vec<PositionView>,
    },
    Gap {
        capture_ns: u64,
        channel_generation: u64,
        gap: GapPayload,
    },
    ChannelGeneration {
        capture_ns: u64,
        channel_generation: u64,
    },
}

#[allow(dead_code)]
pub struct RecordingWorker {
    state: Arc<RecordingWorkerState>,
    join: Option<JoinHandle<io::Result<()>>>,
}

#[allow(dead_code)]
impl RecordingWorker {
    pub fn error(&self) -> Option<RecordingWorkerError> {
        self.state.error()
    }

    pub fn is_finished(&self) -> bool {
        self.state.stopped.load(Ordering::Acquire)
    }

    fn join(&mut self) -> io::Result<()> {
        let Some(join) = self.join.take() else {
            return match self.error() {
                Some(error) => Err(error.to_io_error()),
                None => Ok(()),
            };
        };
        match join.join() {
            Ok(result) => result,
            Err(_) => {
                let error = RecordingWorkerError::worker_panicked();
                self.state.record_worker_error(error.clone());
                Err(error.to_io_error())
            }
        }
    }
}

#[allow(dead_code)]
pub struct BoundedPrivateRecorder {
    sender: Option<SyncSender<RecordingItem>>,
    worker: RecordingWorker,
    finished: bool,
}

#[allow(dead_code)]
impl BoundedPrivateRecorder {
    pub fn create(directory: impl AsRef<Path>, capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording queue capacity must be greater than zero",
            ));
        }
        Self::spawn(PrivateRecorder::create(directory)?, capacity)
    }

    fn spawn(recorder: PrivateRecorder, capacity: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let state = Arc::new(RecordingWorkerState::default());
        let worker_state = Arc::clone(&state);
        let join = thread::Builder::new()
            .name("codev-record-writer".into())
            .spawn(move || run_recording_worker(recorder, receiver, worker_state))?;
        Ok(Self {
            sender: Some(sender),
            worker: RecordingWorker {
                state,
                join: Some(join),
            },
            finished: false,
        })
    }

    pub fn try_record_packet(&self, packet: &CapturedPacket) -> Result<(), RecordingQueueError> {
        self.ensure_available()?;
        if packet.data.len() > MAX_QUEUED_PACKET_BYTES {
            self.worker
                .state
                .mark_incomplete(QUEUE_ITEM_REJECTED_REASON.into());
            return Err(RecordingQueueError::ItemTooLarge("packet size"));
        }
        self.try_send(RecordingItem::Packet(QueuedPacket {
            timestamp_ns: packet.timestamp_ns,
            original_length: packet.original_length,
            link_type: packet.link_type,
            data: packet.data.clone(),
        }))
    }

    pub fn try_record_positions(
        &self,
        capture_ns: u64,
        positions: &[PositionView],
    ) -> Result<(), RecordingQueueError> {
        self.try_record_positions_with_generation(capture_ns, 0, positions)
    }

    pub fn try_record_positions_with_generation(
        &self,
        capture_ns: u64,
        channel_generation: u64,
        positions: &[PositionView],
    ) -> Result<(), RecordingQueueError> {
        self.ensure_available()?;
        if positions.is_empty() {
            return Ok(());
        }
        if positions.len() > MAX_QUEUED_POSITIONS {
            self.worker
                .state
                .mark_incomplete(QUEUE_ITEM_REJECTED_REASON.into());
            return Err(RecordingQueueError::ItemTooLarge("position count"));
        }
        if positions.iter().any(|position| {
            position.track_id.len() > MAX_QUEUED_TRACK_ID_BYTES
                || position
                    .display_name
                    .as_ref()
                    .is_some_and(|name| name.len() > MAX_QUEUED_DISPLAY_NAME_BYTES)
        }) {
            self.worker
                .state
                .mark_incomplete(QUEUE_ITEM_REJECTED_REASON.into());
            return Err(RecordingQueueError::ItemTooLarge("position metadata size"));
        }
        self.try_send(RecordingItem::Positions {
            capture_ns,
            channel_generation,
            positions: positions.to_vec(),
        })
    }

    pub fn try_record_gap(
        &self,
        capture_ns: u64,
        channel_generation: u64,
        gap: &GapPayload,
    ) -> Result<(), RecordingQueueError> {
        self.ensure_available()?;
        if gap.reason.len() > MAX_QUEUED_GAP_REASON_BYTES {
            self.worker
                .state
                .mark_incomplete(QUEUE_ITEM_REJECTED_REASON.into());
            return Err(RecordingQueueError::ItemTooLarge("gap reason size"));
        }
        self.try_send(RecordingItem::Gap {
            capture_ns,
            channel_generation,
            gap: gap.clone(),
        })
    }

    pub fn try_record_channel_generation(
        &self,
        capture_ns: u64,
        channel_generation: u64,
    ) -> Result<(), RecordingQueueError> {
        self.ensure_available()?;
        self.try_send(RecordingItem::ChannelGeneration {
            capture_ns,
            channel_generation,
        })
    }

    pub fn mark_incomplete(&self, reason: impl Into<String>) {
        self.worker.state.mark_incomplete(reason.into());
    }

    pub fn worker_error(&self) -> Option<RecordingWorkerError> {
        self.worker.error()
    }

    pub fn worker_is_finished(&self) -> bool {
        self.worker.is_finished()
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return self.worker.join();
        }
        self.finished = true;
        // Closing the only sender lets the worker drain every item already
        // accepted by try_send before it flushes and writes summary.json.
        self.sender.take();
        self.worker.join()
    }

    fn ensure_available(&self) -> Result<(), RecordingQueueError> {
        if self.finished || self.sender.is_none() {
            return Err(RecordingQueueError::Finished);
        }
        if let Some(error) = self.worker.error() {
            return Err(RecordingQueueError::WorkerFailed(error));
        }
        if self.worker.is_finished() {
            self.worker
                .state
                .mark_incomplete(WORKER_UNAVAILABLE_REASON.into());
            return Err(RecordingQueueError::WorkerUnavailable);
        }
        Ok(())
    }

    fn try_send(&self, item: RecordingItem) -> Result<(), RecordingQueueError> {
        self.ensure_available()?;
        let sender = self.sender.as_ref().ok_or(RecordingQueueError::Finished)?;
        match sender.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                self.worker
                    .state
                    .mark_incomplete(QUEUE_OVERFLOW_REASON.into());
                Err(RecordingQueueError::Full)
            }
            Err(TrySendError::Disconnected(_)) => {
                if let Some(error) = self.worker.error() {
                    Err(RecordingQueueError::WorkerFailed(error))
                } else {
                    self.worker
                        .state
                        .mark_incomplete(WORKER_UNAVAILABLE_REASON.into());
                    Err(RecordingQueueError::WorkerUnavailable)
                }
            }
        }
    }
}

impl Drop for BoundedPrivateRecorder {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.worker
            .state
            .mark_incomplete(UNORDERLY_DROP_REASON.into());
        self.sender.take();
        let _ = self.worker.join();
        self.finished = true;
    }
}

#[derive(Serialize)]
struct RecordedPosition<'a> {
    schema_version: u32,
    record_type: &'static str,
    capture_ns: u64,
    channel_generation: u64,
    position: &'a PositionView,
}

#[derive(Serialize)]
struct RecordedGap<'a> {
    schema_version: u32,
    record_type: &'static str,
    capture_ns: u64,
    channel_generation: u64,
    gap: &'a GapPayload,
}

#[derive(Serialize)]
struct RecordedChannelGeneration {
    schema_version: u32,
    record_type: &'static str,
    capture_ns: u64,
    channel_generation: u64,
}

#[derive(Serialize)]
struct RecordingSummary<'a> {
    schema_version: u32,
    status: &'static str,
    packets: u64,
    coordinate_events: u64,
    gap_events: u64,
    generation_events: u64,
    incomplete_reasons: &'a [String],
    contains_private_session_material: bool,
}

impl PrivateRecorder {
    pub fn create(directory: impl AsRef<Path>) -> io::Result<Self> {
        let directory = directory.as_ref().to_owned();
        prepare_recording_directory(&directory)?;
        let events = BufWriter::new(open_private_new(&directory.join("events-v1.jsonl"))?);
        Ok(Self {
            directory,
            pcap: None,
            events,
            link_type: None,
            packets: 0,
            events_written: 0,
            gap_events_written: 0,
            generation_events_written: 0,
            incomplete_reasons: Vec::new(),
            finished: false,
        })
    }

    #[cfg(test)]
    pub fn record_packet(&mut self, packet: &CapturedPacket) -> io::Result<()> {
        self.record_packet_data(
            packet.timestamp_ns,
            packet.original_length,
            packet.link_type,
            &packet.data,
        )
    }

    fn record_packet_data(
        &mut self,
        timestamp_ns: u64,
        original_length: u32,
        link_type: u32,
        data: &[u8],
    ) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::other("recorder is already finished"));
        }
        if self.pcap.is_none() {
            let mut output =
                BufWriter::new(open_private_new(&self.directory.join("capture.pcap"))?);
            // Little-endian, nanosecond-resolution classic PCAP.
            output.write_all(&[0x4d, 0x3c, 0xb2, 0xa1])?;
            output.write_all(&2_u16.to_le_bytes())?;
            output.write_all(&4_u16.to_le_bytes())?;
            output.write_all(&0_i32.to_le_bytes())?;
            output.write_all(&0_u32.to_le_bytes())?;
            output.write_all(&65_535_u32.to_le_bytes())?;
            output.write_all(&link_type.to_le_bytes())?;
            self.link_type = Some(link_type);
            self.pcap = Some(output);
        }
        if self.link_type != Some(link_type) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "capture link type changed inside one recording",
            ));
        }
        let output = self.pcap.as_mut().unwrap();
        let seconds = timestamp_ns / 1_000_000_000;
        let fraction = timestamp_ns % 1_000_000_000;
        output.write_all(
            &u32::try_from(seconds)
                .map_err(|_| io::Error::other("PCAP timestamp exceeds uint32"))?
                .to_le_bytes(),
        )?;
        output.write_all(&(fraction as u32).to_le_bytes())?;
        output.write_all(
            &u32::try_from(data.len())
                .map_err(|_| io::Error::other("captured packet exceeds uint32"))?
                .to_le_bytes(),
        )?;
        output.write_all(&original_length.to_le_bytes())?;
        output.write_all(data)?;
        self.packets += 1;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn record_positions(
        &mut self,
        capture_ns: u64,
        positions: &[PositionView],
    ) -> io::Result<()> {
        self.record_positions_with_generation(capture_ns, 0, positions)
    }

    fn record_positions_with_generation(
        &mut self,
        capture_ns: u64,
        channel_generation: u64,
        positions: &[PositionView],
    ) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::other("recorder is already finished"));
        }
        for position in positions {
            serde_json::to_writer(
                &mut self.events,
                &RecordedPosition {
                    schema_version: 1,
                    record_type: "position_update",
                    capture_ns,
                    channel_generation,
                    position,
                },
            )?;
            self.events.write_all(b"\n")?;
            self.events_written += 1;
        }
        Ok(())
    }

    fn record_gap(
        &mut self,
        capture_ns: u64,
        channel_generation: u64,
        gap: &GapPayload,
    ) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::other("recorder is already finished"));
        }
        serde_json::to_writer(
            &mut self.events,
            &RecordedGap {
                schema_version: 1,
                record_type: "gap",
                capture_ns,
                channel_generation,
                gap,
            },
        )?;
        self.events.write_all(b"\n")?;
        self.gap_events_written += 1;
        Ok(())
    }

    fn record_channel_generation(
        &mut self,
        capture_ns: u64,
        channel_generation: u64,
    ) -> io::Result<()> {
        if self.finished {
            return Err(io::Error::other("recorder is already finished"));
        }
        serde_json::to_writer(
            &mut self.events,
            &RecordedChannelGeneration {
                schema_version: 1,
                record_type: "channel_generation",
                capture_ns,
                channel_generation,
            },
        )?;
        self.events.write_all(b"\n")?;
        self.generation_events_written += 1;
        Ok(())
    }

    pub fn mark_incomplete(&mut self, reason: String) {
        let reason = sanitize_incomplete_reason(reason);
        if !self.incomplete_reasons.contains(&reason) {
            self.incomplete_reasons.push(reason);
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }

        // A failed data flush must not prevent us from leaving an explicit,
        // machine-readable incomplete marker. Keep the first I/O error for the
        // caller while attempting every remaining finalization step.
        let mut first_error = None;
        if let Some(pcap) = self.pcap.as_mut()
            && let Err(error) = pcap.flush()
        {
            self.mark_incomplete("capture.pcap flush failed".into());
            first_error = Some(error);
        }
        if let Err(error) = self.events.flush() {
            self.mark_incomplete("events-v1.jsonl flush failed".into());
            if first_error.is_none() {
                first_error = Some(error);
            }
        }

        let summary_result = self.write_summary();
        match summary_result {
            Ok(()) => {
                // The recording is orderly finalized even when its data flush
                // failed: summary.json is the durable incomplete marker, and a
                // Drop retry could otherwise overwrite useful diagnostics.
                self.finished = true;
                match first_error {
                    Some(error) => Err(error),
                    None => Ok(()),
                }
            }
            Err(error) => {
                self.mark_incomplete("summary.json write failed".into());
                Err(first_error.unwrap_or(error))
            }
        }
    }

    fn write_summary(&self) -> io::Result<()> {
        let summary_path = self.directory.join("summary.json");
        let mut summary = BufWriter::new(open_private_new(&summary_path)?);
        let write_result = (|| {
            serde_json::to_writer_pretty(
                &mut summary,
                &RecordingSummary {
                    schema_version: 1,
                    status: if self.incomplete_reasons.is_empty() {
                        "complete"
                    } else {
                        "incomplete"
                    },
                    packets: self.packets,
                    coordinate_events: self.events_written,
                    gap_events: self.gap_events_written,
                    generation_events: self.generation_events_written,
                    incomplete_reasons: &self.incomplete_reasons,
                    contains_private_session_material: true,
                },
            )?;
            summary.write_all(b"\n")?;
            summary.flush()
        })();
        if let Err(error) = write_result {
            drop(summary);
            // A failed exclusive creation must not leave a partial JSON file
            // that a later reader could mistake for a finalized summary.
            let _ = fs::remove_file(summary_path);
            return Err(error);
        }
        Ok(())
    }
}

struct WorkerStoppedGuard(Arc<RecordingWorkerState>);

impl Drop for WorkerStoppedGuard {
    fn drop(&mut self) {
        self.0.stopped.store(true, Ordering::Release);
    }
}

fn run_recording_worker(
    mut recorder: PrivateRecorder,
    receiver: Receiver<RecordingItem>,
    state: Arc<RecordingWorkerState>,
) -> io::Result<()> {
    let _stopped = WorkerStoppedGuard(Arc::clone(&state));
    let mut first_error = None;

    while let Ok(item) = receiver.recv() {
        // Once an output has failed, continue draining the bounded channel so
        // shutdown cannot deadlock. Further items are intentionally discarded
        // and the durable summary remains incomplete.
        if first_error.is_some() {
            continue;
        }
        let result = match item {
            RecordingItem::Packet(packet) => recorder.record_packet_data(
                packet.timestamp_ns,
                packet.original_length,
                packet.link_type,
                &packet.data,
            ),
            RecordingItem::Positions {
                capture_ns,
                channel_generation,
                positions,
            } => recorder.record_positions_with_generation(
                capture_ns,
                channel_generation,
                &positions,
            ),
            RecordingItem::Gap {
                capture_ns,
                channel_generation,
                gap,
            } => recorder.record_gap(capture_ns, channel_generation, &gap),
            RecordingItem::ChannelGeneration {
                capture_ns,
                channel_generation,
            } => recorder.record_channel_generation(capture_ns, channel_generation),
        };
        if let Err(error) = result {
            state.record_error(&error);
            first_error = Some(error);
        }
    }

    // The sender is dropped only after all producers have finished mutating
    // this state, so this snapshot includes overflow and unordered-Drop marks.
    for reason in state.incomplete_reasons() {
        recorder.mark_incomplete(reason);
    }

    let finish_result = recorder.finish();
    if let Err(error) = &finish_result {
        state.record_error(error);
    }
    match first_error {
        Some(error) => Err(error),
        None => finish_result,
    }
}

fn sanitize_incomplete_reason(reason: String) -> String {
    let lowercase = reason.to_ascii_lowercase();
    let named_private_identifier = [
        "packetkey",
        "packet_key",
        "packet key",
        "gameid",
        "g0_id",
        "game id",
        "openid",
        "open_id",
        "open id",
    ]
    .iter()
    .any(|name| lowercase.contains(name));
    let uid_token = lowercase.match_indices("uid").any(|(start, _)| {
        let before = lowercase[..start].chars().next_back();
        let after = lowercase[start + 3..].chars().next();
        !before.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
            && !after.is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
    });
    if named_private_identifier || uid_token {
        "recording error detail redacted".into()
    } else {
        reason
    }
}

impl Drop for PrivateRecorder {
    fn drop(&mut self) {
        if !self.finished {
            self.mark_incomplete("recorder dropped before an orderly finish".into());
            let _ = self.finish();
        }
    }
}

pub(crate) fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700).create(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    {
        let existed = path.exists();
        fs::create_dir_all(path)?;
        if let Err(error) = windows_acl::restrict_to_current_user(path, true) {
            // Never delete an existing user path during error cleanup. A path
            // created by this call is removed best-effort if it is still empty.
            if !existed {
                let _ = fs::remove_dir(path);
            }
            return Err(error);
        }
    }
    #[cfg(not(any(unix, windows)))]
    return Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private recording permissions are unsupported on this platform",
    ));
    Ok(())
}

fn prepare_recording_directory(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording directory must not be a symbolic link",
            ));
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "recording output path is not a directory",
            ));
        }
        Ok(_) => ensure_recording_directory_empty(path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    create_private_directory(path)?;

    // Recheck after create_dir_all so an existing final-component symlink or
    // a racing non-empty directory cannot be accepted through its target.
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recording directory is not a real directory",
        ));
    }
    ensure_recording_directory_empty(path)
}

fn ensure_recording_directory_empty(path: &Path) -> io::Result<()> {
    let mut entries = fs::read_dir(path)?;
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "recording directory must be empty",
        )),
        Some(Err(error)) => Err(error),
    }
}

pub(crate) fn open_private(path: &Path, truncate: bool) -> io::Result<File> {
    open_private_with_create_mode(path, truncate, false)
}

fn open_private_new(path: &Path) -> io::Result<File> {
    open_private_with_create_mode(path, false, true)
}

fn open_private_with_create_mode(
    path: &Path,
    truncate: bool,
    create_new: bool,
) -> io::Result<File> {
    #[cfg(windows)]
    let existed = path.exists();
    #[cfg(windows)]
    if existed {
        // Tighten a reused output before truncating or writing it. The parent
        // directory is already private, but this also removes any explicit ACL
        // that the old file may carry.
        windows_acl::restrict_to_current_user(path, false)?;
    }
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create(!create_new)
        .create_new(create_new)
        .truncate(truncate && !create_new);
    #[cfg(unix)]
    options
        .mode(0o600)
        // O_NONBLOCK prevents a hostile FIFO from blocking the recorder before
        // the descriptor type can be checked. It has no effect on regular files.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;

    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private output is not a regular file",
        ));
    }

    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    #[cfg(windows)]
    if let Err(error) = windows_acl::restrict_to_current_user(path, false) {
        drop(file);
        if !existed {
            let _ = fs::remove_file(path);
        }
        return Err(error);
    }
    Ok(file)
}

#[cfg(windows)]
mod windows_acl {
    use std::ffi::c_void;
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, SET_ACCESS, SetEntriesInAclW,
        SetNamedSecurityInfoW, TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetTokenInformation, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY,
        TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct OwnedHandle(windows_sys::Win32::Foundation::HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this owns the successful OpenProcessToken result.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalAcl(*mut windows_sys::Win32::Security::ACL);

    impl Drop for LocalAcl {
        fn drop(&mut self) {
            // SAFETY: SetEntriesInAclW allocates this ACL with LocalAlloc.
            unsafe { LocalFree(self.0.cast::<c_void>()) };
        }
    }

    pub(super) fn restrict_to_current_user(path: &Path, directory: bool) -> io::Result<()> {
        let mut token = null_mut();
        // SAFETY: output pointer is valid and TOKEN_QUERY is the minimum needed.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);

        let mut required = 0_u32;
        // The first call intentionally discovers the required buffer length.
        // SAFETY: a null buffer with length zero is the documented probe form.
        unsafe {
            GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required);
        }
        let probe_error = io::Error::last_os_error();
        if probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || required == 0 {
            return Err(probe_error);
        }

        // Use pointer-sized storage so casting the leading bytes to TOKEN_USER
        // is aligned on every supported Windows architecture.
        let word_size = std::mem::size_of::<usize>();
        let mut token_user = vec![0_usize; (required as usize).div_ceil(word_size)];
        // SAFETY: the buffer has the size returned by the probe call.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                token_user.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful TokenUser query begins with TOKEN_USER and the
        // SID it references remains alive in token_user for the API calls below.
        let user_sid = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };

        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: if directory {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: user_sid.cast(),
            },
        };
        let mut acl = null_mut();
        // A null old ACL means the new DACL contains only this explicit ACE.
        // SAFETY: all pointers remain valid through the call.
        let status = unsafe { SetEntriesInAclW(1, &access, null(), &mut acl) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let acl = LocalAcl(acl);

        let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide_path.push(0);
        // PROTECTED_DACL prevents inherited ACEs from silently widening access.
        // SAFETY: path is NUL-terminated and acl is valid for this call.
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide_path.as_mut_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl.0,
                null(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_stream::{DLT_EN10MB, DLT_RAW};
    use codev_web::{PositionView, Vec3};
    use std::sync::Barrier;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStrExt;

    fn temporary_recording_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "codev-record-{label}-{:032x}",
            rand::random::<u128>()
        ))
    }

    fn packet(index: u64, link_type: u32, value: u8) -> CapturedPacket {
        CapturedPacket {
            index,
            timestamp_ns: 12_345_678_901 + index,
            original_length: 3,
            link_type,
            data: vec![value, value.wrapping_add(1), value.wrapping_add(2)],
        }
    }

    fn blocked_bounded_recorder(
        recorder: PrivateRecorder,
        capacity: usize,
    ) -> (BoundedPrivateRecorder, Arc<Barrier>) {
        let (sender, receiver) = mpsc::sync_channel(capacity);
        let state = Arc::new(RecordingWorkerState::default());
        let worker_state = Arc::clone(&state);
        let barrier = Arc::new(Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let join = thread::spawn(move || {
            worker_barrier.wait();
            run_recording_worker(recorder, receiver, worker_state)
        });
        (
            BoundedPrivateRecorder {
                sender: Some(sender),
                worker: RecordingWorker {
                    state,
                    join: Some(join),
                },
                finished: false,
            },
            barrier,
        )
    }

    #[test]
    fn writes_private_nanosecond_pcap_and_summary() {
        let path = temporary_recording_path("pcap");
        let mut recorder = PrivateRecorder::create(&path).unwrap();
        recorder
            .record_packet(&CapturedPacket {
                index: 0,
                timestamp_ns: 12_345_678_901,
                original_length: 3,
                link_type: DLT_EN10MB,
                data: vec![1, 2, 3],
            })
            .unwrap();
        recorder.finish().unwrap();
        let bytes = fs::read(path.join("capture.pcap")).unwrap();
        assert_eq!(&bytes[..4], &[0x4d, 0x3c, 0xb2, 0xa1]);
        let summary = fs::read_to_string(path.join("summary.json")).unwrap();
        assert!(summary.contains("\"status\": \"complete\""));
        #[cfg(unix)]
        {
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(path.join("capture.pcap"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.join("events-v1.jsonl"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(path.join("summary.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn reusing_nonempty_recording_directory_preserves_prior_complete_recording() {
        let path = temporary_recording_path("reuse-complete");
        let mut prior = PrivateRecorder::create(&path).unwrap();
        prior.record_packet(&packet(0, DLT_EN10MB, 7)).unwrap();
        prior.finish().unwrap();
        drop(prior);

        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o750)).unwrap();

        let prior_events = fs::read(path.join("events-v1.jsonl")).unwrap();
        let prior_capture = fs::read(path.join("capture.pcap")).unwrap();
        let prior_summary = fs::read(path.join("summary.json")).unwrap();

        let error = PrivateRecorder::create(&path).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            fs::read(path.join("events-v1.jsonl")).unwrap(),
            prior_events
        );
        assert_eq!(fs::read(path.join("capture.pcap")).unwrap(), prior_capture);
        assert_eq!(fs::read(path.join("summary.json")).unwrap(), prior_summary);
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o750
        );

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn preexisting_artifact_after_create_is_not_truncated() {
        let path = temporary_recording_path("exclusive-artifact");
        let mut recorder = PrivateRecorder::create(&path).unwrap();
        let capture_path = path.join("capture.pcap");
        fs::write(&capture_path, b"preexisting capture").unwrap();

        let error = recorder
            .record_packet(&packet(0, DLT_EN10MB, 1))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&capture_path).unwrap(), b"preexisting capture");

        drop(recorder);
        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_recording_directory_is_rejected_without_touching_target() {
        let target = temporary_recording_path("directory-link-target");
        let link = temporary_recording_path("directory-link");
        fs::create_dir(&target).unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let error = PrivateRecorder::create(&link).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(fs::read_dir(&target).unwrap().next().is_none());

        fs::remove_file(link).unwrap();
        fs::remove_dir(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_file_open_does_not_follow_symbolic_links() {
        let path = temporary_recording_path("file-link");
        create_private_directory(&path).unwrap();
        let target = path.join("target");
        let link = path.join("output");
        fs::write(&target, b"must remain intact").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(open_private(&link, true).is_err());
        assert_eq!(fs::read(target).unwrap(), b"must remain intact");

        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_file_open_rejects_non_regular_files() {
        let path = temporary_recording_path("non-regular");
        create_private_directory(&path).unwrap();
        let fifo = path.join("output.fifo");
        let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: fifo_path is a valid NUL-terminated path and mode is valid.
        assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);

        // Keep a nonblocking reader open so opening the FIFO for writing does
        // not fail before open_private can verify the descriptor type.
        let mut reader_options = OpenOptions::new();
        reader_options.read(true).custom_flags(libc::O_NONBLOCK);
        let _reader = reader_options.open(&fifo).unwrap();

        let error = open_private(&fifo, true).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn bounded_writer_drains_before_complete_summary() {
        let path = temporary_recording_path("bounded-complete");
        let mut recorder = BoundedPrivateRecorder::create(&path, 4).unwrap();
        recorder
            .try_record_packet(&packet(0, DLT_EN10MB, 1))
            .unwrap();
        recorder
            .try_record_positions(
                42,
                &[PositionView::unresolved(
                    3,
                    42,
                    Vec3 {
                        x: 1.0,
                        y: 2.0,
                        z: 3.0,
                    },
                    90.0,
                )],
            )
            .unwrap();
        recorder.finish().unwrap();

        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "complete");
        assert_eq!(summary["packets"], 1);
        assert_eq!(summary["coordinate_events"], 1);
        assert_eq!(summary["gap_events"], 0);
        assert_eq!(summary["generation_events"], 0);
        assert!(recorder.worker_is_finished());
        assert!(recorder.worker_error().is_none());

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn bounded_writer_preserves_gap_order_and_channel_generation() {
        let path = temporary_recording_path("gap-events");
        let mut recorder = BoundedPrivateRecorder::create(&path, 4).unwrap();
        recorder.try_record_channel_generation(40, 7).unwrap();
        recorder
            .try_record_gap(
                41,
                7,
                &GapPayload {
                    first_missing: 11,
                    last_missing: 13,
                    reason: "sequence gap".into(),
                },
            )
            .unwrap();
        recorder
            .try_record_positions_with_generation(
                42,
                7,
                &[PositionView::unresolved(
                    3,
                    42,
                    Vec3 {
                        x: 1.0,
                        y: 2.0,
                        z: 3.0,
                    },
                    90.0,
                )],
            )
            .unwrap();
        recorder.finish().unwrap();

        let events = fs::read_to_string(path.join("events-v1.jsonl")).unwrap();
        let rows = events
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["record_type"], "channel_generation");
        assert_eq!(rows[0]["channel_generation"], 7);
        assert_eq!(rows[1]["record_type"], "gap");
        assert_eq!(rows[1]["channel_generation"], 7);
        assert_eq!(rows[2]["record_type"], "position_update");
        assert_eq!(rows[2]["channel_generation"], 7);

        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["coordinate_events"], 1);
        assert_eq!(summary["gap_events"], 1);
        assert_eq!(summary["generation_events"], 1);

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn queue_overflow_is_immediate_and_durably_incomplete() {
        let path = temporary_recording_path("bounded-overflow");
        let private = PrivateRecorder::create(&path).unwrap();
        let (mut recorder, barrier) = blocked_bounded_recorder(private, 1);

        recorder
            .try_record_packet(&packet(0, DLT_EN10MB, 1))
            .unwrap();
        assert_eq!(
            recorder.try_record_packet(&packet(1, DLT_EN10MB, 4)),
            Err(RecordingQueueError::Full)
        );

        barrier.wait();
        recorder.finish().unwrap();
        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        assert_eq!(summary["packets"], 1);
        assert_eq!(
            summary["incomplete_reasons"],
            serde_json::json!([QUEUE_OVERFLOW_REASON])
        );

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn oversized_item_is_rejected_before_allocation_and_marks_incomplete() {
        let path = temporary_recording_path("bounded-item-size");
        let mut recorder = BoundedPrivateRecorder::create(&path, 2).unwrap();
        let oversized = CapturedPacket {
            index: 0,
            timestamp_ns: 1,
            original_length: (MAX_QUEUED_PACKET_BYTES + 1) as u32,
            link_type: DLT_EN10MB,
            data: vec![0; MAX_QUEUED_PACKET_BYTES + 1],
        };
        assert_eq!(
            recorder.try_record_packet(&oversized),
            Err(RecordingQueueError::ItemTooLarge("packet size"))
        );
        recorder.finish().unwrap();

        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        assert_eq!(summary["packets"], 0);
        assert_eq!(
            summary["incomplete_reasons"],
            serde_json::json!([QUEUE_ITEM_REJECTED_REASON])
        );
        assert!(!path.join("capture.pcap").exists());

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn worker_io_error_is_returned_and_queryable() {
        let path = temporary_recording_path("bounded-worker-error");
        let mut private = PrivateRecorder::create(&path).unwrap();
        private.record_packet(&packet(0, DLT_EN10MB, 1)).unwrap();
        let mut recorder = BoundedPrivateRecorder::spawn(private, 2).unwrap();
        // A single classic-PCAP stream cannot change link type. This produces
        // a deterministic worker-side I/O/validation failure after enqueue.
        recorder.try_record_packet(&packet(1, DLT_RAW, 4)).unwrap();
        let finish_error = recorder.finish().unwrap_err();
        assert_eq!(finish_error.kind(), io::ErrorKind::InvalidData);
        let worker_error = recorder.worker_error().unwrap();
        assert_eq!(worker_error.kind(), io::ErrorKind::InvalidData);
        assert!(worker_error.detail().contains("link type changed"));

        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        assert_eq!(summary["packets"], 1);
        assert!(
            summary["incomplete_reasons"][0]
                .as_str()
                .unwrap()
                .contains("recording worker I/O failed")
        );

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn dropping_bounded_writer_never_claims_complete() {
        let path = temporary_recording_path("bounded-drop");
        let recorder = BoundedPrivateRecorder::create(&path, 2).unwrap();
        drop(recorder);

        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        assert_eq!(
            summary["incomplete_reasons"],
            serde_json::json!([UNORDERLY_DROP_REASON])
        );

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn zero_queue_capacity_fails_before_creating_private_output() {
        let path = temporary_recording_path("bounded-zero-capacity");
        let error = BoundedPrivateRecorder::create(&path, 0).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!path.exists());
    }

    #[test]
    fn events_are_position_only_and_exclude_private_identifiers() {
        let path = temporary_recording_path("privacy");
        let mut recorder = PrivateRecorder::create(&path).unwrap();
        recorder
            .record_positions(
                42,
                &[PositionView::unresolved(
                    3,
                    42,
                    Vec3 {
                        x: 1.0,
                        y: 2.0,
                        z: 3.0,
                    },
                    90.0,
                )],
            )
            .unwrap();
        recorder.finish().unwrap();

        let line = fs::read_to_string(path.join("events-v1.jsonl")).unwrap();
        let event: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let event_keys = event
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            event_keys,
            [
                "capture_ns",
                "channel_generation",
                "position",
                "record_type",
                "schema_version"
            ]
        );
        assert_eq!(event["channel_generation"], 0);
        let position_keys = event["position"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let expected = [
            "actor_guid",
            "agent_id",
            "camp_id",
            "continuity",
            "display_name",
            "fresh",
            "identity_confidence",
            "map",
            "pitch",
            "player_state_guid",
            "slot",
            "track_id",
            "updated_ns",
            "world",
            "yaw",
        ]
        .into_iter()
        .collect();
        assert_eq!(position_keys, expected);
        for forbidden in [
            "packetkey",
            "packet_key",
            "gameid",
            "g0_id",
            "uid",
            "openid",
            "open_id",
        ] {
            assert!(
                !line
                    .to_ascii_lowercase()
                    .contains(&format!("\"{forbidden}\""))
            );
        }

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn incomplete_reason_cannot_serialize_private_identifiers() {
        let path = temporary_recording_path("reason-privacy");
        let mut recorder = PrivateRecorder::create(&path).unwrap();
        recorder.mark_incomplete(
            "session rejected: PacketKey=secret GameId=123 UID=456 OpenID=789".into(),
        );
        recorder.finish().unwrap();

        let summary = fs::read_to_string(path.join("summary.json")).unwrap();
        assert!(summary.contains("recording error detail redacted"));
        for forbidden in [
            "secret",
            "123",
            "456",
            "789",
            "packetkey",
            "gameid",
            "openid",
        ] {
            assert!(!summary.to_ascii_lowercase().contains(forbidden));
        }

        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn flush_failures_still_write_an_incomplete_summary() {
        let path = temporary_recording_path("flush-failure");
        let mut recorder = PrivateRecorder::create(&path).unwrap();
        let read_only_path = path.join("read-only");
        fs::write(&read_only_path, b"").unwrap();

        recorder.pcap = Some(BufWriter::new(File::open(&read_only_path).unwrap()));
        recorder
            .pcap
            .as_mut()
            .unwrap()
            .write_all(b"buffered pcap data")
            .unwrap();
        recorder.events = BufWriter::new(File::open(&read_only_path).unwrap());
        recorder.events.write_all(b"buffered event data").unwrap();

        assert!(recorder.finish().is_err());
        let summary: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join("summary.json")).unwrap()).unwrap();
        assert_eq!(summary["status"], "incomplete");
        assert_eq!(
            summary["incomplete_reasons"],
            serde_json::json!(["capture.pcap flush failed", "events-v1.jsonl flush failed"])
        );

        // Successful summary creation makes finish idempotent even though it
        // returned the original data-flush error.
        assert!(recorder.finish().is_ok());
        drop(recorder);
        fs::remove_dir_all(path).unwrap();
    }
}
