//! WAL audit writer (append-only, plaintext newline-delimited JSON).
//!
//! Per scope-lock §8 Phase 1 decision: the WAL is plaintext with mode 0600
//! during the Sanctuary-main-down window. Phase 1.5 will encrypt it via the
//! OS keychain (Linux Secret Service, macOS Keychain Services).
//!
//! PR 2a shipped the in-memory ring buffer that absorbs events while
//! Sanctuary main is unreachable. PR 2b adds the disk-backed half:
//!
//! - [`WalWriter`] opens the WAL file with mode `0600`, append-only, and
//!   maintains a SHA-256 hash chain across entries so Sanctuary main can
//!   detect drop / reorder on drain.
//! - [`WalWriter::append_critical`] calls `fsync` per scope-lock §8 OQ #2
//!   "Recommend `fsync` per event in Phase 1 with a tunable knob"; the
//!   `append_metric` path skips the fsync because the surface is best-effort.
//! - [`WalWriter::snapshot_after`] returns entries strictly newer than a
//!   given chain seq; [`WalWriter::truncate_through_seq`] rewrites the file
//!   atomically to hide ACK'd entries while retaining one durable predecessor
//!   row as the restart chain anchor.
//!
//! Privilege boundary (scope-lock §8): the daemon never holds the fortress
//! master key. It does hold a separately provisioned, root-owned audit-producer
//! key and signs each drained event together with its sequence and capture
//! timestamp. The hash chain preserves ordering, while Sanctuary main verifies
//! the producer signature before committing the event to the L1 audit log.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

/// Maximum portion of the configured WAL cap reserved for lifecycle/control
/// evidence. Normal enforcement events stop before this region, leaving enough
/// room for boot, loss, and authenticated drain-recovery records.
pub const WAL_CONTROL_HEADROOM_MAX_BYTES: u64 = 64 * 1024;

/// One audit event awaiting durable persistence.
///
/// `critical` classifies the event for the ring buffer's eviction
/// policy (full-sweep #76). Critical events (audit truncate, key wrap,
/// recovery, daemon panic) survive saturation; only metric-class events
/// are dropped when the cap is hit. If the buffer is entirely full of
/// critical events and a new event arrives, the oldest critical is
/// dropped as a last resort and counted separately so operators can
/// distinguish "noisy metric loss" from "structural saturation."
#[derive(Debug, Clone)]
pub struct PendingAuditEvent {
    pub event_canonical_json: String,
    pub captured_at: SystemTime,
    pub critical: bool,
}

/// In-memory ring buffer for events that have not yet been ACK'd by main.
/// Once main ACKs an event, it's truncated from the WAL. PR 2b adds the
/// disk-backed half (write-then-IPC, truncate-on-ACK).
///
/// Eviction policy (full-sweep #76): when over budget, the buffer drops
/// the oldest **non-critical** event first, scanning the queue from front
/// to back. Critical events are preserved as long as any non-critical
/// event exists ahead of them. Only when the buffer is entirely critical
/// does the oldest critical entry get evicted, and that case bumps the
/// dedicated `critical_drop_count` so operators can tell metric-class
/// pressure from structural saturation.
#[derive(Debug)]
pub struct AuditRingBuffer {
    buffer: VecDeque<PendingAuditEvent>,
    max_bytes: u64,
    ttl: Duration,
    current_bytes: u64,
    overflow_count: u64,
    critical_drop_count: u64,
}

impl AuditRingBuffer {
    pub fn new(max_bytes: u64, ttl: Duration) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            ttl,
            current_bytes: 0,
            overflow_count: 0,
            critical_drop_count: 0,
        }
    }

    /// Append a pending event. If the cap is hit, drop the oldest
    /// **non-critical** event first; only fall back to dropping the
    /// oldest critical event when the buffer holds nothing else (in
    /// which case bump `critical_drop_count` so the loss is visible to
    /// operators on the next drain). The total `overflow_count` keeps
    /// tracking every dropped event regardless of class so existing
    /// "wal_overflow audit event on next ACK" plumbing still observes
    /// the same total.
    pub fn append(&mut self, event: PendingAuditEvent) {
        let event_bytes = event.event_canonical_json.len() as u64;
        while self.current_bytes + event_bytes > self.max_bytes && !self.buffer.is_empty() {
            // Prefer dropping the oldest non-critical entry. We scan
            // front-to-back so "oldest non-critical" wins over "newer
            // non-critical."
            let drop_index = self.buffer.iter().position(|pending| !pending.critical);
            match drop_index {
                Some(index) => {
                    if let Some(dropped) = self.buffer.remove(index) {
                        self.current_bytes = self
                            .current_bytes
                            .saturating_sub(dropped.event_canonical_json.len() as u64);
                        self.overflow_count = self.overflow_count.saturating_add(1);
                    }
                }
                None => {
                    // No non-critical events left. Falling back to the
                    // oldest critical is a last resort. Track this case
                    // separately so operators know the buffer was
                    // structurally saturated, not just noisy.
                    if let Some(dropped) = self.buffer.pop_front() {
                        self.current_bytes = self
                            .current_bytes
                            .saturating_sub(dropped.event_canonical_json.len() as u64);
                        self.overflow_count = self.overflow_count.saturating_add(1);
                        self.critical_drop_count = self.critical_drop_count.saturating_add(1);
                    }
                }
            }
        }
        self.current_bytes += event_bytes;
        self.buffer.push_back(event);
    }

    /// Evict events older than the TTL. Returns the number dropped.
    pub fn evict_expired(&mut self, now: SystemTime) -> u64 {
        let mut dropped = 0u64;
        while let Some(front) = self.buffer.front() {
            let age = now
                .duration_since(front.captured_at)
                .unwrap_or(Duration::ZERO);
            if age <= self.ttl {
                break;
            }
            if let Some(evicted) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(evicted.event_canonical_json.len() as u64);
                dropped += 1;
                self.overflow_count = self.overflow_count.saturating_add(1);
            }
        }
        dropped
    }

    /// Truncate the buffer up to and including the event at `index`. Used
    /// when Sanctuary main has ACK'd a batch.
    pub fn truncate_through(&mut self, index_inclusive: usize) {
        let to_drop = (index_inclusive + 1).min(self.buffer.len());
        for _ in 0..to_drop {
            if let Some(evicted) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(evicted.event_canonical_json.len() as u64);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Count of times a critical event was evicted from a fully-saturated
    /// critical-only buffer. Distinct from `overflow_count` so operators
    /// can tell metric-class pressure (which the ring buffer absorbs by
    /// design) from structural saturation (which means the buffer is
    /// undersized for the workload). Per full-sweep #76.
    pub fn critical_drop_count(&self) -> u64 {
        self.critical_drop_count
    }

    pub fn current_bytes(&self) -> u64 {
        self.current_bytes
    }

    pub fn iter(&self) -> impl Iterator<Item = &PendingAuditEvent> {
        self.buffer.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn pending(body: &str, t: SystemTime) -> PendingAuditEvent {
        // Default to non-critical so existing "drop oldest" tests still
        // exercise the metric-class path. New critical-class tests use
        // `pending_critical` explicitly.
        PendingAuditEvent {
            event_canonical_json: body.to_string(),
            captured_at: t,
            critical: false,
        }
    }

    fn pending_critical(body: &str, t: SystemTime) -> PendingAuditEvent {
        PendingAuditEvent {
            event_canonical_json: body.to_string(),
            captured_at: t,
            critical: true,
        }
    }

    #[test]
    fn append_grows_buffer() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_secs(60));
        buf.append(pending("{\"a\":1}", SystemTime::now()));
        assert_eq!(buf.len(), 1);
        assert_eq!(buf.current_bytes(), 7);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut buf = AuditRingBuffer::new(20, Duration::from_secs(60));
        let now = SystemTime::now();
        buf.append(pending("{\"first\":1}", now));
        buf.append(pending("{\"second\":2}", now));
        buf.append(pending("{\"third\":3}", now));
        assert!(buf.overflow_count() >= 1);
        let bodies: Vec<&str> = buf
            .iter()
            .map(|e| e.event_canonical_json.as_str())
            .collect();
        assert!(!bodies.iter().any(|b| b.contains("first")));
        // A buffer with no critical entries should never bump
        // critical_drop_count, regardless of total overflow pressure.
        assert_eq!(buf.critical_drop_count(), 0);
    }

    #[test]
    fn ttl_eviction_drops_expired() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_millis(100));
        let earlier = SystemTime::now() - Duration::from_secs(1);
        buf.append(pending("{\"old\":1}", earlier));
        let now = SystemTime::now();
        buf.append(pending("{\"new\":2}", now));
        let dropped = buf.evict_expired(now);
        assert_eq!(dropped, 1);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn truncate_through_drops_acked() {
        let mut buf = AuditRingBuffer::new(1024, Duration::from_secs(60));
        let now = SystemTime::now();
        buf.append(pending("{\"a\":1}", now));
        buf.append(pending("{\"b\":2}", now));
        buf.append(pending("{\"c\":3}", now));
        buf.truncate_through(1);
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn critical_events_survive_when_metric_events_fill_buffer() {
        // Full-sweep #76: a critical event placed early in the queue
        // must remain even after later metric-class events flood the
        // buffer past the cap. The eviction policy walks oldest-first
        // looking for a non-critical victim and skips the critical.
        let body_size = 16; // "{\"x\":\"AAAAA\"}" pads to >=16 bytes
        let cap = body_size as u64 * 2; // room for ~2 bodies at a time
        let mut buf = AuditRingBuffer::new(cap, Duration::from_secs(60));
        let now = SystemTime::now();

        // First entry is critical; subsequent entries are metric-class.
        buf.append(pending_critical("{\"crit\":\"AAA\"}", now));
        for i in 0..6 {
            buf.append(pending(&format!("{{\"metric\":\"BBB{i}\"}}"), now));
        }

        let bodies: Vec<&str> = buf
            .iter()
            .map(|e| e.event_canonical_json.as_str())
            .collect();
        assert!(
            bodies.iter().any(|b| b.contains("\"crit\"")),
            "critical event must survive metric-class pressure: {bodies:?}"
        );
        assert!(
            buf.overflow_count() >= 1,
            "metric pressure should have evicted at least one entry"
        );
        assert_eq!(
            buf.critical_drop_count(),
            0,
            "no critical drops while metric events still exist to evict"
        );
    }

    #[test]
    fn critical_events_drop_only_when_buffer_is_entirely_critical() {
        // Full-sweep #76: when the buffer is wholly populated with
        // critical events, a new arrival forces the oldest critical
        // out. That fallback bumps `critical_drop_count` so operators
        // can distinguish noisy metric loss from structural saturation.
        let cap: u64 = 24; // enough for ~2 small critical bodies
        let mut buf = AuditRingBuffer::new(cap, Duration::from_secs(60));
        let now = SystemTime::now();

        buf.append(pending_critical("{\"crit\":\"A\"}", now));
        buf.append(pending_critical("{\"crit\":\"B\"}", now));
        // Saturate further with another critical: oldest critical
        // (\"A\") must be evicted; \"B\" survives.
        buf.append(pending_critical("{\"crit\":\"C\"}", now));

        let bodies: Vec<&str> = buf
            .iter()
            .map(|e| e.event_canonical_json.as_str())
            .collect();
        assert!(
            !bodies.iter().any(|b| b.contains("\"A\"")),
            "oldest critical should have been evicted: {bodies:?}"
        );
        assert!(
            bodies.iter().any(|b| b.contains("\"C\"")),
            "newest critical should be present: {bodies:?}"
        );
        assert_eq!(
            buf.critical_drop_count(),
            1,
            "critical_drop_count must increment on critical-only saturation"
        );
        assert!(
            buf.overflow_count() >= 1,
            "overflow_count must also reflect the dropped critical"
        );
    }

    #[test]
    fn disk_wal_cap_refuses_before_mutation_and_never_deletes_unacked_evidence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bounded.wal");
        let cap = 900;
        let mut wal = WalWriter::open_with_cap(&path, cap).unwrap();
        while wal.append_critical("{\"operation\":\"bounded\"}").is_ok() {}
        let before = std::fs::read(&path).unwrap();
        let before_seq = wal.next_seq;
        let err = wal
            .append_critical("{\"operation\":\"must_refuse\"}")
            .unwrap_err();
        assert!(matches!(err, WalError::CapacityExceeded { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(wal.next_seq, before_seq);
        assert!(wal.bytes_written() <= cap);
    }

    #[test]
    fn oversized_existing_wal_refuses_start_without_truncation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("oversized.wal");
        let mut uncapped = WalWriter::open(&path).unwrap();
        uncapped
            .append_critical("{\"operation\":\"preserve\"}")
            .unwrap();
        drop(uncapped);
        let before = std::fs::read(&path).unwrap();
        let err = WalWriter::open_with_cap(&path, 1).unwrap_err();
        assert!(matches!(err, WalError::CapacityExceeded { .. }));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn ordinary_events_stop_before_reserved_control_recovery_headroom() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("recovery-headroom.wal");
        let cap = 8 * 1024;
        let mut wal = WalWriter::open_with_cap(&path, cap).unwrap();
        while wal.append_critical("{\"operation\":\"ordinary\"}").is_ok() {}
        let before_control = wal.bytes_written();
        wal.append_control_critical("{\"operation\":\"drain_recovery_started\"}")
            .expect("reserved headroom must admit bounded recovery evidence");
        assert!(wal.bytes_written() > before_control);
        assert!(wal.bytes_written() <= cap);
    }

    #[test]
    fn zero_budget_snapshot_and_ack_are_retryable_without_mutating_live_evidence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bounded-control.wal");
        let mut wal = WalWriter::open_with_cap(&path, 1024 * 1024).unwrap();
        wal.append_critical("{\"operation\":\"keep\"}").unwrap();
        let before = std::fs::read(&path).unwrap();
        let shutdown = AtomicBool::new(false);
        assert!(matches!(
            wal.snapshot_after_bounded(None, 1, &shutdown, Duration::ZERO),
            Err(WalError::OperationInProgress { .. })
        ));
        assert!(matches!(
            wal.truncate_through_seq_bounded(0, &shutdown, Duration::ZERO),
            Err(WalError::OperationInProgress { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn multi_megabyte_truncate_retries_resume_and_eventually_commit() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("resumable-large.wal");
        let mut wal = WalWriter::open_with_cap(&path, 8 * 1024 * 1024).unwrap();
        let body = format!("{{\"payload\":\"{}\"}}", "x".repeat(480));
        while wal.bytes_written() < 4 * 1024 * 1024 {
            wal.append_metric(&body).unwrap();
        }
        let ack = wal.next_seq() / 2;
        let shutdown = AtomicBool::new(false);
        let mut last_progress = 0;
        let mut saw_progress = false;
        for _ in 0..20_000 {
            match wal.truncate_through_seq_bounded(ack, &shutdown, Duration::from_micros(100)) {
                Ok(dropped) => {
                    assert!(dropped > 0);
                    assert!(saw_progress);
                    assert!(wal.bytes_written() < 4 * 1024 * 1024);
                    return;
                }
                Err(WalError::OperationInProgress {
                    processed_bytes, ..
                }) => {
                    assert!(processed_bytes >= last_progress);
                    saw_progress |= processed_bytes > last_progress;
                    last_progress = processed_bytes;
                }
                Err(err) => panic!("unexpected resumable truncate error: {err}"),
            }
        }
        panic!("resumable truncate did not eventually finish");
    }
}

// ---------------------------------------------------------------------------
// Disk-backed WAL writer.
// ---------------------------------------------------------------------------

/// One persisted entry in the daemon-side WAL. Serialized to canonical JSON
/// per line (NDJSON). The `prior_sha256_hex` field references the SHA-256 of
/// the prior entry's audit-event canonical-JSON bytes so Sanctuary main can
/// detect drops or reordering on drain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WalEntry {
    pub seq: u64,
    /// Milliseconds since UNIX epoch. `u64` rather than `u128` so the wire
    /// shape round-trips through serde_json (which does not deserialize
    /// u128 by default). u64 ms overflows around year 584,942,417, a
    /// comfortable margin for any plausible Castle Wall WAL.
    pub captured_at_unix_ms: u64,
    pub prior_sha256_hex: Option<String>,
    /// Canonical JSON of the AuditEntry shape. Stored as a string rather than
    /// a parsed serde_json::Value so we never re-serialize and risk drifting
    /// from the byte exact form Sanctuary main signs.
    pub event_canonical_json: String,
    /// Convenience tag the IPC layer uses to decide whether to fsync on
    /// drain. Critical events were fsync'd on append already; metric events
    /// were not.
    pub critical: bool,
    /// A logically ACKed predecessor retained as the first physical row so a
    /// restart never loses sequence/high-water or accepts an unverifiable
    /// post-truncation chain root. Anchor rows are never returned by drain.
    #[serde(default, skip_serializing_if = "is_false")]
    pub acked_anchor: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Errors emitted by the WAL writer.
#[derive(Debug, thiserror::Error)]
pub enum WalError {
    #[error("WAL file IO failed at {path}: {source_message}")]
    Io {
        path: PathBuf,
        source_message: String,
    },
    #[error("WAL parse error at line {line}: {source_message}")]
    Parse { line: u64, source_message: String },
    #[error(
        "WAL chain integrity broken at seq {seq}: expected prior={expected:?}, found={found:?}"
    )]
    ChainBroken {
        seq: u64,
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("WAL malformed prior_sha256_hex at seq {seq}: expected 64 lowercase hex chars, found {found:?}")]
    MalformedPriorHash { seq: u64, found: String },
    #[error("WAL truncate rename failed at {path}: {source_message}; in-memory state unchanged")]
    RenameFailed {
        path: PathBuf,
        source_message: String,
    },
    #[error("WAL operation cancelled during daemon shutdown")]
    Cancelled,
    #[error("WAL operation exceeded its bounded control-path budget")]
    OperationBudgetExceeded,
    #[error("WAL {operation} is still making progress ({processed_bytes} bytes validated)")]
    OperationInProgress {
        operation: &'static str,
        processed_bytes: u64,
    },
    #[error("WAL on-disk capacity exceeded: cap={cap_bytes} current={current_bytes} attempted={attempted_bytes}; no unacknowledged evidence was deleted")]
    CapacityExceeded {
        cap_bytes: u64,
        current_bytes: u64,
        attempted_bytes: u64,
    },
    #[error("WAL is poisoned after an indeterminate durable mutation: {reason}")]
    Poisoned { reason: String },
}

/// Test-only fault points that cross a durable-mutation boundary. Unlike the
/// legacy pre-write injection, every one of these must permanently poison this
/// writer instance because disk and in-memory chain state may have diverged.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalFaultPoint {
    AppendPartialBody,
    AppendSyncFailure,
    TruncateParentSyncFailure,
    TruncateReopenFailure,
}

/// True iff `s` is a sequence of exactly 64 lowercase hex chars
/// (`0-9` and `a-f`). The WAL writes hashes via `sha256_hex` which
/// emits lowercase; an entry whose `prior_sha256_hex` deviates from
/// that shape is structurally malformed and cannot be the legitimate
/// product of an earlier WAL append.
pub(crate) fn is_canonical_lowercase_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Disk-backed append-only writer. Persists `WalEntry` records to a file
/// with mode `0600` (operator-readable only). The file is opened in
/// append-mode; rewrites for [`WalWriter::truncate_through_seq`] use
/// write-then-rename semantics so a partial write cannot corrupt the WAL.
#[derive(Debug)]
pub struct WalWriter {
    path: PathBuf,
    file: File,
    next_seq: u64,
    last_chain_hash_hex: Option<String>,
    bytes_written: u64,
    size_cap_bytes: u64,
    /// Once a mutation crosses a write/rename boundary and then fails, this
    /// process can no longer prove which bytes are durable. The latch is never
    /// cleared in-process: only a restart and full replay may establish truth.
    poisoned_reason: Option<String>,
    pending_snapshot: Option<SnapshotProgress>,
    pending_truncate: Option<TruncateProgress>,
    /// Test-only injection seam. Setting this AtomicBool causes the next
    /// `append_critical` / `append_metric` call to short-circuit with a
    /// synthesized `WalError::Io` BEFORE touching the file. The error
    /// shape is byte-for-byte indistinguishable from a real OS-side
    /// `WalError::Io` from the daemon evaluator's perspective, so the
    /// `RuntimeAuditWalAppendFailed` dispatch path can be exercised
    /// end-to-end without filesystem manipulation. WalWriter state
    /// (next_seq, last_chain_hash_hex, bytes_written) is NOT advanced on
    /// an injected failure, mirroring the real-error invariant.
    ///
    /// Test-only and not part of the production daemon's surface; the
    /// field is `#[cfg(test)]`-gated so a release build does not carry it.
    #[cfg(test)]
    inject_io_error: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    inject_rename_error: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    inject_fault: std::sync::Arc<std::sync::Mutex<Option<WalFaultPoint>>>,
}

#[derive(Debug)]
struct SnapshotProgress {
    after_seq: Option<u64>,
    max_entries: usize,
    reader: BufReader<File>,
    validation: WalValidationState,
    line_num: u64,
    out: Vec<WalEntry>,
}

#[derive(Debug)]
struct TruncateProgress {
    last_acked_seq: u64,
    reader: BufReader<File>,
    tmp: File,
    tmp_path: PathBuf,
    validation: WalValidationState,
    line_num: u64,
    last_acked: Option<WalEntry>,
    anchor_written: bool,
    newly_dropped: u64,
    new_bytes: u64,
    new_chain_hash: Option<String>,
}

fn write_progress_entry(progress: &mut TruncateProgress, entry: &WalEntry) -> Result<(), WalError> {
    let serialized = serde_json::to_string(entry).map_err(|err| WalError::Io {
        path: progress.tmp_path.clone(),
        source_message: err.to_string(),
    })?;
    progress
        .tmp
        .write_all(serialized.as_bytes())
        .map_err(|err| WalError::Io {
            path: progress.tmp_path.clone(),
            source_message: err.to_string(),
        })?;
    progress.tmp.write_all(b"\n").map_err(|err| WalError::Io {
        path: progress.tmp_path.clone(),
        source_message: err.to_string(),
    })?;
    progress.new_bytes = progress
        .new_bytes
        .saturating_add(serialized.len() as u64 + 1);
    progress.new_chain_hash = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
    Ok(())
}

fn write_progress_anchor(progress: &mut TruncateProgress) -> Result<(), WalError> {
    if let Some(mut anchor) = progress.last_acked.take() {
        anchor.acked_anchor = true;
        write_progress_entry(progress, &anchor)?;
    }
    progress.anchor_written = true;
    Ok(())
}

impl WalWriter {
    /// Open or create the WAL file at `path` with mode 0600. Replays any
    /// existing entries to compute the next-seq + last-chain-hash starting
    /// state. On replay error returns `WalError::Parse` or
    /// `WalError::ChainBroken` so the daemon can refuse to come up with a
    /// corrupt audit history.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        Self::open_with_cap(path, u64::MAX)
    }

    /// Open with a strict on-disk byte cap. Existing evidence is never
    /// truncated to satisfy the cap: an oversized WAL refuses startup, and an
    /// append that would cross the cap fails before touching disk or sequence
    /// state. Only an authenticated drain ACK may reclaim bytes.
    pub fn open_with_cap(path: &Path, size_cap_bytes: u64) -> Result<Self, WalError> {
        // Read any existing content first so we can compute resume state.
        // Then re-open with create + append for writes.
        let existing = match File::open(path) {
            Ok(file) => {
                let metadata = file.metadata().map_err(|err| WalError::Io {
                    path: path.to_path_buf(),
                    source_message: err.to_string(),
                })?;
                if metadata.len() > size_cap_bytes {
                    return Err(WalError::CapacityExceeded {
                        cap_bytes: size_cap_bytes,
                        current_bytes: metadata.len(),
                        attempted_bytes: 0,
                    });
                }
                let mut contents = String::new();
                file.take(size_cap_bytes.saturating_add(1))
                    .read_to_string(&mut contents)
                    .map_err(|err| WalError::Io {
                        path: path.to_path_buf(),
                        source_message: err.to_string(),
                    })?;
                if contents.len() as u64 > size_cap_bytes {
                    return Err(WalError::CapacityExceeded {
                        cap_bytes: size_cap_bytes,
                        current_bytes: contents.len() as u64,
                        attempted_bytes: 0,
                    });
                }
                Some(contents)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(WalError::Io {
                    path: path.to_path_buf(),
                    source_message: err.to_string(),
                })
            }
        };
        let (next_seq, last_chain_hash_hex, bytes) = match existing {
            Some(contents) => replay_existing(&contents).map_err(|e| match e {
                WalError::Parse { .. } | WalError::ChainBroken { .. } => e,
                other => other,
            })?,
            None => (0u64, None, 0u64),
        };

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| WalError::Io {
                path: parent.to_path_buf(),
                source_message: err.to_string(),
            })?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path).map_err(|err| WalError::Io {
            path: path.to_path_buf(),
            source_message: err.to_string(),
        })?;
        let opened_len = file
            .metadata()
            .map_err(|err| WalError::Io {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            })?
            .len();
        if opened_len != bytes {
            return Err(WalError::Io {
                path: path.to_path_buf(),
                source_message: "WAL changed while startup replay was in progress".to_string(),
            });
        }
        if bytes > size_cap_bytes {
            return Err(WalError::CapacityExceeded {
                cap_bytes: size_cap_bytes,
                current_bytes: bytes,
                attempted_bytes: 0,
            });
        }
        // On Linux the open does not enforce perms when the file already
        // exists (umask applies only to create). Set explicitly so an
        // operator-pre-created file with looser perms is corrected.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|err| WalError::Io {
                    path: path.to_path_buf(),
                    source_message: err.to_string(),
                })?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms).map_err(|err| WalError::Io {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            })?;
        }

        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_seq,
            last_chain_hash_hex,
            bytes_written: bytes,
            size_cap_bytes,
            poisoned_reason: None,
            pending_snapshot: None,
            pending_truncate: None,
            #[cfg(test)]
            inject_io_error: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            inject_rename_error: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            inject_fault: std::sync::Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Test-only handle to the injection flag. The handle is cloned so the
    /// caller can hold an injection switch independently of any later
    /// `Arc<Mutex<WalWriter>>` borrow. Setting the AtomicBool to `true`
    /// causes the next append (critical or metric) to fail with a
    /// synthesized `WalError::Io` shape; setting it back to `false`
    /// restores normal append behavior.
    #[cfg(test)]
    pub fn injection_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.inject_io_error.clone()
    }

    #[cfg(test)]
    pub fn rename_injection_handle(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.inject_rename_error.clone()
    }

    #[cfg(test)]
    pub(crate) fn fault_injection_handle(
        &self,
    ) -> std::sync::Arc<std::sync::Mutex<Option<WalFaultPoint>>> {
        self.inject_fault.clone()
    }

    /// True after an append/rotation crossed a durable-mutation boundary and
    /// failed. Supervisors use this independently of the writer mutex's poison
    /// bit: ordinary `Result` errors do not poison a Rust mutex.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned_reason.is_some()
    }

    fn refuse_if_poisoned(&self) -> Result<(), WalError> {
        match self.poisoned_reason.as_ref() {
            Some(reason) => Err(WalError::Poisoned {
                reason: reason.clone(),
            }),
            None => Ok(()),
        }
    }

    fn poison(&mut self, reason: String) -> WalError {
        if self.poisoned_reason.is_none() {
            self.poisoned_reason = Some(reason);
        }
        WalError::Poisoned {
            reason: self
                .poisoned_reason
                .clone()
                .expect("poison reason set above"),
        }
    }

    #[cfg(test)]
    fn take_fault(&self, point: WalFaultPoint) -> bool {
        let Ok(mut armed) = self.inject_fault.lock() else {
            return false;
        };
        if *armed == Some(point) {
            *armed = None;
            true
        } else {
            false
        }
    }

    /// Append a critical event with `fsync` per scope-lock §8 OQ #2.
    /// Returns the assigned seq.
    pub fn append_critical(&mut self, event_canonical_json: &str) -> Result<u64, WalError> {
        self.append(event_canonical_json, true, true, false)
    }

    /// Append lifecycle/control evidence from reserved recovery headroom.
    /// This is intentionally not used by ordinary verdict events.
    pub fn append_control_critical(&mut self, event_canonical_json: &str) -> Result<u64, WalError> {
        self.append(event_canonical_json, true, true, true)
    }

    /// Append a metric event without fsync (best-effort durability).
    pub fn append_metric(&mut self, event_canonical_json: &str) -> Result<u64, WalError> {
        self.append(event_canonical_json, false, false, false)
    }

    fn append(
        &mut self,
        event_canonical_json: &str,
        critical: bool,
        fsync: bool,
        use_control_headroom: bool,
    ) -> Result<u64, WalError> {
        self.refuse_if_poisoned()?;
        #[cfg(test)]
        if self
            .inject_io_error
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(WalError::Io {
                path: self.path.clone(),
                source_message: "test-injected append failure".to_string(),
            });
        }
        let seq = self.next_seq;
        let following_seq = seq.checked_add(1).ok_or_else(|| WalError::Io {
            path: self.path.clone(),
            source_message: "WAL sequence space exhausted before append".to_string(),
        })?;
        let prior_sha256_hex = self.last_chain_hash_hex.clone();
        let event_canonical_json =
            add_wal_chain_fields(event_canonical_json, seq, prior_sha256_hex.as_deref())?;
        let entry = WalEntry {
            seq,
            captured_at_unix_ms: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0),
            prior_sha256_hex,
            event_canonical_json,
            critical,
            acked_anchor: false,
        };
        let serialized = serde_json::to_string(&entry).map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?;
        let attempted_bytes = serialized.len() as u64 + 1;
        let reserved = WAL_CONTROL_HEADROOM_MAX_BYTES.min(self.size_cap_bytes / 8);
        let effective_cap = if use_control_headroom {
            self.size_cap_bytes
        } else {
            self.size_cap_bytes.saturating_sub(reserved)
        };
        if match self.bytes_written.checked_add(attempted_bytes) {
            Some(next) => next > effective_cap,
            None => true,
        } {
            return Err(WalError::CapacityExceeded {
                cap_bytes: self.size_cap_bytes,
                current_bytes: self.bytes_written,
                attempted_bytes,
            });
        }
        #[cfg(test)]
        if self.take_fault(WalFaultPoint::AppendPartialBody) {
            let prefix_len = serialized.len().max(2) / 2;
            if let Err(err) = self.file.write_all(&serialized.as_bytes()[..prefix_len]) {
                return Err(self.poison(format!("append partial-body write failed: {err}")));
            }
            return Err(self.poison("test-injected failure after partial body write".to_string()));
        }
        if let Err(err) = self.file.write_all(serialized.as_bytes()) {
            return Err(self.poison(format!("append body write became indeterminate: {err}")));
        }
        if let Err(err) = self.file.write_all(b"\n") {
            return Err(self.poison(format!("append newline write became indeterminate: {err}")));
        }
        if fsync {
            #[cfg(test)]
            if self.take_fault(WalFaultPoint::AppendSyncFailure) {
                return Err(self.poison("test-injected append fsync failure".to_string()));
            }
            if let Err(err) = self.file.sync_all() {
                return Err(self.poison(format!("append fsync became indeterminate: {err}")));
            }
        }
        self.bytes_written += attempted_bytes;
        self.last_chain_hash_hex = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
        self.next_seq = following_seq;
        Ok(entry.seq)
    }

    /// Snapshot all entries strictly after `after_seq`. Returns at most
    /// `max_entries` entries in seq order. Reads from disk to guarantee a
    /// consistent view across drains; a future optimization (Phase 1.5)
    /// could keep an in-memory index.
    pub fn snapshot_after(
        &mut self,
        after_seq: Option<u64>,
        max_entries: usize,
    ) -> Result<Vec<WalEntry>, WalError> {
        self.snapshot_after_impl(after_seq, max_entries, || false)
    }

    /// Shutdown-aware drain variant used by IPC handlers. Cancellation is
    /// checked between bounded line reads and before returning the snapshot.
    pub fn snapshot_after_cancellable(
        &mut self,
        after_seq: Option<u64>,
        max_entries: usize,
        shutdown: &AtomicBool,
    ) -> Result<Vec<WalEntry>, WalError> {
        self.snapshot_after_impl(after_seq, max_entries, || shutdown.load(Ordering::SeqCst))
    }

    pub fn snapshot_after_bounded(
        &mut self,
        after_seq: Option<u64>,
        max_entries: usize,
        shutdown: &AtomicBool,
        budget: Duration,
    ) -> Result<Vec<WalEntry>, WalError> {
        self.refuse_if_poisoned()?;
        if let Some(progress) = self.pending_truncate.as_ref() {
            return Err(WalError::OperationInProgress {
                operation: "truncate",
                processed_bytes: progress.validation.bytes,
            });
        }
        if shutdown.load(Ordering::SeqCst) {
            self.pending_snapshot = None;
            return Err(WalError::Cancelled);
        }
        if let Some(progress) = self.pending_snapshot.as_ref() {
            if progress.after_seq != after_seq || progress.max_entries != max_entries {
                return Err(WalError::OperationInProgress {
                    operation: "snapshot",
                    processed_bytes: progress.validation.bytes,
                });
            }
        } else {
            let mut reader = BufReader::new(self.file.try_clone().map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?);
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|err| WalError::Io {
                    path: self.path.clone(),
                    source_message: err.to_string(),
                })?;
            self.pending_snapshot = Some(SnapshotProgress {
                after_seq,
                max_entries,
                reader,
                validation: WalValidationState::default(),
                line_num: 0,
                out: Vec::new(),
            });
        }
        let deadline = Instant::now() + budget;
        let progress = self.pending_snapshot.as_mut().expect("initialized above");
        loop {
            if shutdown.load(Ordering::SeqCst) {
                self.pending_snapshot = None;
                return Err(WalError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(WalError::OperationInProgress {
                    operation: "snapshot",
                    processed_bytes: progress.validation.bytes,
                });
            }
            let mut line = String::new();
            let read = progress
                .reader
                .read_line(&mut line)
                .map_err(|err| WalError::Io {
                    path: self.path.clone(),
                    source_message: err.to_string(),
                })?;
            if read == 0 {
                let done = self.pending_snapshot.take().expect("snapshot exists");
                return Ok(done.out);
            }
            progress.line_num += 1;
            let row = line.strip_suffix('\n').unwrap_or(&line);
            let row = row.strip_suffix('\r').unwrap_or(row);
            let entry = match validate_wal_line(row, progress.line_num, &mut progress.validation) {
                Ok(entry) => entry,
                Err(err) => {
                    self.pending_snapshot = None;
                    return Err(err);
                }
            };
            let is_after = !entry.acked_anchor
                && progress
                    .after_seq
                    .map_or(true, |threshold| entry.seq > threshold);
            if is_after {
                progress.out.push(entry);
                if progress.out.len() == progress.max_entries {
                    let done = self.pending_snapshot.take().expect("snapshot exists");
                    return Ok(done.out);
                }
            }
        }
    }

    fn snapshot_after_impl(
        &mut self,
        after_seq: Option<u64>,
        max_entries: usize,
        cancelled: impl Fn() -> bool,
    ) -> Result<Vec<WalEntry>, WalError> {
        self.refuse_if_poisoned()?;
        // Rewind the file pointer to the start so BufReader sees everything.
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        let reader = BufReader::new(self.file.try_clone().map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?);
        let mut out = Vec::new();
        let mut validation = WalValidationState::default();
        for (index, line) in reader.lines().enumerate() {
            if cancelled() {
                let _ = self.file.seek(SeekFrom::End(0));
                return Err(WalError::Cancelled);
            }
            let line_num = (index as u64) + 1;
            let line = line.map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
            let entry = validate_wal_line(&line, line_num, &mut validation)?;
            let is_after = !entry.acked_anchor
                && match after_seq {
                    Some(threshold) => entry.seq > threshold,
                    None => true,
                };
            if is_after && out.len() < max_entries {
                out.push(entry);
                if out.len() == max_entries {
                    break;
                }
            }
        }
        // Restore append position for subsequent writes.
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        if cancelled() {
            return Err(WalError::Cancelled);
        }
        Ok(out)
    }

    /// Logically drop all WAL entries with seq <= `last_acked_seq`. One last
    /// ACKed row is retained as a physical chain anchor but is never drained.
    /// Atomic: writes a new WAL to `<path>.tmp`, fsyncs, atomically renames
    /// over the live file, then re-opens for append. Returns the count newly
    /// acknowledged (the retained anchor is included in that logical count).
    pub fn truncate_through_seq(&mut self, last_acked_seq: u64) -> Result<u64, WalError> {
        self.truncate_through_seq_impl(last_acked_seq, || false)
    }

    /// Shutdown-aware ACK transaction. Cancellation before rename removes the
    /// private temporary file and leaves the live WAL/in-memory chain intact.
    pub fn truncate_through_seq_cancellable(
        &mut self,
        last_acked_seq: u64,
        shutdown: &AtomicBool,
    ) -> Result<u64, WalError> {
        self.truncate_through_seq_impl(last_acked_seq, || shutdown.load(Ordering::SeqCst))
    }

    pub fn truncate_through_seq_bounded(
        &mut self,
        last_acked_seq: u64,
        shutdown: &AtomicBool,
        budget: Duration,
    ) -> Result<u64, WalError> {
        self.refuse_if_poisoned()?;
        if let Some(progress) = self.pending_snapshot.as_ref() {
            return Err(WalError::OperationInProgress {
                operation: "snapshot",
                processed_bytes: progress.validation.bytes,
            });
        }
        if shutdown.load(Ordering::SeqCst) {
            if let Some(progress) = self.pending_truncate.take() {
                let _ = std::fs::remove_file(progress.tmp_path);
            }
            return Err(WalError::Cancelled);
        }
        if let Some(progress) = self.pending_truncate.as_ref() {
            if progress.last_acked_seq != last_acked_seq {
                return Err(WalError::OperationInProgress {
                    operation: "truncate",
                    processed_bytes: progress.validation.bytes,
                });
            }
        } else {
            let tmp_path = self.path.with_extension("tmp");
            let mut opts = OpenOptions::new();
            opts.create(true).truncate(true).write(true).read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let tmp = opts.open(&tmp_path).map_err(|err| WalError::Io {
                path: tmp_path.clone(),
                source_message: err.to_string(),
            })?;
            let mut reader = BufReader::new(self.file.try_clone().map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?);
            reader
                .seek(SeekFrom::Start(0))
                .map_err(|err| WalError::Io {
                    path: self.path.clone(),
                    source_message: err.to_string(),
                })?;
            self.pending_truncate = Some(TruncateProgress {
                last_acked_seq,
                reader,
                tmp,
                tmp_path,
                validation: WalValidationState::default(),
                line_num: 0,
                last_acked: None,
                anchor_written: false,
                newly_dropped: 0,
                new_bytes: 0,
                new_chain_hash: None,
            });
        }
        let deadline = Instant::now() + budget;
        loop {
            let progress = self.pending_truncate.as_mut().expect("initialized above");
            if shutdown.load(Ordering::SeqCst) {
                let progress = self.pending_truncate.take().expect("truncate exists");
                let _ = std::fs::remove_file(progress.tmp_path);
                return Err(WalError::Cancelled);
            }
            if Instant::now() >= deadline {
                return Err(WalError::OperationInProgress {
                    operation: "truncate",
                    processed_bytes: progress.validation.bytes,
                });
            }
            let mut line = String::new();
            let read = progress
                .reader
                .read_line(&mut line)
                .map_err(|err| WalError::Io {
                    path: self.path.clone(),
                    source_message: err.to_string(),
                })?;
            if read == 0 {
                if !progress.anchor_written {
                    write_progress_anchor(progress)?;
                }
                break;
            }
            progress.line_num += 1;
            let row = line.strip_suffix('\n').unwrap_or(&line);
            let row = row.strip_suffix('\r').unwrap_or(row);
            let entry = match validate_wal_line(row, progress.line_num, &mut progress.validation) {
                Ok(entry) => entry,
                Err(err) => {
                    let failed = self.pending_truncate.take().expect("truncate exists");
                    let _ = std::fs::remove_file(failed.tmp_path);
                    return Err(err);
                }
            };
            if entry.seq <= last_acked_seq {
                if !entry.acked_anchor {
                    progress.newly_dropped =
                        progress
                            .newly_dropped
                            .checked_add(1)
                            .ok_or_else(|| WalError::Parse {
                                line: progress.line_num,
                                source_message: "WAL acknowledged-entry count overflow".to_string(),
                            })?;
                }
                progress.last_acked = Some(entry);
            } else {
                if !progress.anchor_written {
                    write_progress_anchor(progress)?;
                }
                write_progress_entry(progress, &entry)?;
            }
        }
        let progress = self.pending_truncate.take().expect("truncate exists");
        progress.tmp.sync_all().map_err(|err| WalError::Io {
            path: progress.tmp_path.clone(),
            source_message: err.to_string(),
        })?;
        drop(progress.tmp);
        if shutdown.load(Ordering::SeqCst) {
            let _ = std::fs::remove_file(&progress.tmp_path);
            return Err(WalError::Cancelled);
        }
        #[cfg(test)]
        if self
            .inject_rename_error
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let _ = std::fs::remove_file(&progress.tmp_path);
            return Err(WalError::RenameFailed {
                path: self.path.clone(),
                source_message: "test-injected truncate rename failure".to_string(),
            });
        }
        if let Err(err) = std::fs::rename(&progress.tmp_path, &self.path) {
            let _ = std::fs::remove_file(&progress.tmp_path);
            return Err(WalError::RenameFailed {
                path: self.path.clone(),
                source_message: err.to_string(),
            });
        }
        if let Some(parent) = self.path.parent().map(Path::to_path_buf) {
            #[cfg(test)]
            if self.take_fault(WalFaultPoint::TruncateParentSyncFailure) {
                return Err(self.poison(
                    "test-injected parent-directory fsync failure after WAL rename".to_string(),
                ));
            }
            File::open(&parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| {
                    self.poison(format!(
                        "parent-directory fsync after WAL rename failed: {err}"
                    ))
                })?;
        }
        let mut opts = OpenOptions::new();
        opts.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(test)]
        if self.take_fault(WalFaultPoint::TruncateReopenFailure) {
            return Err(self.poison("test-injected WAL reopen failure after rename".to_string()));
        }
        self.file = opts
            .open(&self.path)
            .map_err(|err| self.poison(format!("WAL reopen after rename failed: {err}")))?;
        self.bytes_written = progress.new_bytes;
        self.last_chain_hash_hex = progress.new_chain_hash;
        Ok(progress.newly_dropped)
    }

    fn truncate_through_seq_impl(
        &mut self,
        last_acked_seq: u64,
        cancelled: impl Fn() -> bool,
    ) -> Result<u64, WalError> {
        self.refuse_if_poisoned()?;
        let tmp_path = self.path.with_extension("tmp");
        let mut last_acked: Option<WalEntry> = None;
        // First pass validates the complete live WAL and identifies the one
        // anchor. Unacked rows are deliberately NOT accumulated in memory.
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        let reader = BufReader::new(self.file.try_clone().map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?);
        let mut newly_dropped: u64 = 0;
        let mut validation = WalValidationState::default();
        for (index, line) in reader.lines().enumerate() {
            if cancelled() {
                let _ = self.file.seek(SeekFrom::End(0));
                return Err(WalError::Cancelled);
            }
            let line_num = (index as u64) + 1;
            let line = line.map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
            let entry = validate_wal_line(&line, line_num, &mut validation)?;
            if entry.seq <= last_acked_seq {
                if !entry.acked_anchor {
                    newly_dropped =
                        newly_dropped
                            .checked_add(1)
                            .ok_or_else(|| WalError::Parse {
                                line: line_num,
                                source_message: "WAL acknowledged-entry count overflow".to_string(),
                            })?;
                }
                last_acked = Some(entry);
            }
        }
        if cancelled() {
            let _ = self.file.seek(SeekFrom::End(0));
            return Err(WalError::Cancelled);
        }

        // Rewrite to .tmp, then atomic-rename. fsync between write and
        // rename so the rename's metadata sees the durable bytes.
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(true).write(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut tmp = opts.open(&tmp_path).map_err(|err| WalError::Io {
            path: tmp_path.clone(),
            source_message: err.to_string(),
        })?;
        let mut new_bytes: u64 = 0;
        let mut new_chain_hash: Option<String> = None;
        let mut write_entry = |entry: &WalEntry| -> Result<(), WalError> {
            if cancelled() {
                return Err(WalError::Cancelled);
            }
            let serialized = serde_json::to_string(entry).map_err(|err| WalError::Io {
                path: tmp_path.clone(),
                source_message: err.to_string(),
            })?;
            tmp.write_all(serialized.as_bytes())
                .map_err(|err| WalError::Io {
                    path: tmp_path.clone(),
                    source_message: err.to_string(),
                })?;
            tmp.write_all(b"\n").map_err(|err| WalError::Io {
                path: tmp_path.clone(),
                source_message: err.to_string(),
            })?;
            new_bytes += serialized.len() as u64 + 1;
            new_chain_hash = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
            Ok(())
        };
        if let Some(mut anchor) = last_acked {
            anchor.acked_anchor = true;
            if let Err(err) = write_entry(&anchor) {
                drop(tmp);
                let _ = std::fs::remove_file(&tmp_path);
                return Err(err);
            }
        }

        // Second pass streams retained rows directly into the private file.
        // Memory is O(one row), and the deadline check between every row bounds
        // how long the shared WAL mutex can be monopolized by a large ACK.
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        let reader = BufReader::new(self.file.try_clone().map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?);
        let mut validation = WalValidationState::default();
        for (index, line) in reader.lines().enumerate() {
            if cancelled() {
                drop(tmp);
                let _ = std::fs::remove_file(&tmp_path);
                let _ = self.file.seek(SeekFrom::End(0));
                return Err(WalError::Cancelled);
            }
            let line_num = (index as u64) + 1;
            let line = line.map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
            let entry = validate_wal_line(&line, line_num, &mut validation)?;
            if entry.seq > last_acked_seq {
                if let Err(err) = write_entry(&entry) {
                    drop(tmp);
                    let _ = std::fs::remove_file(&tmp_path);
                    let _ = self.file.seek(SeekFrom::End(0));
                    return Err(err);
                }
            }
        }
        tmp.sync_all().map_err(|err| WalError::Io {
            path: tmp_path.clone(),
            source_message: err.to_string(),
        })?;
        drop(tmp);
        if cancelled() {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(WalError::Cancelled);
        }
        #[cfg(test)]
        if self
            .inject_rename_error
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(WalError::RenameFailed {
                path: self.path.clone(),
                source_message: "test-injected truncate rename failure".to_string(),
            });
        }
        if let Err(err) = std::fs::rename(&tmp_path, &self.path) {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(WalError::RenameFailed {
                path: self.path.clone(),
                source_message: err.to_string(),
            });
        }

        // A successful rename is not durable until the containing directory's
        // metadata is synced.  Do this before updating in-memory state and
        // before the IPC layer can acknowledge reclamation; otherwise a power
        // loss may resurrect ACKed evidence after main was told it was gone.
        if let Some(parent) = self.path.parent().map(Path::to_path_buf) {
            #[cfg(test)]
            if self.take_fault(WalFaultPoint::TruncateParentSyncFailure) {
                return Err(self.poison(
                    "test-injected parent-directory fsync failure after WAL rename".to_string(),
                ));
            }
            std::fs::File::open(&parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|err| {
                    self.poison(format!(
                        "parent-directory fsync after WAL rename failed: {err}"
                    ))
                })?;
        }

        // Re-open the now-replaced file for append.
        let mut opts = OpenOptions::new();
        opts.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        #[cfg(test)]
        if self.take_fault(WalFaultPoint::TruncateReopenFailure) {
            return Err(self.poison("test-injected WAL reopen failure after rename".to_string()));
        }
        self.file = match opts.open(&self.path) {
            Ok(file) => file,
            Err(err) => return Err(self.poison(format!("WAL reopen after rename failed: {err}"))),
        };
        self.bytes_written = new_bytes;
        self.last_chain_hash_hex = new_chain_hash;
        Ok(newly_dropped)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    pub fn last_chain_hash_hex(&self) -> Option<&str> {
        self.last_chain_hash_hex.as_deref()
    }
}

fn replay_existing(contents: &str) -> Result<(u64, Option<String>, u64), WalError> {
    let mut state = WalValidationState::default();
    for (index, line) in contents.lines().enumerate() {
        let line_num = (index as u64) + 1;
        validate_wal_line(line, line_num, &mut state)?;
    }
    Ok((state.next_seq, state.last_chain_hash, state.bytes))
}

#[derive(Debug, Default)]
struct WalValidationState {
    previous_seq: Option<u64>,
    next_seq: u64,
    last_chain_hash: Option<String>,
    bytes: u64,
}

/// Parse and validate one exact on-disk row before it may be drained or used
/// by an ACK transaction. Re-running this check for snapshots/truncation is
/// deliberate: startup validation cannot protect against later disk mutation.
fn validate_wal_line(
    line: &str,
    line_num: u64,
    state: &mut WalValidationState,
) -> Result<WalEntry, WalError> {
    if line.is_empty() {
        return Err(WalError::Parse {
            line: line_num,
            source_message: "empty interior WAL row".to_string(),
        });
    }
    let entry: WalEntry = serde_json::from_str(line).map_err(|err| WalError::Parse {
        line: line_num,
        source_message: err.to_string(),
    })?;
    let exact = serde_json::to_string(&entry).map_err(|err| WalError::Parse {
        line: line_num,
        source_message: format!("WAL row reserialization failed: {err}"),
    })?;
    if exact != line {
        return Err(WalError::Parse {
            line: line_num,
            source_message:
                "WAL row is not the exact canonical writer encoding (duplicate, unknown, reordered, or decorated fields)"
                    .to_string(),
        });
    }

    if let Some(prior) = entry.prior_sha256_hex.as_deref() {
        if !is_canonical_lowercase_sha256_hex(prior) {
            return Err(WalError::MalformedPriorHash {
                seq: entry.seq,
                found: prior.to_string(),
            });
        }
    }

    match state.previous_seq {
        None => match (
            entry.seq,
            entry.prior_sha256_hex.as_ref(),
            entry.acked_anchor,
        ) {
            (0, None, _) => {}
            (0, Some(_), _) => {
                return Err(WalError::ChainBroken {
                    seq: entry.seq,
                    expected: None,
                    found: entry.prior_sha256_hex.clone(),
                })
            }
            (_, None, _) => {
                return Err(WalError::Parse {
                    line: line_num,
                    source_message:
                        "post-truncation first row must retain its non-null predecessor anchor"
                            .to_string(),
                })
            }
            (_, Some(_), true) => {}
            (_, Some(_), false) => {
                return Err(WalError::Parse {
                    line: line_num,
                    source_message: "post-truncation first row must be the retained ACK anchor"
                        .to_string(),
                })
            }
        },
        Some(previous) => {
            if entry.acked_anchor {
                return Err(WalError::Parse {
                    line: line_num,
                    source_message: "ACK anchor may appear only as the first WAL row".to_string(),
                });
            }
            let expected_seq = previous.checked_add(1).ok_or_else(|| WalError::Parse {
                line: line_num,
                source_message: "WAL sequence space exhausted".to_string(),
            })?;
            if entry.seq != expected_seq {
                return Err(WalError::Parse {
                    line: line_num,
                    source_message: format!(
                        "WAL sequence must increase by exactly one: expected {expected_seq}, found {}",
                        entry.seq
                    ),
                });
            }
            if entry.prior_sha256_hex != state.last_chain_hash {
                return Err(WalError::ChainBroken {
                    seq: entry.seq,
                    expected: state.last_chain_hash.clone(),
                    found: entry.prior_sha256_hex.clone(),
                });
            }
        }
    }

    let event: serde_json::Value =
        serde_json::from_str(&entry.event_canonical_json).map_err(|err| WalError::Parse {
            line: line_num,
            source_message: format!("event_canonical_json is invalid JSON: {err}"),
        })?;
    let event_object = event.as_object().ok_or_else(|| WalError::Parse {
        line: line_num,
        source_message: "event_canonical_json must be a JSON object".to_string(),
    })?;
    let recanonicalized =
        crate::manifest::canonical_json::canonicalize(&event).map_err(|err| WalError::Parse {
            line: line_num,
            source_message: format!("event canonicalization failed: {err:?}"),
        })?;
    if recanonicalized != entry.event_canonical_json {
        return Err(WalError::Parse {
            line: line_num,
            source_message: "event_canonical_json is not canonical".to_string(),
        });
    }
    let details = event_object
        .get("details")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| WalError::Parse {
            line: line_num,
            source_message: "event details must be an object containing WAL chain fields"
                .to_string(),
        })?;
    let inner_seq = details
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| WalError::Parse {
            line: line_num,
            source_message: "event details.seq must be a u64".to_string(),
        })?;
    if inner_seq != entry.seq {
        return Err(WalError::Parse {
            line: line_num,
            source_message: format!(
                "event details.seq does not match outer seq: inner {inner_seq}, outer {}",
                entry.seq
            ),
        });
    }
    let inner_prior = match details.get("prior_sha256_hex") {
        Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        _ => {
            return Err(WalError::Parse {
                line: line_num,
                source_message: "event details.prior_sha256_hex must be null or a string"
                    .to_string(),
            })
        }
    };
    if inner_prior != entry.prior_sha256_hex {
        return Err(WalError::Parse {
            line: line_num,
            source_message:
                "event details.prior_sha256_hex does not match outer predecessor anchor".to_string(),
        });
    }

    state.next_seq = entry.seq.checked_add(1).ok_or_else(|| WalError::Parse {
        line: line_num,
        source_message: "WAL sequence space exhausted".to_string(),
    })?;
    state.previous_seq = Some(entry.seq);
    state.last_chain_hash = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
    state.bytes = state
        .bytes
        .checked_add(line.len() as u64)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| WalError::Parse {
            line: line_num,
            source_message: "WAL byte count overflow".to_string(),
        })?;
    Ok(entry)
}

fn add_wal_chain_fields(
    event_canonical_json: &str,
    seq: u64,
    prior_sha256_hex: Option<&str>,
) -> Result<String, WalError> {
    let mut value: serde_json::Value =
        serde_json::from_str(event_canonical_json).map_err(|err| WalError::Io {
            path: PathBuf::from("<audit-event>"),
            source_message: err.to_string(),
        })?;
    let entry = value.as_object_mut().ok_or_else(|| WalError::Io {
        path: PathBuf::from("<audit-event>"),
        source_message: "audit event must be a JSON object".to_string(),
    })?;
    if !entry
        .get("details")
        .is_some_and(|details| details.is_object())
    {
        entry.insert(
            "details".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
    }
    // Safety: the if-block immediately above guarantees `entry["details"]`
    // exists and is a JSON object; the get_mut + as_object_mut chain cannot
    // return None unless the program is corrupted in memory.
    let details = entry
        .get_mut("details")
        .and_then(|details| details.as_object_mut())
        .expect("details was initialized as an object");
    details.insert(
        "seq".to_string(),
        serde_json::Value::Number(serde_json::Number::from(seq)),
    );
    details.insert(
        "prior_sha256_hex".to_string(),
        prior_sha256_hex
            .map(|hash| serde_json::Value::String(hash.to_string()))
            .unwrap_or(serde_json::Value::Null),
    );
    crate::manifest::canonical_json::canonicalize(&value).map_err(|err| WalError::Io {
        path: PathBuf::from("<audit-event>"),
        source_message: err.to_string(),
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut s = String::with_capacity(out.len() * 2);
    for b in out.iter() {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[cfg(test)]
mod wal_tests {
    use super::*;
    use tempfile::TempDir;

    fn chained_event(seq: u64, prior: Option<&str>, operation: &str) -> String {
        crate::manifest::canonical_json::canonicalize(&serde_json::json!({
            "details": {
                "prior_sha256_hex": prior,
                "seq": seq,
            },
            "operation": operation,
        }))
        .unwrap()
    }

    fn read_entries(path: &Path) -> Vec<WalEntry> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn write_entries(path: &Path, entries: &[WalEntry]) {
        let mut bytes = entries
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        if !entries.is_empty() {
            bytes.push('\n');
        }
        std::fs::write(path, bytes).unwrap();
    }

    fn replace_inner_chain(entry: &mut WalEntry, seq: u64, prior: Option<&str>) {
        let mut event: serde_json::Value =
            serde_json::from_str(&entry.event_canonical_json).unwrap();
        let details = event["details"].as_object_mut().unwrap();
        details.insert("seq".to_string(), serde_json::json!(seq));
        details.insert("prior_sha256_hex".to_string(), serde_json::json!(prior));
        entry.event_canonical_json = crate::manifest::canonical_json::canonicalize(&event).unwrap();
    }

    #[test]
    fn open_creates_wal_with_mode_0600() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let _wal = WalWriter::open(&path).expect("open");
        let meta = std::fs::metadata(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }
        let _ = meta;
    }

    #[test]
    fn append_critical_persists_with_fsync_and_chains() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        let s1 = wal
            .append_critical("{\"layer\":\"l1\",\"operation\":\"first\"}")
            .expect("append");
        let s2 = wal
            .append_critical("{\"layer\":\"l1\",\"operation\":\"second\"}")
            .expect("append");
        assert_eq!(s1, 0);
        assert_eq!(s2, 1);
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert_eq!(on_disk.lines().count(), 2);
        // Reopen the WAL and verify chain replay computes consistent state.
        drop(wal);
        let resumed = WalWriter::open(&path).expect("reopen");
        assert_eq!(resumed.next_seq(), 2);
        assert!(resumed.last_chain_hash_hex().is_some());
    }

    #[test]
    fn append_includes_wal_chain_fields_in_event_details() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        wal.append_critical("{\"details\":{},\"layer\":\"l1\",\"operation\":\"first\"}")
            .expect("append first");
        wal.append_critical("{\"details\":{},\"layer\":\"l1\",\"operation\":\"second\"}")
            .expect("append second");

        let snapshot = wal.snapshot_after(None, 10).expect("snapshot");
        let first: serde_json::Value =
            serde_json::from_str(&snapshot[0].event_canonical_json).unwrap();
        let second: serde_json::Value =
            serde_json::from_str(&snapshot[1].event_canonical_json).unwrap();
        assert_eq!(first["details"]["seq"], 0);
        assert!(first["details"]["prior_sha256_hex"].is_null());
        assert_eq!(second["details"]["seq"], 1);
        assert_eq!(
            second["details"]["prior_sha256_hex"],
            serde_json::Value::String(snapshot[1].prior_sha256_hex.clone().unwrap())
        );
    }

    #[test]
    fn snapshot_after_returns_only_newer_entries() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        let s0 = wal.append_critical("{\"a\":1}").unwrap();
        let _s1 = wal.append_critical("{\"a\":2}").unwrap();
        let _s2 = wal.append_critical("{\"a\":3}").unwrap();
        let after = wal.snapshot_after(Some(s0), 10).unwrap();
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].seq, 1);
        assert_eq!(after[1].seq, 2);
    }

    #[test]
    fn snapshot_after_respects_max_entries_cap() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        for _ in 0..5 {
            wal.append_critical("{\"x\":1}").unwrap();
        }
        let snap = wal.snapshot_after(None, 3).unwrap();
        assert_eq!(snap.len(), 3);
    }

    #[test]
    fn truncate_through_seq_drops_acked_and_keeps_remainder() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        let _ = wal.append_critical("{\"k\":1}").unwrap();
        let _ = wal.append_critical("{\"k\":2}").unwrap();
        let s2 = wal.append_critical("{\"k\":3}").unwrap();
        let _ = wal.append_critical("{\"k\":4}").unwrap();
        let dropped = wal.truncate_through_seq(s2).expect("truncate");
        assert_eq!(dropped, 3);
        let remaining = wal.snapshot_after(None, 100).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].seq, 3);
    }

    #[test]
    fn truncate_all_retains_hidden_durable_anchor_across_restart() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).unwrap();
        wal.append_critical("{\"operation\":\"zero\"}").unwrap();
        let last = wal.append_critical("{\"operation\":\"one\"}").unwrap();
        assert_eq!(wal.truncate_through_seq(last).unwrap(), 2);
        assert!(wal.snapshot_after(None, 10).unwrap().is_empty());
        drop(wal);

        let on_disk = read_entries(&path);
        assert_eq!(on_disk.len(), 1);
        assert_eq!(on_disk[0].seq, 1);
        assert!(on_disk[0].acked_anchor);

        let mut restarted = WalWriter::open(&path).unwrap();
        assert_eq!(restarted.next_seq(), 2);
        assert_eq!(
            restarted
                .append_critical("{\"operation\":\"after-restart\"}")
                .unwrap(),
            2
        );
        let visible = restarted.snapshot_after(None, 10).unwrap();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].seq, 2);
        assert!(!visible[0].acked_anchor);
    }

    #[test]
    fn truncate_rename_failure_leaves_in_memory_state_unchanged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        wal.append_critical("{\"k\":1}").unwrap();
        wal.append_critical("{\"k\":2}").unwrap();
        let acked = wal.append_critical("{\"k\":3}").unwrap();
        let before_next_seq = wal.next_seq();
        let before_bytes = wal.bytes_written();
        let before_chain = wal.last_chain_hash_hex().map(str::to_string);
        let before_disk = std::fs::read_to_string(&path).unwrap();

        let rename_injection = wal.rename_injection_handle();
        rename_injection.store(true, std::sync::atomic::Ordering::SeqCst);
        let err = wal.truncate_through_seq(acked).unwrap_err();
        assert!(matches!(err, WalError::RenameFailed { .. }));
        assert_eq!(wal.next_seq(), before_next_seq);
        assert_eq!(wal.bytes_written(), before_bytes);
        assert_eq!(wal.last_chain_hash_hex().map(str::to_string), before_chain);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before_disk);

        rename_injection.store(false, std::sync::atomic::Ordering::SeqCst);
        let appended = wal.append_critical("{\"k\":4}").unwrap();
        assert_eq!(appended, before_next_seq);
        drop(wal);
        let mut reopened = WalWriter::open(&path).expect("reopen");
        let entries = reopened.snapshot_after(None, 10).expect("snapshot");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[3].seq, appended);
        assert_eq!(entries[3].prior_sha256_hex, before_chain);
    }

    #[test]
    fn ambiguous_append_faults_latch_poison_and_refuse_every_later_operation() {
        for fault in [
            WalFaultPoint::AppendPartialBody,
            WalFaultPoint::AppendSyncFailure,
        ] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal.jsonl");
            let mut wal = WalWriter::open(&path).expect("open");
            let injection = wal.fault_injection_handle();
            *injection.lock().unwrap() = Some(fault);

            assert!(matches!(
                wal.append_critical("{\"operation\":\"ambiguous\"}"),
                Err(WalError::Poisoned { .. })
            ));
            assert!(wal.is_poisoned());
            assert!(matches!(
                wal.append_critical("{\"operation\":\"later\"}"),
                Err(WalError::Poisoned { .. })
            ));
            assert!(matches!(
                wal.snapshot_after(None, 10),
                Err(WalError::Poisoned { .. })
            ));
            assert!(matches!(
                wal.truncate_through_seq(0),
                Err(WalError::Poisoned { .. })
            ));
            drop(wal);
            match fault {
                WalFaultPoint::AppendPartialBody => assert!(matches!(
                    WalWriter::open(&path),
                    Err(WalError::Parse { .. })
                )),
                WalFaultPoint::AppendSyncFailure => {
                    let mut restarted = WalWriter::open(&path).expect("restart replay");
                    assert_eq!(
                        restarted.snapshot_after(None, 10).unwrap().len(),
                        1,
                        "a full line with an ambiguous fsync result is reconciled by replay"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn post_rename_parent_sync_and_reopen_faults_latch_poison_until_restart() {
        for fault in [
            WalFaultPoint::TruncateParentSyncFailure,
            WalFaultPoint::TruncateReopenFailure,
        ] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal.jsonl");
            let mut wal = WalWriter::open(&path).expect("open");
            wal.append_critical("{\"k\":1}").unwrap();
            let acked = wal.append_critical("{\"k\":2}").unwrap();
            wal.append_critical("{\"k\":3}").unwrap();
            let injection = wal.fault_injection_handle();
            *injection.lock().unwrap() = Some(fault);

            assert!(matches!(
                wal.truncate_through_seq(acked),
                Err(WalError::Poisoned { .. })
            ));
            assert!(wal.is_poisoned());
            assert!(matches!(
                wal.append_critical("{\"k\":4}"),
                Err(WalError::Poisoned { .. })
            ));

            // A fresh process may establish truth by replaying the renamed file.
            drop(wal);
            let mut restarted = WalWriter::open(&path).expect("restart replay");
            let remaining = restarted.snapshot_after(None, 10).expect("snapshot");
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].seq, 2);
        }
    }

    #[test]
    fn cancellable_snapshot_and_truncate_abort_without_mutation() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).unwrap();
        wal.append_critical("{\"k\":1}").unwrap();
        wal.append_critical("{\"k\":2}").unwrap();
        let before = std::fs::read(&path).unwrap();
        let before_next = wal.next_seq();
        let shutdown = AtomicBool::new(true);

        assert!(matches!(
            wal.snapshot_after_cancellable(None, 100, &shutdown),
            Err(WalError::Cancelled)
        ));
        assert!(matches!(
            wal.truncate_through_seq_cancellable(0, &shutdown),
            Err(WalError::Cancelled)
        ));
        assert_eq!(wal.next_seq(), before_next);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn open_recovers_chain_state_from_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        {
            let mut wal = WalWriter::open(&path).expect("open");
            wal.append_critical("{\"first\":1}").unwrap();
            wal.append_critical("{\"second\":2}").unwrap();
        }
        // Open a second instance against the same path.
        let mut wal2 = WalWriter::open(&path).expect("reopen");
        let third_seq = wal2.append_critical("{\"third\":3}").unwrap();
        assert_eq!(third_seq, 2);
        let snap = wal2.snapshot_after(None, 10).unwrap();
        assert_eq!(snap.len(), 3);
        // Chain integrity intact across re-open.
        assert_eq!(snap[0].prior_sha256_hex, None);
        assert!(snap[1].prior_sha256_hex.is_some());
        assert!(snap[2].prior_sha256_hex.is_some());
        assert_ne!(snap[1].prior_sha256_hex, snap[2].prior_sha256_hex);
    }

    #[test]
    fn open_rejects_chain_corruption() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        // Hand-craft a file with a broken chain: entry 1 references a
        // prior_sha256_hex that does not match the SHA-256 of entry 0's
        // serialized form.
        let entry0 = WalEntry {
            seq: 0,
            captured_at_unix_ms: 0u64,
            prior_sha256_hex: None,
            event_canonical_json: chained_event(0, None, "first"),
            critical: true,
            acked_anchor: false,
        };
        let entry1 = WalEntry {
            seq: 1,
            captured_at_unix_ms: 0u64,
            // 64 lowercase hex chars (passes the format check from
            // full-sweep #74) but not the actual SHA-256 of entry0,
            // so the chain comparison still fails.
            prior_sha256_hex: Some(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            ),
            event_canonical_json: chained_event(
                1,
                Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
                "second",
            ),
            critical: true,
            acked_anchor: false,
        };
        let mut content = serde_json::to_string(&entry0).unwrap();
        content.push('\n');
        content.push_str(&serde_json::to_string(&entry1).unwrap());
        content.push('\n');
        std::fs::write(&path, content).unwrap();
        let err = WalWriter::open(&path).unwrap_err();
        assert!(matches!(err, WalError::ChainBroken { .. }));
    }

    #[test]
    fn open_rejects_prior_hash_with_wrong_length() {
        // Full-sweep #74: a `prior_sha256_hex` whose length is not 64
        // hex chars is structurally malformed, regardless of chain
        // matching. WAL replay must reject before any comparison so
        // corrupt input cannot be smuggled past by accidental match.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let entry0 = WalEntry {
            seq: 0,
            captured_at_unix_ms: 0u64,
            prior_sha256_hex: None,
            event_canonical_json: chained_event(0, None, "first"),
            critical: true,
            acked_anchor: false,
        };
        let entry1 = WalEntry {
            seq: 1,
            captured_at_unix_ms: 0u64,
            // 8 hex chars: way too short.
            prior_sha256_hex: Some("deadbeef".to_string()),
            event_canonical_json: chained_event(1, Some("deadbeef"), "second"),
            critical: true,
            acked_anchor: false,
        };
        let mut content = serde_json::to_string(&entry0).unwrap();
        content.push('\n');
        content.push_str(&serde_json::to_string(&entry1).unwrap());
        content.push('\n');
        std::fs::write(&path, content).unwrap();
        let err = WalWriter::open(&path).unwrap_err();
        match err {
            WalError::MalformedPriorHash { seq, found } => {
                assert_eq!(seq, 1);
                assert_eq!(found, "deadbeef");
            }
            other => panic!("expected MalformedPriorHash, got {other:?}"),
        }
    }

    #[test]
    fn open_rejects_prior_hash_with_non_hex_chars() {
        // Full-sweep #74: 64-char string that contains non-hex chars
        // (e.g. uppercase or punctuation) is rejected as malformed.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let entry0 = WalEntry {
            seq: 0,
            captured_at_unix_ms: 0u64,
            prior_sha256_hex: None,
            event_canonical_json: chained_event(0, None, "first"),
            critical: true,
            acked_anchor: false,
        };
        // Exactly 64 chars but with uppercase letters; canonical
        // SHA-256 hex is lowercase only.
        let entry1 = WalEntry {
            seq: 1,
            captured_at_unix_ms: 0u64,
            prior_sha256_hex: Some(
                "DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF".to_string(),
            ),
            event_canonical_json: chained_event(
                1,
                Some("DEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF"),
                "second",
            ),
            critical: true,
            acked_anchor: false,
        };
        let mut content = serde_json::to_string(&entry0).unwrap();
        content.push('\n');
        content.push_str(&serde_json::to_string(&entry1).unwrap());
        content.push('\n');
        std::fs::write(&path, content).unwrap();
        let err = WalWriter::open(&path).unwrap_err();
        assert!(matches!(err, WalError::MalformedPriorHash { seq: 1, .. }));
    }

    #[test]
    fn replay_rejects_duplicate_regressed_and_gapped_sequences() {
        for mutation in ["duplicate", "regression", "gap"] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal.jsonl");
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_critical("{\"operation\":\"zero\"}").unwrap();
            wal.append_critical("{\"operation\":\"one\"}").unwrap();
            wal.append_critical("{\"operation\":\"two\"}").unwrap();
            drop(wal);
            let mut entries = read_entries(&path);
            let (index, seq) = match mutation {
                "duplicate" => (1, 0),
                "regression" => (2, 0),
                "gap" => (1, 2),
                _ => unreachable!(),
            };
            let prior = entries[index].prior_sha256_hex.clone();
            entries[index].seq = seq;
            replace_inner_chain(&mut entries[index], seq, prior.as_deref());
            write_entries(&path, &entries);
            let err = WalWriter::open(&path).unwrap_err();
            assert!(
                matches!(err, WalError::Parse { .. }),
                "{mutation} must refuse: {err:?}"
            );
        }
    }

    #[test]
    fn replay_requires_exact_inner_outer_chain_binding() {
        for mutation in ["seq", "prior"] {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("wal.jsonl");
            let mut wal = WalWriter::open(&path).unwrap();
            wal.append_critical("{\"operation\":\"zero\"}").unwrap();
            wal.append_critical("{\"operation\":\"one\"}").unwrap();
            drop(wal);
            let mut entries = read_entries(&path);
            let mut event: serde_json::Value =
                serde_json::from_str(&entries[1].event_canonical_json).unwrap();
            let details = event["details"].as_object_mut().unwrap();
            if mutation == "seq" {
                details.insert("seq".to_string(), serde_json::json!(0));
            } else {
                details.insert("prior_sha256_hex".to_string(), serde_json::Value::Null);
            }
            entries[1].event_canonical_json =
                crate::manifest::canonical_json::canonicalize(&event).unwrap();
            write_entries(&path, &entries);
            assert!(matches!(
                WalWriter::open(&path),
                Err(WalError::Parse { .. })
            ));
        }
    }

    #[test]
    fn replay_requires_post_truncation_anchor_and_canonical_event() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).unwrap();
        wal.append_critical("{\"operation\":\"zero\"}").unwrap();
        wal.append_critical("{\"operation\":\"one\"}").unwrap();
        wal.truncate_through_seq(0).unwrap();
        drop(wal);
        assert_eq!(WalWriter::open(&path).unwrap().next_seq(), 2);

        let mut entries = read_entries(&path);
        entries[0].prior_sha256_hex = None;
        replace_inner_chain(&mut entries[0], 1, None);
        write_entries(&path, &entries);
        assert!(matches!(
            WalWriter::open(&path),
            Err(WalError::Parse { .. })
        ));

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("noncanonical.wal");
        let mut wal = WalWriter::open(&path).unwrap();
        wal.append_critical("{\"operation\":\"zero\"}").unwrap();
        drop(wal);
        let mut entries = read_entries(&path);
        entries[0].event_canonical_json = format!(" {}", entries[0].event_canonical_json);
        write_entries(&path, &entries);
        assert!(matches!(
            WalWriter::open(&path),
            Err(WalError::Parse { .. })
        ));
    }

    #[test]
    fn ack_revalidates_disk_and_never_drops_distinct_duplicate_sequence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).unwrap();
        wal.append_critical("{\"operation\":\"zero\"}").unwrap();
        wal.append_critical("{\"operation\":\"one\"}").unwrap();
        let mut entries = read_entries(&path);
        let prior = entries[1].prior_sha256_hex.clone();
        entries[1].seq = 0;
        replace_inner_chain(&mut entries[1], 0, prior.as_deref());
        write_entries(&path, &entries);
        let tampered = std::fs::read(&path).unwrap();

        assert!(matches!(
            wal.truncate_through_seq(0),
            Err(WalError::Parse { .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), tampered);
    }

    #[test]
    fn append_metric_does_not_fsync_but_persists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("wal.jsonl");
        let mut wal = WalWriter::open(&path).expect("open");
        let _ = wal.append_metric("{\"metric\":\"counts\"}").unwrap();
        let lines = std::fs::read_to_string(&path).unwrap();
        assert_eq!(lines.lines().count(), 1);
        assert!(lines.contains("\"critical\":false"));
    }
}
