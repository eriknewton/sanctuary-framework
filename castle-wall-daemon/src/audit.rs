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
//!   atomically to drop ACK'd entries on Sanctuary main's signal.
//!
//! Privilege boundary (scope-lock §8): the daemon never holds the fortress
//! master key. The hash chain provides ordering integrity *without* a
//! daemon-side signature. Sanctuary main signs each event into the existing
//! L1 audit log on drain, satisfying the "tamper-evident" property at the
//! main-process boundary while keeping the daemon free of signing keys.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// One audit event awaiting durable persistence.
#[derive(Debug, Clone)]
pub struct PendingAuditEvent {
    pub event_canonical_json: String,
    pub captured_at: SystemTime,
}

/// In-memory ring buffer for events that have not yet been ACK'd by main.
/// Once main ACKs an event, it's truncated from the WAL. PR 2b adds the
/// disk-backed half (write-then-IPC, truncate-on-ACK).
#[derive(Debug)]
pub struct AuditRingBuffer {
    buffer: VecDeque<PendingAuditEvent>,
    max_bytes: u64,
    ttl: Duration,
    current_bytes: u64,
    overflow_count: u64,
}

impl AuditRingBuffer {
    pub fn new(max_bytes: u64, ttl: Duration) -> Self {
        Self {
            buffer: VecDeque::new(),
            max_bytes,
            ttl,
            current_bytes: 0,
            overflow_count: 0,
        }
    }

    /// Append a pending event. If the cap is hit, drop oldest first and
    /// increment the overflow counter (surfaces as wal_overflow audit
    /// event on next ACK per scope-lock §8).
    pub fn append(&mut self, event: PendingAuditEvent) {
        let event_bytes = event.event_canonical_json.len() as u64;
        while self.current_bytes + event_bytes > self.max_bytes && !self.buffer.is_empty() {
            if let Some(dropped) = self.buffer.pop_front() {
                self.current_bytes = self
                    .current_bytes
                    .saturating_sub(dropped.event_canonical_json.len() as u64);
                self.overflow_count = self.overflow_count.saturating_add(1);
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

    fn pending(body: &str, t: SystemTime) -> PendingAuditEvent {
        PendingAuditEvent {
            event_canonical_json: body.to_string(),
            captured_at: t,
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
}

// ---------------------------------------------------------------------------
// Disk-backed WAL writer.
// ---------------------------------------------------------------------------

/// One persisted entry in the daemon-side WAL. Serialized to canonical JSON
/// per line (NDJSON). The `prior_sha256_hex` field references the SHA-256 of
/// the prior entry's audit-event canonical-JSON bytes so Sanctuary main can
/// detect drops or reordering on drain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    #[error("WAL chain integrity broken at seq {seq}: expected prior={expected:?}, found={found:?}")]
    ChainBroken {
        seq: u64,
        expected: Option<String>,
        found: Option<String>,
    },
    #[error("WAL truncate rename failed at {path}: {source_message}; in-memory state unchanged")]
    RenameFailed {
        path: PathBuf,
        source_message: String,
    },
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
}

impl WalWriter {
    /// Open or create the WAL file at `path` with mode 0600. Replays any
    /// existing entries to compute the next-seq + last-chain-hash starting
    /// state. On replay error returns `WalError::Parse` or
    /// `WalError::ChainBroken` so the daemon can refuse to come up with a
    /// corrupt audit history.
    pub fn open(path: &Path) -> Result<Self, WalError> {
        // Read any existing content first so we can compute resume state.
        // Then re-open with create + append for writes.
        let (next_seq, last_chain_hash_hex, bytes) = match std::fs::read_to_string(path) {
            Ok(contents) => replay_existing(&contents).map_err(|e| match e {
                WalError::Parse { .. } | WalError::ChainBroken { .. } => e,
                other => other,
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => (0u64, None, 0u64),
            Err(err) => {
                return Err(WalError::Io {
                    path: path.to_path_buf(),
                    source_message: err.to_string(),
                })
            }
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
        // On Linux the open does not enforce perms when the file already
        // exists (umask applies only to create). Set explicitly so an
        // operator-pre-created file with looser perms is corrected.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.metadata().map_err(|err| WalError::Io {
                path: path.to_path_buf(),
                source_message: err.to_string(),
            })?.permissions();
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
            #[cfg(test)]
            inject_io_error: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            inject_rename_error: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
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

    /// Append a critical event with `fsync` per scope-lock §8 OQ #2.
    /// Returns the assigned seq.
    pub fn append_critical(&mut self, event_canonical_json: &str) -> Result<u64, WalError> {
        self.append(event_canonical_json, true, true)
    }

    /// Append a metric event without fsync (best-effort durability).
    pub fn append_metric(&mut self, event_canonical_json: &str) -> Result<u64, WalError> {
        self.append(event_canonical_json, false, false)
    }

    fn append(
        &mut self,
        event_canonical_json: &str,
        critical: bool,
        fsync: bool,
    ) -> Result<u64, WalError> {
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
        };
        let serialized = serde_json::to_string(&entry).map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?;
        self.file
            .write_all(serialized.as_bytes())
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        self.file.write_all(b"\n").map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?;
        if fsync {
            self.file.sync_all().map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        }
        self.bytes_written += serialized.len() as u64 + 1;
        self.last_chain_hash_hex = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
        self.next_seq += 1;
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
        for (index, line) in reader.lines().enumerate() {
            let line_num = (index as u64) + 1;
            let line = line.map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
            if line.is_empty() {
                continue;
            }
            let entry: WalEntry =
                serde_json::from_str(&line).map_err(|err| WalError::Parse {
                    line: line_num,
                    source_message: err.to_string(),
                })?;
            if let Some(threshold) = after_seq {
                if entry.seq <= threshold {
                    continue;
                }
            }
            out.push(entry);
            if out.len() >= max_entries {
                break;
            }
        }
        // Restore append position for subsequent writes.
        self.file
            .seek(SeekFrom::End(0))
            .map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
        Ok(out)
    }

    /// Drop all WAL entries with seq <= `last_acked_seq`. Atomic: writes a
    /// new WAL to `<path>.tmp`, fsyncs, atomically renames over the live
    /// file, then re-opens for append. Returns the count truncated.
    pub fn truncate_through_seq(&mut self, last_acked_seq: u64) -> Result<u64, WalError> {
        let tmp_path = self.path.with_extension("tmp");
        let mut keepers: Vec<WalEntry> = Vec::new();
        // Read everything; carry forward the entries strictly above the ack.
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
        let mut total_seen: u64 = 0;
        for (index, line) in reader.lines().enumerate() {
            let line_num = (index as u64) + 1;
            let line = line.map_err(|err| WalError::Io {
                path: self.path.clone(),
                source_message: err.to_string(),
            })?;
            if line.is_empty() {
                continue;
            }
            let entry: WalEntry =
                serde_json::from_str(&line).map_err(|err| WalError::Parse {
                    line: line_num,
                    source_message: err.to_string(),
                })?;
            total_seen += 1;
            if entry.seq > last_acked_seq {
                keepers.push(entry);
            }
        }
        let dropped = total_seen - keepers.len() as u64;

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
        for entry in &keepers {
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
        }
        tmp.sync_all().map_err(|err| WalError::Io {
            path: tmp_path.clone(),
            source_message: err.to_string(),
        })?;
        drop(tmp);
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

        // Re-open the now-replaced file for append.
        let mut opts = OpenOptions::new();
        opts.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        self.file = opts.open(&self.path).map_err(|err| WalError::Io {
            path: self.path.clone(),
            source_message: err.to_string(),
        })?;
        self.bytes_written = new_bytes;
        self.last_chain_hash_hex = new_chain_hash;
        Ok(dropped)
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
    let mut next_seq = 0u64;
    let mut last_chain_hash: Option<String> = None;
    let mut bytes: u64 = 0;
    for (index, line) in contents.lines().enumerate() {
        let line_num = (index as u64) + 1;
        if line.is_empty() {
            continue;
        }
        let entry: WalEntry = serde_json::from_str(line).map_err(|err| WalError::Parse {
            line: line_num,
            source_message: err.to_string(),
        })?;
        // Verify chain integrity. Two valid shapes for the first remaining
        // WAL line: (a) genesis (entry.seq == 0, prior_sha256_hex == None)
        // or (b) post-truncate first entry (entry.seq > 0, prior_sha256_hex
        // points at an already-ACKed entry no longer on disk; cannot verify
        // locally). A genesis entry with a non-None prior_sha256_hex is
        // tampering and must be rejected. Subsequent entries follow the
        // standard chain check.
        let is_first_iteration = next_seq == 0;
        if is_first_iteration {
            if entry.seq == 0 && entry.prior_sha256_hex.is_some() {
                return Err(WalError::ChainBroken {
                    seq: entry.seq,
                    expected: None,
                    found: entry.prior_sha256_hex.clone(),
                });
            }
        } else if entry.prior_sha256_hex != last_chain_hash {
            return Err(WalError::ChainBroken {
                seq: entry.seq,
                expected: last_chain_hash.clone(),
                found: entry.prior_sha256_hex.clone(),
            });
        }
        next_seq = entry.seq + 1;
        last_chain_hash = Some(sha256_hex(entry.event_canonical_json.as_bytes()));
        bytes += line.len() as u64 + 1;
    }
    Ok((next_seq, last_chain_hash, bytes))
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
    if !entry.get("details").is_some_and(|details| details.is_object()) {
        entry.insert(
            "details".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
    }
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
            event_canonical_json: "{\"first\":1}".to_string(),
            critical: true,
        };
        let entry1 = WalEntry {
            seq: 1,
            captured_at_unix_ms: 0u64,
            prior_sha256_hex: Some("deadbeef".to_string()),
            event_canonical_json: "{\"second\":2}".to_string(),
            critical: true,
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
