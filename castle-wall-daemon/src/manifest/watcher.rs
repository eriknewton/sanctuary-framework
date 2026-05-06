//! Manifest watcher: surfaces filesystem-change events for the policy
//! manifest.
//!
//! Two implementations live behind a common `ManifestWatcher` API:
//!
//! - On Linux the watcher subscribes via `inotify` to the parent directory of
//!   the manifest file. Atomic-rename-of-manifest.json (the recommended write
//!   pattern per scope-lock §4) lands as a `MOVED_TO` event with name
//!   `manifest.json`. CREATE and CLOSE_WRITE are also surfaced because some
//!   write paths produce them instead.
//! - On non-Linux platforms, or when inotify subscription itself fails (F-7
//!   disposition: degrade to periodic polling), the watcher falls back to a
//!   `mtime` poll on the manifest file every `poll_interval`. The first
//!   `poll_event` after construction returns `None` so the daemon does not
//!   re-load the manifest on boot just because the file appeared.
//!
//! The watcher does NOT load or verify the manifest; it just signals "the
//! manifest may have changed; consider reloading." The daemon glue calls
//! `ManifestStore::reload()` in response.
//!
//! Tests run on both Linux and non-Linux hosts because the poll path is the
//! shared baseline; the inotify path adds a Linux-only test.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::manifest::store::MANIFEST_FILENAME;

/// Errors emitted by the watcher subsystem.
#[derive(Debug, thiserror::Error)]
pub enum WatcherError {
    #[error("watcher initialization failed: {0}")]
    Init(String),
    #[error("watcher poll failed: {0}")]
    Poll(String),
}

/// One filesystem signal surfaced by the watcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WatcherEvent {
    /// The manifest file may have changed on disk; caller should attempt a
    /// reload through `ManifestStore::reload()`.
    ManifestChanged,
    /// The watcher fell back from inotify to polling. Surfaced so the
    /// daemon can audit the degradation per scope-lock §7 (F-7 disposition).
    DegradedToPoll { reason: String },
}

/// Backing implementation surface for the watcher.
#[derive(Debug)]
pub enum WatcherImpl {
    /// inotify-backed watcher (Linux only).
    #[cfg(target_os = "linux")]
    Inotify(InotifyWatcher),
    /// mtime-poll watcher (non-Linux, or Linux F-7 fallback).
    Poll(PollWatcher),
}

/// Top-level manifest watcher. Construct via [`ManifestWatcher::start`].
#[derive(Debug)]
pub struct ManifestWatcher {
    inner: WatcherImpl,
    policy_dir: PathBuf,
}

impl ManifestWatcher {
    /// Start watching `<policy_dir>/manifest.json`. On Linux, prefers
    /// inotify; falls back to polling at `poll_interval` if inotify fails.
    /// On non-Linux always uses polling.
    ///
    /// `prefer_inotify` is a hint; setting it to false forces polling on
    /// every platform. Tests use this to exercise the poll path uniformly.
    pub fn start(
        policy_dir: PathBuf,
        poll_interval: Duration,
        prefer_inotify: bool,
    ) -> Result<(Self, Option<WatcherEvent>), WatcherError> {
        #[cfg(target_os = "linux")]
        {
            if prefer_inotify {
                match InotifyWatcher::start(&policy_dir) {
                    Ok(inotify) => {
                        return Ok((
                            Self {
                                inner: WatcherImpl::Inotify(inotify),
                                policy_dir,
                            },
                            None,
                        ));
                    }
                    Err(err) => {
                        let reason = format!("inotify init failed; degrading to poll: {}", err);
                        let poll = PollWatcher::start(&policy_dir, poll_interval);
                        return Ok((
                            Self {
                                inner: WatcherImpl::Poll(poll),
                                policy_dir,
                            },
                            Some(WatcherEvent::DegradedToPoll { reason }),
                        ));
                    }
                }
            }
        }
        let _ = prefer_inotify;
        let poll = PollWatcher::start(&policy_dir, poll_interval);
        Ok((
            Self {
                inner: WatcherImpl::Poll(poll),
                policy_dir,
            },
            None,
        ))
    }

    /// Poll the watcher for one event, blocking up to `wait_for` if the
    /// underlying impl supports a wait. Returns `None` when no event has
    /// occurred within the wait window. On error returns `Err`; the daemon
    /// glue audits and continues.
    pub fn poll_event(&mut self, wait_for: Duration) -> Result<Option<WatcherEvent>, WatcherError> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            WatcherImpl::Inotify(w) => w.poll_event(wait_for),
            WatcherImpl::Poll(w) => Ok(w.poll_event(wait_for)),
        }
    }

    /// True when the watcher is operating in degraded (polling) mode. The
    /// daemon surfaces this through its status response so the operator can
    /// see when manifest reloads have higher latency than usual.
    pub fn is_degraded(&self) -> bool {
        match &self.inner {
            #[cfg(target_os = "linux")]
            WatcherImpl::Inotify(_) => false,
            WatcherImpl::Poll(_) => !cfg!(target_os = "linux"),
        }
    }

    pub fn policy_dir(&self) -> &Path {
        &self.policy_dir
    }
}

// ---------------------------------------------------------------------------
// Poll watcher (cross-platform baseline + Linux F-7 fallback).
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PollWatcher {
    manifest_path: PathBuf,
    poll_interval: Duration,
    last_seen: Option<SystemTime>,
    primed: bool,
}

impl PollWatcher {
    pub fn start(policy_dir: &Path, poll_interval: Duration) -> Self {
        let manifest_path = policy_dir.join(MANIFEST_FILENAME);
        let last_seen = std::fs::metadata(&manifest_path)
            .ok()
            .and_then(|m| m.modified().ok());
        Self {
            manifest_path,
            poll_interval,
            last_seen,
            primed: false,
        }
    }

    /// Read the manifest's mtime and compare against the prior observation.
    /// Sleeps up to `wait_for` (capped at `poll_interval`) before checking.
    /// First call after `start` always returns None unless the file appears
    /// or disappears, so daemons do not re-fire a reload on boot.
    pub fn poll_event(&mut self, wait_for: Duration) -> Option<WatcherEvent> {
        let nap = wait_for.min(self.poll_interval);
        if !nap.is_zero() {
            std::thread::sleep(nap);
        }
        let current = std::fs::metadata(&self.manifest_path)
            .ok()
            .and_then(|m| m.modified().ok());
        let event = match (self.last_seen, current) {
            (Some(prev), Some(now)) if now != prev => Some(WatcherEvent::ManifestChanged),
            (None, Some(_)) if self.primed => Some(WatcherEvent::ManifestChanged),
            (Some(_), None) if self.primed => Some(WatcherEvent::ManifestChanged),
            _ => None,
        };
        self.last_seen = current;
        self.primed = true;
        event
    }
}

// ---------------------------------------------------------------------------
// Inotify watcher (Linux).
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct InotifyWatcher {
    inotify: inotify::Inotify,
    buf: Vec<u8>,
}

#[cfg(target_os = "linux")]
impl InotifyWatcher {
    pub fn start(policy_dir: &Path) -> Result<Self, String> {
        use inotify::WatchMask;
        let inotify = inotify::Inotify::init().map_err(|e| e.to_string())?;
        // Watch the parent directory rather than the file itself so we
        // observe atomic-rename (MOVED_TO) and re-create (CREATE) events.
        std::fs::create_dir_all(policy_dir).map_err(|e| e.to_string())?;
        inotify
            .watches()
            .add(
                policy_dir,
                WatchMask::MOVED_TO
                    | WatchMask::CREATE
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::DELETE,
            )
            .map_err(|e| e.to_string())?;
        Ok(Self {
            inotify,
            buf: vec![0u8; 4096],
        })
    }

    pub fn poll_event(&mut self, wait_for: Duration) -> Result<Option<WatcherEvent>, WatcherError> {
        // Use a short blocking read with timeout via fd-level polling. The
        // inotify crate exposes a non-blocking read; we translate WouldBlock
        // into Ok(None) after sleeping for `wait_for`.
        if !wait_for.is_zero() {
            std::thread::sleep(wait_for);
        }
        let events = match self.inotify.read_events(&mut self.buf) {
            Ok(e) => e,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => return Ok(None),
            Err(err) => return Err(WatcherError::Poll(err.to_string())),
        };
        for event in events {
            if let Some(name) = event.name {
                if name == std::ffi::OsStr::new(MANIFEST_FILENAME) {
                    return Ok(Some(WatcherEvent::ManifestChanged));
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn poll_watcher_returns_none_on_first_idle_poll() {
        let dir = TempDir::new().unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10));
        let event = w.poll_event(Duration::from_millis(20));
        assert_eq!(event, None);
    }

    #[test]
    fn poll_watcher_detects_manifest_creation() {
        let dir = TempDir::new().unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10));
        // Prime the watcher with one idle poll.
        let _ = w.poll_event(Duration::from_millis(20));
        // Now create the manifest; next poll should fire.
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        // Sleep just enough so mtime resolution catches the change.
        std::thread::sleep(Duration::from_millis(20));
        let event = w.poll_event(Duration::from_millis(20));
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn poll_watcher_detects_manifest_modification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10));
        // Idle poll primes the watcher.
        let _ = w.poll_event(Duration::from_millis(20));
        // Sleep then rewrite to bump mtime past resolution.
        std::thread::sleep(Duration::from_millis(50));
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{\"changed\":1}").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let event = w.poll_event(Duration::from_millis(20));
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn poll_watcher_detects_manifest_deletion() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10));
        let _ = w.poll_event(Duration::from_millis(20));
        fs::remove_file(dir.path().join(MANIFEST_FILENAME)).unwrap();
        let event = w.poll_event(Duration::from_millis(20));
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn manifest_watcher_with_prefer_inotify_false_uses_poll() {
        let dir = TempDir::new().unwrap();
        let (w, degraded) = ManifestWatcher::start(
            dir.path().to_path_buf(),
            Duration::from_millis(10),
            false,
        )
        .expect("start");
        assert!(degraded.is_none());
        // On non-Linux is_degraded == true (no inotify at all). On Linux
        // with prefer_inotify=false the poll path is intentional, not a
        // degradation; is_degraded reports false to avoid spurious banners.
        if cfg!(target_os = "linux") {
            assert!(!w.is_degraded());
        } else {
            assert!(w.is_degraded());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_watcher_detects_manifest_create() {
        let dir = TempDir::new().unwrap();
        let mut w = InotifyWatcher::start(dir.path()).expect("inotify start");
        std::thread::spawn({
            let path = dir.path().join(MANIFEST_FILENAME);
            move || {
                std::thread::sleep(Duration::from_millis(50));
                fs::write(&path, b"{}").unwrap();
            }
        });
        // Wait long enough for the writer thread to fire.
        std::thread::sleep(Duration::from_millis(150));
        let event = w.poll_event(Duration::from_millis(0)).expect("poll");
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }
}
