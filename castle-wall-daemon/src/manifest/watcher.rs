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
//! - On non-Linux platforms, or when the initial inotify subscription fails (F-7
//!   disposition: degrade to periodic polling), the watcher falls back to a
//!   bounded identity poll (device/inode/length/mtime plus streaming SHA-256)
//!   on the manifest file every `poll_interval`. Production uses a
//!   2-second cadence and must durably audit the fallback before readiness. A
//!   later watcher error is fatal and is never converted into a new fallback.
//!   An absent-to-present transition is detected on the first poll; an unchanged
//!   file present during construction does not spuriously reload.
//!
//! The watcher does NOT load or verify the manifest; it just signals "the
//! manifest may have changed; consider reloading." The daemon glue calls
//! `ManifestStore::reload()` in response.
//!
//! Tests run on both Linux and non-Linux hosts because the poll path is the
//! shared baseline; the inotify path adds a Linux-only test.

use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
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
    /// The initial inotify subscription fell back to polling. Surfaced so the
    /// daemon can durably audit the degradation before declaring readiness per
    /// scope-lock §7 (F-7 disposition).
    DegradedToPoll { reason: String },
}

/// Backing implementation surface for the watcher.
#[derive(Debug)]
pub enum WatcherImpl {
    /// inotify-backed watcher (Linux only).
    #[cfg(target_os = "linux")]
    Inotify(InotifyWatcher),
    /// bounded identity/content-poll watcher (non-Linux, or Linux F-7 fallback).
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
                        // The poll fallback validates the policy dir SYNCHRONOUSLY
                        // here (blocker 5): an initial hard filesystem error fails
                        // startup rather than surfacing only after the component is
                        // advertised ready.
                        let poll = PollWatcher::start(&policy_dir, poll_interval)?;
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
        // Synchronous first validation before the watcher is advertised ready.
        let poll = PollWatcher::start(&policy_dir, poll_interval)?;
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
    /// glue terminates watcher health and restarts fail-closed.
    pub fn poll_event(&mut self, wait_for: Duration) -> Result<Option<WatcherEvent>, WatcherError> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            WatcherImpl::Inotify(w) => w.poll_event(wait_for),
            // The poll adapter now surfaces hard filesystem failures as Err
            // (blocker 5); propagate them so supervision can fail closed.
            WatcherImpl::Poll(w) => w.poll_event(wait_for),
        }
    }

    /// True when the watcher is operating in polling mode. Polling has weaker
    /// latency/capability than inotify and is therefore always reported as
    /// degraded, including deliberately forced polling in tests.
    pub fn is_degraded(&self) -> bool {
        match &self.inner {
            #[cfg(target_os = "linux")]
            WatcherImpl::Inotify(_) => false,
            WatcherImpl::Poll(_) => true,
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
    last_seen: Option<ManifestIdentity>,
}

const MAX_POLLED_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestIdentity {
    modified: SystemTime,
    len: u64,
    dev: u64,
    ino: u64,
    sha256: [u8; 32],
}

impl PollWatcher {
    /// Start the poll watcher, performing a SYNCHRONOUS first metadata/read
    /// validation of the manifest path before returning (blocker 5). A legitimately
    /// ABSENT manifest (`NotFound`) is fine — the daemon boots deny-by-default and
    /// the watcher primes on the first appearance — but a HARD filesystem error
    /// (the policy "dir" is a file, permission denied, a broken mount) is an
    /// initial hard error that FAILS STARTUP here, so the component is never
    /// advertised ready over a blind watcher. Later hard errors are surfaced by
    /// `poll_event` and terminate health while preserving enforcement.
    pub fn start(policy_dir: &Path, poll_interval: Duration) -> Result<Self, WatcherError> {
        let manifest_path = policy_dir.join(MANIFEST_FILENAME);
        // Synchronous validation: distinguishes hard failure (Err) from a
        // legitimately-absent manifest (Ok(None)).
        let last_seen = read_manifest_identity(&manifest_path)?;
        Ok(Self {
            manifest_path,
            poll_interval,
            last_seen,
        })
    }

    /// Read a bounded manifest identity/content digest and compare it against
    /// the prior observation.
    /// Sleeps up to `wait_for` (capped at `poll_interval`) before checking.
    /// A file that appears after `start` fires immediately, including on the
    /// first call; a file already present and unchanged does not.
    ///
    /// A HARD filesystem failure — `PermissionDenied`, `NotADirectory`, an I/O
    /// error, a broken mount, any path breakage — returns `Err` so supervision
    /// withdraws readiness and the daemon exits fail-closed. (blocker 5) Only a
    /// `NotFound` metadata result is the modeled ABSENCE/deletion transition; it
    /// is `Ok(None)` (or a `ManifestChanged` deletion event), never an error. The
    /// prior code swallowed EVERY metadata error into "no file", so a manifest
    /// dir that became unreadable looked identical to a deleted manifest and the
    /// watcher kept reporting healthy while blind — the exact degraded-polling
    /// failure this surfaces.
    pub fn poll_event(&mut self, wait_for: Duration) -> Result<Option<WatcherEvent>, WatcherError> {
        let nap = wait_for.min(self.poll_interval);
        if !nap.is_zero() {
            std::thread::sleep(nap);
        }
        let current = read_manifest_identity(&self.manifest_path)?;
        let event = (self.last_seen != current).then_some(WatcherEvent::ManifestChanged);
        self.last_seen = current;
        Ok(event)
    }
}

/// Read the manifest's mtime, distinguishing the modeled FILE-ABSENCE case from
/// a hard read failure. `NotFound` is `Ok(None)` only while the parent policy
/// directory still exists and is a directory; losing or replacing that watched
/// directory is a hard watcher failure.
/// Every OTHER metadata error — permission denied, not-a-directory, I/O, mount
/// breakage — is a hard failure returned as `Err`, so a blind watcher surfaces
/// rather than masquerading as "manifest deleted." A metadata read that succeeds
/// but whose mtime is unavailable is likewise a hard failure (the platform
/// cannot give us the signal the poll watcher depends on).
fn read_manifest_identity(path: &Path) -> Result<Option<ManifestIdentity>, WatcherError> {
    let policy_dir = path.parent().ok_or_else(|| {
        WatcherError::Poll(format!(
            "manifest path has no policy directory: {}",
            path.display()
        ))
    })?;
    match std::fs::metadata(policy_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(WatcherError::Poll(format!(
                "policy path is no longer a directory: {}",
                policy_dir.display()
            )))
        }
        Err(err) => {
            return Err(WatcherError::Poll(format!(
                "policy directory metadata read failed at {}: {err}",
                policy_dir.display()
            )))
        }
    }
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        // The ONLY modeled non-error: the manifest file is absent.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // PermissionDenied, NotADirectory, I/O, broken mount, path breakage.
        Err(err) => {
            return Err(WatcherError::Poll(format!(
            "manifest metadata read failed at {} (hard filesystem failure, not a deletion): {err}",
            path.display()
        )))
        }
    };
    let before = file.metadata().map_err(|err| {
        WatcherError::Poll(format!(
            "manifest metadata read failed at {}: {err}",
            path.display()
        ))
    })?;
    if !before.is_file() || before.len() > MAX_POLLED_MANIFEST_BYTES {
        return Err(WatcherError::Poll(format!(
            "manifest is not a bounded regular file at {} (size={}, cap={MAX_POLLED_MANIFEST_BYTES})",
            path.display(), before.len()
        )));
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let count = file.read(&mut chunk).map_err(|err| {
            WatcherError::Poll(format!("manifest read failed at {}: {err}", path.display()))
        })?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > MAX_POLLED_MANIFEST_BYTES {
            return Err(WatcherError::Poll(
                "manifest grew beyond polling cap during read".to_string(),
            ));
        }
        hasher.update(&chunk[..count]);
    }
    let after = file.metadata().map_err(|err| {
        WatcherError::Poll(format!(
            "manifest post-read metadata failed at {}: {err}",
            path.display()
        ))
    })?;
    if total != before.len()
        || before.len() != after.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(WatcherError::Poll(
            "manifest mutated during identity read".to_string(),
        ));
    }
    Ok(Some(ManifestIdentity {
        modified: after
            .modified()
            .map_err(|err| WatcherError::Poll(err.to_string()))?,
        len: after.len(),
        dev: after.dev(),
        ino: after.ino(),
        sha256: hasher.finalize().into(),
    }))
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
        let metadata = std::fs::symlink_metadata(policy_dir).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir() {
            return Err("policy watch root is not a real directory".to_string());
        }
        inotify
            .watches()
            .add(
                policy_dir,
                WatchMask::MOVED_TO
                    | WatchMask::CREATE
                    | WatchMask::CLOSE_WRITE
                    | WatchMask::DELETE
                    | WatchMask::MOVE_SELF
                    | WatchMask::DELETE_SELF,
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
        // Consume the WHOLE batch before returning a normal change. Watch-loss
        // and overflow events are commonly unnamed, and a fatal event can follow
        // a manifest event in the same read. Returning early on the manifest name
        // would leave a blind watcher reporting healthy.
        classify_inotify_event_batch(events.map(|event| (event.mask, event.name)))
    }
}

#[cfg(target_os = "linux")]
fn classify_inotify_event_batch<'a>(
    events: impl IntoIterator<Item = (inotify::EventMask, Option<&'a std::ffi::OsStr>)>,
) -> Result<Option<WatcherEvent>, WatcherError> {
    use inotify::EventMask;

    let mut manifest_changed = false;
    for (mask, name) in events {
        // IGNORED, Q_OVERFLOW, and UNMOUNT are kernel-generated status events;
        // they are not selectable WatchMask bits. MOVE_SELF and DELETE_SELF are
        // subscribed above. Every one means the watcher can no longer prove it
        // has a lossless view of policy changes, so terminate component health.
        if mask.intersects(
            EventMask::IGNORED
                | EventMask::Q_OVERFLOW
                | EventMask::UNMOUNT
                | EventMask::MOVE_SELF
                | EventMask::DELETE_SELF,
        ) {
            return Err(WatcherError::Poll(format!(
                "inotify watch became unreliable (terminal event mask {mask:?})"
            )));
        }
        if name == Some(std::ffi::OsStr::new(MANIFEST_FILENAME)) {
            manifest_changed = true;
        }
    }
    Ok(manifest_changed.then_some(WatcherEvent::ManifestChanged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn poll_watcher_returns_none_on_first_idle_poll() {
        let dir = TempDir::new().unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10)).expect("valid dir");
        let event = w
            .poll_event(Duration::from_millis(20))
            .expect("no hard error");
        assert_eq!(event, None);
    }

    #[test]
    fn poll_watcher_detects_manifest_creation() {
        let dir = TempDir::new().unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10)).expect("valid dir");
        // Prime the watcher with one idle poll.
        let _ = w.poll_event(Duration::from_millis(20));
        // Now create the manifest; next poll should fire.
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        // Sleep just enough so mtime resolution catches the change.
        std::thread::sleep(Duration::from_millis(20));
        let event = w
            .poll_event(Duration::from_millis(20))
            .expect("no hard error");
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn poll_watcher_detects_absent_to_present_on_first_poll() {
        let dir = TempDir::new().unwrap();
        let mut watcher =
            PollWatcher::start(dir.path(), Duration::ZERO).expect("valid absent start");
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        assert_eq!(
            watcher.poll_event(Duration::ZERO).unwrap(),
            Some(WatcherEvent::ManifestChanged)
        );
    }

    #[test]
    fn poll_watcher_detects_same_length_immediate_replacement() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        fs::write(&path, b"aaaa").unwrap();
        let mut watcher = PollWatcher::start(dir.path(), Duration::ZERO).unwrap();
        // No delay and equal length: digest/inode identity, not timestamp
        // resolution, must still detect the replacement.
        let replacement = dir.path().join("replacement.json");
        fs::write(&replacement, b"bbbb").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(
            watcher.poll_event(Duration::ZERO).unwrap(),
            Some(WatcherEvent::ManifestChanged)
        );
    }

    #[test]
    fn poll_watcher_rejects_oversized_manifest_identity_read() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join(MANIFEST_FILENAME);
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_POLLED_MANIFEST_BYTES + 1).unwrap();
        let error = PollWatcher::start(dir.path(), Duration::ZERO).unwrap_err();
        assert!(error.to_string().contains("bounded regular file"));
    }

    #[test]
    fn poll_watcher_detects_manifest_modification() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10)).expect("valid dir");
        // Idle poll primes the watcher.
        let _ = w.poll_event(Duration::from_millis(20));
        // Sleep then rewrite to bump mtime past resolution.
        std::thread::sleep(Duration::from_millis(50));
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{\"changed\":1}").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let event = w
            .poll_event(Duration::from_millis(20))
            .expect("no hard error");
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn poll_watcher_detects_manifest_deletion_as_the_modeled_absence_transition() {
        // NotFound stays the modeled absence/deletion transition (Ok, not Err):
        // a deleted manifest fires ManifestChanged, never a hard error.
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        let mut w = PollWatcher::start(dir.path(), Duration::from_millis(10)).expect("valid dir");
        let _ = w.poll_event(Duration::from_millis(20));
        fs::remove_file(dir.path().join(MANIFEST_FILENAME)).unwrap();
        let event = w
            .poll_event(Duration::from_millis(20))
            .expect("deletion is not a hard error");
        assert_eq!(event, Some(WatcherEvent::ManifestChanged));
    }

    #[test]
    fn poll_watcher_treats_policy_directory_loss_as_terminal() {
        let root = TempDir::new().unwrap();
        let policy_dir = root.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();
        let mut w = PollWatcher::start(&policy_dir, Duration::ZERO).expect("valid dir");
        let _ = w.poll_event(Duration::ZERO).expect("initial poll");
        fs::remove_dir(&policy_dir).unwrap();
        let err = w
            .poll_event(Duration::ZERO)
            .expect_err("losing the watched policy directory must terminate health");
        assert!(err
            .to_string()
            .contains("policy directory metadata read failed"));
    }

    #[test]
    fn poll_watcher_start_fails_synchronously_on_a_hard_metadata_failure() {
        // blocker 5: the SYNCHRONOUS first validation at `start` must FAIL when the
        // policy path is a hard filesystem failure (here a regular FILE, so
        // metadata on `<file>/manifest.json` is a NotADirectory error distinct from
        // NotFound). This makes an initial hard error fail STARTUP — the component
        // is never advertised ready over a blind watcher — instead of surfacing
        // only after readiness on the first serve-loop poll.
        let dir = TempDir::new().unwrap();
        let policy_is_a_file = dir.path().join("policy_is_a_file");
        fs::write(&policy_is_a_file, b"not a directory").unwrap();
        let result = PollWatcher::start(&policy_is_a_file, Duration::from_millis(0));
        assert!(
            result.is_err(),
            "an initial hard filesystem failure must fail startup synchronously: {result:?}"
        );
    }

    #[test]
    fn manifest_watcher_with_prefer_inotify_false_uses_poll() {
        let dir = TempDir::new().unwrap();
        let (w, degraded) =
            ManifestWatcher::start(dir.path().to_path_buf(), Duration::from_millis(10), false)
                .expect("start");
        assert!(degraded.is_none());
        // Polling is always honestly reported as degraded, even when a test
        // deliberately forced the fallback rather than inducing init failure.
        assert!(w.is_degraded());
    }

    #[test]
    fn production_poll_adapter_completes_an_explicit_first_read() {
        let dir = TempDir::new().unwrap();
        let (mut watcher, degraded) =
            ManifestWatcher::start(dir.path().to_path_buf(), Duration::ZERO, false)
                .expect("poll start");
        assert!(degraded.is_none());
        assert!(matches!(watcher.inner, WatcherImpl::Poll(_)));
        assert_eq!(
            watcher.poll_event(Duration::ZERO).expect("first poll read"),
            None
        );
    }

    #[test]
    fn production_poll_first_read_error_fails_worker_startup() {
        use crate::thread_component::ThreadBackedComponent;

        let root = TempDir::new().unwrap();
        let policy_dir = root.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();
        let (watcher, _) =
            ManifestWatcher::start(policy_dir.clone(), Duration::ZERO, false).expect("poll start");

        // Turn the watched directory into a regular file AFTER bind but BEFORE
        // the worker's explicit first read. This produces a real NotADirectory
        // error from the production poll adapter.
        fs::remove_dir(&policy_dir).unwrap();
        fs::write(&policy_dir, b"not a directory").unwrap();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let served_c = std::sync::Arc::clone(&served);
        let result = ThreadBackedComponent::spawn_with_worker_init(
            crate::enforcement::ComponentKind::ManifestWatcher,
            move || Ok(watcher),
            |watcher| {
                watcher
                    .poll_event(Duration::ZERO)
                    .map(|_| ())
                    .map_err(|err| crate::enforcement::EnforcementError::AcquireFailed {
                        kind: crate::enforcement::ComponentKind::ManifestWatcher.as_str(),
                        detail: err.to_string(),
                    })
            },
            move |_watcher, _stop| {
                served_c.store(true, std::sync::atomic::Ordering::SeqCst);
            },
        );
        assert!(result.is_err(), "first poll read error must fail startup");
        assert!(
            !served.load(std::sync::atomic::Ordering::SeqCst),
            "no ready serve loop may run after a first-read failure"
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn production_inotify_adapter_completes_an_explicit_first_read() {
        let dir = TempDir::new().unwrap();
        let (mut watcher, degraded) =
            ManifestWatcher::start(dir.path().to_path_buf(), Duration::ZERO, true)
                .expect("production inotify start");
        assert!(degraded.is_none());
        assert!(matches!(watcher.inner, WatcherImpl::Inotify(_)));
        assert_eq!(
            watcher
                .poll_event(Duration::ZERO)
                .expect("first production inotify read"),
            None
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_inotify_first_read_error_fails_worker_startup() {
        use crate::thread_component::ThreadBackedComponent;

        let dir = TempDir::new().unwrap();
        let mut inotify = InotifyWatcher::start(dir.path()).expect("inotify start");
        // Queue a real event, then make the production read buffer too small for
        // that event. Linux read(2) returns EINVAL in this state, giving us a
        // deterministic first-read failure without faking the adapter or closing
        // its fd behind the owning type.
        fs::write(dir.path().join(MANIFEST_FILENAME), b"{}").unwrap();
        inotify.buf = vec![0u8; 1];
        let watcher = ManifestWatcher {
            inner: WatcherImpl::Inotify(inotify),
            policy_dir: dir.path().to_path_buf(),
        };
        let served = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let served_c = std::sync::Arc::clone(&served);
        let result = ThreadBackedComponent::spawn_with_worker_init(
            crate::enforcement::ComponentKind::ManifestWatcher,
            move || Ok(watcher),
            |watcher| {
                watcher
                    .poll_event(Duration::ZERO)
                    .map(|_| ())
                    .map_err(|err| crate::enforcement::EnforcementError::AcquireFailed {
                        kind: crate::enforcement::ComponentKind::ManifestWatcher.as_str(),
                        detail: err.to_string(),
                    })
            },
            move |_watcher, _stop| {
                served_c.store(true, std::sync::atomic::Ordering::SeqCst);
            },
        );
        assert!(
            result.is_err(),
            "first inotify read error must fail startup"
        );
        assert!(
            !served.load(std::sync::atomic::Ordering::SeqCst),
            "READY=1 cannot be reached through a component whose first inotify read failed"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_terminal_masks_fail_even_when_unnamed() {
        use inotify::EventMask;

        for mask in [
            EventMask::IGNORED,
            EventMask::Q_OVERFLOW,
            EventMask::UNMOUNT,
            EventMask::MOVE_SELF,
            EventMask::DELETE_SELF,
        ] {
            let result = classify_inotify_event_batch([(mask, None)]);
            assert!(
                matches!(result, Err(WatcherError::Poll(_))),
                "terminal unnamed event {mask:?} must withdraw watcher health: {result:?}"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inotify_scans_past_manifest_change_and_terminal_event_wins() {
        use inotify::EventMask;

        let manifest = std::ffi::OsStr::new(MANIFEST_FILENAME);
        let result = classify_inotify_event_batch([
            (EventMask::CLOSE_WRITE, Some(manifest)),
            (EventMask::Q_OVERFLOW, None),
        ]);
        assert!(
            matches!(result, Err(WatcherError::Poll(_))),
            "a preceding manifest event must not hide a later terminal event: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn deleting_watched_policy_directory_is_a_real_terminal_error() {
        let root = TempDir::new().unwrap();
        let policy_dir = root.path().join("policy");
        fs::create_dir(&policy_dir).unwrap();
        let mut watcher = InotifyWatcher::start(&policy_dir).expect("inotify start");
        fs::remove_dir(&policy_dir).unwrap();

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match watcher.poll_event(Duration::from_millis(10)) {
                Err(WatcherError::Poll(_)) => break,
                Ok(_) if std::time::Instant::now() < deadline => continue,
                other => panic!(
                    "deleting the watched directory must produce a terminal watcher error: {other:?}"
                ),
            }
        }
    }
}
