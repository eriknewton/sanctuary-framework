//! Host-global ownership lock for the shared nftables runtime.
//!
//! Exactly one castle-wall daemon on a host may own the `sanctuary-castle`
//! nftables table and its bound NFQUEUE at a time. Two daemons installing or
//! mutating the same host-global kernel resources would race: the second could
//! clobber the first's table, double-bind the queue, or tear down rules the
//! first still relies on. This lock is the structural guard that makes "one
//! owner per host nftables runtime" true rather than merely intended.
//!
//! The lock is HOST-GLOBAL, not per-fortress: the guarded resource (the single
//! `inet sanctuary-castle` table, NFQUEUE number 0) is shared across the whole
//! host, so the lock path is a FIXED host path independent of `fortress_id`. A
//! second daemon booted with a DIFFERENT fortress id must still refuse to touch
//! the nftables runtime — its IPC control surface lives on a per-fortress socket
//! and can come up, but the enforcement runtime must not. Deriving the lock
//! path from the fortress id would defeat this by giving each fortress its own
//! lock, so the path is deliberately fortress-independent.
//!
//! Mechanism: an advisory `flock(LOCK_EX | LOCK_NB)` on a lock file held open
//! for the daemon's lifetime. `flock` is per-open-file-description and released
//! when the fd closes, so a crashed daemon's lock is reclaimed by the kernel
//! automatically — no stale lock state to clean up by hand. The lock inode lives
//! in the persistent root-owned state directory so an operator can take the exact
//! same lock while the systemd RuntimeDirectory is absent after service stop. It
//! contains no ownership proof; persistence only preserves the rendezvous inode.
//! The lock file itself
//! is never unlinked (unlinking races a concurrent opener onto a different
//! inode than the one the surviving lock is held on, which would let two daemons
//! each hold `LOCK_EX` on distinct inodes of the same path); it persists and
//! carries no state beyond its identity.
//!
//! Distro-neutral: `flock(2)` is a mainline POSIX/Linux primitive with no
//! systemd, package-manager, or distro-path dependency. It also works on the
//! macOS dev host, so the "second daemon refuses" contract is exercised by the
//! cross-platform tests below rather than only on Linux hardware.

use std::fs::OpenOptions;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

/// The host-global lock path. FIXED and fortress-independent by design: the
/// guarded nftables table/queue are host-global, so a second daemon — even one
/// with a different `fortress_id` — contends on this same path and refuses.
/// Lives under the root-owned persistent `StateDirectory=` rather than the
/// stop-time-removed `RuntimeDirectory=`. The flock itself still has no meaning
/// after fd close/reboot; the persistent inode lets daemon and last-resort
/// recovery serialize on one path without recreating competing lock files.
pub const DEFAULT_HOST_LOCK_PATH: &str = "/var/lib/sanctuary/castle-wall.nft.lock";

/// Errors from acquiring the host ownership lock.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeLockError {
    /// The lock file could not be opened (missing parent directory, permission
    /// denied). Distinct from `AlreadyHeld` so the operator can tell "another
    /// daemon owns it" apart from "the runtime dir is not provisioned."
    #[error("could not open host ownership lock at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Another process already holds the exclusive lock. This is the
    /// second-daemon-refuses path: the caller must NOT touch nftables.
    #[error("another castle-wall daemon already owns the host nftables runtime (lock {path})")]
    AlreadyHeld { path: PathBuf },
    /// `flock` failed for a reason other than contention.
    #[error("failed to acquire host ownership lock at {path}: {source}")]
    Lock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The opened persistent lock inode could not be restricted to owner-only.
    #[error("could not set host ownership lock permissions at {path}: {source}")]
    Permissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// An acquired host-ownership lock. Holding this value proves this process owns
/// the host nftables runtime. Releasing it (explicitly or on drop) frees the
/// lock for the next daemon. Ordinary release deliberately preserves the exact
/// owned nftables table and authenticated journal while freeing this process-
/// local lock; the next daemon must reacquire the lock and re-prove that journal,
/// marker, boot/source identity, and live handles before adopting the table.
/// Only the separate explicit disarm path removes the table.
pub struct HostRuntimeLock {
    // Keep the File alive: the advisory lock is bound to this open file
    // description and is released the instant the fd closes. Dropping the File
    // (via `released`/`Drop`) is what frees the lock.
    file: std::fs::File,
    path: PathBuf,
    released: bool,
}

impl HostRuntimeLock {
    /// Try to take the exclusive host lock without blocking. Returns
    /// `AlreadyHeld` if another daemon holds it, so the caller can refuse
    /// BEFORE touching any nftables resource.
    pub fn acquire(path: &Path) -> Result<Self, RuntimeLockError> {
        // Open (creating if absent) so the very first daemon on a fresh host can
        // take the lock. The token is not secret, but 0600 plus the root-owned
        // StateDirectory prevents an unprivileged process from holding it to
        // force a persistent fail-before denial of service.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(path)
            .map_err(|source| RuntimeLockError::Open {
                path: path.to_path_buf(),
                source,
            })?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| RuntimeLockError::Permissions {
                path: path.to_path_buf(),
                source,
            })?;
        // Non-blocking exclusive advisory lock. LOCK_NB makes contention an
        // immediate refusal (EWOULDBLOCK) instead of a hang, which is what turns
        // a second daemon into a clean refuse rather than a stall.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            // EWOULDBLOCK (== EAGAIN on Linux/macOS) is the "held by another
            // owner" signal; anything else is a genuine lock failure.
            let contended = err.raw_os_error() == Some(libc::EWOULDBLOCK)
                || err.raw_os_error() == Some(libc::EAGAIN);
            return Err(if contended {
                RuntimeLockError::AlreadyHeld {
                    path: path.to_path_buf(),
                }
            } else {
                RuntimeLockError::Lock {
                    path: path.to_path_buf(),
                    source: err,
                }
            });
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            released: false,
        })
    }

    /// The lock path this guard holds. Inspection helper for logs/tests.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Explicitly release the lock. Idempotent; also runs from `Drop`. Panic-free
    /// so it is safe to call from a component `release()` that runs during an
    /// unwind. `LOCK_UN` is best-effort — closing the fd (on the subsequent File
    /// drop) releases the lock regardless, so a failed `flock(LOCK_UN)` is not an
    /// error worth surfacing here.
    pub fn release(&mut self) {
        if self.released {
            return;
        }
        // Best-effort unlock; the authoritative release is the fd close when
        // `self.file` drops. We do not unlink the lock file (see module docs).
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        self.released = true;
    }
}

impl std::fmt::Debug for HostRuntimeLock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HostRuntimeLock")
            .field("path", &self.path)
            .field("released", &self.released)
            .finish()
    }
}

impl Drop for HostRuntimeLock {
    fn drop(&mut self) {
        // Last line of defense: even a caller that forgets `release()` frees the
        // lock when the guard drops (both the explicit LOCK_UN and the fd close).
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn lock_path(dir: &TempDir) -> PathBuf {
        dir.path().join("castle-wall.nft.lock")
    }

    #[test]
    fn first_acquire_succeeds() {
        let dir = TempDir::new().unwrap();
        let lock = HostRuntimeLock::acquire(&lock_path(&dir)).expect("first acquire");
        assert!(!lock.released);
    }

    #[test]
    fn second_acquire_while_held_refuses_as_already_held() {
        // The second daemon must refuse BEFORE touching nftables. With the first
        // lock still held, a second acquisition on the SAME host path returns
        // AlreadyHeld — the structural "one owner per host runtime" guarantee.
        let dir = TempDir::new().unwrap();
        let path = lock_path(&dir);
        let _first = HostRuntimeLock::acquire(&path).expect("first acquire");
        let err = HostRuntimeLock::acquire(&path).expect_err("second must refuse");
        assert!(
            matches!(err, RuntimeLockError::AlreadyHeld { .. }),
            "second acquisition must be AlreadyHeld, got {err:?}"
        );
    }

    #[test]
    fn lock_is_reclaimable_after_the_owner_releases() {
        // Once the first owner drops its guard, the lock is free again — a fresh
        // daemon (e.g. after a restart) can take it. Proves release actually
        // frees the fd-bound lock rather than leaking it.
        let dir = TempDir::new().unwrap();
        let path = lock_path(&dir);
        {
            let _first = HostRuntimeLock::acquire(&path).expect("first acquire");
        } // guard dropped here -> lock released
        let _second = HostRuntimeLock::acquire(&path).expect("reacquire after release");
    }

    #[test]
    fn explicit_release_is_idempotent_and_frees_the_lock() {
        let dir = TempDir::new().unwrap();
        let path = lock_path(&dir);
        let mut first = HostRuntimeLock::acquire(&path).expect("first acquire");
        first.release();
        first.release(); // idempotent: no panic, no double-unlock hazard
                         // After explicit release the lock is free for the next owner.
        let _second = HostRuntimeLock::acquire(&path).expect("reacquire after explicit release");
    }

    #[test]
    fn open_failure_on_missing_parent_is_reported_distinctly() {
        // A lock path whose parent directory does not exist is an Open error,
        // NOT AlreadyHeld: the operator needs to see "runtime dir not
        // provisioned" separately from "another daemon owns it."
        let dir = TempDir::new().unwrap();
        let path = dir
            .path()
            .join("missing-subdir")
            .join("castle-wall.nft.lock");
        let err = HostRuntimeLock::acquire(&path).expect_err("missing parent must fail to open");
        assert!(
            matches!(err, RuntimeLockError::Open { .. }),
            "missing parent dir must be Open, got {err:?}"
        );
    }

    #[test]
    fn symlink_lock_path_is_refused_without_following_it() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        let target = dir.path().join("attacker-target");
        std::fs::write(&target, b"must remain untouched").unwrap();
        let path = lock_path(&dir);
        symlink(&target, &path).unwrap();
        let err = HostRuntimeLock::acquire(&path).expect_err("O_NOFOLLOW must reject symlink");
        assert!(matches!(err, RuntimeLockError::Open { .. }));
        assert_eq!(std::fs::read(&target).unwrap(), b"must remain untouched");
    }
}
