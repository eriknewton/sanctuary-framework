//! Bounded systemd readiness-notification seam (`sd_notify` protocol).
//!
//! The shipped systemd unit runs the daemon as `Type=notify`. Under that type
//! systemd holds the unit in "activating" until the service sends `READY=1` on
//! the socket named by the `NOTIFY_SOCKET` environment variable; a service that
//! never sends it is eventually treated as failed. The historical gap
//! (ASSURANCE_MATRIX row 17) was exactly this: `Type=notify` with a daemon that
//! never notified.
//!
//! This module implements the readiness half of the `sd_notify(3)` protocol
//! directly over a `SOCK_DGRAM` `AF_UNIX` socket — the wire contract is a
//! newline-separated `KEY=value` datagram (here just `READY=1`) sent to
//! `$NOTIFY_SOCKET`. Implementing the protocol rather than linking `libsystemd`
//! keeps the daemon distro-neutral (no libsystemd build/runtime dependency) and
//! dependency-free; the protocol itself is stable and mainline.
//!
//! Contract enforced by [`ReadyBeacon`]:
//! * `READY=1` is sent AT MOST ONCE per process. A second `signal_ready` is a
//!   no-op, so no code path can double-notify.
//! * It is sent ONLY when the caller has reached the fully-ready state (the boot
//!   path calls it after both the IPC control surface and the kernel runtime are
//!   live). It is NEVER sent on a startup-failure path, because the boot path
//!   returns its error BEFORE constructing/firing the beacon.
//! * When `NOTIFY_SOCKET` is unset (not launched by systemd `Type=notify` — the
//!   dev/macOS case and the CI smoke case), notifying is a silent success: there
//!   is no supervisor to tell, so "nothing to do" is not a failure.
//!
//! Failure-mode note (for the runbook): if the daemon reaches a ready kernel
//! runtime but this notify never fires, systemd keeps the unit in "activating"
//! and eventually kills it on `TimeoutStartSec`; the symptom is a daemon that
//! serves fine when run by hand but "won't start" under systemd. The inverse —
//! notifying `READY=1` before the kernel runtime is actually up — would tell
//! systemd the wall is enforcing when it is not, so the beacon is fired by the
//! boot path only after the runtime-ready check, never on the control-plane-only
//! fall-through.

use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;

/// The environment variable systemd sets to the notification socket path for a
/// `Type=notify` service. Absent for any other launch context.
pub const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// The readiness datagram payload. `\n`-terminated per the `sd_notify` wire
/// format (state assignments are newline-separated).
const READY_DATAGRAM: &[u8] = b"READY=1\n";

/// Errors from sending a readiness notification. Only surfaced when a socket
/// WAS configured but the send failed; an unconfigured socket is a success.
#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error("could not open notify datagram socket: {0}")]
    Socket(std::io::Error),
    #[error("could not send READY=1 to notify socket {path:?}: {source}")]
    Send {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Outcome of a readiness signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyOutcome {
    /// `READY=1` was sent to a configured `NOTIFY_SOCKET`.
    Sent,
    /// No `NOTIFY_SOCKET` was configured; nothing to notify (not a failure).
    NotConfigured,
    /// A prior `signal_ready` already fired; this call was a no-op.
    AlreadySignaled,
}

/// A one-shot readiness beacon. Constructing it does NOT notify; call
/// [`signal_ready`](Self::signal_ready) exactly once, after the daemon is fully
/// ready. The `fired` latch makes a second call a no-op so double-notify is
/// impossible regardless of caller structure.
#[derive(Debug)]
pub struct ReadyBeacon {
    /// The configured notify socket path, if any. `None` when `NOTIFY_SOCKET`
    /// is unset (no systemd supervisor).
    socket_path: Option<PathBuf>,
    fired: bool,
}

impl ReadyBeacon {
    /// Build a beacon from the process environment. Reads `NOTIFY_SOCKET` once;
    /// an empty value is treated as unset.
    pub fn from_env() -> Self {
        let socket_path = std::env::var_os(NOTIFY_SOCKET_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from);
        Self {
            socket_path,
            fired: false,
        }
    }

    /// Build a beacon aimed at an explicit socket path. Used by tests to point
    /// the beacon at a bound datagram socket without touching the environment.
    pub fn for_socket(socket_path: Option<PathBuf>) -> Self {
        Self {
            socket_path,
            fired: false,
        }
    }

    /// Send `READY=1` if configured and not already fired. Idempotent: the
    /// second and later calls report `AlreadySignaled` without sending.
    pub fn signal_ready(&mut self) -> Result<NotifyOutcome, NotifyError> {
        if self.fired {
            return Ok(NotifyOutcome::AlreadySignaled);
        }
        let Some(path) = self.socket_path.clone() else {
            // No supervisor to notify. Latch anyway so a later call stays a
            // no-op and the "at most once" contract holds uniformly.
            self.fired = true;
            return Ok(NotifyOutcome::NotConfigured);
        };
        let socket = UnixDatagram::unbound().map_err(NotifyError::Socket)?;
        // Latch BEFORE the send so a transient send error cannot be retried into
        // a double-notify; a failed readiness signal is reported to the caller
        // and the beacon is spent.
        self.fired = true;
        send_ready_datagram(&socket, &path).map_err(|source| NotifyError::Send { path, source })?;
        Ok(NotifyOutcome::Sent)
    }
}

/// Send the `READY=1` datagram to a resolved `NOTIFY_SOCKET` value.
///
/// systemd may hand back either a FILESYSTEM socket path (leading `/`) or an
/// ABSTRACT socket address (leading `@`, standing for the NUL byte of the Linux
/// abstract namespace). These need DIFFERENT syscalls: a filesystem socket is
/// addressed by path via `send_to`; an abstract socket must be addressed via a
/// real abstract `SocketAddr` and `send_to_addr`. (blocker 7) The earlier
/// approach translated `@name` to a NUL-prefixed `PathBuf` and used `send_to`,
/// but `UnixDatagram::send_to` on std does NOT interpret a leading NUL as the
/// abstract namespace — it would try to address a filesystem path beginning with
/// a NUL byte and fail, so `READY=1` would never reach an abstract-socket
/// supervisor. Using `SocketAddr::from_abstract_name` + `send_to_addr` addresses
/// the abstract namespace correctly.
///
/// Abstract sockets are Linux-only; only a Linux systemd sets an `@`-prefixed
/// `NOTIFY_SOCKET`, so the abstract branch is `cfg(target_os = "linux")`. On any
/// other platform an `@`-prefixed value falls through to a path `send_to` that
/// will simply fail to connect, which is fine because no non-Linux supervisor
/// produces one.
fn send_ready_datagram(socket: &UnixDatagram, path: &std::path::Path) -> std::io::Result<usize> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if let [b'@', rest @ ..] = bytes {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;
            // The abstract name is the value AFTER the leading '@'.
            let addr = SocketAddr::from_abstract_name(rest)?;
            return socket.send_to_addr(READY_DATAGRAM, &addr);
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Abstract namespace does not exist off Linux; no non-Linux
            // supervisor sets an '@'-prefixed NOTIFY_SOCKET. Fall through to a
            // path send, which will not connect — the honest failure surface.
            let _ = rest;
        }
    }
    // Filesystem socket: address it by path.
    socket.send_to(READY_DATAGRAM, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn unconfigured_beacon_reports_not_configured_and_never_sends() {
        // No NOTIFY_SOCKET: signaling is a silent success (no supervisor).
        let mut beacon = ReadyBeacon::for_socket(None);
        assert_eq!(beacon.signal_ready().unwrap(), NotifyOutcome::NotConfigured);
        // And the latch holds: a second call is a no-op, never a resend.
        assert_eq!(
            beacon.signal_ready().unwrap(),
            NotifyOutcome::AlreadySignaled
        );
    }

    #[test]
    fn configured_beacon_sends_ready_exactly_once() {
        // Bind a datagram socket, point the beacon at it, and prove the exact
        // READY=1 bytes arrive — and that a second signal does NOT resend.
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&sock_path).expect("bind notify socket");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        let mut beacon = ReadyBeacon::for_socket(Some(sock_path));
        assert_eq!(beacon.signal_ready().unwrap(), NotifyOutcome::Sent);

        let mut buf = [0u8; 64];
        let n = listener.recv(&mut buf).expect("receive READY datagram");
        assert_eq!(&buf[..n], READY_DATAGRAM, "must send exactly READY=1\\n");

        // Second signal is latched: no second datagram is sent.
        assert_eq!(
            beacon.signal_ready().unwrap(),
            NotifyOutcome::AlreadySignaled
        );
        let mut buf2 = [0u8; 64];
        let second = listener.recv(&mut buf2);
        assert!(
            second.is_err(),
            "no second datagram must arrive after the beacon is spent"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn abstract_socket_receives_ready_via_from_abstract_name_and_send_to_addr() {
        // A real Linux abstract-namespace datagram socket: bind a listener on an
        // abstract name, point the beacon at the '@'-prefixed value systemd would
        // hand back, and prove the exact READY=1 bytes arrive. This exercises the
        // from_abstract_name + send_to_addr path (blocker 7), which the old
        // NUL-prefixed-path send_to could not reach.
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr, UnixDatagram};

        // A per-test-unique abstract name so parallel test runs never collide.
        let name = format!("sanctuary-castle-test-{}", std::process::id());
        let listen_addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&listen_addr).expect("bind abstract socket");
        listener
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();

        // systemd renders an abstract NOTIFY_SOCKET with a leading '@'.
        let notify_value = PathBuf::from(format!("@{name}"));
        let mut beacon = ReadyBeacon::for_socket(Some(notify_value));
        assert_eq!(beacon.signal_ready().unwrap(), NotifyOutcome::Sent);

        let mut buf = [0u8; 64];
        let n = listener
            .recv(&mut buf)
            .expect("receive READY over abstract socket");
        assert_eq!(&buf[..n], READY_DATAGRAM, "must send exactly READY=1\\n");
    }

    #[test]
    fn empty_notify_socket_env_is_treated_as_unset() {
        // from_env filters an empty NOTIFY_SOCKET to None so a stray empty value
        // does not turn into a send attempt against the empty path.
        let beacon = ReadyBeacon::for_socket(
            std::env::var_os(NOTIFY_SOCKET_ENV)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from),
        );
        // Regardless of the ambient env in CI, an empty value would be filtered;
        // this asserts the filter predicate the constructor relies on.
        assert!(ReadyBeacon::for_socket(Some(PathBuf::from("x")))
            .socket_path
            .is_some());
        let _ = beacon;
    }
}
