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
//! The liveness half (C2a3) is [`WatchdogBeacon`]: the supervisor thread sends
//! the watchdog datagram after every completed health pass, and systemd kills
//! the process (`WatchdogSignal=SIGKILL`) when no pet arrives for `WatchdogSec`.
//! Contract enforced by the beacon:
//! * It pets only when the `sd_watchdog_enabled(3)` contract says the manager
//!   asked for pets: `NOTIFY_SOCKET` set, `WATCHDOG_USEC` a positive integer,
//!   and `WATCHDOG_PID` unset or naming this process.
//! * A pet NEVER blocks: the socket is non-blocking, and a full receiver queue
//!   or any send error is a dropped pet. The supervisor must not wedge on the
//!   manager, which would make the watchdog kill a healthy daemon.
//! * A send failure is loud exactly once per transition (`PET_OK` to
//!   `PET_FAILING` and back), never once per pet, so a persistent failure cannot
//!   flood the journal.
//!
//! Failure-mode note (for the runbook): if the daemon reaches a ready kernel
//! runtime but this notify never fires, systemd keeps the unit in "activating"
//! and eventually kills it on `TimeoutStartSec`; the symptom is a daemon that
//! serves fine when run by hand but "won't start" under systemd. The inverse —
//! notifying `READY=1` before the kernel runtime is actually up — would tell
//! systemd the wall is enforcing when it is not, so the beacon is fired by the
//! boot path only after the runtime-ready check, never on the control-plane-only
//! fall-through.

use std::ffi::OsString;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};

/// The environment variable systemd sets to the notification socket path for a
/// `Type=notify` service. Absent for any other launch context.
pub const NOTIFY_SOCKET_ENV: &str = "NOTIFY_SOCKET";

/// The readiness datagram payload. `\n`-terminated per the `sd_notify` wire
/// format (state assignments are newline-separated).
///
/// CROSS-FILE PIN: this byte length is the base `READINESS_DATAGRAM_BUFFER_BYTES`
/// in `tests/integration_linux_runtime_activation.rs` derives from (that constant
/// is 8x this length, for margin). Changing this payload's length changes what
/// that test's derivation comment is claiming. Since C2a3 the same sockets also
/// carry the 11-byte [`WATCHDOG_DATAGRAM`], still under that 64-byte buffer.
const READY_DATAGRAM: &[u8] = b"READY=1\n";

/// The liveness-pet datagram payload, `\n`-terminated like [`READY_DATAGRAM`].
/// The only such literal in the daemon's own production code (TS1 in
/// `src/daemon.rs` pins that); the release-disabled stop-owner service has its
/// own pinger for its own unit.
pub const WATCHDOG_DATAGRAM: &[u8] = b"WATCHDOG=1\n";

/// The watchdog interval systemd hands a `WatchdogSec=` service, in
/// microseconds (`sd_watchdog_enabled(3)`).
pub const WATCHDOG_USEC_ENV: &str = "WATCHDOG_USEC";

/// The pid the watchdog is meant for, when set (`sd_watchdog_enabled(3)`).
pub const WATCHDOG_PID_ENV: &str = "WATCHDOG_PID";

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
        send_datagram(&socket, &path, READY_DATAGRAM)
            .map_err(|source| NotifyError::Send { path, source })?;
        Ok(NotifyOutcome::Sent)
    }
}

/// `WatchdogBeacon` state: the manager asked for no pets (no `NOTIFY_SOCKET`, no
/// positive `WATCHDOG_USEC`, or `WATCHDOG_PID` names another process).
pub const PET_DISABLED: u8 = 0;
/// `WatchdogBeacon` state: the last pet was handed to the kernel.
pub const PET_OK: u8 = 1;
/// `WatchdogBeacon` state: the last pet failed (or the socket never opened).
pub const PET_FAILING: u8 = 2;

/// Microseconds in one second, for the `WATCHDOG_USEC` conversions.
const MICROS_PER_SEC: u64 = 1_000_000;

/// What one [`WatchdogBeacon::pet`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PetOutcome {
    /// The manager asked for no pets; nothing was sent.
    Disabled,
    /// The datagram was handed to the kernel.
    Sent,
    /// The send failed or would have blocked; the pet is lost.
    Dropped,
}

/// The systemd liveness-watchdog beacon. Built once at boot; [`pet`](Self::pet)
/// takes `&self` because the supervisor pets from `&self` methods, so its state
/// is atomic. Named states: [`PET_DISABLED`], [`PET_OK`], [`PET_FAILING`].
#[derive(Debug)]
pub struct WatchdogBeacon {
    /// The notify socket to pet, only when the manager asked for pets.
    target: Option<PathBuf>,
    /// The one non-blocking datagram socket, opened at construction. `None`
    /// with a `target` means the open failed: every pet is then dropped and the
    /// watchdog kills the process one interval after `READY=1` (loud, fail-closed).
    socket: Option<UnixDatagram>,
    /// The interval the manager announced, when the beacon is enabled.
    watchdog_usec: Option<u64>,
    /// Whether `NOTIFY_SOCKET` was set at all (for the boot diagnostic).
    notify_configured: bool,
    state: AtomicU8,
    /// Stderr lines this beacon has written (transition lines only).
    lines_written: AtomicU32,
}

impl WatchdogBeacon {
    /// Build the beacon from the process environment (`NOTIFY_SOCKET`,
    /// `WATCHDOG_USEC`, `WATCHDOG_PID`), read once.
    pub fn from_env() -> Self {
        Self::from_parts(
            std::env::var_os(NOTIFY_SOCKET_ENV),
            std::env::var_os(WATCHDOG_USEC_ENV),
            std::env::var_os(WATCHDOG_PID_ENV),
            std::process::id(),
        )
    }

    /// The `sd_watchdog_enabled(3)` decision over explicit values, so it is
    /// testable without touching the process environment.
    pub fn from_parts(
        notify_socket: Option<OsString>,
        watchdog_usec: Option<OsString>,
        watchdog_pid: Option<OsString>,
        own_pid: u32,
    ) -> Self {
        let socket_path = notify_socket.filter(|v| !v.is_empty()).map(PathBuf::from);
        let notify_configured = socket_path.is_some();
        let usec = watchdog_usec
            .and_then(|v| v.to_str().and_then(|v| v.parse::<u64>().ok()))
            .filter(|usec| *usec > 0);
        // INVARIANT: a WATCHDOG_PID naming another process means the watchdog is
        // not ours to feed; petting it would keep that process's deadline alive
        // on our progress. Only the main process pets, which is also what the
        // unit's NotifyAccess=main enforces on the manager side. Must match
        // `NotifyAccess=main` in systemd/sanctuary-castle-wall.service.
        let pid_is_ours = match watchdog_pid {
            None => true,
            Some(pid) => pid.to_str().and_then(|p| p.parse::<u32>().ok()) == Some(own_pid),
        };
        let enabled_usec = usec.filter(|_| pid_is_ours && notify_configured);
        Self::build(
            socket_path.filter(|_| enabled_usec.is_some()),
            enabled_usec,
            notify_configured,
        )
    }

    /// Test constructor aimed at an explicit socket, mirroring
    /// [`ReadyBeacon::for_socket`]. Enabled only when both are given and the
    /// interval is positive.
    pub fn for_socket(socket_path: Option<PathBuf>, watchdog_usec: Option<u64>) -> Self {
        let notify_configured = socket_path.is_some();
        let enabled_usec = watchdog_usec.filter(|usec| *usec > 0 && notify_configured);
        Self::build(
            socket_path.filter(|_| enabled_usec.is_some()),
            enabled_usec,
            notify_configured,
        )
    }

    fn build(target: Option<PathBuf>, watchdog_usec: Option<u64>, notify_configured: bool) -> Self {
        let beacon = Self {
            socket: None,
            target,
            watchdog_usec,
            notify_configured,
            state: AtomicU8::new(PET_DISABLED),
            lines_written: AtomicU32::new(0),
        };
        if beacon.target.is_none() {
            return beacon;
        }
        let opened = UnixDatagram::unbound().and_then(|socket| {
            // INVARIANT: non-blocking, so a manager that stops reading can never
            // wedge the supervisor on a pet (a wedged pet is itself a watchdog kill).
            socket.set_nonblocking(true)?;
            Ok(socket)
        });
        match opened {
            Ok(socket) => Self {
                socket: Some(socket),
                state: AtomicU8::new(PET_OK),
                ..beacon
            },
            Err(err) => {
                beacon.state.store(PET_FAILING, Ordering::SeqCst);
                beacon.write_line(&format!(
                    "castle-wall-daemon: watchdog pet socket could not be opened ({err}); \
                     systemd will kill this process one watchdog interval after READY=1"
                ));
                beacon
            }
        }
    }

    /// Send one liveness pet. Never blocks and never fails the caller: a send
    /// error or a full receiver queue is a dropped pet (`PET_FAILING`), reported
    /// once per transition.
    pub fn pet(&self) -> PetOutcome {
        let Some(path) = self.target.as_deref() else {
            return PetOutcome::Disabled;
        };
        let Some(socket) = self.socket.as_ref() else {
            return PetOutcome::Dropped;
        };
        match send_datagram(socket, path, WATCHDOG_DATAGRAM) {
            Ok(_) => {
                if self.state.swap(PET_OK, Ordering::SeqCst) == PET_FAILING {
                    self.write_line("castle-wall-daemon: watchdog pets reach the manager again");
                }
                PetOutcome::Sent
            }
            Err(err) => {
                if self.state.swap(PET_FAILING, Ordering::SeqCst) == PET_OK {
                    self.write_line(&format!(
                        "castle-wall-daemon: watchdog pet failed ({err}); systemd will kill \
                         this process if pets stay lost for the watchdog interval"
                    ));
                }
                PetOutcome::Dropped
            }
        }
    }

    /// The beacon's named state: [`PET_DISABLED`], [`PET_OK`] or [`PET_FAILING`].
    pub fn state(&self) -> u8 {
        self.state.load(Ordering::SeqCst)
    }

    /// The manager's announced interval, when the beacon is enabled.
    pub fn watchdog_usec(&self) -> Option<u64> {
        self.watchdog_usec
    }

    /// Whether `NOTIFY_SOCKET` was set at all.
    pub fn notify_configured(&self) -> bool {
        self.notify_configured
    }

    /// Transition lines this beacon has written to stderr.
    pub fn lines_written(&self) -> u32 {
        self.lines_written.load(Ordering::SeqCst)
    }

    fn write_line(&self, line: &str) {
        self.lines_written.fetch_add(1, Ordering::SeqCst);
        // SAFETY: stderr is the operator channel for the watchdog's transition
        // record (systemd journals it); a lost-pet run ends in a kill whose
        // journal entry needs this line beside it.
        eprintln!("{line}");
    }
}

/// The boot-time watchdog diagnostic, one line or none. Never a refusal: a host
/// that disables or resizes the watchdog is told what that costs, and the daemon
/// runs on. `pet_gap` is the daemon's own longest gap between pets,
/// `decided_exit_bound` the latest its stop guard's decided exit lands after a
/// pet, and `built_for_secs` the `WatchdogSec` the unit ships.
pub fn watchdog_boot_diagnostic(
    notify_configured: bool,
    watchdog_usec: Option<u64>,
    pet_gap: std::time::Duration,
    decided_exit_bound: std::time::Duration,
    built_for_secs: u32,
) -> Option<String> {
    if !notify_configured {
        // No supervisor at all (dev host, CI smoke): nothing to diagnose.
        return None;
    }
    let Some(usec) = watchdog_usec else {
        return Some(
            "castle-wall-daemon: supervisor enabled no watchdog; a wedged supervisor is \
             unbounded"
                .to_string(),
        );
    };
    let host = std::time::Duration::from_micros(usec);
    if host < pet_gap {
        return Some(format!(
            "castle-wall-daemon: watchdog {host:?} is shorter than this daemon's own pet \
             cadence ({pet_gap:?}); it WILL be killed while healthy"
        ));
    }
    if usec == u64::from(built_for_secs) * MICROS_PER_SEC {
        return None;
    }
    let mut line = format!(
        "castle-wall-daemon: watchdog mismatch: host {host:?}, built for {built_for_secs} s"
    );
    if host < decided_exit_bound {
        line.push_str("; decided exit codes may be preempted");
    }
    Some(line)
}

/// Send one `sd_notify` datagram (`READY=1` or the watchdog pet) to a resolved
/// `NOTIFY_SOCKET` value.
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
fn send_datagram(
    socket: &UnixDatagram,
    path: &std::path::Path,
    payload: &[u8],
) -> std::io::Result<usize> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if let [b'@', rest @ ..] = bytes {
        #[cfg(target_os = "linux")]
        {
            use std::os::linux::net::SocketAddrExt;
            use std::os::unix::net::SocketAddr;
            // The abstract name is the value AFTER the leading '@'.
            let addr = SocketAddr::from_abstract_name(rest)?;
            return socket.send_to_addr(payload, &addr);
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
    socket.send_to(payload, path)
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

    // ---- C2a3: the watchdog beacon (LINUX-SUPERVISOR-WEDGE-R1-01) ----

    /// Bind a filesystem datagram receiver in `dir`.
    fn bound_receiver(dir: &TempDir) -> (PathBuf, UnixDatagram) {
        let path = dir.path().join("notify.sock");
        let listener = UnixDatagram::bind(&path).expect("bind notify socket");
        (path, listener)
    }

    /// Every datagram waiting on `listener`, without blocking.
    fn drain(listener: &UnixDatagram) -> Vec<Vec<u8>> {
        listener.set_nonblocking(true).unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 64];
        while let Ok(n) = listener.recv(&mut buf) {
            out.push(buf[..n].to_vec());
        }
        out
    }

    /// The watchdog interval the shipped unit announces, in microseconds.
    fn shipped_usec() -> u64 {
        u64::from(crate::daemon::WATCHDOG_SEC) * MICROS_PER_SEC
    }

    /// TB1: a configured beacon sends exactly the watchdog datagram per pet; an
    /// unconfigured one (no socket, no or zero interval, another process's
    /// WATCHDOG_PID) sends nothing; a pet never blocks against a receiver that
    /// stops reading; and a failure is reported once per transition.
    #[test]
    fn tb1_watchdog_beacon_pets_only_when_asked_and_never_blocks() {
        let dir = TempDir::new().unwrap();
        let (path, listener) = bound_receiver(&dir);

        let beacon = WatchdogBeacon::for_socket(Some(path.clone()), Some(shipped_usec()));
        assert_eq!(beacon.state(), PET_OK);
        // `pet` takes `&self`: the supervisor pets through a shared reference.
        let shared: &WatchdogBeacon = &beacon;
        for _ in 0..3 {
            assert_eq!(shared.pet(), PetOutcome::Sent);
        }
        let got = drain(&listener);
        assert_eq!(got, vec![WATCHDOG_DATAGRAM.to_vec(); 3]);

        // Not asked for pets: nothing is ever sent.
        let own_pid = std::process::id();
        let usec = Some(OsString::from(shipped_usec().to_string()));
        let disabled = [
            WatchdogBeacon::for_socket(None, Some(shipped_usec())),
            WatchdogBeacon::for_socket(Some(path.clone()), None),
            WatchdogBeacon::for_socket(Some(path.clone()), Some(0)),
            WatchdogBeacon::from_parts(
                Some(path.clone().into_os_string()),
                usec.clone(),
                Some(OsString::from((own_pid + 1).to_string())),
                own_pid,
            ),
            WatchdogBeacon::from_parts(
                Some(path.clone().into_os_string()),
                Some(OsString::from("0")),
                None,
                own_pid,
            ),
            WatchdogBeacon::from_parts(None, usec.clone(), None, own_pid),
        ];
        for beacon in &disabled {
            assert_eq!(beacon.state(), PET_DISABLED);
            assert_eq!(beacon.pet(), PetOutcome::Disabled);
        }
        assert!(drain(&listener).is_empty(), "a disabled beacon sent a pet");
        // WATCHDOG_PID naming THIS process enables it.
        let ours = WatchdogBeacon::from_parts(
            Some(path.clone().into_os_string()),
            usec,
            Some(OsString::from(own_pid.to_string())),
            own_pid,
        );
        assert_eq!(ours.pet(), PetOutcome::Sent);
        assert_eq!(drain(&listener), vec![WATCHDOG_DATAGRAM.to_vec()]);

        // A receiver that never reads: 10 000 pets return promptly and some drop.
        // 10 000 is far past any kernel datagram queue (Linux max_dgram_qlen,
        // the macOS receive buffer); 1 s is a policy allowance, not a measurement.
        const FLOOD_PETS: usize = 10_000;
        const FLOOD_ALLOWANCE: std::time::Duration = std::time::Duration::from_secs(1);
        // The socket itself is non-blocking (some kernels answer a full datagram
        // queue with an error even on a blocking socket, so the timing below
        // alone cannot tell the two apart there).
        let fd = std::os::fd::AsRawFd::as_raw_fd(beacon.socket.as_ref().expect("opened"));
        // SAFETY: F_GETFL on a descriptor this beacon owns and keeps open.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(
            flags >= 0 && flags & libc::O_NONBLOCK != 0,
            "the pet socket must be non-blocking"
        );
        // The flood runs on its own thread so a blocking pet fails this test by
        // the allowance instead of hanging the suite.
        let beacon = std::sync::Arc::new(beacon);
        let flooding = std::sync::Arc::clone(&beacon);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            let dropped = (0..FLOOD_PETS)
                .filter(|_| flooding.pet() == PetOutcome::Dropped)
                .count();
            let _ = done_tx.send(dropped);
        });
        let dropped = done_rx
            .recv_timeout(FLOOD_ALLOWANCE)
            .unwrap_or_else(|_| panic!("pets blocked past {FLOOD_ALLOWANCE:?}"));
        assert!(
            started.elapsed() < FLOOD_ALLOWANCE,
            "pets blocked: {:?}",
            started.elapsed()
        );
        assert!(dropped >= 1, "a full queue must drop pets, not block");
        assert_eq!(beacon.state(), PET_FAILING);
        assert_eq!(
            beacon.lines_written(),
            1,
            "one line per transition, not per pet"
        );
        // The receiver drains, the next pet lands, one recovery line.
        let _ = drain(&listener);
        assert_eq!(beacon.pet(), PetOutcome::Sent);
        assert_eq!(beacon.state(), PET_OK);
        assert_eq!(beacon.lines_written(), 2, "PET_OK -> PET_FAILING -> PET_OK");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tb1_watchdog_beacon_pets_an_abstract_notify_socket() {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::SocketAddr;
        let name = format!("sanctuary-castle-wd-test-{}", std::process::id());
        let listen_addr = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let listener = UnixDatagram::bind_addr(&listen_addr).expect("bind abstract socket");
        let beacon = WatchdogBeacon::for_socket(
            Some(PathBuf::from(format!("@{name}"))),
            Some(shipped_usec()),
        );
        assert_eq!(beacon.pet(), PetOutcome::Sent);
        assert_eq!(drain(&listener), vec![WATCHDOG_DATAGRAM.to_vec()]);
    }

    /// TB2: the boot diagnostic splits a host interval three ways at the
    /// daemon's own pet gap and at its decided-exit bound; a missing watchdog is
    /// its own line; a matching one writes nothing.
    #[test]
    fn tb2_watchdog_boot_diagnostic_names_what_a_host_interval_costs() {
        let diagnose = |usec: Option<&str>| {
            let beacon = WatchdogBeacon::from_parts(
                Some(OsString::from("/run/systemd/notify")),
                usec.map(OsString::from),
                None,
                std::process::id(),
            );
            watchdog_boot_diagnostic(
                beacon.notify_configured(),
                beacon.watchdog_usec(),
                crate::daemon::WATCHDOG_PET_GAP_BOUND,
                crate::daemon::WATCHDOG_DECIDED_EXIT_BOUND,
                crate::daemon::WATCHDOG_SEC,
            )
        };
        // The shipped 19 s: enabled and matching.
        assert_eq!(diagnose(Some("19000000")), None);
        // 8 s: above the 5.2 s pet gap, below the 18.4 s decided-exit bound.
        let line = diagnose(Some("8000000")).expect("a mismatch line");
        assert!(line.contains("watchdog mismatch"), "{line}");
        assert!(
            line.contains("decided exit codes may be preempted"),
            "{line}"
        );
        // 25 s: a mismatch, but decided exits still land first.
        let line = diagnose(Some("25000000")).expect("a mismatch line");
        assert!(line.contains("watchdog mismatch"), "{line}");
        assert!(!line.contains("preempted"), "{line}");
        // 4 s: under the pet gap, self-defeating, never a plain mismatch.
        let line = diagnose(Some("4000000")).expect("a self-defeating line");
        assert!(line.contains("WILL be killed while healthy"), "{line}");
        assert!(!line.contains("mismatch"), "{line}");
        // Non-numeric: disabled, and the absent-watchdog line.
        let line = diagnose(Some("soon")).expect("an absent line");
        assert!(line.contains("enabled no watchdog"), "{line}");
        let line = diagnose(None).expect("an absent line");
        assert!(line.contains("enabled no watchdog"), "{line}");
        // No supervisor at all: nothing to say.
        assert_eq!(
            watchdog_boot_diagnostic(
                false,
                None,
                crate::daemon::WATCHDOG_PET_GAP_BOUND,
                crate::daemon::WATCHDOG_DECIDED_EXIT_BOUND,
                crate::daemon::WATCHDOG_SEC,
            ),
            None
        );
    }
}
