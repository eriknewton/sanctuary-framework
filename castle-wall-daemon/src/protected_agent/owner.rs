//! Independent stop owner. It accepts, fsyncs and answers stop INTENT for a
//! previously durable, exact owned cgroup; it neither executes a stop nor
//! creates a unit nor accepts release/exec authority. Acceptance without
//! execution is the whole of this slice: no path through this module reaches
//! `systemctl stop`, a `cgroup.kill` write, or any other action against a
//! producer, and the one process invocation that remains here reads service
//! properties (`systemctl show`) to authenticate a peer and name the running
//! daemon generation. The execution these records exist for is not in this
//! slice; it is tracked as PR3B-STOP-EXECUTION and marked at the single site in
//! this file where it attaches, which is the function that writes the answer.
use super::{
    ledger::{self, Ledger},
    receipt::{self, Domain, ManagerIdentity, Pins, SignedReceipt},
    stop_policy::{self, HookRoute},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
            net::{UnixDatagram, UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};

pub const SOCKET_PATH: &str = "/run/sanctuary-stop-owner/owner.sock";
const RUNTIME_PARENT: &str = "/run/sanctuary-stop-owner";
const OWNER_PRIVATE_PARENT: &str = "/var/lib/sanctuary-stop-owner";
const DAEMON_PRIVATE_PARENT: &str = "/var/lib/sanctuary";
const DAEMON_LAUNCHER_PARENT: &str = "/var/lib/sanctuary/launcher";
const DAEMON_UNIT: &str = "sanctuary-castle-wall.service";
const PEERPIDFD: libc::c_int = 77; // Linux SO_PEERPIDFD (no pidfd_open fallback)
const MAX_WIRE: usize = 16 * 1024;
const MAX_RESPONSE: usize = 20 * 1024;
const CLIENT_DEADLINE: Duration = Duration::from_millis(250);
/// How long the accept loop waits between polls of its non-blocking listener.
const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(25);
/// Watchdog keepalive cadence. MUST stay well under `WatchdogSec=` in
/// `systemd/sanctuary-stop-owner.service`, which is the deadline it feeds.
const WATCHDOG_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Request {
    StopFailure(SignedReceipt),
    PreparedCheck {
        generation: receipt::Generation,
        manager: ManagerIdentity,
    },
    ReleasedRowCopy(SignedReceipt),
    CompletionPull {
        unit_name: String,
    },
    StopHint {
        boot_id: String,
        daemon_invocation: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerOutcome {
    IntentAccepted,
    NoOwnedRelease,
    OwnerUnavailable,
    Inhibit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub outcome: OwnerOutcome,
    pub completion: Option<SignedReceipt>,
}

/// Every host-global name the stop owner and its daemon-side hook read, in one
/// injectable value. The two production composition roots, `serve_production`
/// and `stop_failure_for_hook`, supply the installed set; a test supplies a
/// temporary tree. Failure mode if a site reads a constant directly instead:
/// it works in production and quietly reaches installed state from a test run,
/// which surfaces as an unrelated flake on whichever machine happens to have
/// Sanctuary installed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerPaths {
    /// The owner's listening socket, and the first name the hook looks at.
    pub socket: PathBuf,
    /// The immutable receipt pins.
    pub pins: PathBuf,
    /// The daemon's own reservation and release log.
    pub release_log: PathBuf,
    /// The admission signing key the daemon holds.
    pub admission_key: PathBuf,
    /// The parents of `admission_key` whose custody is checked before it is
    /// read. Listed rather than derived from the key path so that changing the
    /// layout cannot silently drop a level from the check.
    pub admission_key_parents: Vec<PathBuf>,
    /// The owner's private state parent, which must NOT be readable from the
    /// daemon side.
    pub owner_private_parent: PathBuf,
    /// The daemon's private state parent, which must NOT be readable from the
    /// owner side.
    pub daemon_private_parent: PathBuf,
    /// The owner's append-only ledger.
    pub ledger: PathBuf,
    /// The key that authenticates the daemon log's reservation rows. Named
    /// here rather than read from its constant inside the replay, because a
    /// caller that injects a log but not this key still opens the installed
    /// credential store while replaying the injected rows.
    pub journal_mac_key: PathBuf,
    /// The owner's completion signing key.
    pub completion_key: PathBuf,
}

impl OwnerPaths {
    /// The installed layout. MUST MATCH the paths the package transaction
    /// prepares and the reciprocal masks declared in
    /// `systemd/sanctuary-stop-owner.service`.
    pub fn installed() -> Self {
        Self {
            socket: PathBuf::from(SOCKET_PATH),
            pins: PathBuf::from(receipt::PINS_PATH),
            release_log: PathBuf::from(super::daemon_log::RELEASE_LOG_PATH),
            admission_key: PathBuf::from(receipt::ADMISSION_KEY_PATH),
            admission_key_parents: vec![
                PathBuf::from(DAEMON_PRIVATE_PARENT),
                PathBuf::from(DAEMON_LAUNCHER_PARENT),
            ],
            owner_private_parent: PathBuf::from(OWNER_PRIVATE_PARENT),
            daemon_private_parent: PathBuf::from(DAEMON_PRIVATE_PARENT),
            ledger: PathBuf::from(ledger::LEDGER_PATH),
            journal_mac_key: PathBuf::from(crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH),
            completion_key: PathBuf::from(receipt::COMPLETION_KEY_PATH),
        }
    }

    /// The same layout rooted inside a caller's own temporary tree, which is
    /// what a test binds in place of the installed set.
    ///
    /// Unconditional because it grants nothing the public fields already do
    /// not; the structural guarantee is that a production build has no way to
    /// BIND one (`use_isolated_owner_paths` is absent from it), so the hook and
    /// `serve_production` there can resolve only [`OwnerPaths::installed`].
    pub fn isolated_under(root: &Path) -> Self {
        Self {
            socket: root.join("owner.sock"),
            pins: root.join("receipt-pins-v1.json"),
            release_log: root.join("releases.log"),
            admission_key: root.join("admission-signing.key"),
            admission_key_parents: vec![root.to_path_buf()],
            owner_private_parent: root.join("owner-private"),
            daemon_private_parent: root.join("daemon-private"),
            ledger: root.join("owner-ledger-v1.log"),
            journal_mac_key: root.join("nft-journal-auth.key"),
            completion_key: root.join("completion-signing.key"),
        }
    }

    /// Every name this value carries, destructured field by field. Adding a
    /// path to `OwnerPaths` without listing it here fails to compile, which is
    /// what keeps the containment check in this module's tests total rather
    /// than a snapshot of the fields that existed when it was written.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn every_path(&self) -> Vec<&Path> {
        let Self {
            socket,
            pins,
            release_log,
            admission_key,
            admission_key_parents,
            owner_private_parent,
            daemon_private_parent,
            ledger,
            journal_mac_key,
            completion_key,
        } = self;
        let mut all = vec![
            socket.as_path(),
            pins.as_path(),
            release_log.as_path(),
            admission_key.as_path(),
            owner_private_parent.as_path(),
            daemon_private_parent.as_path(),
            ledger.as_path(),
            journal_mac_key.as_path(),
            completion_key.as_path(),
        ];
        all.extend(admission_key_parents.iter().map(PathBuf::as_path));
        all
    }

    /// True when this tree cannot reach an installed name. Checked name by
    /// name rather than on the whole value, because a partly isolated tree (a
    /// temporary ledger beside the installed pins) is exactly the shape that
    /// still reads operator state and an equality on the whole value would pass
    /// it. Checked as CONTAINMENT in both directions rather than as equality,
    /// because a tree rooted inside an installed directory carries no installed
    /// name of its own and would pass an equality check while sitting in
    /// operator state, and a tree that contains an installed name reaches it
    /// from the other side. `Path::starts_with` compares whole components, so
    /// a sibling such as `/var/lib/sanctuary-stop-owner` is not read as being
    /// inside `/var/lib/sanctuary`.
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn is_isolated_from_production(&self) -> bool {
        let installed = Self::installed();
        let installed_names = installed.every_path();
        self.every_path().iter().all(|name| {
            installed_names
                .iter()
                .all(|shipped| !name.starts_with(shipped) && !shipped.starts_with(name))
        })
    }
}

/// Which paths the daemon-side hook speaks to. Production is always the
/// installed set. EVERY build that carries a test seam refuses unless that test
/// has bound a tree of its own, so no test run reads an installed pins file,
/// release log, key or socket: this divergence only ever makes a test build
/// MORE refusing, and never enables a path that production would not take.
///
/// The gate is `any(test, feature = "test-isolation")` and not `test` alone
/// because the two are different build configurations. `cfg(test)` covers the
/// crate's own unit tests; the integration binaries link this library WITHOUT
/// it and enable the feature instead, and they drive the real startup path that
/// calls this hook. Failure mode if the feature arm were missing: an
/// integration binary resolves the installed socket and pins, so `cargo test`
/// reads operator-owned state on any host with Sanctuary installed, with no
/// error attributable to the suite that did it.
#[cfg(not(any(test, feature = "test-isolation")))]
fn hook_paths() -> Option<OwnerPaths> {
    Some(OwnerPaths::installed())
}
#[cfg(any(test, feature = "test-isolation"))]
fn hook_paths() -> Option<OwnerPaths> {
    test_paths::bound()
}

/// The tree the daemon-side hook resolves right now, for an isolated suite to
/// assert against. It CALLS `hook_paths` rather than restating its rules, so
/// the assertion cannot drift from the resolution it is about.
#[cfg(feature = "test-isolation")]
pub fn resolved_hook_paths() -> Option<OwnerPaths> {
    hook_paths()
}

/// Point this process's daemon-side hook at an isolated tree for the rest of
/// its life, and prove the tree carries no installed name before anything can
/// read it.
///
/// Absent from the shipped binary: the integration suites declare
/// `feature = "test-isolation"` through `required-features`, and a release
/// build has no way to call this at all, so its hook can resolve only
/// [`OwnerPaths::installed`].
///
/// Refuses a second, DIFFERENT tree once one is resolved, because state already
/// read under the first would then be attributed to the second; binding the
/// same tree again is the idempotent case and succeeds, which is what lets a
/// per-test entry point re-assert the binding.
#[cfg(feature = "test-isolation")]
pub fn use_isolated_owner_paths(root: &Path) -> Result<(), String> {
    let paths = OwnerPaths::isolated_under(root);
    if !paths.is_isolated_from_production() {
        return Err(format!(
            "an isolated owner tree must carry no installed name; refusing the tree under {} so \
             this seam can never point the daemon-side hook at operator-owned state",
            root.display()
        ));
    }
    test_paths::bind_suite(paths)
}

#[cfg(any(test, feature = "test-isolation"))]
mod test_paths {
    //! Binds the daemon-side hook to a temporary tree, so no test run reads an
    //! installed pins file, release log, key or socket.
    //!
    //! Two slots, because the two kinds of test build bind differently. The
    //! crate's own unit tests bind and unbind around a single test while their
    //! siblings run on other threads, so that slot is thread-local and ends
    //! with a guard. An integration binary binds once for its whole process,
    //! before any suite runs, and the startup path it drives may reach the hook
    //! on a thread the test never named, so that slot is process-wide.
    use super::OwnerPaths;
    #[cfg(test)]
    use std::cell::RefCell;

    #[cfg(test)]
    thread_local! {
        static BOUND: RefCell<Option<OwnerPaths>> = const { RefCell::new(None) };
    }

    /// The whole process's tree, written at most once by
    /// [`super::use_isolated_owner_paths`].
    #[cfg(feature = "test-isolation")]
    static SUITE: std::sync::OnceLock<OwnerPaths> = std::sync::OnceLock::new();

    /// The tree the hook resolves: this thread's own binding first, then the
    /// binary's process-wide one, and otherwise NOTHING, which is what makes an
    /// unbound test build refuse rather than fall back to installed state.
    pub fn bound() -> Option<OwnerPaths> {
        #[cfg(test)]
        if let Some(paths) = BOUND.with(|slot| slot.borrow().clone()) {
            return Some(paths);
        }
        #[cfg(feature = "test-isolation")]
        if let Some(paths) = SUITE.get().cloned() {
            return Some(paths);
        }
        None
    }

    /// Binds `paths` for this thread until the returned guard drops.
    #[cfg(test)]
    pub fn bind(paths: OwnerPaths) -> Guard {
        BOUND.with(|slot| *slot.borrow_mut() = Some(paths));
        Guard
    }

    #[cfg(test)]
    pub struct Guard;
    #[cfg(test)]
    impl Drop for Guard {
        fn drop(&mut self) {
            BOUND.with(|slot| *slot.borrow_mut() = None);
        }
    }

    /// Binds `paths` for the whole process. The equality is over the WHOLE
    /// value, so a tree that differs in one name is a different tree and is
    /// refused rather than silently ignored.
    #[cfg(feature = "test-isolation")]
    pub fn bind_suite(paths: OwnerPaths) -> Result<(), String> {
        match SUITE.set(paths) {
            Ok(()) => Ok(()),
            Err(rejected) => match SUITE.get() {
                Some(active) if *active == rejected => Ok(()),
                _ => Err(
                    "this process already bound a different isolated owner tree; refusing to \
                     switch, because names already read under the first tree would be \
                     attributed to the second"
                        .to_owned(),
                ),
            },
        }
    }
}

fn bad(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn exact_dir(path: &Path, uid: u32, gid: u32, mode: u32) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_dir() || m.uid() != uid || m.gid() != gid || (m.mode() & 0o7777) != mode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe owner directory",
        ));
    }
    Ok(())
}

fn exact_socket(path: &Path) -> io::Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.file_type().is_socket() || m.uid() != 0 || m.gid() != 0 || (m.mode() & 0o7777) != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unsafe owner socket",
        ));
    }
    Ok(())
}

/// The directories above a custodied file whose ownership and mode this owner
/// enforces, longest first.
///
/// The filesystem root is excluded, which MUST MATCH the explicit base list
/// this derived walk replaced: that list stopped at `/etc`. `/` is not a
/// custody boundary the owner enforces. It is root-owned on every supported
/// host and no non-root user can replace it whatever its mode, so a hardened
/// root-owned 0711 root already satisfies the property the walk exists for
/// while failing an exact 0755 comparison. Failure mode if it were included:
/// the owner refuses to start on a healthy, more strictly configured host,
/// which is a lockout and not a protection.
fn custody_ancestors(parent: &Path) -> Vec<&Path> {
    parent
        .ancestors()
        .take_while(|ancestor| *ancestor != Path::new("/"))
        .collect()
}

fn read_pins(pins_path: &Path) -> io::Result<Pins> {
    // Every directory above the pins file must be a root-owned 0755 directory.
    // A writable ancestor would let a non-root user replace the pinned keys and
    // so choose which receipts verify, which is the whole trust root here. The
    // walk is derived from the path actually read, so the custody check cannot
    // drift away from the file it protects.
    let parent = pins_path.parent().ok_or_else(|| bad("pins parent"))?;
    for ancestor in custody_ancestors(parent) {
        exact_dir(ancestor, 0, 0, 0o755)?;
    }
    let bytes = receipt::read_custodied_file(pins_path, 0, &[0], 0o644, 4096)?;
    let pins: Pins = serde_json::from_slice(&bytes).map_err(|_| bad("invalid pins"))?;
    pins.validate().map_err(bad)?;
    Ok(pins)
}

/// Reads the owner's completion signing key. `key_path` MUST MATCH the
/// `completion_key` field of the caller's `OwnerPaths`; it is a parameter and
/// never the constant for the same reason the log and MAC key are.
fn read_owner_key(key_path: &Path, pins: &Pins) -> io::Result<ed25519_dalek::SigningKey> {
    let mut bytes = receipt::read_custodied_file(key_path, 0, &[0], 0o600, 128)?;
    let key_bytes: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| bad("owner key length"))?;
    bytes.fill(0);
    let key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
    if receipt::key_id(&key.verifying_key()) != pins.completion_key_id {
        return Err(bad("owner key pin mismatch"));
    }
    Ok(key)
}

/// Hook routing is release-disabled but executable: only a locally authenticated
/// current-boot unresolved release whose UID is in (a) union (b) reaches the
/// owner. Empty/source-(c)-only/unwrapped targets remain no-signal.
pub fn stop_failure_for_hook(
    kill_set: &[u32],
    hook: &str,
    attempted_scope: Option<&crate::nftables::SafetyNetScope>,
) -> OwnerOutcome {
    let Some(paths) = hook_paths() else {
        return OwnerOutcome::OwnerUnavailable;
    };
    stop_failure_for_hook_at(&paths, kill_set, hook, attempted_scope)
}

fn stop_failure_for_hook_at(
    paths: &OwnerPaths,
    kill_set: &[u32],
    hook: &str,
    attempted_scope: Option<&crate::nftables::SafetyNetScope>,
) -> OwnerOutcome {
    let result = (|| -> io::Result<OwnerOutcome> {
        // The socket is checked FIRST, and when it is absent it is the only
        // name this hook touches. No listening owner means there is no stop
        // authority to ask, whatever the pins, the log or the group database
        // would say, so reading them could only produce a misleading outcome
        // and reach installed state from hosts and test runs that have no
        // owner at all.
        if fs::symlink_metadata(&paths.socket).is_err() {
            return Ok(OwnerOutcome::OwnerUnavailable);
        }
        if fs::read_dir(&paths.owner_private_parent).is_ok() {
            return Err(bad("owner private parent readable from daemon"));
        }
        let pins = read_pins(&paths.pins)?;
        let mut log = super::daemon_log::replay(&paths.release_log, &paths.journal_mac_key, &pins)?;
        // Cloned before the pull so no borrow of `log` is alive across the
        // reassignment below.
        let unresolved_unit = log
            .released
            .as_ref()
            .filter(|_| log.completion.is_none())
            .map(|r| r.body.generation.unit_name.clone());
        if let Some(unit_name) = unresolved_unit {
            // A completion may have been fsynced by the owner just before the
            // daemon crashed. Only a locally fsynced, exact signed copy closes
            // the daemon row; a missing/failed pull leaves it unresolved.
            if let Ok(reply) = request_to(&paths.socket, &Request::CompletionPull { unit_name }) {
                if let Some(completion) = reply.completion {
                    super::daemon_log::accept_completion_copy(
                        &paths.release_log,
                        &paths.journal_mac_key,
                        completion,
                        &pins,
                    )?;
                    log = super::daemon_log::replay(
                        &paths.release_log,
                        &paths.journal_mac_key,
                        &pins,
                    )?;
                }
            }
        }
        // One decision for every no-signal shape. An authentic release row for
        // an account the safety net did not deny is evidence about a different
        // agent: acting on it would ask the owner to stop whichever generation
        // its ledger holds rather than the one this failed install named.
        let unresolved = log.released.as_ref().filter(|_| log.completion.is_none());
        if stop_policy::hook_route(kill_set, unresolved.map(|r| r.body.generation.uid))
            == HookRoute::NoSignal
        {
            return Ok(OwnerOutcome::NoOwnedRelease);
        }
        let Some(release) = unresolved else {
            return Ok(OwnerOutcome::NoOwnedRelease);
        };
        let g = &release.body.generation;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let invocation =
            std::env::var("INVOCATION_ID").map_err(|_| bad("daemon invocation absent"))?;
        if g.boot_id != boot.trim() || g.daemon_invocation != invocation {
            return Ok(OwnerOutcome::Inhibit);
        }
        let gid = nix::unistd::Group::from_name("sanctuary")?
            .ok_or_else(|| bad("sanctuary group absent"))?
            .gid
            .as_raw();
        for parent in &paths.admission_key_parents {
            let m = fs::symlink_metadata(parent)?;
            if !m.file_type().is_dir()
                || m.uid() != 0
                || ![0, gid].contains(&m.gid())
                || m.mode() & 0o7777 != 0o700
            {
                return Err(bad("admission signer parent custody"));
            }
        }
        let mut bytes =
            receipt::read_custodied_file(&paths.admission_key, 0, &[0, gid], 0o600, 128)?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| bad("admission key length"))?;
        bytes.fill(0);
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        if receipt::key_id(&key.verifying_key()) != pins.admission_key_id {
            return Err(bad("admission key pin mismatch"));
        }
        let mut nonce = [0u8; 32];
        use rand_core::RngCore;
        rand_core::OsRng.fill_bytes(&mut nonce);
        let old_hash = ledger::receipt_hash(release)?;
        let body = receipt::ReceiptBody {
            generation: g.clone(),
            manager: release.body.manager.clone(),
            hook: Some(hook.to_owned()),
            attempt_id: Some(hex::encode(nonce)),
            attempted_scope: attempted_scope
                .map(|s| format!("{}:{:?}", s.shape_tag(), s.denied_uids())),
            candidate_uids: kill_set.to_vec(),
            old_release_hash: Some(old_hash),
            positive_extinction: None,
        };
        let signed = receipt::sign(Domain::StopFailureV1, body, &key).map_err(bad)?;
        Ok(request_to(&paths.socket, &Request::StopFailure(signed))?.outcome)
    })();
    match result {
        Ok(o) => o,
        Err(_) => OwnerOutcome::OwnerUnavailable,
    }
}

fn fixed_manager_show(unit: &str) -> io::Result<String> {
    if unit != DAEMON_UNIT
        && !(unit.starts_with("sanctuary-agent-v1-")
            && unit.ends_with(".service")
            && unit.len() == "sanctuary-agent-v1-".len() + 64 + ".service".len()
            && unit["sanctuary-agent-v1-".len()..unit.len() - ".service".len()]
                .bytes()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()))
    {
        return Err(bad("untrusted unit name"));
    }
    let mut child = Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "--property=MainPID",
            "--property=ControlPID",
            "--property=ControlGroup",
            "--property=InvocationID",
            "--property=ActiveState",
            unit,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(bad("manager show failed"));
            }
            let mut out = String::new();
            child
                .stdout
                .take()
                .ok_or_else(|| bad("manager stdout"))?
                .take(4096)
                .read_to_string(&mut out)?;
            return Ok(out);
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(bad("manager timeout"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn prop<'a>(s: &'a str, key: &str) -> io::Result<&'a str> {
    let prefix = format!("{key}=");
    let mut values = s.lines().filter_map(|l| l.strip_prefix(&prefix));
    let value = values
        .next()
        .ok_or_else(|| bad("manager property absent"))?;
    if values.next().is_some() {
        return Err(bad("duplicate manager property"));
    }
    Ok(value)
}

fn proc_start(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let suffix = stat.rsplit_once(") ").ok_or_else(|| bad("proc stat"))?.1;
    suffix
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| bad("proc start absent"))?
        .parse()
        .map_err(|_| bad("proc start invalid"))
}

/// The daemon generation this owner will act for: the running boot and the
/// manager's own invocation of the daemon unit. One type for both readers that
/// used to spell this pair out separately, so the per-receipt freshness check
/// and the shutdown hint cannot drift into comparing different things.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DaemonGeneration {
    boot_id: String,
    daemon_invocation: String,
}

impl DaemonGeneration {
    /// Whether `g` names exactly this daemon generation. A receipt for any
    /// other boot or invocation describes a daemon that is no longer running,
    /// and acting on it would stop whatever holds that unit name now.
    fn names(&self, g: &receipt::Generation) -> bool {
        g.boot_id == self.boot_id && g.daemon_invocation == self.daemon_invocation
    }
}

/// The production reader. It is host-coupled by construction: the boot id comes
/// from the running kernel and the invocation from the service manager, so the
/// composition root supplies it and the handler never reads either directly.
fn live_daemon_generation() -> io::Result<DaemonGeneration> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let manager = fixed_manager_show(DAEMON_UNIT)?;
    Ok(DaemonGeneration {
        boot_id: boot.trim().to_owned(),
        daemon_invocation: prop(&manager, "InvocationID")?.to_owned(),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PeerKind {
    DaemonMain,
    StopNotifier,
}
fn peer_identity(stream: &UnixStream) -> io::Result<PeerKind> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut clen = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut _,
            &mut clen,
        )
    } != 0
        || clen as usize != std::mem::size_of::<libc::ucred>()
        || cred.uid != 0
        || cred.pid <= 0
    {
        return Err(bad("peer credentials"));
    }
    let mut pidfd: libc::c_int = -1;
    let mut plen = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            PEERPIDFD,
            &mut pidfd as *mut _ as *mut _,
            &mut plen,
        )
    } != 0
        || plen as usize != std::mem::size_of::<libc::c_int>()
        || pidfd < 0
    {
        return Err(bad("SO_PEERPIDFD unavailable"));
    }
    let held = unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) };
    let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", held.as_raw_fd()))?;
    let pidline = info
        .lines()
        .find_map(|l| l.strip_prefix("Pid:\t"))
        .ok_or_else(|| bad("pidfd identity"))?;
    if pidline.parse::<i32>().map_err(|_| bad("pidfd pid"))? != cred.pid {
        return Err(bad("pidfd/peer mismatch"));
    }
    let show = fixed_manager_show(DAEMON_UNIT)?;
    let manager_pid: u32 = prop(&show, "MainPID")?
        .parse()
        .map_err(|_| bad("daemon MainPID"))?;
    let control_pid: u32 = prop(&show, "ControlPID")?
        .parse()
        .map_err(|_| bad("daemon ControlPID"))?;
    let kind = if manager_pid == cred.pid as u32 {
        PeerKind::DaemonMain
    } else if control_pid == cred.pid as u32 {
        PeerKind::StopNotifier
    } else {
        return Err(bad("peer not manager daemon or stop notifier"));
    };
    if proc_start(cred.pid as u32)? == 0 {
        return Err(bad("peer start time"));
    }
    let exe = fs::read_link(format!("/proc/{}/exe", cred.pid))?;
    let expected = match kind {
        PeerKind::DaemonMain => "/usr/local/libexec/sanctuary/castle-wall-daemon",
        PeerKind::StopNotifier => "/usr/local/libexec/sanctuary/castle-wall-stop-notify-v1",
    };
    if exe != Path::new(expected) {
        return Err(bad("peer executable mismatch"));
    }
    let cgroup = fs::read_to_string(format!("/proc/{}/cgroup", cred.pid))?;
    let expected = prop(&show, "ControlGroup")?;
    if !cgroup.lines().any(|l| l == format!("0::{expected}")) {
        return Err(bad("peer cgroup mismatch"));
    }
    Ok(kind)
}

/// Decides one request and fsyncs whatever it accepts. The outcome it returns
/// is the WHOLE of its effect: acceptance here means a durable ledger row and
/// an answer, never that anything was stopped.
fn handle_action(
    req: Request,
    peer: PeerKind,
    ledger: &mut Ledger,
    pins: &Pins,
    daemon_private_parent: &Path,
    daemon_generation: &dyn Fn() -> io::Result<DaemonGeneration>,
) -> io::Result<OwnerOutcome> {
    if fs::read_dir(daemon_private_parent).is_ok() {
        return Err(bad("daemon private parent became readable"));
    }
    match req {
        Request::CompletionPull { .. } => Ok(OwnerOutcome::Inhibit),
        // DEBT(PR3B-REOFFER-PROTOCOL): the two handlers below are inert. No
        // daemon caller sends either request in this slice, so a daemon that
        // fsyncs a release and then crashes before its owner copy is delivered
        // has no path that reoffers the row; the record simply stays Prepared
        // on one side and released-unresolved on the other, which is the
        // conservative direction. They become live only when the producer
        // slice supplies the caller.
        Request::PreparedCheck {
            generation,
            manager,
        } => {
            if peer != PeerKind::DaemonMain {
                return Ok(OwnerOutcome::Inhibit);
            }
            if !daemon_generation()?.names(&generation) {
                return Ok(OwnerOutcome::Inhibit);
            }
            ledger.prepared_ack(&generation, &manager)?;
            Ok(OwnerOutcome::IntentAccepted)
        }
        // Inert for the same reason, and paired with the handler above: this
        // is the delivery half of the reoffer the producer slice will send.
        Request::ReleasedRowCopy(r) => {
            if peer != PeerKind::DaemonMain {
                return Ok(OwnerOutcome::Inhibit);
            }
            let (admission, _) = pins.validate().map_err(bad)?;
            receipt::verify(&r, Domain::ReleasedUnresolvedV1, &admission).map_err(bad)?;
            let g = &r.body.generation;
            if !daemon_generation()?.names(g) {
                return Ok(OwnerOutcome::Inhibit);
            }
            let Some(m) = r.body.manager.as_ref() else {
                return Ok(OwnerOutcome::Inhibit);
            };
            if let Some(existing) = ledger
                .state
                .generations
                .get(&g.unit_name)
                .and_then(|e| e.release.as_ref())
            {
                return if existing == &r {
                    Ok(OwnerOutcome::IntentAccepted)
                } else {
                    Ok(OwnerOutcome::Inhibit)
                };
            }
            ledger.prepared_ack(g, m)?;
            ledger.accept_release_copy(r)?;
            Ok(OwnerOutcome::IntentAccepted)
        }
        Request::StopFailure(r) => {
            if peer != PeerKind::DaemonMain {
                return Ok(OwnerOutcome::Inhibit);
            }
            let (admission, _) = pins.validate().map_err(bad)?;
            receipt::verify(&r, Domain::StopFailureV1, &admission).map_err(bad)?;
            let g = &r.body.generation;
            if !daemon_generation()?.names(g) {
                return Ok(OwnerOutcome::Inhibit);
            }
            let Some(entry) = ledger.state.generations.get(&g.unit_name) else {
                return Ok(OwnerOutcome::NoOwnedRelease);
            };
            if entry.prepared.as_ref() != Some(g)
                || entry.manager.as_ref() != r.body.manager.as_ref()
                || !entry.is_open()
            {
                return Ok(OwnerOutcome::Inhibit);
            }
            // A record that names no manager identity names no cgroup, so an
            // accepted attempt against it could never resolve to anything.
            if entry.manager.is_none() {
                return Ok(OwnerOutcome::Inhibit);
            }
            let Some(id) = r.body.attempt_id.as_ref() else {
                return Ok(OwnerOutcome::Inhibit);
            };
            let command_hash = hex::encode(Sha256::digest(
                serde_json::to_vec(&r).map_err(|_| bad("command encode"))?,
            ));
            let release_hash = entry
                .release
                .as_ref()
                .map(ledger::receipt_hash)
                .transpose()?;
            if r.body.old_release_hash != release_hash {
                return Ok(OwnerOutcome::Inhibit);
            }
            ledger.accept_attempt(&g.unit_name, id, &command_hash, release_hash.as_deref())?;
            // The fsynced attempt row IS the acceptance this answer reports,
            // and in this slice it is also the end of it: nothing downstream
            // acts on the row.
            Ok(OwnerOutcome::IntentAccepted)
        }
        Request::StopHint {
            boot_id,
            daemon_invocation,
        } => {
            if peer != PeerKind::StopNotifier {
                return Ok(OwnerOutcome::Inhibit);
            }
            let live = daemon_generation()?;
            if boot_id != live.boot_id || daemon_invocation != live.daemon_invocation {
                return Ok(OwnerOutcome::Inhibit);
            }
            let targets: Vec<_> = ledger
                .state
                .generations
                .values()
                .filter_map(|e| {
                    let g = e.prepared.as_ref()?;
                    if e.is_open()
                        && g.boot_id == boot_id
                        && g.daemon_invocation == daemon_invocation
                    {
                        Some((g.clone(), e.manager.clone()))
                    } else {
                        None
                    }
                })
                .collect();
            if targets.is_empty() {
                return Ok(OwnerOutcome::NoOwnedRelease);
            }
            let mut accepted = 0usize;
            for (g, m) in targets {
                // A record that names no manager identity names no cgroup, so
                // there is nothing an accepted attempt against it could ever
                // resolve to; leaving it unaccepted is the refusing direction.
                if m.is_none() {
                    continue;
                }
                let release_hash = ledger
                    .state
                    .generations
                    .get(&g.unit_name)
                    .and_then(|e| e.release.as_ref())
                    .map(ledger::receipt_hash)
                    .transpose()?;
                let id = format!("hint:{boot_id}:{daemon_invocation}");
                let hash = hex::encode(Sha256::digest(id.as_bytes()));
                ledger.accept_attempt(&g.unit_name, &id, &hash, release_hash.as_deref())?;
                accepted += 1;
            }
            // Same contract as the failure hook: the notifier's answer reports
            // fsynced acceptance and never waits for extinction, which is what
            // keeps shutdown inside TimeoutStopSec. An answer of acceptance is
            // owed exactly one durable row, so a scan that accepted none of its
            // targets reports NoOwnedRelease rather than an empty acceptance.
            Ok(if accepted > 0 {
                OwnerOutcome::IntentAccepted
            } else {
                OwnerOutcome::NoOwnedRelease
            })
        }
    }
}

fn handle(
    req: Request,
    peer: PeerKind,
    ledger: &mut Ledger,
    pins: &Pins,
    daemon_private_parent: &Path,
    daemon_generation: &dyn Fn() -> io::Result<DaemonGeneration>,
) -> io::Result<Response> {
    if let Request::CompletionPull { unit_name } = req {
        if peer != PeerKind::DaemonMain || fs::read_dir(daemon_private_parent).is_ok() {
            return Ok(Response {
                outcome: OwnerOutcome::Inhibit,
                completion: None,
            });
        }
        let completion = ledger.state.generations.get(&unit_name).and_then(|e| {
            if e.release.is_some() {
                e.outcome.clone()
            } else {
                None
            }
        });
        return Ok(Response {
            outcome: if completion.is_some() {
                OwnerOutcome::IntentAccepted
            } else {
                OwnerOutcome::NoOwnedRelease
            },
            completion,
        });
    }
    let outcome = handle_action(
        req,
        peer,
        ledger,
        pins,
        daemon_private_parent,
        daemon_generation,
    )?;
    Ok(Response {
        outcome,
        completion: None,
    })
}

/// Writes the client's answer, which is where one request ends.
///
/// The answer reports fsynced acceptance of INTENT and never completion, so it
/// must not wait for `StopUnit`, a grace period or positive extinction: a
/// populated target alone can hold those far past the client's single 250 ms
/// budget. In this slice nothing waits on any of them, because nothing runs
/// them.
///
/// DEBT(PR3B-STOP-EXECUTION): execution attaches HERE, after the answer is on
/// the wire, when the producer slice supplies the caller that needs it. It is
/// ABSENT rather than disabled: this binary has no stop worker, no queue, no
/// dispatch and no resume scan, and `accepted intent, never execution` is the
/// whole of the property this owner enforces today. The invariant a reader must
/// hold: an `IntentAccepted` from this owner means a durable attempt row exists,
/// never that anything was stopped. Whatever attaches here must preserve the
/// order this function fixes -- fsynced intent, then answer, then execution --
/// because an execution that ran before the answer would put a populated
/// target's extinction budget inside the client deadline.
fn respond(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(|_| bad("response"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(bad("owner response oversized"));
    }
    let _ = stream.set_write_timeout(Some(CLIENT_DEADLINE));
    let _ = stream.write_all(&bytes);
    let _ = stream.write_all(b"\n");
    Ok(())
}

/// One serving session: the accept loop and the ledger it answers from.
///
/// `serve_production` supplies the installed paths, the real peer
/// authentication and the real daemon-generation reader. Those two are
/// host-coupled by construction (peer identity needs `SO_PEERPIDFD` plus the
/// service manager's own view of its pids and cgroup; the daemon generation
/// needs the running kernel and that manager), so they are the steps a test
/// stands in for, and everything else on this path -- the framed read, the
/// handler, the ledger's fsynced acceptance and the answer -- is the shipped
/// code in either case.
struct Serving<'a> {
    pins: &'a Pins,
    daemon_private_parent: &'a Path,
    /// One writer, and the lock is held only across a handler. It is a lock
    /// rather than a plain field because the handlers take `&self`, not because
    /// a second thread writes: this session spawns none.
    ledger: Mutex<Ledger>,
    // `Sync` because one serving session is shared with the threads that drive
    // it; both stand-ins are read-only, so this costs the composition root
    // nothing and keeps `Serving` shareable.
    identify: &'a (dyn Fn(&UnixStream) -> io::Result<PeerKind> + Sync),
    daemon_generation: &'a (dyn Fn() -> io::Result<DaemonGeneration> + Sync),
}

impl Serving<'_> {
    /// Serves one accepted connection: identify the peer, read one framed
    /// request, run the handler (which fsyncs any acceptance it grants), and
    /// write the answer. That order is the contract: fsynced intent, then
    /// answer. Every failure inside it answers INHIBIT, which is the refusing
    /// direction, and never an acceptance.
    fn serve_connection(&self, stream: &mut UnixStream) -> io::Result<()> {
        let answered = match (self.identify)(stream) {
            Ok(peer) => read_message(stream).and_then(|request| {
                let mut ledger = self
                    .ledger
                    .lock()
                    .map_err(|_| bad("owner ledger lock poisoned"))?;
                handle(
                    request,
                    peer,
                    &mut ledger,
                    self.pins,
                    self.daemon_private_parent,
                    self.daemon_generation,
                )
            }),
            Err(e) => Err(e),
        };
        let response = answered.unwrap_or(Response {
            outcome: OwnerOutcome::Inhibit,
            completion: None,
        });
        respond(stream, &response)
    }

    /// The accept loop. `keep_serving` is always true in production; a test
    /// uses it to end the loop, and it is checked once per pass so the loop
    /// leaves within one `ACCEPT_IDLE_SLEEP`.
    fn run(&self, listener: &UnixListener, keep_serving: &dyn Fn() -> bool) -> io::Result<()> {
        let mut last_watch = Instant::now();
        while keep_serving() {
            match listener.accept() {
                Ok((mut stream, _)) => self.serve_connection(&mut stream)?,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_IDLE_SLEEP)
                }
                Err(e) => return Err(e),
            }
            if last_watch.elapsed() >= WATCHDOG_INTERVAL {
                watchdog_ping()?;
                last_watch = Instant::now();
            }
        }
        Ok(())
    }
}

fn read_message(stream: &mut UnixStream) -> io::Result<Request> {
    let deadline = Instant::now() + CLIENT_DEADLINE;
    let mut bytes = Vec::new();
    let mut one = [0u8; 1];
    while bytes.len() < MAX_WIRE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owner request deadline",
            ));
        }
        stream.set_read_timeout(Some(remaining))?;
        stream.read_exact(&mut one)?;
        if one[0] == b'\n' {
            break;
        }
        bytes.push(one[0]);
    }
    if bytes.len() == MAX_WIRE {
        return Err(bad("request oversized"));
    }
    serde_json::from_slice(&bytes).map_err(|_| bad("request invalid"))
}

pub fn serve_production() -> io::Result<()> {
    let paths = OwnerPaths::installed();
    if unsafe { libc::geteuid() } != 0 {
        return Err(bad("owner requires root"));
    }
    exact_dir(Path::new(RUNTIME_PARENT), 0, 0, 0o700)?;
    exact_dir(&paths.owner_private_parent, 0, 0, 0o700)?;
    // Owner private state must be inaccessible from the daemon; the daemon
    // private parent is masked in the installed owner unit. Refuse if readable.
    if fs::read_dir(&paths.daemon_private_parent).is_ok() {
        return Err(bad("daemon private directory readable"));
    }
    let pins = read_pins(&paths.pins)?;
    // A startup precondition, not a live signer: this slice signs no completion
    // at all. An owner whose completion key is absent, wrongly custodied or off
    // its pin could never close a record it accepted, so it refuses to start
    // here rather than accepting intent it is structurally unable to resolve.
    read_owner_key(&paths.completion_key, &pins)?;
    // The fixed agent/profile and registry are required installed inputs, even
    // though this binary has no CREATE arm. Missing artifacts cannot make an
    // apparently ready owner for a later protected release.
    super::profile::validate_installed()?;
    let ledger = Ledger::open(&paths.ledger)?;
    ledger.validate_signatures(&pins)?;
    // An existing socket path means another owner may be listening on it, and
    // binding over it would split stop authority between two processes, so this
    // refuses rather than unlinking. It is safe to refuse rather than clean up
    // ONLY because the socket's parent is a systemd RuntimeDirectory= with no
    // RuntimeDirectoryPreserve=, so systemd removes the directory and this
    // inode with it on every stop of the unit, including the stop before a
    // restart. MUST MATCH `RuntimeDirectory=sanctuary-stop-owner` in
    // `systemd/sanctuary-stop-owner.service`; adding RuntimeDirectoryPreserve
    // there would turn a crash into a permanent refusal to start here.
    if paths.socket.exists() {
        return Err(bad("owner socket already exists"));
    }
    let listener = UnixListener::bind(&paths.socket)?;
    listener.set_nonblocking(true)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&paths.socket, fs::Permissions::from_mode(0o600))?;
    exact_socket(&paths.socket)?;
    // One ledger handle, written only by the accept loop. This composition root
    // spawns no thread of its own, so the flock taken by `Ledger::open` and this
    // single writer are the whole of the concurrency story.
    let ledger = Mutex::new(ledger);
    let mut ready = crate::systemd_notify::ReadyBeacon::from_env();
    ready
        .signal_ready()
        .map_err(|_| bad("owner READY notify"))?;
    let identify = peer_identity;
    let daemon_generation = live_daemon_generation;
    let serving = Serving {
        pins: &pins,
        daemon_private_parent: &paths.daemon_private_parent,
        ledger,
        identify: &identify,
        daemon_generation: &daemon_generation,
    };
    serving.run(&listener, &|| true)
}

fn watchdog_ping() -> io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let sock = UnixDatagram::unbound()?;
    let bytes = path.as_bytes();
    if let Some(name) = bytes.strip_prefix(b"@") {
        use std::os::{linux::net::SocketAddrExt, unix::net::SocketAddr};
        let address = SocketAddr::from_abstract_name(name)?;
        sock.send_to_addr(b"WATCHDOG=1\n", &address)?;
    } else {
        sock.send_to(b"WATCHDOG=1\n", Path::new(&path))?;
    }
    Ok(())
}

/// Fixed owner-client transport: one monotonic 250 ms connect + response
/// budget. A timeout never counts as an accepted stop intent.
pub fn request(req: &Request) -> io::Result<Response> {
    request_to(&OwnerPaths::installed().socket, req)
}

fn request_to(socket_path: &Path, req: &Request) -> io::Result<Response> {
    let wire = serde_json::to_vec(req).map_err(|_| bad("request encode"))?;
    if wire.len() + 1 > MAX_WIRE {
        return Err(bad("request oversized"));
    }
    let deadline = Instant::now() + CLIENT_DEADLINE;
    let mut stream = nonblocking_connect(socket_path, deadline)?;
    let mut sent = 0;
    let mut bytes = wire;
    bytes.push(b'\n');
    while sent < bytes.len() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "owner deadline"));
        }
        match stream.write(&bytes[sent..]) {
            Ok(0) => return Err(bad("owner closed")),
            Ok(n) => sent += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(stream.as_raw_fd(), libc::POLLOUT, deadline)?
            }
            Err(e) => return Err(e),
        }
    }
    let mut reply = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "owner deadline"));
        }
        match stream.read(&mut one) {
            Ok(0) => return Err(bad("owner closed")),
            Ok(_) => {
                if one[0] == b'\n' {
                    break;
                }
                reply.push(one[0]);
                if reply.len() > MAX_RESPONSE {
                    return Err(bad("owner response oversized"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait_fd(stream.as_raw_fd(), libc::POLLIN, deadline)?
            }
            Err(e) => return Err(e),
        }
    }
    serde_json::from_slice(&reply).map_err(|_| bad("owner response invalid"))
}

fn wait_fd(fd: RawFd, events: i16, deadline: Instant) -> io::Result<()> {
    let now = Instant::now();
    if now >= deadline {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "owner deadline"));
    }
    let mut pfd = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let ms = deadline
        .saturating_duration_since(now)
        .as_millis()
        .min(i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut pfd, 1, ms) };
    if result <= 0 {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "owner deadline"));
    }
    // The awaited readiness is honoured before any hangup. An owner that writes
    // a complete answer and closes immediately leaves POLLIN and POLLHUP set
    // together, and a hangup never discards bytes already in this socket's
    // receive queue, so treating it as fatal here would throw away an answer the
    // owner did send and report an unavailable owner to a daemon that was in
    // fact answered. Nothing can hang on this: the caller drains to end of file
    // and gets `owner closed` when the queue is empty, and POLLERR and POLLNVAL
    // carry no drainable data and stay fatal.
    if pfd.revents & events != 0 {
        return Ok(());
    }
    if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
        return Err(bad("owner socket error"));
    }
    Ok(())
}

fn nonblocking_connect(socket_path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as _;
    let path = socket_path.as_os_str().as_bytes();
    if path.len() >= addr.sun_path.len() {
        unsafe { libc::close(fd) };
        return Err(bad("socket path too long"));
    }
    for (dest, src) in addr.sun_path.iter_mut().zip(path) {
        // c_char is i8 on glibc x86_64 and u8 on musl and aarch64; the cast must name the
        // platform type or the static musl build of this library fails to compile.
        *dest = *src as libc::c_char;
    }
    let len = (std::mem::size_of::<libc::sa_family_t>() + path.len() + 1) as libc::socklen_t;
    let rc = unsafe { libc::connect(fd, &addr as *const _ as *const libc::sockaddr, len) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EINPROGRESS) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        if let Err(e) = wait_fd(fd, libc::POLLOUT, deadline) {
            unsafe { libc::close(fd) };
            return Err(e);
        }
        let mut so_error: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut so_error as *mut _ as *mut _,
                &mut size,
            )
        } < 0
            || size as usize != std::mem::size_of::<libc::c_int>()
            || so_error != 0
        {
            unsafe { libc::close(fd) };
            return Err(bad("owner connect failed"));
        }
    }
    Ok(unsafe { UnixStream::from_raw_fd(fd) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The isolated layout, built by the SAME constructor the integration seam
    /// binds, so a unit test and an isolated suite cannot be proving their
    /// containment against two different trees.
    fn temporary_paths(dir: &Path) -> OwnerPaths {
        OwnerPaths::isolated_under(dir)
    }

    #[test]
    fn an_absent_owner_socket_answers_unavailable_without_reading_anything_else() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temporary_paths(dir.path());
        // Nothing else in this tree exists, so any read beyond the socket would
        // have to reach a host-global name to find anything at all.
        assert_eq!(
            stop_failure_for_hook_at(
                &paths,
                &[1001],
                "post-ready ownership reading indeterminate",
                None
            ),
            OwnerOutcome::OwnerUnavailable
        );
        assert!(!paths.pins.exists());
        assert!(!paths.release_log.exists());
        // And the production entry point refuses in a test build unless a test
        // binds its own tree, so a lib test cannot reach the installed owner.
        assert_eq!(
            stop_failure_for_hook(&[1001], "post-ready ownership reading indeterminate", None),
            OwnerOutcome::OwnerUnavailable
        );
        let _bound = test_paths::bind(paths);
        assert_eq!(
            stop_failure_for_hook(&[1001], "post-ready ownership reading indeterminate", None),
            OwnerOutcome::OwnerUnavailable
        );
    }

    fn fixture_generation() -> receipt::Generation {
        let mut g = receipt::Generation {
            boot_id: "boot".into(),
            daemon_invocation: "inv".into(),
            fortress_id: "abcdef12".into(),
            manifest_generation: "m".into(),
            ownership_generation: "o".into(),
            reservation_nonce: "a".repeat(64),
            reservation_hash: "b".repeat(64),
            account: "agent".into(),
            uid: 1001,
            gid: 1001,
            profile_id: "agent-v1".into(),
            profile_hash: "c".repeat(64),
            executable_sha256: "d".repeat(64),
            unit_name: String::new(),
        };
        g.unit_name = receipt::deterministic_unit_name(&g);
        g
    }

    fn fixture_manager() -> ManagerIdentity {
        let unit_name = fixture_generation().unit_name;
        ManagerIdentity {
            cgroup_path: format!("system.slice/{unit_name}"),
            unit_name,
            cgroup_dev: 1,
            cgroup_ino: 2,
            main_pid: 10,
            main_start_time: 100,
        }
    }

    fn fixture_hint() -> Request {
        Request::StopHint {
            boot_id: "fixture".into(),
            daemon_invocation: "fixture".into(),
        }
    }

    fn fixture_pins(
        admission: &ed25519_dalek::SigningKey,
        completion: &ed25519_dalek::SigningKey,
    ) -> Pins {
        Pins {
            schema: 1,
            algorithm: "ed25519".into(),
            admission_public: hex::encode(admission.verifying_key().as_bytes()),
            admission_key_id: receipt::key_id(&admission.verifying_key()),
            completion_public: hex::encode(completion.verifying_key().as_bytes()),
            completion_key_id: receipt::key_id(&completion.verifying_key()),
        }
    }

    fn signed_stop_failure(
        g: &receipt::Generation,
        m: &ManagerIdentity,
        attempt_id: &str,
        key: &ed25519_dalek::SigningKey,
    ) -> SignedReceipt {
        let body = receipt::ReceiptBody {
            generation: g.clone(),
            manager: Some(m.clone()),
            hook: Some("post-ready ownership reading indeterminate".to_owned()),
            attempt_id: Some(attempt_id.to_owned()),
            attempted_scope: None,
            candidate_uids: vec![g.uid],
            old_release_hash: None,
            positive_extinction: None,
        };
        receipt::sign(Domain::StopFailureV1, body, key).expect("a stop-failure body signs")
    }

    #[test]
    fn the_pins_custody_walk_covers_every_directory_above_the_file_but_not_the_root() {
        let parent = Path::new(receipt::PINS_PATH)
            .parent()
            .expect("the installed pins path has a parent");
        assert_eq!(
            custody_ancestors(parent),
            vec![
                Path::new("/etc/sanctuary/launcher"),
                Path::new("/etc/sanctuary"),
                Path::new("/etc"),
            ],
            "the walk covers every directory the explicit base list covered, and stops above the \
             filesystem root"
        );
    }

    #[test]
    fn an_injected_owner_tree_holds_every_name_the_owner_and_its_hook_read() {
        let dir = tempfile::tempdir().unwrap();
        let paths = temporary_paths(dir.path());
        for path in paths.every_path() {
            assert!(
                path.starts_with(dir.path()),
                "an injected tree must contain every name the owner reads: {path:?}"
            );
        }
        // The installed layout still points the two key names at the files the
        // daemon and the owner actually install, so the injected tree above is
        // a substitution and not a divergence.
        let installed = OwnerPaths::installed();
        assert_eq!(
            installed.journal_mac_key,
            Path::new(crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH)
        );
        assert_eq!(
            installed.completion_key,
            Path::new(receipt::COMPLETION_KEY_PATH)
        );
        for path in installed.every_path() {
            assert!(!path.starts_with(dir.path()));
        }
        // And the same containment holds through the binding the hook itself
        // resolves, so this is a property of what the hook reaches and not only
        // of the constructor a test calls.
        let _bound = test_paths::bind(paths.clone());
        let resolved = hook_paths().expect("a bound tree resolves");
        for path in resolved.every_path() {
            assert!(
                path.starts_with(dir.path()),
                "the bound tree must be the only tree the hook resolves: {path:?}"
            );
        }
    }

    #[test]
    fn an_isolated_tree_is_one_that_cannot_reach_an_installed_name() {
        let dir = tempfile::tempdir().unwrap();
        assert!(temporary_paths(dir.path()).is_isolated_from_production());
        // A tree rooted INSIDE the daemon's own private parent carries no
        // installed file name of its own, so only the containment direction
        // refuses it; an equality check would call it isolated while it sat in
        // operator state.
        assert!(
            !OwnerPaths::isolated_under(Path::new(DAEMON_PRIVATE_PARENT))
                .is_isolated_from_production()
        );
        // And the installed layout is never isolated from itself.
        assert!(!OwnerPaths::installed().is_isolated_from_production());
    }

    #[test]
    fn an_answer_written_before_the_owner_closes_is_still_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&path).unwrap();
        // A quarter of the client's own budget: long enough that the client is
        // already parked in poll when the answer and the close arrive together,
        // and short enough that the assertion is about the answer rather than
        // about the deadline.
        let parked = CLIENT_DEADLINE / 4;
        let owner = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_message(&mut stream).unwrap();
            std::thread::sleep(parked);
            let answer = serde_json::to_vec(&Response {
                outcome: OwnerOutcome::IntentAccepted,
                completion: None,
            })
            .unwrap();
            stream.write_all(&answer).unwrap();
            stream.write_all(b"\n").unwrap();
            drop(stream);
        });
        let reply = request_to(&path, &fixture_hint()).unwrap();
        assert_eq!(reply.outcome, OwnerOutcome::IntentAccepted);
        owner.join().unwrap();

        // And a close with nothing to drain is still a failure, so honouring
        // the readable flag has not made a silent owner look like an answer.
        let quiet_path = dir.path().join("quiet.sock");
        let quiet = UnixListener::bind(&quiet_path).unwrap();
        let silent = std::thread::spawn(move || {
            let (mut stream, _) = quiet.accept().unwrap();
            read_message(&mut stream).unwrap();
            drop(stream);
        });
        assert!(request_to(&quiet_path, &fixture_hint()).is_err());
        silent.join().unwrap();
    }

    #[test]
    fn every_acceptance_the_accept_loop_answers_is_durable_before_the_answer_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let admission = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let completion = ed25519_dalek::SigningKey::from_bytes(&[4; 32]);
        let pins = fixture_pins(&admission, &completion);
        let g = fixture_generation();
        let m = fixture_manager();
        let ledger_path = dir.path().join("owner-ledger-v1.log");
        let mut opened = Ledger::open(&ledger_path).unwrap();
        opened.prepare_fixture(g.clone()).unwrap();
        opened
            .manager_created_fixture(g.unit_name.clone(), m.clone())
            .unwrap();

        let socket = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        // Never created, so the handler's reciprocal-mask check passes exactly
        // as it does against the installed mask.
        let daemon_private_parent = dir.path().join("daemon-private");
        let live = DaemonGeneration {
            boot_id: g.boot_id.clone(),
            daemon_invocation: g.daemon_invocation.clone(),
        };
        // The two host-coupled steps, and only those, are supplied here; the
        // framed read, the handler, the fsynced acceptance and the answer below
        // are the shipped path.
        let identify = |_: &UnixStream| -> io::Result<PeerKind> { Ok(PeerKind::DaemonMain) };
        let daemon_generation = || -> io::Result<DaemonGeneration> { Ok(live.clone()) };
        let serving = Serving {
            pins: &pins,
            daemon_private_parent: &daemon_private_parent,
            ledger: Mutex::new(opened),
            identify: &identify,
            daemon_generation: &daemon_generation,
        };
        let serving_on = AtomicBool::new(true);
        /// Ends the accept loop on EVERY exit from the scope body, including an
        /// unwind. Failure mode without it: one failed assertion leaves the flag
        /// true, `thread::scope` blocks forever joining a serving thread that
        /// never returns, and the suite reports a hang instead of the assertion
        /// that failed.
        struct EndServing<'a>(&'a AtomicBool);
        impl Drop for EndServing<'_> {
            fn drop(&mut self) {
                self.0.store(false, Ordering::SeqCst);
            }
        }
        std::thread::scope(|scope| {
            let _end = EndServing(&serving_on);
            scope.spawn(|| {
                serving
                    .run(&listener, &|| serving_on.load(Ordering::SeqCst))
                    .unwrap()
            });
            // Two requests through one loop: the second proves the loop is still
            // serving after the first answer, and both answers are measured
            // against the client's own budget.
            for attempt_id in ["1", "2"] {
                let start = Instant::now();
                let reply = request_to(
                    &socket,
                    &Request::StopFailure(signed_stop_failure(
                        &g,
                        &m,
                        &attempt_id.repeat(64),
                        &admission,
                    )),
                )
                .unwrap();
                let elapsed = start.elapsed();
                assert_eq!(reply.outcome, OwnerOutcome::IntentAccepted);
                assert!(
                    elapsed < CLIENT_DEADLINE,
                    "an acceptance must arrive inside one client deadline: {elapsed:?}"
                );
            }
        });
        drop(serving);
        // Both acceptances went through the ledger, so both replay from disk in
        // a fresh handle: the answers reported rows that are actually there, and
        // the record stays OPEN because nothing in this slice closes it.
        let replayed = Ledger::open(&ledger_path).unwrap();
        let entry = &replayed.state.generations[&g.unit_name];
        assert_eq!(entry.attempts.len(), 2);
        assert!(entry.is_open());
        assert!(
            entry.outcome.is_none(),
            "no code path here records a stop outcome, so an accepted record stays open"
        );
    }

    #[test]
    fn socket_response_stall_obeys_one_client_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let held = std::thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            std::thread::sleep(Duration::from_millis(600));
        });
        let start = Instant::now();
        let err = request_to(
            &path,
            &Request::StopHint {
                boot_id: "fixture".into(),
                daemon_invocation: "fixture".into(),
            },
        )
        .unwrap_err();
        let elapsed = start.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            elapsed < Duration::from_millis(450),
            "deadline drift: {elapsed:?}"
        );
        held.join().unwrap();
    }
}
