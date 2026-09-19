//! Independent stop owner. The shipped binary can stop a previously durable,
//! exact owned cgroup; it cannot create a unit or accept release/exec authority.
use super::{
    ledger::{self, Ledger},
    receipt::{self, Domain, ManagerIdentity, Pins, SignedReceipt},
    stop_policy::{self, HookRoute, MainProcessAuthority},
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
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            net::{UnixDatagram, UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
#[derive(Clone, Debug)]
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
        }
    }
}

/// Which paths the daemon-side hook speaks to. Production is always the
/// installed set. In a test build the hook refuses unless a test has bound a
/// temporary tree for itself, so a lib test cannot reach an installed owner by
/// forgetting to: this divergence only ever makes the test build MORE
/// refusing, and never enables a path that production would not take.
#[cfg(not(test))]
fn hook_paths() -> Option<OwnerPaths> {
    Some(OwnerPaths::installed())
}
#[cfg(test)]
fn hook_paths() -> Option<OwnerPaths> {
    test_paths::bound()
}

#[cfg(test)]
mod test_paths {
    //! Binds the daemon-side hook to a temporary tree for the duration of one
    //! test, so no test run reads an installed pins file, release log, key or
    //! socket.
    use super::OwnerPaths;
    use std::cell::RefCell;

    thread_local! {
        static BOUND: RefCell<Option<OwnerPaths>> = const { RefCell::new(None) };
    }

    pub fn bound() -> Option<OwnerPaths> {
        BOUND.with(|slot| slot.borrow().clone())
    }

    /// Binds `paths` until the returned guard drops.
    pub fn bind(paths: OwnerPaths) -> Guard {
        BOUND.with(|slot| *slot.borrow_mut() = Some(paths));
        Guard
    }

    pub struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            BOUND.with(|slot| *slot.borrow_mut() = None);
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

fn read_pins(pins_path: &Path) -> io::Result<Pins> {
    // Every directory above the pins file must be a root-owned 0755 directory.
    // A writable ancestor would let a non-root user replace the pinned keys and
    // so choose which receipts verify, which is the whole trust root here. The
    // walk is derived from the path actually read, so the custody check cannot
    // drift away from the file it protects.
    let parent = pins_path.parent().ok_or_else(|| bad("pins parent"))?;
    for ancestor in parent.ancestors() {
        exact_dir(ancestor, 0, 0, 0o755)?;
    }
    let bytes = receipt::read_custodied_file(pins_path, 0, &[0], 0o644, 4096)?;
    let pins: Pins = serde_json::from_slice(&bytes).map_err(|_| bad("invalid pins"))?;
    pins.validate().map_err(bad)?;
    Ok(pins)
}

fn read_owner_key(pins: &Pins) -> io::Result<ed25519_dalek::SigningKey> {
    let mut bytes =
        receipt::read_custodied_file(Path::new(receipt::COMPLETION_KEY_PATH), 0, &[0], 0o600, 128)?;
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
        let mut log = super::daemon_log::replay(&paths.release_log, &pins)?;
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
                        completion,
                        &pins,
                    )?;
                    log = super::daemon_log::replay(&paths.release_log, &pins)?;
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

fn current_daemon_generation(g: &receipt::Generation) -> io::Result<bool> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let manager = fixed_manager_show(DAEMON_UNIT)?;
    Ok(g.boot_id == boot.trim() && g.daemon_invocation == prop(&manager, "InvocationID")?)
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

fn exact_cgroup(m: &ManagerIdentity) -> io::Result<PathBuf> {
    let show = fixed_manager_show(&m.unit_name)?;
    let group = prop(&show, "ControlGroup")?;
    if group != format!("/{}", m.cgroup_path) {
        return Err(bad("manager cgroup moved"));
    }
    let path = Path::new("/sys/fs/cgroup").join(&m.cgroup_path);
    let hierarchy = fs::symlink_metadata("/sys/fs/cgroup/cgroup.controllers")?;
    if !hierarchy.file_type().is_file() {
        return Err(bad("not unified cgroup v2"));
    }
    let meta = fs::symlink_metadata(&path)?;
    if !meta.file_type().is_dir() || meta.dev() != m.cgroup_dev || meta.ino() != m.cgroup_ino {
        return Err(bad("cgroup identity mismatch"));
    }
    Ok(path)
}

fn populated(path: &Path) -> io::Result<bool> {
    let mut opts = fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut s = String::new();
    opts.open(path.join("cgroup.events"))?
        .take(4096)
        .read_to_string(&mut s)?;
    let values: Vec<_> = s
        .lines()
        .filter_map(|l| l.strip_prefix("populated "))
        .collect();
    if values.len() != 1 {
        return Err(bad("cgroup.events populated missing"));
    }
    match values[0] {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(bad("bad populated value")),
    }
}

fn manager_stop(m: &ManagerIdentity) -> io::Result<()> {
    let path = exact_cgroup(m)?;
    let show = fixed_manager_show(&m.unit_name)?;
    let pid: u32 = prop(&show, "MainPID")?
        .parse()
        .map_err(|_| bad("main pid"))?;
    // The exact cgroup tuple above is the stop authority; the original main
    // process only corroborates it. A pid that has already left /proc is an
    // exit, not a foreign main, and its descendants can still be inside the
    // owned cgroup, so `NotFound` here must not become a refusal to act.
    let start = match pid {
        0 => None,
        pid => match proc_start(pid) {
            Ok(start) => Some(start),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        },
    };
    if stop_policy::main_process_authority(pid, start, m) == MainProcessAuthority::Foreign {
        return Err(bad("main process changed"));
    }
    let mut child = Command::new("/usr/bin/systemctl")
        .args(["--no-block", "stop", &m.unit_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(bad("StopUnit refused"));
            }
            break;
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(bad("StopUnit timeout"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let grace = Instant::now() + Duration::from_millis(300);
    while Instant::now() < grace {
        if !populated(&path)? {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if populated(&path)? {
        let path = exact_cgroup(m)?; // repeat identity before kernel kill
        let mut opts = fs::OpenOptions::new();
        opts.write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        opts.open(path.join("cgroup.kill"))?.write_all(b"1")?;
    }
    let until = Instant::now() + Duration::from_secs(2);
    while Instant::now() < until {
        let path = exact_cgroup(m)?;
        if !populated(&path)? {
            let show = fixed_manager_show(&m.unit_name)?;
            if matches!(prop(&show, "ActiveState")?, "inactive" | "failed") {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(bad("positive extinction/producer closure unproved"))
}

/// A stop whose intent row is already fsynced and acknowledged. It is carried
/// back out of the handler so the client's ACK can be written first: the ACK
/// means accepted intent, never completion, and executing the stop inside the
/// handler would put a populated target's grace period and extinction budget
/// inside the client's single 250 ms deadline.
struct AcceptedStop {
    generation: receipt::Generation,
    manager: ManagerIdentity,
}

fn handle_action(
    req: Request,
    peer: PeerKind,
    ledger: &mut Ledger,
    pins: &Pins,
    daemon_private_parent: &Path,
) -> io::Result<(OwnerOutcome, Vec<AcceptedStop>)> {
    if fs::read_dir(daemon_private_parent).is_ok() {
        return Err(bad("daemon private parent became readable"));
    }
    match req {
        Request::CompletionPull { .. } => Ok((OwnerOutcome::Inhibit, Vec::new())),
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
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            if !current_daemon_generation(&generation)? {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            ledger.prepared_ack(&generation, &manager)?;
            Ok((OwnerOutcome::IntentAccepted, Vec::new()))
        }
        // Inert for the same reason, and paired with the handler above: this
        // is the delivery half of the reoffer the producer slice will send.
        Request::ReleasedRowCopy(r) => {
            if peer != PeerKind::DaemonMain {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let (admission, _) = pins.validate().map_err(bad)?;
            receipt::verify(&r, Domain::ReleasedUnresolvedV1, &admission).map_err(bad)?;
            let g = &r.body.generation;
            if !current_daemon_generation(g)? {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let Some(m) = r.body.manager.as_ref() else {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            };
            if let Some(existing) = ledger
                .state
                .generations
                .get(&g.unit_name)
                .and_then(|e| e.release.as_ref())
            {
                return if existing == &r {
                    Ok((OwnerOutcome::IntentAccepted, Vec::new()))
                } else {
                    Ok((OwnerOutcome::Inhibit, Vec::new()))
                };
            }
            ledger.prepared_ack(g, m)?;
            ledger.accept_release_copy(r)?;
            Ok((OwnerOutcome::IntentAccepted, Vec::new()))
        }
        Request::StopFailure(r) => {
            if peer != PeerKind::DaemonMain {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let (admission, _) = pins.validate().map_err(bad)?;
            receipt::verify(&r, Domain::StopFailureV1, &admission).map_err(bad)?;
            let g = &r.body.generation;
            if !current_daemon_generation(g)? {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let Some(entry) = ledger.state.generations.get(&g.unit_name) else {
                return Ok((OwnerOutcome::NoOwnedRelease, Vec::new()));
            };
            if entry.prepared.as_ref() != Some(g)
                || entry.manager.as_ref() != r.body.manager.as_ref()
                || !entry.is_open()
            {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let Some(m) = entry.manager.clone() else {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            };
            let Some(id) = r.body.attempt_id.as_ref() else {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
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
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            ledger.accept_attempt(&g.unit_name, id, &command_hash, release_hash.as_deref())?;
            // The fsynced attempt row IS the acceptance this ACK reports. The
            // stop itself is handed back to the caller so it runs after the
            // answer is on the wire.
            Ok((
                OwnerOutcome::IntentAccepted,
                vec![AcceptedStop {
                    generation: g.clone(),
                    manager: m,
                }],
            ))
        }
        Request::StopHint {
            boot_id,
            daemon_invocation,
        } => {
            if peer != PeerKind::StopNotifier {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
            }
            let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
            let manager = fixed_manager_show(DAEMON_UNIT)?;
            if boot_id != boot.trim() || daemon_invocation != prop(&manager, "InvocationID")? {
                return Ok((OwnerOutcome::Inhibit, Vec::new()));
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
                return Ok((OwnerOutcome::NoOwnedRelease, Vec::new()));
            }
            let mut accepted = Vec::new();
            for (g, m) in targets {
                if let Some(m) = m {
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
                    // Same contract as the failure hook: the notifier's answer
                    // reports accepted intent and never waits for extinction,
                    // which is what keeps shutdown inside TimeoutStopSec.
                    accepted.push(AcceptedStop {
                        generation: g,
                        manager: m,
                    });
                }
            }
            Ok((OwnerOutcome::IntentAccepted, accepted))
        }
    }
}

fn handle(
    req: Request,
    peer: PeerKind,
    ledger: &mut Ledger,
    pins: &Pins,
    daemon_private_parent: &Path,
) -> io::Result<(Response, Vec<AcceptedStop>)> {
    if let Request::CompletionPull { unit_name } = req {
        if peer != PeerKind::DaemonMain || fs::read_dir(daemon_private_parent).is_ok() {
            return Ok((
                Response {
                    outcome: OwnerOutcome::Inhibit,
                    completion: None,
                },
                Vec::new(),
            ));
        }
        let completion = ledger.state.generations.get(&unit_name).and_then(|e| {
            if e.release.is_some() {
                e.outcome.clone()
            } else {
                None
            }
        });
        return Ok((
            Response {
                outcome: if completion.is_some() {
                    OwnerOutcome::IntentAccepted
                } else {
                    OwnerOutcome::NoOwnedRelease
                },
                completion,
            },
            Vec::new(),
        ));
    }
    let (outcome, accepted) = handle_action(req, peer, ledger, pins, daemon_private_parent)?;
    Ok((
        Response {
            outcome,
            completion: None,
        },
        accepted,
    ))
}

/// Writes the client's answer and only then executes the stops whose intent
/// that answer accepted. The ACK is fsynced-intent acceptance, never
/// completion, so it must not wait for `StopUnit`, the grace period or positive
/// extinction: a populated target alone can hold those for longer than the
/// client's single 250 ms budget, and every later request queues behind it.
fn respond_then_stop(
    stream: &mut UnixStream,
    response: &Response,
    accepted: &[AcceptedStop],
    run_stop: &mut dyn FnMut(&AcceptedStop),
) -> io::Result<()> {
    let bytes = serde_json::to_vec(response).map_err(|_| bad("response"))?;
    if bytes.len() > MAX_RESPONSE {
        return Err(bad("owner response oversized"));
    }
    let _ = stream.set_write_timeout(Some(CLIENT_DEADLINE));
    let _ = stream.write_all(&bytes);
    let _ = stream.write_all(b"\n");
    for stop in accepted {
        run_stop(stop);
    }
    Ok(())
}

fn stop_and_complete(
    ledger: &mut Ledger,
    g: &receipt::Generation,
    m: &ManagerIdentity,
    key: &ed25519_dalek::SigningKey,
) -> io::Result<()> {
    manager_stop(m)?;
    let entry = ledger
        .state
        .generations
        .get(&g.unit_name)
        .ok_or_else(|| bad("missing generation"))?;
    let (domain, old) = if let Some(r) = &entry.release {
        (Domain::StopCompletionV1, Some(ledger::receipt_hash(r)?))
    } else {
        (Domain::PreparedExtinctionV1, None)
    };
    let body = receipt::ReceiptBody {
        generation: g.clone(),
        manager: Some(m.clone()),
        hook: None,
        attempt_id: None,
        attempted_scope: None,
        candidate_uids: Vec::new(),
        old_release_hash: old,
        positive_extinction: Some(true),
    };
    let signed = receipt::sign(domain, body, key).map_err(bad)?;
    ledger.record_outcome(signed)
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
    let key = read_owner_key(&pins)?;
    // The fixed agent/profile and registry are required installed inputs, even
    // though this binary has no CREATE arm. Missing artifacts cannot make an
    // apparently ready owner for a later protected release.
    super::profile::validate_installed()?;
    let mut ledger = Ledger::open(&paths.ledger)?;
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
    let mut ready = crate::systemd_notify::ReadyBeacon::from_env();
    ready
        .signal_ready()
        .map_err(|_| bad("owner READY notify"))?;
    let mut last_watch = Instant::now();
    let mut last_reconcile = Instant::now();
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let inhibit = || {
                    (
                        Response {
                            outcome: OwnerOutcome::Inhibit,
                            completion: None,
                        },
                        Vec::new(),
                    )
                };
                let (response, accepted) = if let Ok(peer) = peer_identity(&stream) {
                    match read_message(&mut stream).and_then(|r| {
                        handle(r, peer, &mut ledger, &pins, &paths.daemon_private_parent)
                    }) {
                        Ok(answered) => answered,
                        Err(_) => inhibit(),
                    }
                } else {
                    inhibit()
                };
                respond_then_stop(&mut stream, &response, &accepted, &mut |stop| {
                    let _ = stop_and_complete(&mut ledger, &stop.generation, &stop.manager, &key);
                })?;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25))
            }
            Err(e) => return Err(e),
        }
        if last_watch.elapsed() >= Duration::from_secs(3) {
            watchdog_ping()?;
            last_watch = Instant::now();
        }
        if last_reconcile.elapsed() >= Duration::from_secs(5) {
            // This scan RESUMES stops whose intent was already accepted and
            // fsynced; it is never itself an authority to stop anything. See
            // `stop_policy::reconcile_verdict` for why the accepted attempt
            // row, and not the presence of a release, is the predicate: a
            // healthy released agent nobody asked to stop must survive every
            // scan, and a record whose notifier died mid-stop must be finished.
            let pending: Vec<_> = ledger
                .state
                .generations
                .values()
                .filter_map(stop_policy::reconcile_target)
                .collect();
            for (g, m) in pending {
                let _ = stop_and_complete(&mut ledger, &g, &m, &key);
            }
            last_reconcile = Instant::now();
        }
    }
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
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    fn temporary_paths(dir: &Path) -> OwnerPaths {
        OwnerPaths {
            socket: dir.join("owner.sock"),
            pins: dir.join("receipt-pins-v1.json"),
            release_log: dir.join("releases.log"),
            admission_key: dir.join("admission-signing.key"),
            admission_key_parents: vec![dir.to_path_buf()],
            owner_private_parent: dir.join("owner-private"),
            daemon_private_parent: dir.join("daemon-private"),
            ledger: dir.join("owner-ledger-v1.log"),
        }
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

    #[test]
    fn an_accepted_intent_is_acknowledged_before_its_stop_runs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let stopped = Arc::new(AtomicBool::new(false));
        let server = {
            let stopping = Arc::clone(&stopping);
            let stopped = Arc::clone(&stopped);
            std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let response = Response {
                    outcome: OwnerOutcome::IntentAccepted,
                    completion: None,
                };
                let accepted = vec![AcceptedStop {
                    generation: fixture_generation(),
                    manager: fixture_manager(),
                }];
                respond_then_stop(&mut stream, &response, &accepted, &mut |_| {
                    // Stands in for a populated target holding the grace period
                    // and the extinction budget, both far past the client's
                    // 250 ms deadline.
                    stopping.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(600));
                    stopped.store(true, Ordering::SeqCst);
                })
                .unwrap();
            })
        };
        let start = Instant::now();
        let reply = request_to(
            &path,
            &Request::StopHint {
                boot_id: "fixture".into(),
                daemon_invocation: "fixture".into(),
            },
        )
        .unwrap();
        let elapsed = start.elapsed();
        assert_eq!(reply.outcome, OwnerOutcome::IntentAccepted);
        assert!(
            elapsed < CLIENT_DEADLINE,
            "acceptance must arrive inside the one client deadline: {elapsed:?}"
        );
        assert!(
            !stopped.load(Ordering::SeqCst),
            "the stop must still be running when the acknowledgement lands"
        );
        server.join().unwrap();
        assert!(stopping.load(Ordering::SeqCst) && stopped.load(Ordering::SeqCst));
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
