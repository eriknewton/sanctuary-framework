//! Inert service composition; daemon boot and admission are intentionally separate consumers.
use super::{
    custody::*,
    signer_contract::*,
    signer_peer::{self, Peer},
    signer_watchdog::{self, Lease, State, NS_PER_SECOND, WATCHDOG_TICK_MS},
};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, OwnedFd, RawFd},
        unix::process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Stdio},
};

// Must match server/src/signing/service.ts: four big-endian bytes, canonical header, then exact preimage bytes.
pub const LENGTH_BYTES: usize = 4;
pub const RESPONSE_MAX_BYTES: usize = SIGNER_HEADER_MAX_BYTES;
pub const SIGN_SOCKET: &str = "sign.sock";
pub const LIFECYCLE_SOCKET: &str = "lifecycle.sock";
const MS_TO_NS: u64 = 1_000_000;
static STOP: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
extern "C" fn stop_signal(_: i32) {
    STOP.store(true, std::sync::atomic::Ordering::Relaxed);
}
const TOKEN_ID_BYTES: usize = 16;
const HEX_ID_CHARS: usize = TOKEN_ID_BYTES * 2;
const ED25519_SIGNATURE_BYTES: usize = 64;
const SIGNATURE_RESPONSE_FIELDS: usize = 4;
const SAFE_INTEGER_MAX: u64 = 9_007_199_254_740_991;
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub v: u8,
    pub protocol: String,
    pub request_id: String,
    pub activation_id: String,
    pub lease_id: String,
    pub generation: u64,
    pub epoch: u64,
    pub role: String,
    pub deadline_boottime_ns: String,
    pub preimage_length: usize,
}
pub fn canonical(bytes: &[u8], max: usize) -> io::Result<Value> {
    let value = crate::smb::strict_json::parse(bytes, max).map_err(|_| refused())?;
    if crate::smb::jcs::encode(&value)
        .map_err(|_| refused())?
        .as_bytes()
        != bytes
    {
        return Err(refused());
    }
    serde_json::from_slice(bytes).map_err(|_| refused())
}
pub fn encode(header: &Value, body: &[u8]) -> io::Result<Vec<u8>> {
    let text = crate::smb::jcs::encode(header).map_err(|_| refused())?;
    if text.len() > SIGNER_HEADER_MAX_BYTES || body.len() > SIGNER_PREIMAGE_MAX_BYTES {
        return Err(refused());
    }
    Ok([
        &(text.len() as u32).to_be_bytes()[..],
        text.as_bytes(),
        body,
    ]
    .concat())
}
pub fn decode(frame: &[u8]) -> io::Result<(Header, &[u8])> {
    // Bounds precede allocation and schema work so truncated or oversized packets cannot create queued work.
    if frame.len() < LENGTH_BYTES || frame.len() > SIGNER_FRAME_MAX_BYTES {
        return Err(refused());
    }
    let length =
        u32::from_be_bytes(frame[..LENGTH_BYTES].try_into().map_err(|_| refused())?) as usize;
    if length > SIGNER_HEADER_MAX_BYTES || LENGTH_BYTES + length > frame.len() {
        return Err(refused());
    }
    let value = canonical(
        &frame[LENGTH_BYTES..LENGTH_BYTES + length],
        SIGNER_HEADER_MAX_BYTES,
    )?;
    let header: Header = serde_json::from_value(value).map_err(|_| refused())?;
    let id = |s: &str| {
        s.len() == HEX_ID_CHARS
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let deadline = header
        .deadline_boottime_ns
        .parse::<u64>()
        .map_err(|_| refused())?;
    if header.v != 1
        || header.protocol != SIGNER_PROTOCOL
        || !id(&header.request_id)
        || !id(&header.activation_id)
        || !id(&header.lease_id)
        || header.epoch == 0
        || header.epoch > SAFE_INTEGER_MAX
        || header.generation > SAFE_INTEGER_MAX
        || !ROLE_REGISTRY.iter().any(|row| row.0 == header.role)
        || deadline.to_string() != header.deadline_boottime_ns
        || header.preimage_length > SIGNER_PREIMAGE_MAX_BYTES
        || frame.len() != LENGTH_BYTES + length + header.preimage_length
    {
        return Err(refused());
    }
    Ok((header, &frame[LENGTH_BYTES + length..]))
}
#[derive(Debug)]
pub struct WorkBudget {
    active: bool,
    global: u128,
    callers: [u128; SIGNER_CONNECTIONS_MAX],
    refill: u64,
}
impl WorkBudget {
    pub fn new(now: u64) -> Self {
        Self {
            active: false,
            global: SIGNER_BURST_MAX as u128 * NS_PER_SECOND as u128,
            callers: [SIGNER_PER_CALLER_BURST_MAX as u128 * NS_PER_SECOND as u128;
                SIGNER_CONNECTIONS_MAX],
            refill: now,
        }
    }
    pub fn admit(&mut self, caller: usize, now: u64) -> bool {
        const TOKEN_UNITS: u128 = NS_PER_SECOND as u128;
        if now < self.refill {
            return false;
        }
        // Continuous fixed-point refill prevents a window boundary from doubling the permitted burst.
        let elapsed = (now - self.refill) as u128;
        self.global = (self.global + elapsed * SIGNER_RATE_PER_SECOND as u128)
            .min(SIGNER_BURST_MAX as u128 * TOKEN_UNITS);
        for tokens in &mut self.callers {
            *tokens = (*tokens + elapsed * SIGNER_PER_CALLER_RATE_PER_SECOND as u128)
                .min(SIGNER_PER_CALLER_BURST_MAX as u128 * TOKEN_UNITS);
        }
        self.refill = now;
        // Fixed buckets and one unsettled slot bound memory independently of attacker identities or timeout waves.
        if caller >= self.callers.len()
            || self.global < TOKEN_UNITS
            || self.callers[caller] < TOKEN_UNITS
        {
            return false;
        }
        self.global -= TOKEN_UNITS;
        self.callers[caller] -= TOKEN_UNITS;
        if self.active {
            return false;
        }
        self.active = true;
        true
    }
    pub fn settled(&mut self) {
        self.active = false;
    }
}
pub struct Paths {
    pub control: PathBuf,
    pub custody: PathBuf,
    pub node: PathBuf,
    pub worker: PathBuf,
    pub owner: u32,
}
impl Default for Paths {
    fn default() -> Self {
        Self {
            control: CONTROL_ROOT.into(),
            custody: CUSTODY_ROOT.into(),
            node: NODE_BINARY.into(),
            worker: WORKER_BINARY.into(),
            owner: ROOT_UID,
        }
    }
}
struct Connection {
    fd: OwnedFd,
    peer: Peer,
    last: u64,
    handshaken: bool,
}
struct Worker {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
    error: ChildStderr,
    pending: Vec<u8>,
    offset: usize,
    received: Vec<u8>,
    tty: Option<OwnedFd>,
    term: libc::termios,
    settlement: Settlement,
    lock_queued: bool,
}
impl Worker {
    fn release_terminal(&mut self) {
        // Restoration ends with the ceremony so later terminal owners cannot receive stale settings.
        if let Some(tty) = self.tty.take() {
            unsafe {
                libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &self.term);
            }
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Every service exit kills and waits for its own child before restoring the terminal.
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.release_terminal();
    }
}
#[cfg(feature = "test-isolation")]
fn observe(paths: &Paths, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(PRIVATE_MODE)
        .open(paths.control.join("k1-test-frames.bin"))
    {
        let _ = file.write_all(bytes);
    }
}
fn nonblock(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(refused());
    }
    Ok(())
}
fn spawn_worker(
    paths: &Paths,
    config: &Config,
    grant: &Value,
    tty: OwnedFd,
    peer: &Peer,
    lease: &Lease,
) -> io::Result<Worker> {
    let term = signer_peer::tty_check(tty.as_raw_fd(), peer.pid)?;
    let node = artifact(&paths.node, &config.node_sha256, ROOT_UID)?;
    let script = artifact(&paths.worker, &config.worker_sha256, paths.owner)?;
    let original_fd = tty.as_raw_fd();
    let tty_pid = peer.pid;
    let parent_pid = unsafe { libc::getpid() };
    let mut tty_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(original_fd, &mut tty_stat) } != 0 {
        return Err(refused());
    }
    let mut cmd = worker_command(&paths.node, &paths.worker);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Verified executable and script inodes are checked again immediately before fork under an owner-only runtime root.
    verify_artifact_identity(&paths.node, &node)?;
    verify_artifact_identity(&paths.worker, &script)?;
    unsafe {
        cmd.pre_exec(move || {
            signer_peer::tty_check(original_fd, tty_pid)?;
            if libc::dup2(original_fd, TTY_FD) < 0 || libc::fcntl(TTY_FD, libc::F_SETFD, 0) < 0 {
                return Err(refused());
            }
            // CLOEXEC preserves the exec-error pipe until exec while excluding ambient descriptors from the worker.
            close_worker_descriptors()?;
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != parent_pid
            {
                return Err(refused());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn()?;
    let input = child.stdin.take().ok_or_else(refused)?;
    let output = child.stdout.take().ok_or_else(refused)?;
    let error = child.stderr.take().ok_or_else(refused)?;
    nonblock(input.as_raw_fd())?;
    nonblock(output.as_raw_fd())?;
    nonblock(error.as_raw_fd())?;
    let bootstrap = crate::smb::jcs::encode(&json!({"grant":grant,"fortress_id":config.fortress_id,"roster_digest":config.roster_digest,
        "binding_high_water":config.binding_high_water,"root":paths.custody,"owner":paths.owner,
        "started_boottime_ns":lease.started().to_string(),"expires_boottime_ns":lease.expires().to_string(),"tty_inode":tty_stat.st_ino.to_string(),"tty_device":tty_stat.st_rdev.to_string(),"tty_session":unsafe {libc::getsid(peer.pid)},"tty_foreground":unsafe {libc::getpgid(peer.pid)}})).map_err(|_| refused())?;
    let pending = encode(
        &json!({"op":"UNLOCK","preimage_length":bootstrap.len()}),
        bootstrap.as_bytes(),
    )?;
    Ok(Worker {
        child,
        input,
        output,
        error,
        pending,
        offset: 0,
        received: Vec::new(),
        tty: Some(tty),
        term,
        settlement: Settlement::default(),
        lock_queued: false,
    })
}
fn reply(fd: RawFd, value: Value) -> io::Result<()> {
    signer_peer::send(fd, &encode(&value, &[])?, &[])
}
fn state_name(state: State) -> &'static str {
    match state {
        State::Locked => "LOCKED",
        State::Unlocking => "UNLOCKING",
        State::Unlocked => "UNLOCKED",
        State::Locking => "LOCKING",
        State::Wiped => "WIPED",
        State::WipeUnconfirmed => "WIPE_UNCONFIRMED",
        State::RecoveryRequired => "RECOVERY_REQUIRED",
    }
}
fn response(bytes: &[u8]) -> io::Result<Value> {
    if bytes.len() < LENGTH_BYTES {
        return Err(refused());
    }
    let length =
        u32::from_be_bytes(bytes[..LENGTH_BYTES].try_into().map_err(|_| refused())?) as usize;
    if length > RESPONSE_MAX_BYTES || length + LENGTH_BYTES != bytes.len() {
        return Err(refused());
    }
    canonical(&bytes[LENGTH_BYTES..], RESPONSE_MAX_BYTES)
}
pub fn run(config: Config, paths: Paths) -> io::Result<()> {
    unsafe {
        libc::signal(libc::SIGTERM, stop_signal as *const () as usize);
        libc::signal(libc::SIGINT, stop_signal as *const () as usize);
    }
    signer_peer::kernel_probe()?;
    if paths.owner == ROOT_UID {
        verify_host_memory_policy()?;
    }
    verify_runtime(&config, &paths.node)?;
    let _control = check_root(&paths.control, paths.owner)?;
    let _custody = check_root(&paths.custody, paths.owner)?;
    let sign = signer_peer::listen(&paths.control.join(SIGN_SOCKET))?;
    let mut lifecycle = signer_peer::listen(&paths.control.join(LIFECYCLE_SOCKET))?;
    let mut lifecycle_sealed = false;
    let mut clients: Vec<Option<Connection>> = (0..SIGNER_CONNECTIONS_MAX).map(|_| None).collect();
    let mut ceremonies: Vec<Option<Connection>> =
        (0..LIFECYCLE_CONNECTIONS_MAX).map(|_| None).collect();
    let marker = paths.custody.join(UNCLEAN_MARKER);
    let mut lease = Lease::default();
    if marker.try_exists()? {
        lease.state = State::RecoveryRequired;
    }
    let mut worker: Option<Worker> = None;
    let mut bound: Option<usize> = None;
    let mut ceremony_slot: Option<usize> = None;
    let mut active: Option<(usize, String, u64, Vec<u8>)> = None;
    let mut budget = WorkBudget::new(signer_watchdog::boottime_ns()?);
    let mut grant = config.grant.clone();
    let mut generation = 0u64;
    let mut attempt_window = 0;
    let mut attempts = 0;
    let mut lifecycle_window = signer_watchdog::boottime_ns()?;
    let mut lifecycle_tokens = LIFECYCLE_BURST_MAX;
    // Readiness only reports a locked service and never grants application admission.
    notify_ready()?;
    loop {
        if STOP.load(std::sync::atomic::Ordering::Relaxed) {
            lease.revoke();
            drop(worker.take());
            return Ok(());
        }
        let now = signer_watchdog::boottime_ns()?;
        let peer_live = bound
            .and_then(|i| clients[i].as_ref())
            .map(|c| c.peer.live())
            .unwrap_or(false);
        let ceremony_live = ceremony_slot
            .and_then(|i| ceremonies[i].as_ref())
            .map(|c| c.peer.live())
            .unwrap_or(true);
        let timed_out = active.as_ref().map(|a| now >= a.2).unwrap_or(false);
        if worker.is_some()
            && ((matches!(lease.state, State::Unlocking | State::Unlocked)
                && (!lease.live(now) || !peer_live || !ceremony_live))
                || timed_out
                || (lease.state == State::Locking
                    && worker.as_ref().is_some_and(|w| w.settlement.due(now))))
        {
            if let Some(mut w) = worker.take() {
                signer_watchdog::kill_and_reap(&mut w.child, &mut lease)?;
            }
            if let Some((i, _, _, _)) = active.take() {
                if let Some(c) = &clients[i] {
                    let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                }
            }
            budget.settled();
            if let Some(i) = ceremony_slot.take() {
                if let Some(c) = ceremonies[i].take() {
                    let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                }
            }
        }
        if let Some(w) = worker.as_mut() {
            if w.offset < w.pending.len() {
                match w.input.write(&w.pending[w.offset..]) {
                    Ok(n) if n > 0 => {
                        #[cfg(feature = "test-isolation")]
                        observe(&paths, &w.pending[w.offset..w.offset + n]);
                        w.offset += n;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    _ => {
                        lease.revoke();
                        w.settlement.fault(now);
                    }
                }
            }
            let mut chunk = [0u8; RESPONSE_MAX_BYTES + LENGTH_BYTES];
            match w.error.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    #[cfg(feature = "test-isolation")]
                    observe(&paths, &chunk[..n]);
                    // Worker diagnostics are never forwarded because exceptions may contain private material.
                    lease.revoke();
                    w.settlement.fault(now);
                }
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    lease.revoke();
                    w.settlement.fault(now);
                }
                _ => (),
            }
            match w.output.read(&mut chunk) {
                Ok(n) if n > 0 => {
                    #[cfg(feature = "test-isolation")]
                    observe(&paths, &chunk[..n]);
                    if w.received.len() + n > RESPONSE_MAX_BYTES + LENGTH_BYTES {
                        lease.revoke();
                        w.settlement.fault(now);
                    } else {
                        w.received.extend_from_slice(&chunk[..n]);
                        while w.received.len() >= LENGTH_BYTES {
                            let length = u32::from_be_bytes(
                                w.received[..LENGTH_BYTES]
                                    .try_into()
                                    .map_err(|_| refused())?,
                            ) as usize;
                            if length > RESPONSE_MAX_BYTES {
                                lease.revoke();
                                w.settlement.fault(now);
                                break;
                            } else if w.received.len() >= length + LENGTH_BYTES {
                                let result = response(&w.received[..length + LENGTH_BYTES]);
                                w.received.drain(..length + LENGTH_BYTES);
                                // Refresh time and peer liveness at settlement because earlier loop work cannot extend a grant.
                                let peer_live = bound
                                    .and_then(|i| clients[i].as_ref())
                                    .map(|c| c.peer.live())
                                    .unwrap_or(false);
                                let now = signer_watchdog::boottime_ns()?;
                                match result {
                                    Ok(v)
                                        if v == json!({"op":"READY"})
                                            && peer_live
                                            && lease.ready(now) =>
                                    {
                                        w.release_terminal();
                                        if let Some(c) = bound.and_then(|i| clients[i].as_mut()) {
                                            c.last = now;
                                        }
                                        if let Some(i) = ceremony_slot.take() {
                                            if let Some(c) = ceremonies[i].take() {
                                                let _ =
                                                    reply(c.fd.as_raw_fd(), json!({"op":"READY"}));
                                            }
                                        }
                                    }
                                    Ok(v)
                                        if v == json!({"op":"WIPED"})
                                            && matches!(
                                                lease.state,
                                                State::Unlocking | State::Locking
                                            )
                                            && !w.settlement.cleanup =>
                                    {
                                        w.settlement.acknowledge(lease.state, now);
                                        lease.revoke();
                                    }
                                    Ok(v)
                                        if v.get("op") == Some(&json!("SIGNED"))
                                            && lease.can_sign(now)
                                            && peer_live =>
                                    {
                                        if let Some((i, request_id, deadline, preimage)) =
                                            active.take()
                                        {
                                            // Only typed public signatures cross the worker boundary; arbitrary worker errors or extra fields never do.
                                            if now < deadline
                                                && valid_signature_response(&v, &request_id, &grant)
                                                && verify_worker_signature(&v, &grant, &preimage)
                                            {
                                                if let Some(c) = &clients[i] {
                                                    let _ = reply(c.fd.as_raw_fd(), v);
                                                }
                                                budget.settled();
                                            } else {
                                                if let Some(c) = &clients[i] {
                                                    let _ = reply(
                                                        c.fd.as_raw_fd(),
                                                        json!({"op":"REFUSED"}),
                                                    );
                                                }
                                                lease.revoke();
                                                w.settlement.fault(now);
                                            }
                                        } else {
                                            lease.revoke();
                                            w.settlement.fault(now);
                                        }
                                    }
                                    Ok(v)
                                        if v.get("op") == Some(&json!("SIGNED"))
                                            && lease.state == State::Locking =>
                                    {
                                        // A revoked result is discarded while the queued LOCK still gets its cooperative wipe acknowledgement.
                                        if let Some((i, _, _, _)) = active.take() {
                                            if let Some(c) = &clients[i] {
                                                let _ = reply(
                                                    c.fd.as_raw_fd(),
                                                    json!({"op":"REFUSED"}),
                                                );
                                            }
                                        }
                                        budget.settled();
                                    }
                                    _ => {
                                        lease.revoke();
                                        w.settlement.fault(now);
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                Err(e) if e.kind() != io::ErrorKind::WouldBlock => {
                    lease.revoke();
                    w.settlement.fault(now);
                }
                _ => (),
            }
        }
        if let Some(w) = worker.as_mut() {
            if let Some(status) =
                reaped_after_outputs(&mut w.child, &[w.output.as_raw_fd(), w.error.as_raw_fd()])?
            {
                if !w.received.is_empty() {
                    w.settlement.fault(now);
                }
                lease.revoke();
                lease.reaped(w.settlement.cooperative(status.success()));
                w.release_terminal();
                if lease.state == State::Wiped {
                    // Only cooperative wipe followed by successful reaping permits the next attended attempt.
                    std::fs::remove_file(&marker)?;
                    check_root(&paths.custody, paths.owner)?.sync_all()?;
                    lease.state = State::Locked;
                }
                if let Some(i) = ceremony_slot.take() {
                    if let Some(c) = ceremonies[i].take() {
                        let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                    }
                }
                worker.take();
                if let Some((i, _, _, _)) = active.take() {
                    if let Some(c) = &clients[i] {
                        let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                    }
                }
                budget.settled();
            }
        }
        if lifecycle_sealed && ceremonies.iter().flatten().count() < LIFECYCLE_CONNECTIONS_MAX {
            // Reopen admission only after an accepted slot is free because the kernel backlog counts toward the cap.
            std::fs::remove_file(paths.control.join(LIFECYCLE_SOCKET))?;
            lifecycle = signer_peer::listen(&paths.control.join(LIFECYCLE_SOCKET))?;
            lifecycle_sealed = false;
        }
        for (listener, slots, policy) in [
            (sign.as_raw_fd(), &mut clients, &config.controller),
            (lifecycle.as_raw_fd(), &mut ceremonies, &config.launcher),
        ] {
            if listener == lifecycle.as_raw_fd() {
                // An empty probe skips accept entirely so a later connect cannot bypass final-slot sealing.
                if lifecycle_sealed || !readable(listener) {
                    continue;
                }
                lifecycle_sealed =
                    seal_lifecycle_backlog(listener, slots.iter().flatten().count())?;
            }
            // The sealed lifecycle listener transfers its single queued connection into the final accepted slot.
            let accepted_limit = if listener == lifecycle.as_raw_fd() {
                slots.len()
            } else {
                slots.len().saturating_sub(1)
            };
            if let Some(slot) = slots
                .iter_mut()
                .take(accepted_limit)
                .find(|slot| slot.is_none())
            {
                if let Ok(fd) = signer_peer::accept(listener) {
                    if let Ok(peer) = Peer::capture(fd.as_raw_fd(), policy) {
                        // Must match signer_peer::validate_capability_status: only a completed capability drop admits a peer.
                        if signer_peer::empty_capabilities(peer.pid, paths.owner == ROOT_UID)
                            .is_err()
                        {
                            continue;
                        }
                        *slot = Some(Connection {
                            fd,
                            peer,
                            last: now,
                            handshaken: false,
                        });
                    }
                }
            }
        }
        for (i, slot) in clients.iter_mut().enumerate() {
            let now = signer_watchdog::boottime_ns()?;
            let Some(c) = slot.as_mut() else {
                continue;
            };
            let idle_ms = if c.handshaken {
                SIGNER_IDLE_DEADLINE_MS
            } else {
                SIGNER_HANDSHAKE_DEADLINE_MS
            };
            if !c.peer.live()
                || (!(Some(i) == bound && lease.state == State::Unlocking)
                    && now.saturating_sub(c.last) > idle_ms as u64 * MS_TO_NS)
            {
                slot.take();
                continue;
            }
            if !readable(c.fd.as_raw_fd()) {
                continue;
            }
            let packet = match signer_peer::receive(c.fd.as_raw_fd(), SIGNER_FRAME_MAX_BYTES) {
                Ok(p) => p,
                Err(_) => {
                    slot.take();
                    continue;
                }
            };
            c.last = now;
            c.handshaken = true;
            if !c.peer.matches(&packet) || !packet.rights.is_empty() {
                slot.take();
                continue;
            }
            if packet.bytes == b"{\"op\":\"STATUS\"}" {
                let _ = reply(
                    c.fd.as_raw_fd(),
                    json!({"op":"STATUS","state":state_name(lease.state),"grant":grant,"expires_boottime_ns":lease.expires().to_string()}),
                );
                continue;
            }
            if !budget.admit(i, now) {
                let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                continue;
            }
            let decoded = decode(&packet.bytes);
            let admitted = decoded.as_ref().ok().filter(|(h, _)| {
                lease.can_sign(now) && bound == Some(i) && header_matches(h, &grant, now)
            });
            if let Some((h, preimage)) = admitted {
                if let Some(w) = worker.as_mut() {
                    w.pending = packet.bytes.clone();
                    w.offset = 0;
                    active = Some((
                        i,
                        h.request_id.clone(),
                        h.deadline_boottime_ns
                            .parse::<u64>()
                            .map_err(|_| refused())?
                            .min(now + SIGNER_REQUEST_DEADLINE_MS as u64 * MS_TO_NS),
                        preimage.to_vec(),
                    ));
                    continue;
                }
            }
            budget.settled();
            let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
        }
        for (i, slot) in ceremonies.iter_mut().enumerate() {
            let now = signer_watchdog::boottime_ns()?;
            if ceremony_slot == Some(i) {
                continue;
            }
            let Some(c) = slot.as_ref() else {
                continue;
            };
            if now.saturating_sub(c.last) > SIGNER_HANDSHAKE_DEADLINE_MS as u64 * MS_TO_NS
                || !c.peer.live()
            {
                slot.take();
                continue;
            }
            if !readable(c.fd.as_raw_fd()) {
                continue;
            }
            let packet = match signer_peer::receive(c.fd.as_raw_fd(), LIFECYCLE_FRAME_MAX_BYTES) {
                Ok(p) => p,
                Err(_) => {
                    slot.take();
                    continue;
                }
            };
            if !c.peer.matches(&packet) {
                slot.take();
                continue;
            }
            let request = canonical(&packet.bytes, LIFECYCLE_FRAME_MAX_BYTES);
            if request.as_ref().ok() == Some(&json!({"op":"LOCK"})) && packet.rights.is_empty() {
                // Local revocation bypasses ceremony quotas so a KDF or remote flood cannot retain signing authority.
                if let Some(w) = worker.as_mut() {
                    let unlocking = lease.state == State::Unlocking;
                    let previous = lease.state;
                    lease.revoke();
                    // Keep the terminal until reap because an unlocking child can still change its attributes.
                    w.settlement.lock(previous, now);
                    // Finish a partially written frame before LOCK so framing cannot turn a cooperative wipe into a forced kill.
                    if !unlocking && !w.lock_queued {
                        queue_lock(&mut w.pending, &mut w.offset)?;
                        w.lock_queued = true;
                    }
                }
                let _ = reply(c.fd.as_raw_fd(), json!({"op":"LOCKING"}));
                slot.take();
                continue;
            }
            if now >= lifecycle_window + NS_PER_SECOND {
                // Preserve the bounded initial burst so a cooperative refusal can be retried without renewing quotas.
                let elapsed = (now - lifecycle_window) / NS_PER_SECOND;
                lifecycle_tokens = lifecycle_tokens
                    .saturating_add(elapsed as usize * LIFECYCLE_RATE_PER_SECOND)
                    .min(LIFECYCLE_BURST_MAX);
                lifecycle_window += elapsed * NS_PER_SECOND;
            }
            if now >= attempt_window + UNLOCK_TTL_MAX_SECONDS as u64 * NS_PER_SECOND {
                attempt_window = now;
                attempts = 0;
            }
            let ttl = request
                .as_ref()
                .ok()
                .and_then(|r| r.get("ttl"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let valid = request.as_ref().ok() == Some(&json!({"op":"UNLOCK","ttl":ttl}))
                && packet.rights.len() == 1
                && lifecycle_tokens > 0
                && attempts < SIGNER_UNLOCK_ATTEMPTS_PER_300_SECONDS
                && worker.is_none()
                && lease.state == State::Locked;
            lifecycle_tokens = lifecycle_tokens.saturating_sub(1);
            if !valid {
                let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                slot.take();
                continue;
            }
            attempts += 1;
            let candidates: Vec<usize> = clients
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.as_ref().filter(|c| c.peer.live()).map(|_| i))
                .collect();
            if candidates.len() != 1 || !lease.begin(now, ttl) {
                let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                slot.take();
                continue;
            }
            bound = Some(candidates[0]);
            generation = generation.checked_add(1).ok_or_else(refused)?;
            let mut random = [0u8; TOKEN_ID_BYTES];
            OsRng.fill_bytes(&mut random);
            grant["lease_id"] = json!(hex::encode(random));
            grant["generation"] = json!(generation);
            let tty = packet.rights.into_iter().next().ok_or_else(refused)?;
            // Invalid terminal rights refuse before any worker or durable uncertainty can exist.
            if signer_peer::tty_check(tty.as_raw_fd(), c.peer.pid).is_err() {
                lease.state = State::Locked;
                let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                slot.take();
                continue;
            }
            // A durable nonsecret marker precedes every possible secret worker so restart cannot erase uncertainty.
            mark_unclean(&paths.custody)?;
            match spawn_worker(&paths, &config, &grant, tty, &c.peer, &lease) {
                Ok(w) => {
                    worker = Some(w);
                    ceremony_slot = Some(i);
                }
                Err(_) => {
                    lease.state = State::RecoveryRequired;
                    let _ = reply(c.fd.as_raw_fd(), json!({"op":"REFUSED"}));
                    slot.take();
                }
            }
        }
        let mut wait = libc::pollfd {
            fd: sign.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut wait, 1, WATCHDOG_TICK_MS);
        }
    }
}
pub fn header_matches(h: &Header, grant: &Value, now: u64) -> bool {
    let deadline = h.deadline_boottime_ns.parse::<u64>().unwrap_or(0);
    h.role == grant["role"].as_str().unwrap_or("")
        && h.epoch == grant["epoch"].as_u64().unwrap_or(0)
        && h.activation_id == grant["activation_id"].as_str().unwrap_or("")
        && h.lease_id == grant["lease_id"].as_str().unwrap_or("")
        && h.generation == grant["generation"].as_u64().unwrap_or(0)
        && deadline > now
        && deadline <= now.saturating_add(SIGNER_REQUEST_DEADLINE_MS as u64 * MS_TO_NS)
}
pub fn valid_signature_response(v: &Value, request_id: &str, grant: &Value) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    v.as_object().map(|o| o.len()) == Some(SIGNATURE_RESPONSE_FIELDS)
        && v["op"] == "SIGNED"
        && v["request_id"] == request_id
        && v["kid"] == grant["kid"]
        && v["signature"]
            .as_str()
            .and_then(|s| URL_SAFE_NO_PAD.decode(s).ok())
            .map(|b| {
                b.len() == ED25519_SIGNATURE_BYTES
                    && super::strict_encoding_profile(
                        &b,
                        &URL_SAFE_NO_PAD
                            .decode(grant["public_key"].as_str().unwrap_or(""))
                            .unwrap_or_default(),
                    )
            })
            .unwrap_or(false)
}
pub fn readable(fd: RawFd) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, 0) > 0 }
}
fn notify_ready() -> io::Result<()> {
    if let Some(path) = std::env::var_os("NOTIFY_SOCKET") {
        let sock = std::os::unix::net::UnixDatagram::unbound()?;
        sock.send_to(b"READY=1\nSTATUS=LOCKED", Path::new(&path))?;
    }
    Ok(())
}
/// Native bridge preserves SOCK_SEQPACKET and kernel authentication for the TS client.
pub fn bridge(
    path: &Path,
    policy: &super::signer_peer::PeerPolicy,
    parent_policy: &super::signer_peer::PeerPolicy,
) -> io::Result<()> {
    const BRIDGE_INPUT: RawFd = 0;
    signer_peer::require_unix_socket(BRIDGE_INPUT)?;
    signer_peer::passcred(BRIDGE_INPUT)?;
    let parent = Peer::capture(BRIDGE_INPUT, parent_policy)?;
    if parent.pid != unsafe { libc::getppid() } {
        return Err(refused());
    }
    signer_peer::drop_capabilities()?;
    let socket = signer_peer::connect(path)?;
    let peer = Peer::capture(socket.as_raw_fd(), policy)?;
    let mut output = io::stdout().lock();
    // The ready frame ensures SO_PASSCRED is armed before the parent writes its first byte.
    let ready = encode(&json!({"op":"BRIDGE_READY"}), &[])?;
    output.write_all(&(ready.len() as u32).to_be_bytes())?;
    output.write_all(&ready)?;
    output.flush()?;
    loop {
        let mut bytes = Vec::new();
        let input_end = signer_watchdog::boottime_ns()? + SIGNER_IDLE_DEADLINE_MS as u64 * MS_TO_NS;
        loop {
            if !parent.live() || !peer.live() || signer_watchdog::boottime_ns()? >= input_end {
                return Err(refused());
            }
            if !readable(BRIDGE_INPUT) {
                std::thread::sleep(std::time::Duration::from_millis(WATCHDOG_TICK_MS as u64));
                continue;
            }
            let packet = signer_peer::receive(BRIDGE_INPUT, SIGNER_FRAME_MAX_BYTES)?;
            // The bridge authenticates every upstream write so passing its stream cannot launder another process's credentials.
            if !parent.matches(&packet)
                || !packet.rights.is_empty()
                || bytes.len() + packet.bytes.len() > SIGNER_FRAME_MAX_BYTES + LENGTH_BYTES
            {
                return Err(refused());
            }
            bytes.extend_from_slice(&packet.bytes);
            if bytes.len() < LENGTH_BYTES {
                continue;
            }
            let length =
                u32::from_be_bytes(bytes[..LENGTH_BYTES].try_into().map_err(|_| refused())?)
                    as usize;
            if length > SIGNER_FRAME_MAX_BYTES || bytes.len() > length + LENGTH_BYTES {
                return Err(refused());
            }
            if bytes.len() == length + LENGTH_BYTES {
                break;
            }
        }
        signer_peer::send(socket.as_raw_fd(), &bytes[LENGTH_BYTES..], &[])?;
        let end = signer_watchdog::boottime_ns()? + SIGNER_REQUEST_DEADLINE_MS as u64 * MS_TO_NS;
        while !readable(socket.as_raw_fd()) {
            if !peer.live() || !parent.live() || signer_watchdog::boottime_ns()? >= end {
                return Err(refused());
            }
            std::thread::sleep(std::time::Duration::from_millis(WATCHDOG_TICK_MS as u64));
        }
        let packet = signer_peer::receive(socket.as_raw_fd(), RESPONSE_MAX_BYTES + LENGTH_BYTES)?;
        if !peer.matches(&packet) || !packet.rights.is_empty() {
            return Err(refused());
        }
        output.write_all(&(packet.bytes.len() as u32).to_be_bytes())?;
        output.write_all(&packet.bytes)?;
        output.flush()?;
    }
}

pub fn verify_worker_signature(value: &Value, grant: &Value, preimage: &[u8]) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let Some((_, domain, _)) = ROLE_REGISTRY
        .iter()
        .find(|row| grant["role"].as_str() == Some(row.0))
    else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(value["signature"].as_str().unwrap_or("")) else {
        return false;
    };
    let Ok(key) = URL_SAFE_NO_PAD.decode(grant["public_key"].as_str().unwrap_or("")) else {
        return false;
    };
    // Native settlement verifies the exact admitted preimage under the pinned role domain before forwarding any signature.
    let message = [domain.as_bytes(), preimage].concat();
    super::strict_verify(&message, &signature, &key)
}

pub fn queue_lock(pending: &mut Vec<u8>, offset: &mut usize) -> io::Result<()> {
    // Keep the unsent suffix intact so LOCK follows one complete worker frame.
    pending.drain(..*offset);
    *offset = 0;
    pending.extend(encode(&json!({"op":"LOCK","preimage_length":0}), &[])?);
    Ok(())
}

#[derive(Debug, Default)]
pub struct Settlement {
    deadline: Option<u64>,
    cleanup: bool,
    faulted: bool,
}
impl Settlement {
    pub fn deadline(&self) -> Option<u64> {
        self.deadline
    }
    pub fn due(&self, now: u64) -> bool {
        self.deadline.is_some_and(|end| now >= end)
    }
    fn shorten_deadline(&mut self, proposed: u64) {
        // Every kill request shares this minimum so later events cannot prolong worker custody.
        self.deadline = Some(
            self.deadline
                .map_or(proposed, |current| current.min(proposed)),
        );
    }
    pub fn fault(&mut self, now: u64) {
        // A worker fault is sticky because a later cleanup frame cannot undo observed uncertainty.
        self.faulted = true;
        self.shorten_deadline(now);
    }
    pub fn lock(&mut self, state: State, now: u64) {
        self.shorten_deadline(if state == State::Unlocking {
            now
        } else {
            now.saturating_add(NS_PER_SECOND)
        });
    }
    pub fn acknowledge(&mut self, state: State, now: u64) {
        if self.cleanup || !matches!(state, State::Unlocking | State::Locking) {
            self.fault(now);
        } else {
            self.cleanup = true;
            self.shorten_deadline(now.saturating_add(NS_PER_SECOND));
        }
    }
    pub fn cooperative(&self, success: bool) -> bool {
        // Marker removal requires exactly one cleanup acknowledgement, no observed fault and successful reaping.
        self.cleanup && !self.faulted && success
    }
}

pub fn reaped_after_output(
    child: &mut Child,
    output: RawFd,
) -> io::Result<Option<std::process::ExitStatus>> {
    reaped_after_outputs(child, &[output])
}

pub fn reaped_after_outputs(
    child: &mut Child,
    outputs: &[RawFd],
) -> io::Result<Option<std::process::ExitStatus>> {
    let status = child.try_wait()?;
    if status.is_some() {
        for output in outputs {
            let mut available: libc::c_int = 0;
            // A child can exit between read and wait, so buffered cleanup frames must settle before the lease observes reaping.
            if unsafe { libc::ioctl(*output, libc::FIONREAD, &mut available) } != 0 {
                return Err(refused());
            }
            if available > 0 {
                return Ok(None);
            }
        }
    }
    Ok(status)
}

pub fn seal_lifecycle_backlog(listener: RawFd, accepted: usize) -> io::Result<bool> {
    if accepted < LIFECYCLE_CONNECTIONS_MAX.saturating_sub(1) {
        return Ok(false);
    }
    // Match signer_peer::listen's single queued connection by sealing before the final accept even when a prior probe was empty.
    if unsafe { libc::shutdown(listener, libc::SHUT_RD) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(true)
}
