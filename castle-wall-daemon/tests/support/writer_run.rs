#![allow(dead_code)]
use super::{writer_bus, writer_state};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::business_profile::{
    signer_client::{self, CurrentGrantView, SignedReply, StatusReply},
    signer_contract, signer_peer,
    signer_service::{self, Header},
    writer_peer::{HeldConfig, ListenerExpectations},
    writer_protocol::{self, Direction, Operation, StatusPayload},
    writer_service::*,
};
use std::{
    fs, io,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{fs::PermissionsExt, process::CommandExt},
    },
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
pub const CAPS: &str = "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
const WAIT_MS: i32 = 3000; // Three native request windows for child setup and teardown.
pub fn child_case(test: &str, case: &str, body: impl FnOnce()) {
    if let Ok(selected) = std::env::var("WRITER_COMPOSE_CASE") {
        if selected == case {
            body();
        }
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("record.sock");
    let listener = signer_peer::listen(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    let fd = listener.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--nocapture"])
        .env("WRITER_COMPOSE_CASE", case)
        .env("WRITER_COMPOSE_SOCKET", &path);
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{case}: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
struct Notify(mpsc::Sender<String>);
impl Notifier for Notify {
    fn notify(&mut self, text: &str) -> io::Result<()> {
        self.0
            .send(text.into())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}
enum Port {
    Script(Box<test_support::ScriptedSigner>),
    Native(Box<ClientSignerPort>, Arc<std::sync::atomic::AtomicUsize>),
}
impl SignerPort for Port {
    fn initial_status(&self) -> StatusReply {
        match self {
            Self::Script(s) => s.initial_status(),
            Self::Native(s, _) => s.initial_status(),
        }
    }
    fn status(&mut self) -> signer_client::Result<StatusReply> {
        match self {
            Self::Script(s) => s.status(),
            Self::Native(s, _) => s.status(),
        }
    }
    fn bind(&mut self, g: &CurrentGrantView) -> signer_client::Result<()> {
        match self {
            Self::Script(s) => s.bind(g),
            Self::Native(s, count) => {
                s.bind(g)?;
                count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }
    }
    fn sign_record(&mut self, h: Header, b: &[u8]) -> signer_client::Result<SignedReply> {
        match self {
            Self::Script(s) => s.sign_record(h, b),
            Self::Native(s, _) => s.sign_record(h, b),
        }
    }
    fn close_and_settle(&mut self) {
        match self {
            Self::Script(s) => s.close_and_settle(),
            Self::Native(s, _) => s.close_and_settle(),
        }
    }
}
struct Reconcile {
    closed: bool,
    calls: Arc<std::sync::atomic::AtomicUsize>,
}
impl Reconciler for Reconcile {
    fn reconcile(&mut self, e: ReconcileEvidence<'_>) -> Reconciliation {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.closed {
            ClosedReconciler::production().reconcile(e)
        } else {
            Reconciliation::Reconciled(Box::new(e.observation.clone()))
        }
    }
}
struct Received {
    operation: Operation,
    payload: Vec<u8>,
    session_id: String,
}
fn receive(fd: i32) -> Received {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut p, 1, WAIT_MS) },
        1,
        "wall reply deadline"
    );
    let packet = writer_protocol::receive(fd, Direction::ToWall).unwrap();
    let length = u32::from_be_bytes(packet.bytes[..4].try_into().unwrap()) as usize;
    let header: serde_json::Value = serde_json::from_slice(&packet.bytes[4..4 + length]).unwrap();
    let session_id = header["session_id"].as_str().unwrap().to_string();
    let frame = writer_protocol::decode(&packet.bytes, Direction::ToWall, &session_id).unwrap();
    Received {
        operation: frame.operation,
        payload: frame.payload.to_vec(),
        session_id,
    }
}
fn send(fd: i32, session: &str, op: &Operation, body: &[u8]) {
    signer_peer::send(
        fd,
        &writer_protocol::encode(Direction::ToWriter, session, op, body).unwrap(),
        &[],
    )
    .unwrap();
}
fn status(fd: i32, session: &str) -> StatusPayload {
    send(
        fd,
        session,
        &Operation::Status {
            request_id: "e".repeat(32),
        },
        &[],
    );
    let frame = receive(fd);
    assert!(matches!(frame.operation, Operation::StatusReply { .. }));
    StatusPayload::decode(&frame.payload).unwrap()
}
pub fn scenario(case: &str) {
    let mut bus = writer_bus::Fixture::new();
    let state = writer_state::Fixture::new();
    if case == "start-recovery" {
        state.state("RECOVERY_REQUIRED");
    }
    if case == "start-wipe" {
        state.state("WIPE_UNCONFIRMED");
    }
    if case.starts_with("start-refuse-") {
        state.state(case.strip_prefix("start-refuse-").unwrap());
    }
    let root = bus.root.path();
    bus.config.writer_sha256 = bus.config.wall_sha256.clone();
    let config_path = bus.config_path();
    if case == "capture-wall-hash" || case == "capture-fragment-hash" {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&config_path).unwrap()).unwrap();
        value[if case == "capture-wall-hash" {
            "wall_sha256"
        } else {
            "wall_unit_sha256"
        }] = serde_json::json!("0".repeat(64));
        fs::write(&config_path, serde_json::to_vec(&value).unwrap()).unwrap();
    }
    let cap = root.join("status");
    let maps = root.join("maps");
    let boot = root.join("boot");
    fs::write(&cap, CAPS).unwrap();
    fs::write(
        &maps,
        super::ClosureFixture::mapping(&bus.config.wall_exec, "r-xp"),
    )
    .unwrap();
    fs::write(&boot, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n").unwrap();
    if case.starts_with("native-") {
        // BusinessSignerClient::bind verifies the actual kernel boot, so both native peers consume that same source.
        let kernel = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
        state.view.lock().unwrap().boot_id =
            signer_service::parse_boot_id(kernel.as_bytes()).unwrap();
        fs::write(&boot, kernel).unwrap();
    }
    let closure_writer = if case == "slow-closure" {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(cap.as_os_str().as_bytes()).unwrap();
        fs::remove_file(&cap).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let fifo = cap.clone();
        let now = state.now.clone();
        Some(thread::spawn(move || {
            use std::io::Write;
            let mut writer = fs::OpenOptions::new().write(true).open(fifo).unwrap();
            // Opening the FIFO synchronizes with closure's read; elapsed work exceeds a whole signer idle window.
            now.fetch_add(
                (signer_contract::SIGNER_IDLE_DEADLINE_MS as u64 + 1) * writer_state::NS_PER_MS,
                Ordering::SeqCst,
            );
            writer.write_all(CAPS.as_bytes()).unwrap();
        }))
    } else {
        None
    };
    if case == "closure-refusal" {
        fs::write(&cap, CAPS.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).unwrap();
    }
    let paths = ClosurePaths::isolated(
        bus.config.wall_exec.clone(),
        cap,
        maps,
        bus.config.wall_exec.clone(),
        boot,
        unsafe { libc::geteuid() },
    );
    let config = HeldConfig::isolated(&config_path, unsafe { libc::geteuid() }).unwrap();
    let socket = std::path::PathBuf::from(std::env::var_os("WRITER_COMPOSE_SOCKET").unwrap());
    let listener = unsafe { OwnedFd::from_raw_fd(3) };
    let expectations =
        ListenerExpectations::isolated(socket.clone(), unsafe { libc::geteuid() }, unsafe {
            libc::getegid()
        });
    let (tx, rx) = mpsc::channel();
    let stop = Arc::new(AtomicBool::new(false));
    let mut script = state.signer();
    let stopping = stop.clone();
    let mut script_status = script.status;
    script.status = Box::new(move || {
        if stopping.load(Ordering::SeqCst) {
            Err(signer_client::Refusal::Transport)
        } else {
            script_status()
        }
    });
    if case.starts_with("postwait-") {
        let mut sign = script.sign;
        let unit = bus.unit.clone();
        let faults = bus.fault.clone();
        let case = case.to_string();
        script.sign = Box::new(move |h, b| {
            match case.as_str() {
                "postwait-mainpid" => unit.lock().unwrap().pid += 1,
                "postwait-invocation" => unit.lock().unwrap().invocation[0] ^= 1,
                "postwait-cgroup" => unit.lock().unwrap().cgroup.push('x'),
                "postwait-owner" => faults.lock().unwrap().uid_offset = 1,
                _ => panic!("unknown completion case"),
            }
            sign(h, b)
        });
    }
    if case == "maximum-sign" {
        state.delay.store(
            writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS * writer_state::NS_PER_MS,
            Ordering::SeqCst,
        );
    }
    let remote_pid = Arc::new(std::sync::atomic::AtomicI32::new(0));
    if case == "death-during-sign" {
        let pid = remote_pid.clone();
        let mut sign = script.sign;
        script.sign = Box::new(move |h, b| {
            assert_eq!(
                unsafe { libc::kill(pid.load(Ordering::SeqCst), libc::SIGKILL) },
                0
            );
            sign(h, b)
        });
    }
    let mut native_thread = None;
    let bootstrap: Box<dyn FnOnce() -> Result<Port> + Send> = if case.starts_with("native-") {
        let path = root.join("sign.sock");
        let listener = signer_peer::listen(&path).unwrap();
        let view = state.view.clone();
        let signature = state.signature.clone();
        let signs = state.signs.clone();
        let statuses = state.statuses.clone();
        let stopping = stop.clone();
        native_thread = Some(thread::spawn(move || {
            let socket = loop {
                if let Ok(fd) = signer_peer::accept(listener.as_raw_fd()) {
                    break fd;
                }
                thread::sleep(Duration::from_millis(1));
            };
            loop {
                if stopping.load(Ordering::SeqCst) {
                    break;
                }
                let mut poll = libc::pollfd {
                    fd: socket.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 10) } != 1 {
                    continue;
                }
                let Ok(packet) = signer_peer::receive(socket.as_raw_fd(), 66564) else {
                    break;
                };
                if packet.bytes.is_empty() {
                    break;
                }
                let response = if packet.bytes == b"{\"op\":\"STATUS\"}" {
                    statuses.fetch_add(1, Ordering::SeqCst);
                    serde_json::to_value(view.lock().unwrap().clone()).unwrap()
                } else {
                    let (h, _) = signer_service::decode(&packet.bytes).unwrap();
                    signs.fetch_add(1, Ordering::SeqCst);
                    serde_json::json!({"op":"SIGNED","request_id":h.request_id,"kid":view.lock().unwrap().grant.kid,"signature":URL_SAFE_NO_PAD.encode(*signature.lock().unwrap())})
                };
                if signer_peer::send(
                    socket.as_raw_fd(),
                    &signer_service::encode(&response, &[]).unwrap(),
                    &[],
                )
                .is_err()
                {
                    break;
                }
            }
        }));
        use sha2::{Digest, Sha256};
        let policy = signer_peer::PeerPolicy {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            executable_sha256: hex::encode(Sha256::digest(fs::read("/proc/self/exe").unwrap())),
            cgroup: fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .trim()
                .into(),
        };
        let clock = state.clock();
        let binds = state.binds.clone();
        Box::new(move || {
            Ok(Port::Native(
                Box::new(ClientSignerPort::bootstrap_at_with_clock(
                    &path, policy, clock,
                )?),
                binds,
            ))
        })
    } else {
        Box::new(move || Ok(Port::Script(Box::new(script))))
    };
    let bootstrapped_at = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let bootstrap_time = bootstrapped_at.clone();
    let bootstrap_clock = state.now.clone();
    let bootstrap = Box::new(move || {
        bootstrap_time.store(bootstrap_clock.load(Ordering::SeqCst), Ordering::SeqCst);
        bootstrap()
    });
    let deps = Dependencies {
        bootstrap,
        reconciler: Reconcile {
            closed: case == "inert",
            calls: state.reconciles.clone(),
        },
        notifier: Notify(tx),
        config,
        bus: bus.target.clone(),
        listener,
        expectations,
        activation: Activation {
            pid: std::process::id().to_string(),
            fds: if case == "activation-two" { "2" } else { "1" }.into(),
            names: "records".into(),
        },
        clock: state.clock(),
        paths,
        environment: vec![],
    };
    let runner = thread::spawn(move || run(deps));
    let first = rx
        .recv_timeout(Duration::from_millis(WAIT_MS as u64))
        .unwrap();
    if let Some(writer) = closure_writer {
        writer.join().unwrap();
    }
    if case == "closure-refusal" {
        assert_eq!(first, "STATUS=writer refused at start");
        assert!(runner.join().unwrap().is_err());
        assert_eq!(
            bootstrapped_at.load(Ordering::SeqCst),
            0,
            "closure precedes bootstrap"
        );
        return;
    }
    if case == "slow-closure" {
        assert_eq!(first, "READY=1\nSTATUS=writer closed");
        state.now.fetch_add(
            writer_protocol::WRITER_HEARTBEAT_MS * writer_state::NS_PER_MS,
            Ordering::SeqCst,
        );
        let start = std::time::Instant::now();
        while state.statuses.load(Ordering::SeqCst) == 0 {
            assert!(start.elapsed() < Duration::from_millis(WAIT_MS as u64));
            thread::yield_now();
        }
        let gap = state.now.load(Ordering::SeqCst) - bootstrapped_at.load(Ordering::SeqCst);
        assert!(
            gap < signer_contract::SIGNER_IDLE_DEADLINE_MS as u64 * writer_state::NS_PER_MS,
            "bootstrap to first heartbeat stays within idle window"
        );
        stop.store(true, Ordering::SeqCst);
        state.now.fetch_add(
            writer_protocol::WRITER_HEARTBEAT_MS * writer_state::NS_PER_MS,
            Ordering::SeqCst,
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.closes.load(Ordering::SeqCst), 1);
        return;
    }
    if case.starts_with("start-refuse-") || case == "activation-two" {
        assert_eq!(first, "STATUS=writer refused at start");
        assert!(runner.join().unwrap().is_err());
        assert_eq!(
            state.closes.load(Ordering::SeqCst),
            usize::from(case != "activation-two")
        );
        return;
    }
    assert_eq!(
        first,
        if case == "start-recovery" || case == "start-wipe" {
            "READY=1\nSTATUS=writer closed for recovery"
        } else {
            "READY=1\nSTATUS=writer closed"
        }
    );
    if case == "death-during-sign" {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let parent = socket.parent().unwrap();
        let holder = signer_peer::listen(&parent.join("holder.sock")).unwrap();
        let child = Child(
            Command::new(env!("CARGO_BIN_EXE_writer-standin"))
                .args(["wall", parent.to_str().unwrap(), "sign"])
                .spawn()
                .unwrap(),
        );
        remote_pid.store(child.0.id() as i32, Ordering::SeqCst);
        bus.unit.lock().unwrap().pid = child.0.id();
        fs::write(parent.join("go"), b"go").unwrap();
        let start = std::time::Instant::now();
        while !parent.join("wall-bound").exists() {
            assert!(start.elapsed() < Duration::from_millis(WAIT_MS as u64));
            thread::sleep(Duration::from_millis(2));
        }
        let control = signer_peer::accept(holder.as_raw_fd()).unwrap();
        let packet = signer_peer::receive(control.as_raw_fd(), 1024).unwrap();
        assert_eq!(packet.rights.len(), 1);
        let held = &packet.rights[0];
        assert_eq!(state.binds.load(Ordering::SeqCst), 0);
        state.unlock();
        for _ in 0..2 {
            state
                .now
                .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(30));
        }
        assert_eq!(state.binds.load(Ordering::SeqCst), 1);
        let session = fs::read_to_string(parent.join("wall-bound")).unwrap();
        let bytes = writer_protocol::encode(
            Direction::ToWriter,
            &session,
            &Operation::Sign(state.header()),
            &state.body,
        )
        .unwrap();
        fs::write(parent.join("pending-sign"), bytes).unwrap();
        fs::rename(parent.join("pending-sign"), parent.join("sign-packet")).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.signs.load(Ordering::SeqCst), 1);
        signer_peer::passcred(held.as_raw_fd()).unwrap();
        // No successful envelope can be sent after the bound peer dies during the native wait.
        let mut poll = libc::pollfd {
            fd: held.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, WAIT_MS) }, 1);
        let mut bytes = vec![0; writer_protocol::WRITER_REPLY_PACKET_MAX_BYTES];
        let n = unsafe { libc::recv(held.as_raw_fd(), bytes.as_mut_ptr() as _, bytes.len(), 0) };
        assert!(n >= 0);
        if n > 0 {
            let frame =
                writer_protocol::decode(&bytes[..n as usize], Direction::ToWall, &session).unwrap();
            assert!(matches!(frame.operation, Operation::Refused { .. }));
        }
        assert!(!parent.join("sign-result").exists());
        return;
    }
    if case.starts_with("heartbeat-timeout-") {
        state
            .status_delay
            .store(1000 * writer_state::NS_PER_MS, Ordering::SeqCst);
        state
            .now
            .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.statuses.load(Ordering::SeqCst), 1);
        assert_eq!(state.closes.load(Ordering::SeqCst), 1);
        return;
    }
    if case.starts_with("capture-") {
        match case {
            "capture-mainpid" => bus.unit.lock().unwrap().pid += 1,
            "capture-cgroup" => bus.unit.lock().unwrap().cgroup.push('x'),
            "capture-unit-id" => bus.unit.lock().unwrap().id.push('x'),
            "capture-invocation" => {
                bus.unit.lock().unwrap().invocation.pop();
            }
            "capture-argv" => bus.unit.lock().unwrap().argv.reverse(),
            "capture-dropins" => bus.unit.lock().unwrap().dropins.push("/extra".into()),
            "capture-owner" => bus.fault.lock().unwrap().pid_offset = 1,
            _ => (),
        }
        let wall = signer_peer::connect(&socket).unwrap();
        signer_peer::passcred(wall.as_raw_fd()).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.signs.load(Ordering::SeqCst), 0);
        assert_eq!(state.closes.load(Ordering::SeqCst), 1);
        return;
    }
    if case.starts_with("bus-") {
        bus.fault.lock().unwrap().malformed = Some(case.strip_prefix("bus-").unwrap().into());
        let wall = signer_peer::connect(&socket).unwrap();
        signer_peer::passcred(wall.as_raw_fd()).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.signs.load(Ordering::SeqCst), 0);
        assert_eq!(state.closes.load(Ordering::SeqCst), 1);
        return;
    }
    let wall = signer_peer::connect(&socket).unwrap();
    signer_peer::passcred(wall.as_raw_fd()).unwrap();
    let hello = receive(wall.as_raw_fd());
    assert!(matches!(hello.operation, Operation::Hello));
    if case == "ack-foreign" {
        let bytes = writer_protocol::encode(
            Direction::ToWriter,
            &hello.session_id,
            &Operation::HelloAck,
            &[],
        )
        .unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            unsafe {
                libc::send(
                    wall.as_raw_fd(),
                    bytes.as_ptr() as _,
                    bytes.len(),
                    libc::MSG_NOSIGNAL,
                );
                libc::_exit(0);
            }
        }
        assert_eq!(
            unsafe { libc::waitpid(child, std::ptr::null_mut(), 0) },
            child
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.signs.load(Ordering::SeqCst), 0);
        return;
    }
    send(
        wall.as_raw_fd(),
        &hello.session_id,
        &Operation::HelloAck,
        &[],
    );
    let closed = status(wall.as_raw_fd(), &hello.session_id);
    assert!(
        closed.grant.is_none(),
        "authenticated WallBound remains closed"
    );
    if case.starts_with("packet-") {
        if case == "packet-mainpid" {
            bus.unit.lock().unwrap().pid += 1;
        }
        let session = if case == "packet-session" {
            "f".repeat(32)
        } else {
            hello.session_id.clone()
        };
        let bytes = writer_protocol::encode(
            Direction::ToWriter,
            &session,
            &Operation::Status {
                request_id: "e".repeat(32),
            },
            &[],
        )
        .unwrap();
        let rights = if case == "packet-rights" {
            vec![wall.as_raw_fd()]
        } else {
            vec![]
        };
        signer_peer::send(wall.as_raw_fd(), &bytes, &rights).unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            "STOPPING=1"
        );
        assert!(runner.join().unwrap().is_err());
        assert_eq!(state.signs.load(Ordering::SeqCst), 0);
        return;
    }
    if case == "second-accept" {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let parent = socket.parent().unwrap();
        let child = Child(
            Command::new(env!("CARGO_BIN_EXE_writer-standin"))
                .args(["wall", parent.to_str().unwrap(), "main"])
                .spawn()
                .unwrap(),
        );
        {
            let mut unit = bus.unit.lock().unwrap();
            unit.pid = child.0.id();
            unit.invocation[0] ^= 1;
        }
        fs::write(parent.join("go"), b"go").unwrap();
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap_or_else(|_| panic!(
                    "second accept remained active; second peer bound={}",
                    parent.join("wall-bound").exists()
                )),
            STOP_STATUS
        );
    } else if case == "start-recovery" || case == "start-wipe" {
        assert_eq!(
            closed.state,
            if case == "start-recovery" {
                "RECOVERY_REQUIRED"
            } else {
                "WIPE_UNCONFIRMED"
            }
        );
        drop(wall);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
    } else {
        if case.starts_with("recovery-") {
            state.state("RECOVERY_REQUIRED");
            state
                .now
                .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(30));
            assert!(status(wall.as_raw_fd(), &hello.session_id).grant.is_none());
            if case != "recovery-no-lock" {
                state.state("LOCKED");
                state
                    .now
                    .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(30));
                assert_eq!(status(wall.as_raw_fd(), &hello.session_id).state, "LOCKED");
                if case == "recovery-fresh" {
                    state.now.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        state.unlock();
        if case == "boot-mismatch" {
            state.view.lock().unwrap().boot_id = "b".repeat(32);
        }
        if case == "native-null" {
            let mut v = state.view.lock().unwrap();
            v.anchor_revision = None;
            v.anchor_digest = None;
        }
        for _ in 0..2 {
            let count = state.statuses.load(Ordering::SeqCst);
            state
                .now
                .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
            for _ in 0..100 {
                if state.statuses.load(Ordering::SeqCst) > count {
                    break;
                }
                thread::sleep(Duration::from_millis(2));
            }
            assert!(state.statuses.load(Ordering::SeqCst) > count);
            // A status reply serializes after the heartbeat's reconciliation step.
            let _ = status(wall.as_raw_fd(), &hello.session_id);
        }
        assert_eq!(
            state.reconciles.load(Ordering::SeqCst) > 0,
            !matches!(
                case,
                "recovery-no-lock" | "recovery-stale" | "boot-mismatch"
            ),
            "reconciliation only follows valid recovery and boot observations"
        );
        let granted = status(wall.as_raw_fd(), &hello.session_id);
        assert_eq!(
            granted.grant.is_some(),
            !matches!(
                case,
                "native-null" | "inert" | "recovery-no-lock" | "recovery-stale" | "boot-mismatch"
            )
        );
        assert_eq!(
            state.binds.load(Ordering::SeqCst),
            usize::from(!matches!(
                case,
                "native-null" | "inert" | "recovery-no-lock" | "recovery-stale" | "boot-mismatch"
            )),
            "one successful bind only after matching populated observation"
        );
        if case == "frozen-expiry" || case.starts_with("bound-change-") {
            if case == "frozen-expiry" {
                let expiry = state
                    .view
                    .lock()
                    .unwrap()
                    .expires_boottime_ns
                    .parse::<u64>()
                    .unwrap();
                state.now.store(expiry, Ordering::SeqCst);
            } else {
                let mut view = state.view.lock().unwrap();
                match case {
                    "bound-change-grant" => view.grant.generation += 1,
                    "bound-change-start" => {
                        view.started_boottime_ns = (writer_state::NOW + 1).to_string()
                    }
                    "bound-change-expiry" => {
                        view.expires_boottime_ns =
                            (writer_state::NOW + 299000 * writer_state::NS_PER_MS).to_string()
                    }
                    "bound-change-boot" => view.boot_id = "b".repeat(32),
                    _ => panic!("unknown bound fault"),
                }
                state
                    .now
                    .fetch_add(250 * writer_state::NS_PER_MS, Ordering::SeqCst);
            }
            assert_eq!(
                rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                    .unwrap(),
                STOP_STATUS
            );
            assert_eq!(
                rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                    .unwrap(),
                "STOPPING=1"
            );
            assert!(runner.join().unwrap().is_err());
            assert_eq!(state.closes.load(Ordering::SeqCst), 1);
            return;
        }
        if case.starts_with("aged-") {
            use castle_wall_daemon::business_profile::signer_watchdog::WATCHDOG_TICK_MS;
            use writer_protocol::{WRITER_HEARTBEAT_MS, WRITER_SIGN_DEADLINE_MAX_MS};
            let tick = WATCHDOG_TICK_MS as u64;
            let age_ms = WRITER_HEARTBEAT_MS - tick;
            let last = *state.status_times.lock().unwrap().last().unwrap();
            state
                .now
                .store(last + age_ms * writer_state::NS_PER_MS, Ordering::SeqCst);
            let late = case.ends_with("late");
            // Leave one watchdog tick for a successful bus exchange; the late reply crosses the local window.
            let delay_ms = if late {
                WRITER_SIGN_DEADLINE_MAX_MS - tick
            } else {
                WRITER_SIGN_DEADLINE_MAX_MS - age_ms - tick
            };
            let advance_ms = if late {
                WRITER_SIGN_DEADLINE_MAX_MS + tick
            } else {
                delay_ms
            };
            bus.fault.lock().unwrap().hello_delay = Some((
                delay_ms,
                advance_ms * writer_state::NS_PER_MS,
                state.now.clone(),
            ));
            let operation = if case.starts_with("aged-sign") {
                Operation::Sign(state.header())
            } else {
                Operation::Status {
                    request_id: "e".repeat(32),
                }
            };
            send(
                wall.as_raw_fd(),
                &hello.session_id,
                &operation,
                if case.starts_with("aged-sign") {
                    &state.body
                } else {
                    &[]
                },
            );
            if late {
                assert_eq!(
                    rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                        .unwrap(),
                    STOP_STATUS
                );
                let settled = state.now.load(Ordering::SeqCst);
                assert!(
                    settled - last
                        < signer_contract::SIGNER_IDLE_DEADLINE_MS as u64 * writer_state::NS_PER_MS,
                    "settlement stays inside the signer idle window"
                );
                assert_eq!(state.signs.load(Ordering::SeqCst), 0);
            } else {
                let reply = receive(wall.as_raw_fd());
                assert!(matches!(
                    reply.operation,
                    Operation::StatusReply { .. } | Operation::Verified { .. }
                ));
                bus.fault.lock().unwrap().hello_delay = None;
                let start = std::time::Instant::now();
                while *state.status_times.lock().unwrap().last().unwrap() == last {
                    assert!(start.elapsed() < Duration::from_millis(WAIT_MS as u64));
                    thread::yield_now();
                }
                let times = state.status_times.lock().unwrap();
                assert!(
                    times.windows(2).all(|pair| pair[1] - pair[0]
                        < signer_contract::SIGNER_IDLE_DEADLINE_MS as u64
                            * writer_state::NS_PER_MS),
                    "every status gap stays inside the signer idle window"
                );
                drop(times);
                drop(wall);
                assert_eq!(
                    rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                        .unwrap(),
                    STOP_STATUS
                );
            }
            assert_eq!(
                rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                    .unwrap(),
                "STOPPING=1"
            );
            assert!(runner.join().unwrap().is_err());
            return;
        }
        let mut h = state.header();
        let mut body = state.body.clone();
        if case == "short-sign" {
            // One caller millisecond is shorter than one watchdog tick of bus work; the injected signer clock stays fixed.
            h.deadline_boottime_ns =
                (state.now.load(Ordering::SeqCst) + writer_state::NS_PER_MS).to_string();
            bus.fault.lock().unwrap().reply_delay_ms =
                castle_wall_daemon::business_profile::signer_watchdog::WATCHDOG_TICK_MS as u64;
        }
        if case.starts_with("admission-") {
            match case {
                "admission-activation" => h.activation_id = "b".repeat(32),
                "admission-lease" => h.lease_id = "b".repeat(32),
                "admission-generation" => h.generation += 1,
                "admission-epoch" => h.epoch += 1,
                "admission-deadline" => {
                    h.deadline_boottime_ns = (state.now.load(Ordering::SeqCst)
                        + (writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS + 1)
                            * writer_state::NS_PER_MS)
                        .to_string()
                }
                "admission-text" => h.deadline_boottime_ns = "invalid".into(),
                "admission-noncanonical" => h.deadline_boottime_ns.insert(0, '0'),
                "admission-expired" => {
                    h.deadline_boottime_ns = state.now.load(Ordering::SeqCst).to_string()
                }
                _ => panic!("unknown admission"),
            }
        }

        if case == "noncanonical" {
            body.push(b' ');
            h.preimage_length = body.len();
        }
        if case == "oversized-canonical" {
            let mut value: serde_json::Value = serde_json::from_slice(&body).unwrap();
            value["payload"]["oversized"] =
                serde_json::json!("x".repeat(writer_protocol::WRITER_ENVELOPE_MAX_BYTES));
            body = serde_json::to_vec(&value).unwrap();
            h.preimage_length = body.len();
            assert!(body.len() > writer_protocol::WRITER_ENVELOPE_MAX_BYTES);
        }
        if case == "wrong-signature" {
            let corpus: serde_json::Value = serde_json::from_str(include_str!(
                "../../src/business_profile/record_join_vectors.json"
            ))
            .unwrap();
            *state.signature.lock().unwrap() = URL_SAFE_NO_PAD
                .decode(
                    corpus["cases"][2]["records"][1]["outer"]["signature"]
                        .as_str()
                        .unwrap(),
                )
                .unwrap()
                .try_into()
                .unwrap();
        }
        send(
            wall.as_raw_fd(),
            &hello.session_id,
            &Operation::Sign(h),
            &body,
        );
        let reply = receive(wall.as_raw_fd());
        if matches!(
            case,
            "native-null"
                | "inert"
                | "recovery-no-lock"
                | "recovery-stale"
                | "boot-mismatch"
                | "noncanonical"
                | "oversized-canonical"
                | "wrong-signature"
        ) || case.starts_with("postwait-")
            || case.starts_with("admission-")
        {
            assert!(
                matches!(reply.operation, Operation::Refused { ref request_id } if *request_id == state.header().request_id)
            );
            assert_eq!(
                state.signs.load(Ordering::SeqCst),
                usize::from(case == "wrong-signature" || case.starts_with("postwait-"))
            );
        } else {
            assert!(matches!(reply.operation, Operation::Verified { .. }));
            let envelope: serde_json::Value = serde_json::from_slice(&reply.payload).unwrap();
            assert_eq!(serde_json::to_vec(&envelope["body"]).unwrap(), state.body);
            assert_eq!(state.signs.load(Ordering::SeqCst), 1);
        }
        drop(wall);
        assert_eq!(
            rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                .unwrap(),
            STOP_STATUS
        );
    }
    assert_eq!(
        rx.recv_timeout(Duration::from_millis(WAIT_MS as u64))
            .unwrap(),
        "STOPPING=1"
    );
    assert!(runner.join().unwrap().is_err());
    stop.store(true, Ordering::SeqCst);
    if let Some(thread) = native_thread {
        thread.join().unwrap();
    }
}
