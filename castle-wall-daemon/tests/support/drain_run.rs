// fail-before-exempt: New real-process drain driver with explicit isolated roots and bounded child IO.
#![allow(dead_code)]
use super::writer_bus;
use castle_wall_daemon::business_profile::{
    drain_protocol as protocol, drain_service::packet_digest, drain_store::DRAIN_SLOTS,
    signer_contract, writer_protocol,
};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixDatagram},
    },
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};
pub const ROLE: &str = DRAIN_SLOTS[0].1;
pub const SLOT: &str = DRAIN_SLOTS[0].0;
pub const FORTRESS: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
pub const WAIT_MS: u64 = protocol::D_REQUEST_DEADLINE_MS as u64 * 5;
static SERIAL: AtomicUsize = AtomicUsize::new(0);
pub fn canonical(v: &Value) -> Vec<u8> {
    castle_wall_daemon::smb::jcs::encode(v)
        .unwrap()
        .into_bytes()
}
pub fn native(name: &str) -> PathBuf {
    let root = std::env::var_os("SANCTUARY_K1_TEST_BINARIES").expect("K1_NATIVE_BINARIES_REQUIRED");
    let path = PathBuf::from(root).join("debug").join(name);
    assert!(
        path.is_file(),
        "K1_NATIVE_BINARY_UNBUILT: {}",
        path.display()
    );
    path
}
pub fn actor_path() -> PathBuf {
    std::env::var_os("DRAIN_TEST_ACTOR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_drain-actor")))
}
pub struct Actor {
    pub child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}
impl Actor {
    pub fn new() -> Self {
        let path = actor_path();
        let mut child = Command::new(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Self {
            child,
            input,
            output,
        }
    }
    pub fn command(&mut self, v: Value) -> Value {
        writeln!(self.input, "{v}").unwrap();
        self.input.flush().unwrap();
        let mut p = libc::pollfd {
            fd: self.output.get_ref().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut p, 1, (WAIT_MS * 2) as i32) },
            1,
            "actor IO timeout"
        );
        let mut line = String::new();
        assert!(
            self.output.read_line(&mut line).unwrap() > 0,
            "actor exited"
        );
        serde_json::from_str(&line).unwrap()
    }
    pub fn connect(&mut self, path: &Path) {
        self.command(json!({"op":"close"}));
        assert_eq!(
            self.command(json!({"op":"connect","path":path}))["ok"],
            true
        );
    }
    pub fn send(&mut self, bytes: &[u8]) {
        assert_eq!(
            self.command(json!({"op":"send","hex":hex::encode(bytes)}))["ok"],
            true
        );
    }
    pub fn receive(&mut self, ms: u64) -> Option<Vec<u8>> {
        let v = self.command(json!({"op":"receive","ms":ms}));
        v["hex"].as_str().map(|s| hex::decode(s).unwrap())
    }
}
impl Drop for Actor {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
pub struct Fixture {
    pub root: PathBuf,
    pub s: Actor,
    pub w: Actor,
    pub bus: writer_bus::Fixture,
    pub child: Option<Child>,
    pub notify: UnixDatagram,
    pub anchor: Value,
    pub body: Value,
    pub key: SigningKey,
}
impl Fixture {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "dr-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["state", "runtime", "custody"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let s = Actor::new();
        let w = Actor::new();
        let bus = writer_bus::Fixture::new();
        bus.unit.lock().unwrap().pid = w.child.id();
        let owner = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let actor = actor_path();
        let config = json!({"version":1,"fortress_id":FORTRESS,"signer":{"uid":owner,"gid":gid,"executable_sha256":hex::encode(Sha256::digest(fs::read(actor).unwrap())),"cgroup":fs::read_to_string("/proc/self/cgroup").unwrap()},"wall":{"unit":bus.config.wall_unit,"exec":bus.config.wall_exec,"sha256":bus.config.wall_sha256,"argv_sha256":bus.config.wall_argv_sha256,"unit_sha256":bus.config.wall_unit_sha256,"dropins":[],"gid":gid}});
        write_private(&root.join("config.json"), &canonical(&config));
        write_private(
            &root.join("seam.json"),
            &canonical(
                &json!({"owner":owner,"peer_uid":owner,"signer_pid":s.child.id(),"signer_group":"/drain-fixture-signer","bus":{"socket":bus.root.path().join("bus"),"socket_owner_uid":owner,"expected_manager_uid":owner,"expected_manager_pid":std::process::id(),"wall_unit":bus.config.wall_unit}}),
            ),
        );
        write_private(&root.join("store-faults.json"), b"[]");
        let closure: Value = serde_json::from_str(include_str!(
            "../../src/business_profile/closure_vectors.json"
        ))
        .unwrap();
        let mut a = closure["anchor"].clone();
        let corpus: Value = serde_json::from_str(include_str!(
            "../../src/business_profile/record_join_vectors.json"
        ))
        .unwrap();
        let mut body = corpus["cases"][0]["records"][0]["body"].clone();
        let key = SigningKey::from_bytes(&[7; 32]); // Public synthetic fixture seed, never production material.
        body["kid"] = json!(castle_wall_daemon::business_profile::role_kid(
            ROLE,
            body["epoch"].as_u64().unwrap(),
            &key.verifying_key().to_bytes()
        )
        .unwrap());
        for (to, from) in [
            ("machine_id", "machine_id"),
            ("activation_id", "activation_id"),
            ("boot_id", "boot_id"),
            ("generation_high_water", "generation"),
        ] {
            a[to] = body[from].clone();
        }
        let descriptor = json!({"version":1,"fortress_id":FORTRESS,"machine_id":body["machine_id"],"identity_id":body["identity_id"],"epochs":[{"role":ROLE,"epoch":body["epoch"],"kid":body["kid"],"public_key":hex::encode(key.verifying_key().to_bytes())}]});
        let bytes = canonical(&descriptor);
        a["descriptor_digest"] = json!(packet_digest(&bytes));
        let dirs = [
            root.join("custody").join(FORTRESS),
            root.join("custody").join(FORTRESS).join(SLOT),
            root.join("custody")
                .join(FORTRESS)
                .join(SLOT)
                .join("public"),
        ];
        for d in &dirs {
            fs::create_dir(d).unwrap();
            fs::set_permissions(d, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(dirs[2].join("epochs.json"), bytes).unwrap();
        fs::set_permissions(
            dirs[2].join("epochs.json"),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        let notify = UnixDatagram::bind(root.join("notify")).unwrap();
        notify
            .set_read_timeout(Some(Duration::from_millis(WAIT_MS)))
            .unwrap();
        Self {
            root,
            s,
            w,
            bus,
            child: None,
            notify,
            anchor: a,
            body,
            key,
        }
    }
    pub fn spawn(&self) -> Child {
        Command::new(native("sanctuary-business-drain"))
            .args(["--test-root", self.root.to_str().unwrap()])
            .env("NOTIFY_SOCKET", self.root.join("notify"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::OpenOptions::new().create(true).append(true).open(self.root.join("diagnostics.log")).unwrap())
            .spawn()
            .unwrap()
    }
    pub fn start(&mut self) {
        self.child = Some(self.spawn());
        let status = self.notification();
        assert!(
            status.contains("READY=1"),
            "{status}; stages={:?}",
            self.stages()
        );
    }
    pub fn notification(&self) -> String {
        self.try_notification().expect("drain notify deadline")
    }
    pub fn try_notification(&self) -> Option<String> {
        let mut bytes = [0; 1024];
        let n = self.notify.recv(&mut bytes).ok()?;
        String::from_utf8(bytes[..n].to_vec()).ok()
    }
    pub fn stop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.s.command(json!({"op":"close"}));
        self.w.command(json!({"op":"close"}));
    }
    pub fn socket(&self) -> PathBuf {
        self.root.join("runtime/drain.sock")
    }
    pub fn request(&mut self, signer: bool, bytes: &[u8]) -> Option<Value> {
        let path = self.socket();
        let actor = if signer { &mut self.s } else { &mut self.w };
        actor.connect(&path);
        if actor.command(json!({"op":"send","hex":hex::encode(bytes)}))["ok"] != true {
            return None;
        }
        actor.receive(WAIT_MS).map(|bytes| {
            let (h, _) = castle_wall_daemon::business_profile::frame::split(
                &bytes,
                protocol::D_HEADER_MAX_BYTES,
                protocol::D_REPLY_MAX_BYTES,
            )
            .unwrap();
            h
        })
    }
    pub fn read(&mut self, signer: bool) -> Value {
        let p = protocol::encode(
            &protocol::header("READ", &"e".repeat(32), ROLE),
            &[],
            protocol::Direction::ToDrain,
        )
        .unwrap();
        self.request(signer, &p).unwrap()
    }
    pub fn prepare(&mut self) -> (Vec<u8>, Vec<u8>) {
        let id = "c".repeat(32);
        let mut next = self.anchor.clone();
        next["transaction_id"] = json!(id);
        let m = json!({"version":1,"op":"PREPARE","request_id":id,"expected":null,"next":next});
        let p = anchor_packet(&m, &[]);
        assert_eq!(self.request(true, &p).unwrap()["op"], "ANCHOR_ACK");
        let m =
            json!({"version":1,"op":"COMMIT","request_id":id,"expected":next,"next":self.anchor});
        let c = anchor_packet(&m, &[]);
        assert_eq!(self.request(true, &c).unwrap()["op"], "ANCHOR_ACK");
        (p, c)
    }
    pub fn signed(&self, body: &Value) -> Vec<u8> {
        let b = canonical(body);
        let domain = signer_contract::ROLE_REGISTRY
            .iter()
            .find(|r| r.0 == ROLE)
            .unwrap()
            .1;
        let sig = self.key.sign(&[domain.as_bytes(), &b].concat()).to_bytes();
        writer_protocol::envelope(&b, &sig).unwrap()
    }
    pub fn reserve_commit(&mut self, id: &str) -> (Vec<u8>, Vec<u8>) {
        let mut body = self.body.clone();
        body["sequence"] = json!(self.anchor["committed_sequence"].as_u64().unwrap() + 1);
        body["prior_commitment"] = self.anchor["committed_digest"].clone();
        let envelope = self.signed(&body);
        let body_digest = packet_digest(&canonical(&body));
        let mut next = self.anchor.clone();
        next["reserved_sequence"] = body["sequence"].clone();
        next["reserved_body_digest"] = json!(body_digest);
        let m = json!({"version":1,"op":"RESERVE","request_id":id,"expected":self.anchor,"next":next,"body_digest":body_digest});
        assert_eq!(
            self.request(false, &anchor_packet(&m, &[])).unwrap()["op"],
            "ANCHOR_ACK"
        );
        self.anchor = next.clone();
        next["reserved_body_digest"] = Value::Null;
        next["committed_sequence"] = body["sequence"].clone();
        next["committed_digest"] = json!(
            castle_wall_daemon::business_profile::records::join_commitment(
                &writer_protocol::decode_envelope(&envelope).unwrap()
            )
            .unwrap()
        );
        let m = json!({"version":1,"op":"COMMIT","request_id":id,"expected":self.anchor,"next":next,"body_digest":body_digest});
        let packet = anchor_packet(&m, &envelope);
        assert_eq!(self.request(false, &packet).unwrap()["op"], "ANCHOR_ACK");
        self.anchor = next;
        (packet, envelope)
    }
    pub fn events(&self) -> Vec<Value> {
        fs::read_to_string(self.root.join("events.jsonl"))
            .unwrap_or_default()
            .split_inclusive('\n')
            // The producer can be between write_fmt and its newline when the polling driver reads.
            .filter(|s| s.ends_with('\n'))
            .map(|s| serde_json::from_str(s).unwrap())
            .collect()
    }
    pub fn stages(&self) -> Vec<String> {
        fs::read_to_string(self.root.join("refusals.jsonl"))
            .unwrap_or_default()
            .split_inclusive('\n')
            .filter(|s| s.ends_with('\n'))
            .map(|s| {
                serde_json::from_str::<Value>(s).unwrap()["stage"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }
    pub fn fault(&self, publication: &str, step: &str, action: &str, value: Value, times: u64) {
        write_private(
            &self.root.join("store-faults.json"),
            &canonical(
                &json!([{"slot":SLOT,"publication":publication,"step":step,"position":"before","action":action,"value":value,"times":times}]),
            ),
        );
    }
    pub fn clear(&self) {
        write_private(&self.root.join("store-faults.json"), b"[]");
    }
}
pub fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
pub fn anchor_packet(m: &Value, envelope: &[u8]) -> Vec<u8> {
    let mut h = protocol::header("ANCHOR", m["request_id"].as_str().unwrap(), ROLE);
    let bytes = canonical(m);
    h["message_length"] = json!(bytes.len());
    h["envelope_length"] = json!(envelope.len());
    protocol::encode(
        &h,
        &[bytes, envelope.to_vec()].concat(),
        protocol::Direction::ToDrain,
    )
    .unwrap()
}
pub fn original_packet(id: &str, sequence: u64, envelope: &[u8]) -> Vec<u8> {
    let mut h = protocol::header("ORIGINAL", id, ROLE);
    h["sequence"] = json!(sequence);
    h["payload_length"] = json!(envelope.len());
    protocol::encode(&h, envelope, protocol::Direction::ToDrain).unwrap()
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop();
        let f = self.root.join("state").join(FORTRESS);
        let c = self.root.join("custody").join(FORTRESS);
        for dir in [
            f.join("originals").join(SLOT),
            f.join("originals"),
            f.join("anchors"),
            f,
            c.join(SLOT).join("public"),
            c.join(SLOT),
            c,
            self.root.join("state"),
            self.root.join("runtime"),
            self.root.join("custody"),
            self.root.clone(),
        ] {
            if let Ok(entries) = fs::read_dir(&dir) {
                for e in entries.flatten() {
                    if e.file_type().is_ok_and(|t| !t.is_dir()) {
                        let _ = fs::remove_file(e.path());
                    }
                }
            }
            let _ = fs::remove_dir(dir);
        }
    }
}

/// Extra child instances are reaped even when a negative assertion unwinds.
pub struct Reaped(pub Child);
impl Drop for Reaped {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
