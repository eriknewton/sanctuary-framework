// fail-before-exempt: the native client and relay entries are new; mutation witnesses establish their guards.
#![cfg(target_os = "linux")]
#[path = "support/checked_corpus.rs"]
mod checked_corpus;
mod isolation;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::business_profile::{
    signer_client::{parse_status_packet, BusinessSignerClient, Refusal, SignerClientState},
    signer_contract::*,
    signer_peer::{self, PeerPolicy},
    signer_service::{self, Header},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
const NS_PER_MS: u64 = 1_000_000; // Nanoseconds per millisecond.
const WAIT_MS: i32 = 2000; // Twice the signer request window, bounded fixture teardown margin.
const TICK_MS: u64 = 5; // Test polling cadence, below the handshake budget.
const DEADLINE_WAVES: usize = 50; // Required repeated-admission fault schedule policy bound.
static SCRIPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn policy() -> PeerPolicy {
    static POLICY: std::sync::OnceLock<PeerPolicy> = std::sync::OnceLock::new();
    POLICY
        .get_or_init(|| PeerPolicy {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            executable_sha256: hex::encode(Sha256::digest(
                std::fs::read("/proc/self/exe").unwrap(),
            )),
            cgroup: std::fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .trim()
                .into(),
        })
        .clone()
}

fn status() -> Value {
    let corpus = checked_corpus::corpus("signer_status_vectors.json");
    let bytes = hex::decode(corpus["cases"][0]["packet_hex"].as_str().unwrap()).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes[signer_service::LENGTH_BYTES..]).unwrap();
    value["boot_id"] = json!(signer_service::parse_boot_id(
        &std::fs::read("/proc/sys/kernel/random/boot_id").unwrap()
    )
    .unwrap());
    let now = 1; // Controlled fixture clock; the real binary probe covers CLOCK_BOOTTIME.
    value["started_boottime_ns"] = json!(now.to_string());
    value["expires_boottime_ns"] = json!((now + 300 * NS_PER_MS * 1000).to_string()); // Maximum 300-second lease.
    value
}
fn packet(value: &Value) -> Vec<u8> {
    signer_service::encode(value, &[]).unwrap()
}
fn signed() -> (Value, Vec<u8>) {
    let corpus = checked_corpus::corpus("role_vectors.json");
    let row = &corpus[0];
    (
        json!({"op":"SIGNED","request_id":"d".repeat(32),"kid":row["kid"],"signature":URL_SAFE_NO_PAD.encode(hex::decode(row["signature"].as_str().unwrap()).unwrap())}),
        hex::decode(row["preimage"].as_str().unwrap()).unwrap(),
    )
}
fn header(view: &Value, preimage: &[u8], now: u64) -> Header {
    let g = &view["grant"];
    Header {
        v: 1,
        protocol: SIGNER_PROTOCOL.into(),
        request_id: "d".repeat(32),
        role: g["role"].as_str().unwrap().into(),
        epoch: g["epoch"].as_u64().unwrap(),
        activation_id: g["activation_id"].as_str().unwrap().into(),
        lease_id: g["lease_id"].as_str().unwrap().into(),
        generation: g["generation"].as_u64().unwrap(),
        deadline_boottime_ns: (now + SIGNER_REQUEST_DEADLINE_MS as u64 * NS_PER_MS).to_string(),
        preimage_length: preimage.len(),
    }
}
fn readable(fd: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut p, 1, WAIT_MS) == 1 }
}
#[derive(Default)]
struct Action {
    bytes: Vec<u8>,
    rights: bool,
    ancillary_truncation: bool,
    foreign: bool,
    duplicate: bool,
    unsolicited: bool,
    gate: Option<std::sync::mpsc::Receiver<()>>,
    sent: Option<Arc<AtomicBool>>,
    delay: Option<Duration>,
    set_clock: Option<(Arc<AtomicU64>, u64)>,
}
impl Action {
    fn reply(value: &Value) -> Self {
        Self {
            bytes: packet(value),
            ..Self::default()
        }
    }
}
#[derive(Default)]
struct Counters {
    active: AtomicU64,
    peak: AtomicU64,
    io: AtomicU64,
    io_peak: AtomicU64,
    sends: std::sync::Mutex<Vec<bool>>,
}
struct Script {
    _guard: std::sync::MutexGuard<'static, ()>,
    root: tempfile::TempDir,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Script {
    fn start(actions: Vec<Action>) -> Self {
        Self::counted(actions, Arc::new(Counters::default()))
    }
    fn counted(actions: Vec<Action>, counters: Arc<Counters>) -> Self {
        Self::waves(vec![actions], counters)
    }
    fn waves(waves: Vec<Vec<Action>>, counters: Arc<Counters>) -> Self {
        let guard = SCRIPT_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let _ = policy();
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("sign.sock");
        let listener = signer_peer::listen(&path).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let thread = thread::spawn(move || {
            let multiple = waves.len() > 1;
            let mut workers = Vec::new();
            for actions in waves {
                if !readable(listener.as_raw_fd()) {
                    return;
                }
                let Ok(socket) = signer_peer::accept(listener.as_raw_fd()) else {
                    return;
                };
                let counters = counters.clone();
                let done = done.clone();
                workers.push(thread::spawn(move || {
                    let retained = counters.io.fetch_add(1, Ordering::SeqCst) + 1;
                    counters.io_peak.fetch_max(retained, Ordering::SeqCst);
                    for action in actions {
                        if let Some(gate) = action.gate {
                            gate.recv_timeout(Duration::from_millis(WAIT_MS as u64))
                                .unwrap();
                        }
                        if !action.unsolicited {
                            if done.load(Ordering::SeqCst) || !readable(socket.as_raw_fd()) {
                                break;
                            }
                            let Ok(request) =
                                signer_peer::receive(socket.as_raw_fd(), SIGNER_FRAME_MAX_BYTES)
                            else {
                                break;
                            };
                            if request.bytes.is_empty() {
                                break;
                            }
                            if request.bytes != b"{\"op\":\"STATUS\"}" {
                                // The scripted signer admits the same direct Header-plus-preimage packet as the real service, without an outer transport frame.
                                let (header, preimage) =
                                    signer_service::decode(&request.bytes).unwrap();
                                assert_eq!(preimage, signed().1);
                                assert_eq!(header.request_id, "d".repeat(32)); // The fixed 128-bit outstanding request identifier.
                            }
                        }
                        let active = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
                        counters.peak.fetch_max(active, Ordering::SeqCst);
                        if let Some(delay) = action.delay {
                            thread::sleep(delay);
                        }
                        if let Some((clock, value)) = action.set_clock {
                            clock.store(value, Ordering::SeqCst);
                        }
                        let file = std::fs::File::open("/dev/null").unwrap();
                        let rights = if action.rights {
                            vec![file.as_raw_fd()]
                        } else {
                            vec![]
                        };
                        if action.ancillary_truncation {
                            const RIGHTS_COUNT: usize = signer_peer::ANCILLARY_WORDS * 2; // More descriptor bytes than the receiver's ancillary buffer can hold.
                            let rights = vec![file.as_raw_fd(); RIGHTS_COUNT];
                            let mut iov = libc::iovec {
                                iov_base: action.bytes.as_ptr() as _,
                                iov_len: action.bytes.len(),
                            };
                            let mut control = vec![0usize; signer_peer::ANCILLARY_WORDS * 4]; // Aligned capacity for the oversized rights header and descriptors.
                            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                            msg.msg_iov = &mut iov;
                            msg.msg_iovlen = 1;
                            msg.msg_control = control.as_mut_ptr() as _;
                            unsafe {
                                msg.msg_controllen =
                                    libc::CMSG_SPACE(std::mem::size_of_val(rights.as_slice()) as _)
                                        as _;
                                let c = libc::CMSG_FIRSTHDR(&msg);
                                (*c).cmsg_level = libc::SOL_SOCKET;
                                (*c).cmsg_type = libc::SCM_RIGHTS;
                                (*c).cmsg_len =
                                    libc::CMSG_LEN(std::mem::size_of_val(rights.as_slice()) as _)
                                        as _;
                                std::ptr::copy_nonoverlapping(
                                    rights.as_ptr(),
                                    libc::CMSG_DATA(c) as *mut i32,
                                    rights.len(),
                                );
                                assert_eq!(
                                    libc::sendmsg(socket.as_raw_fd(), &msg, libc::MSG_NOSIGNAL),
                                    action.bytes.len() as isize
                                );
                            }
                        } else if action.foreign {
                            let pid = unsafe { libc::fork() };
                            assert!(pid >= 0);
                            if pid == 0 {
                                let _ =
                                    signer_peer::send(socket.as_raw_fd(), &action.bytes, &rights);
                                unsafe {
                                    libc::usleep(200_000);
                                    libc::_exit(0)
                                }
                            } // Keep the sender alive through authenticated receipt.
                            unsafe {
                                libc::waitpid(pid, std::ptr::null_mut(), 0);
                            }
                        } else {
                            let mut sends = counters.sends.lock().unwrap();
                            let result =
                                signer_peer::send(socket.as_raw_fd(), &action.bytes, &rights);
                            sends.push(result.is_ok());
                            if let Some(sent) = &action.sent {
                                sent.store(result.is_ok(), Ordering::SeqCst);
                            }
                            if action.duplicate {
                                let _ =
                                    signer_peer::send(socket.as_raw_fd(), &action.bytes, &rights);
                            }
                        }
                        counters.active.fetch_sub(1, Ordering::SeqCst);
                    }
                    // Keep the original peer alive and its socket open until the client has settled.
                    while !done.load(Ordering::SeqCst) {
                        if multiple && signer_service::readable(socket.as_raw_fd()) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(TICK_MS));
                    }
                    counters.io.fetch_sub(1, Ordering::SeqCst);
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        Self {
            _guard: guard,
            root,
            path,
            stop,
            thread: Some(thread),
        }
    }
    fn client(&self) -> BusinessSignerClient {
        BusinessSignerClient::bootstrap_at_with_clock(&self.path, policy(), Arc::new(|| Ok(1)))
            .unwrap()
    }
}
impl Drop for Script {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
        let _ = &self.root;
    }
}
fn bind(client: &mut BusinessSignerClient) {
    let grant = client.latest_status().grant.clone();
    client.bind(&grant).unwrap();
}
#[test]
fn shared_status_corpus_has_exact_outcome_and_case_set() {
    let corpus = checked_corpus::corpus("signer_status_vectors.json");
    let rows = corpus["cases"].as_array().unwrap();
    let mut ids = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for row in rows {
        let id = row["id"].as_str().unwrap();
        assert!(!id.is_empty() && ids.insert(id));
        let accept =
            parse_status_packet(&hex::decode(row["packet_hex"].as_str().unwrap()).unwrap()).is_ok();
        assert_eq!(accept, row["accept"].as_bool().unwrap(), "{id}");
        results.push(json!([id, accept]));
    }
    assert_eq!(
        results,
        rows.iter()
            .map(|row| json!([row["id"], row["accept"]]))
            .collect::<Vec<_>>()
    );
    eprintln!("STATUS_RESULTS {}", json!(results));
}
#[test]
fn stable_signer_bootstraps_binds_and_verifies_the_admitted_preimage() {
    let view = status();
    let (reply, body) = signed();
    let script = Script::start(vec![Action::reply(&view), Action::reply(&reply)]);
    let mut c = script.client();
    assert_eq!(c.state(), SignerClientState::Unbound);
    bind(&mut c);
    let result = c.sign_record(header(&view, &body, 1), &body).unwrap();
    assert_eq!(result.kid, reply["kid"]);
    c.close_and_settle();
    assert_eq!(c.state(), SignerClientState::Closed);
}
#[test]
fn each_capture_policy_fact_is_independently_required() {
    for changed in ["uid", "gid", "executable", "cgroup"] {
        let script = Script::start(vec![Action::reply(&status())]);
        let mut p = policy();
        match changed {
            "uid" => p.uid += 1,
            "gid" => p.gid += 1,
            "executable" => p.executable_sha256 = "0".repeat(64),
            _ => p.cgroup.push('x'),
        };
        assert_eq!(
            BusinessSignerClient::bootstrap_at(&script.path, p).err(),
            Some(Refusal::Policy),
            "{changed}"
        );
    }
}
#[test]
fn a_foreign_sender_on_the_original_socket_has_no_signer_authority() {
    let view = status();
    let mut foreign = Action::reply(&view);
    foreign.foreign = true;
    let script = Script::start(vec![Action::reply(&view), foreign]);
    let mut c = script.client();
    assert_eq!(c.status(), Err(Refusal::Peer));
    assert_eq!(c.state(), SignerClientState::Settling);
}
#[test]
fn every_frozen_identity_field_is_immutable() {
    let view = status();
    let mut variants = Vec::new();
    for field in view["grant"].as_object().unwrap().keys() {
        let mut v = view.clone();
        v["grant"][field] = match field.as_str() {
            "epoch" | "generation" => json!(v["grant"][field].as_u64().unwrap() + 1),
            "role" => json!(ROLE_REGISTRY[1].0),
            "public_key" => json!(URL_SAFE_NO_PAD.encode(
                hex::decode(
                    checked_corpus::corpus("role_vectors.json")[1]["public_key"]
                        .as_str()
                        .unwrap()
                )
                .unwrap()
            )),
            "kid" => json!(format!("k1:sha256:{}", "b".repeat(64))),
            _ => json!("e".repeat(32)),
        };
        variants.push((field.clone(), v));
    }
    for field in ["boot_id", "started_boottime_ns", "expires_boottime_ns"] {
        let mut v = view.clone();
        v[field] = if field == "boot_id" {
            json!("b".repeat(32))
        } else {
            json!((v[field].as_str().unwrap().parse::<u64>().unwrap() + 1).to_string())
        };
        variants.push((field.into(), v));
    }
    for (field, changed) in variants {
        let script = Script::start(vec![Action::reply(&view), Action::reply(&changed)]);
        let mut c = script.client();
        bind(&mut c);
        assert_eq!(c.status(), Err(Refusal::Grant), "{field}");
        assert_eq!(c.state(), SignerClientState::Settling);
    }
}
#[test]
fn binding_is_once_only_and_requires_the_latest_live_unlocked_grant() {
    for variant in ["locked", "expired", "mismatch", "repeat"] {
        let mut view = status();
        if variant == "locked" {
            view["state"] = json!("LOCKED");
        }
        if variant == "expired" {
            view["expires_boottime_ns"] = json!("1");
        }
        let script = Script::start(vec![Action::reply(&view)]);
        let mut c = script.client();
        let mut expected = c.latest_status().grant.clone();
        if variant == "mismatch" {
            expected.generation += 1;
        }
        if variant == "repeat" {
            c.bind(&expected).unwrap();
        }
        let reason = match variant {
            "expired" => Refusal::Expired,
            "repeat" => Refusal::State,
            _ => Refusal::Grant,
        };
        assert_eq!(c.bind(&expected), Err(reason), "{variant}");
    }
}
#[test]
fn status_recovery_and_locked_observations_are_valid_before_binding() {
    for state in ["LOCKED", "RECOVERY_REQUIRED"] {
        let mut view = status();
        view["state"] = json!(state);
        view["started_boottime_ns"] = json!("0");
        view["expires_boottime_ns"] = json!("0");
        let script = Script::start(vec![Action::reply(&view), Action::reply(&view)]);
        let mut c = script.client();
        assert_eq!(c.status().unwrap().state, state);
    }
}
fn signed_reply_case(selected: &str) {
    let view = status();
    let (reply, body) = signed();
    let good = packet(&reply);
    let mut cases: Vec<(&str, Action, Refusal)> = Vec::new();
    let mut a = Action::reply(&reply);
    a.rights = true;
    cases.push(("rights", a, Refusal::Rights));
    let mut a = Action::reply(&reply);
    a.bytes.extend_from_slice(b"x");
    cases.push(("trailing", a, Refusal::Trailing));
    let mut a = Action::reply(&reply);
    a.bytes.truncate(3);
    cases.push(("short-prefix", a, Refusal::Length));
    let mut a = Action::reply(&reply);
    a.bytes[0..4].copy_from_slice(&((RESPONSE_BOUND + 1) as u32).to_be_bytes());
    cases.push(("oversized-prefix", a, Refusal::Length));
    let mut a = Action::reply(&reply);
    a.bytes.pop();
    cases.push(("short-body", a, Refusal::Length));
    let raw = std::str::from_utf8(&good[4..]).unwrap();
    for (name, text) in [
        ("duplicate-key", raw.replacen("{", "{\"op\":\"SIGNED\",", 1)),
        ("noncanonical", format!(" {raw}")),
    ] {
        let bytes = [&(text.len() as u32).to_be_bytes()[..], text.as_bytes()].concat();
        cases.push((
            name,
            Action {
                bytes,
                ..Action::default()
            },
            Refusal::Canonical,
        ));
    }
    for (name, key, value, reason) in [
        ("unknown-op", "op", json!("UNKNOWN"), Refusal::Unmatched),
        ("refused", "op", json!("REFUSED"), Refusal::Refused),
        (
            "unmatched-id",
            "request_id",
            json!("e".repeat(32)),
            Refusal::Unmatched,
        ),
        (
            "wrong-kid",
            "kid",
            json!(format!("k1:sha256:{}", "f".repeat(64))),
            Refusal::Grant,
        ),
        (
            "wrong-signature-type",
            "signature",
            json!(false),
            Refusal::Schema,
        ),
        ("extra-field", "extra", json!(true), Refusal::Schema),
    ] {
        let mut v = reply.clone();
        v[key] = value;
        cases.push((name, Action::reply(&v), reason));
    }
    let mut v = reply.clone();
    v.as_object_mut().unwrap().remove("signature");
    cases.push(("missing-field", Action::reply(&v), Refusal::Schema));
    let mut sig = URL_SAFE_NO_PAD
        .decode(reply["signature"].as_str().unwrap())
        .unwrap();
    sig[0] ^= 1;
    let mut v = reply.clone();
    v["signature"] = json!(URL_SAFE_NO_PAD.encode(sig));
    cases.push(("bad-signature-byte", Action::reply(&v), Refusal::Signature));
    cases.push((
        "unsolicited-status",
        Action::reply(&view),
        Refusal::Unmatched,
    ));
    let mut a = Action::reply(&reply);
    a.bytes = vec![0; RESPONSE_BOUND + signer_service::LENGTH_BYTES + 1];
    cases.push(("packet-truncation", a, Refusal::Transport));
    let mut ancillary = Action::reply(&reply);
    ancillary.ancillary_truncation = true;
    cases.push(("ancillary-truncation", ancillary, Refusal::Transport));
    for (name, action, reason) in cases.into_iter().filter(|(name, _, _)| *name == selected) {
        let script = Script::start(vec![Action::reply(&view), action]);
        let mut c = script.client();
        bind(&mut c);
        assert_eq!(
            c.sign_record(header(&view, &body, 1), &body),
            Err(reason),
            "{name}"
        );
        assert_eq!(c.state(), SignerClientState::Settling, "{name}");
        assert_eq!(c.status(), Err(Refusal::State));
        c.close_and_settle();
        assert_eq!(c.state(), SignerClientState::Closed);
    }
}
const RESPONSE_BOUND: usize = signer_service::RESPONSE_MAX_BYTES;
fn admission_case(field: &str) {
    let view = status();
    let (_, body) = signed();
    {
        let script = Script::start(vec![Action::reply(&view)]);
        let mut c = script.client();
        if field != "unbound" {
            bind(&mut c);
        }
        let mut bytes = body.clone();
        let mut h = header(&view, &bytes, 1);
        let reason = match field {
            "role" => {
                h.role = ROLE_REGISTRY[1].0.into();
                Refusal::Grant
            }
            "epoch" => {
                h.epoch += 1;
                Refusal::Grant
            }
            "activation" => {
                h.activation_id = "e".repeat(32);
                Refusal::Grant
            }
            "lease" => {
                h.lease_id = "e".repeat(32);
                Refusal::Grant
            }
            "generation" => {
                h.generation += 1;
                Refusal::Grant
            }
            "length" => {
                h.preimage_length += 1;
                Refusal::Preimage
            }
            "oversize" => {
                bytes = vec![0; SIGNER_PREIMAGE_MAX_BYTES + 1];
                h.preimage_length = bytes.len();
                Refusal::Preimage
            }
            "version" => {
                h.v += 1;
                Refusal::Header
            }
            "protocol" => {
                h.protocol.push('x');
                Refusal::Header
            }
            "request-id" => {
                h.request_id = "short".into();
                Refusal::Header
            }
            "deadline-expired" => {
                h.deadline_boottime_ns = "1".into();
                Refusal::Deadline
            }
            "deadline-long" => {
                h.deadline_boottime_ns = u64::MAX.to_string();
                Refusal::Deadline
            }
            "closed" => {
                c.close_and_settle();
                Refusal::State
            }
            _ => Refusal::State,
        };
        assert_eq!(c.sign_record(h, &bytes), Err(reason), "{field}");
    }
}
#[test]
fn unchanged_status_never_renews_the_frozen_lease() {
    let now = Arc::new(AtomicU64::new(1));
    let mut view = status();
    view["started_boottime_ns"] = json!("1");
    view["expires_boottime_ns"] = json!((100 * NS_PER_MS).to_string());
    let script = Script::start(vec![
        Action::reply(&view),
        Action::reply(&view),
        Action::reply(&signed().0),
    ]);
    let clock = now.clone();
    let mut c = BusinessSignerClient::bootstrap_at_with_clock(
        &script.path,
        policy(),
        Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
    )
    .unwrap();
    bind(&mut c);
    now.store(50 * NS_PER_MS, Ordering::SeqCst);
    c.status().unwrap();
    now.store(101 * NS_PER_MS, Ordering::SeqCst);
    let (_, body) = signed();
    assert_eq!(
        c.sign_record(header(&view, &body, 101 * NS_PER_MS), &body),
        Err(Refusal::Expired)
    );
}
#[test]
fn completion_after_effective_deadline_refuses_with_live_grant() {
    let now = Arc::new(AtomicU64::new(1));
    let mut view = status();
    view["started_boottime_ns"] = json!("1");
    view["expires_boottime_ns"] = json!((1000 * NS_PER_MS).to_string());
    let (reply, body) = signed();
    let mut action = Action::reply(&reply);
    action.delay = Some(Duration::from_millis(TICK_MS * 2));
    action.set_clock = Some((now.clone(), 100 * NS_PER_MS + 1));
    let script = Script::start(vec![Action::reply(&view), action]);
    let clock = now.clone();
    let mut c = BusinessSignerClient::bootstrap_at_with_clock(
        &script.path,
        policy(),
        Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
    )
    .unwrap();
    bind(&mut c);
    let mut h = header(&view, &body, 1);
    h.deadline_boottime_ns = (100 * NS_PER_MS).to_string();
    assert_eq!(c.sign_record(h, &body), Err(Refusal::Deadline));
}
#[test]
fn repeated_timeout_waves_keep_one_owned_request_and_terminal_clients() {
    let counters = Arc::new(Counters::default());
    let view = status();
    let (reply, body) = signed();
    let sent: Vec<_> = (0..DEADLINE_WAVES)
        .map(|_| Arc::new(AtomicBool::new(false)))
        .collect();
    let waves = sent
        .iter()
        .map(|sent| {
            let mut action = Action::reply(&reply);
            action.delay = Some(Duration::from_millis(TICK_MS * 4));
            action.sent = Some(sent.clone());
            vec![Action::reply(&view), action]
        })
        .collect();
    let script = Script::waves(waves, counters.clone());
    for sent in sent {
        let mut c = script.client();
        bind(&mut c);
        let mut h = header(&view, &body, 1);
        h.deadline_boottime_ns = (1 + TICK_MS * NS_PER_MS).to_string();
        assert_eq!(c.sign_record(h, &body), Err(Refusal::Deadline));
        // Synchronize with the recorded send result before inspecting its completion flag.
        let sends = counters.sends.lock().unwrap();
        assert!(
            sent.load(Ordering::SeqCst),
            "deadline returned before the late send settled"
        );
        assert!(sends.iter().all(|sent| *sent), "scripted late send failed");
        drop(sends);
        assert_eq!(
            c.sign_record(header(&view, &body, 1), &body),
            Err(Refusal::State)
        );
        c.close_and_settle();
        c.close_and_settle();
        assert_eq!(c.state(), SignerClientState::Closed);
        let end = Instant::now() + Duration::from_millis(WAIT_MS as u64);
        while counters.io.load(Ordering::SeqCst) != 0 {
            assert!(Instant::now() < end);
            thread::yield_now();
        }
        assert_eq!(counters.active.load(Ordering::SeqCst), 0);
    }
    drop(script);
    assert_eq!(counters.sends.lock().unwrap().len(), DEADLINE_WAVES * 2);
    assert_eq!(counters.peak.load(Ordering::SeqCst), 1);
    assert_eq!(counters.io_peak.load(Ordering::SeqCst), 1);
}

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn relay_sender_child() {
    let Some(root) = std::env::var_os("SIGNER_RELAY_CHILD_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let listener = signer_peer::listen(&root.join("sign.sock")).unwrap();
    std::fs::write(root.join("ready"), b"ready").unwrap();
    assert!(readable(listener.as_raw_fd()));
    let socket = signer_peer::accept(listener.as_raw_fd()).unwrap();
    assert!(readable(socket.as_raw_fd()));
    let request = signer_peer::receive(socket.as_raw_fd(), SIGNER_FRAME_MAX_BYTES).unwrap();
    assert_eq!(request.bytes, b"{\"op\":\"STATUS\"}");
    let reply = packet(&status());
    let file = std::fs::File::open("/dev/null").unwrap();
    let rights = if std::env::var_os("SIGNER_RELAY_RIGHTS").is_some() {
        vec![file.as_raw_fd()]
    } else {
        vec![]
    };
    signer_peer::send(socket.as_raw_fd(), &reply, &rights).unwrap();
    let end = Instant::now() + Duration::from_millis(WAIT_MS as u64);
    while !root.join("done").exists() && Instant::now() < end {
        thread::sleep(Duration::from_millis(TICK_MS));
    }
}
fn relay_rights(rights: bool) {
    let _guard = SCRIPT_LOCK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    let _ = policy();
    use std::io::{Read, Write};
    use std::os::unix::{net::UnixStream, process::CommandExt};
    use std::process::{Command, Stdio};
    let root = tempfile::tempdir().unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "relay_sender_child", "--nocapture"])
        .env("SIGNER_RELAY_CHILD_ROOT", root.path())
        .stdout(Stdio::null());
    if rights {
        command.env("SIGNER_RELAY_RIGHTS", "1");
    }
    // The scripted signer drops capabilities before exec, so this witness is identical in root CI and on the box.
    unsafe {
        command.pre_exec(signer_peer::drop_capabilities);
    }
    let mut sender = ChildGuard(command.spawn().unwrap());
    let end = Instant::now() + Duration::from_millis(WAIT_MS as u64);
    while !root.path().join("ready").exists() {
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(TICK_MS));
    }
    let (mut parent, child) = UnixStream::pair().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_millis(WAIT_MS as u64)))
        .unwrap();
    parent
        .set_write_timeout(Some(Duration::from_millis(WAIT_MS as u64)))
        .unwrap();
    let mut relay = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_sanctuary-business-signer"))
            .args([
                "--test-relay",
                root.path().join("sign.sock").to_str().unwrap(),
                &serde_json::to_string(&policy()).unwrap(),
            ])
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                child.try_clone().unwrap(),
            )))
            .stdout(Stdio::from(std::os::fd::OwnedFd::from(child)))
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let request = b"{\"op\":\"STATUS\"}";
    parent
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();
    parent.write_all(request).unwrap();
    if rights {
        let mut byte = [0u8; 1];
        assert_eq!(
            parent.read(&mut byte).unwrap(),
            0,
            "relay forwarded a reply carrying rights"
        );
    } else {
        let mut prefix = [0u8; signer_service::LENGTH_BYTES];
        parent.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        assert!(length <= RESPONSE_BOUND + signer_service::LENGTH_BYTES);
        let mut bytes = vec![0; length];
        parent.read_exact(&mut bytes).unwrap();
        assert_eq!(parse_status_packet(&bytes).unwrap().state, "UNLOCKED");
    }
    parent.shutdown(std::net::Shutdown::Both).unwrap();
    let exit = relay.0.wait().unwrap();
    assert_eq!(exit.code(), Some(1));
    let mut stderr = String::new();
    relay
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert_eq!(stderr, "K1_REFUSED\n");
    std::fs::write(root.path().join("done"), b"done").unwrap();
    assert!(sender.0.wait().unwrap().success());
}
#[test]
fn relay_refuses_authenticated_rights_before_stdout() {
    relay_rights(true);
}
#[test]
fn relay_forwards_authenticated_reply_without_rights() {
    relay_rights(false);
}

macro_rules! refusal_cases { ($helper:ident; $( $name:ident => $case:literal ),* $(,)?) => { $( #[test] fn $name() { $helper($case); } )* }; }
refusal_cases! { signed_reply_case;
    reply_rights => "rights",
    reply_ancillary_truncation => "ancillary-truncation",
    reply_trailing => "trailing",
    reply_short_prefix => "short-prefix",
    reply_oversized_prefix => "oversized-prefix",
    reply_short_body => "short-body",
    reply_duplicate_key => "duplicate-key",
    reply_noncanonical => "noncanonical",
    reply_unknown_op => "unknown-op",
    reply_refused => "refused",
    reply_unmatched_id => "unmatched-id",
    reply_wrong_kid => "wrong-kid",
    reply_wrong_signature_type => "wrong-signature-type",
    reply_extra_field => "extra-field",
    reply_missing_field => "missing-field",
    reply_bad_signature_byte => "bad-signature-byte",
    reply_unsolicited_status => "unsolicited-status",
    reply_packet_truncation => "packet-truncation",
}
refusal_cases! { admission_case;
    admission_role => "role",
    admission_epoch => "epoch",
    admission_activation => "activation",
    admission_lease => "lease",
    admission_generation => "generation",
    admission_length => "length",
    admission_oversize => "oversize",
    admission_version => "version",
    admission_protocol => "protocol",
    admission_request_id => "request-id",
    admission_deadline_expired => "deadline-expired",
    admission_deadline_long => "deadline-long",
    admission_unbound => "unbound",
    admission_closed => "closed",
}

#[test]
fn a_reply_without_an_outstanding_request_closes_before_new_traffic() {
    let view = status();
    let (tx, rx) = std::sync::mpsc::channel();
    let sent = Arc::new(AtomicBool::new(false));
    let mut action = Action::reply(&view);
    action.unsolicited = true;
    action.gate = Some(rx);
    action.sent = Some(sent.clone());
    let script = Script::start(vec![Action::reply(&view), action]);
    let mut c = script.client();
    tx.send(()).unwrap();
    while !sent.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(TICK_MS));
    }
    assert_eq!(c.status(), Err(Refusal::Unmatched));
    assert_eq!(c.state(), SignerClientState::Settling);
}
#[test]
fn a_second_reply_to_one_request_is_terminal() {
    let view = status();
    let (reply, body) = signed();
    let sent = Arc::new(AtomicBool::new(false));
    let armed = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicU64::new(0));
    let mut action = Action::reply(&reply);
    action.duplicate = true;
    action.sent = Some(sent.clone());
    let script = Script::start(vec![Action::reply(&view), action]);
    let enabled = armed.clone();
    let clock = Arc::new(move || {
        if enabled.load(Ordering::SeqCst) && calls.fetch_add(1, Ordering::SeqCst) >= 2 {
            let end = Instant::now() + Duration::from_millis(WAIT_MS as u64);
            while !sent.load(Ordering::SeqCst) {
                assert!(Instant::now() < end);
                thread::sleep(Duration::from_millis(TICK_MS));
            }
        }
        Ok(1)
    });
    let mut c =
        BusinessSignerClient::bootstrap_at_with_clock(&script.path, policy(), clock).unwrap();
    bind(&mut c);
    armed.store(true, Ordering::SeqCst);
    assert_eq!(
        c.sign_record(header(&view, &body, 1), &body),
        Err(Refusal::DuplicateReply)
    );
}
#[test]
fn a_non_signing_status_revokes_a_bound_client() {
    let view = status();
    let mut changed = view.clone();
    changed["state"] = json!("LOCKING");
    let script = Script::start(vec![Action::reply(&view), Action::reply(&changed)]);
    let mut c = script.client();
    bind(&mut c);
    assert_eq!(c.status(), Err(Refusal::Grant));
}
#[test]
fn signer_eof_never_reconnects_an_old_client() {
    let view = status();
    let mut script = Script::start(vec![Action::reply(&view)]);
    let mut old = script.client();
    script.stop.store(true, Ordering::SeqCst);
    script.thread.take().unwrap().join().unwrap();
    std::fs::remove_file(&script.path).unwrap();
    let listener = signer_peer::listen(&script.path).unwrap();
    assert_eq!(old.status(), Err(Refusal::Unmatched));
    old.close_and_settle();
    assert_eq!(old.state(), SignerClientState::Closed);
    assert!(!signer_service::readable(listener.as_raw_fd()));
    let thread = thread::spawn(move || {
        assert!(readable(listener.as_raw_fd()));
        let socket = signer_peer::accept(listener.as_raw_fd()).unwrap();
        assert!(readable(socket.as_raw_fd()));
        signer_peer::receive(socket.as_raw_fd(), SIGNER_FRAME_MAX_BYTES).unwrap();
        signer_peer::send(socket.as_raw_fd(), &packet(&view), &[]).unwrap();
        thread::sleep(Duration::from_millis(TICK_MS * 10));
    });
    let mut replacement =
        BusinessSignerClient::bootstrap_at_with_clock(&script.path, policy(), Arc::new(|| Ok(1)))
            .unwrap();
    replacement.close_and_settle();
    thread.join().unwrap();
}

#[test]
fn admission_clock_overflow_refuses_before_sending() {
    let start = u64::MAX - UNLOCK_TTL_MAX_SECONDS as u64 * 1000 * NS_PER_MS;
    let now = Arc::new(AtomicU64::new(start));
    let mut view = status();
    view["expires_boottime_ns"] = json!(u64::MAX.to_string());
    view["started_boottime_ns"] = json!(start.to_string());
    let script = Script::start(vec![Action::reply(&view)]);
    let clock = now.clone();
    let mut client = BusinessSignerClient::bootstrap_at_with_clock(
        &script.path,
        policy(),
        Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
    )
    .unwrap();
    bind(&mut client);
    let (_, preimage) = signed();
    let mut request = header(&view, &preimage, 1);
    request.deadline_boottime_ns = u64::MAX.to_string();
    now.store(u64::MAX - NS_PER_MS, Ordering::SeqCst); // A live lease with less room than one request budget remaining in the clock type.
    assert_eq!(
        client.sign_record(request, &preimage),
        Err(Refusal::Deadline)
    );
    assert_eq!(client.state(), SignerClientState::Settling);
}

static SIGNAL_DELIVERED: AtomicBool = AtomicBool::new(false);
extern "C" fn test_signal(_: libc::c_int) {
    SIGNAL_DELIVERED.store(true, Ordering::SeqCst);
}
fn interrupted_sign(settling: bool) {
    let view = status();
    let (reply, body) = signed();
    let sent = Arc::new(AtomicBool::new(false));
    let mut action = Action::reply(&reply);
    action.delay = Some(Duration::from_millis(TICK_MS * 20));
    action.sent = Some(sent.clone());
    let counters = Arc::new(Counters::default());
    let script = Script::counted(vec![Action::reply(&view), action], counters.clone());
    let mut client = script.client();
    bind(&mut client);
    SIGNAL_DELIVERED.store(false, Ordering::SeqCst);
    let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
    let mut handler: libc::sigaction = unsafe { std::mem::zeroed() };
    handler.sa_sigaction = test_signal as *const () as usize;
    // No SA_RESTART: SIGUSR2 must interrupt the target thread's blocking poll.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR2, &handler, &mut previous) },
        0
    );
    let target = unsafe { libc::pthread_self() };
    let signal = thread::spawn(move || {
        thread::sleep(Duration::from_millis(TICK_MS * 6));
        assert_eq!(unsafe { libc::pthread_kill(target, libc::SIGUSR2) }, 0);
    });
    let mut request = header(&view, &body, 1);
    if settling {
        request.deadline_boottime_ns = (1 + TICK_MS * NS_PER_MS).to_string();
    }
    let result = client.sign_record(request, &body);
    let sends = counters.sends.lock().unwrap();
    let settled_at_return = sent.load(Ordering::SeqCst);
    drop(sends);
    signal.join().unwrap();
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGUSR2, &previous, std::ptr::null_mut()) },
        0
    );
    assert!(SIGNAL_DELIVERED.load(Ordering::SeqCst));
    if settling {
        assert_eq!(result, Err(Refusal::Deadline));
        assert!(
            settled_at_return,
            "signal released retained I/O before the late send"
        );
    } else {
        assert!(result.is_ok(), "signal interrupted receipt: {result:?}");
    }
    client.close_and_settle();
}
#[test]
fn signal_during_settlement_keeps_the_slot_until_late_send() {
    interrupted_sign(true);
}
#[test]
fn signal_during_receive_preserves_the_request() {
    interrupted_sign(false);
}

#[test]
fn bind_refuses_excessive_lease_lifetime() {
    let mut view = status();
    view["expires_boottime_ns"] =
        json!((2 + UNLOCK_TTL_MAX_SECONDS as u64 * 1000 * NS_PER_MS).to_string());
    let script = Script::start(vec![Action::reply(&view)]);
    let mut client = script.client();
    let grant = client.latest_status().grant.clone();
    assert_eq!(client.bind(&grant), Err(Refusal::Grant));
}
#[test]
fn bind_refuses_another_kernel_boot() {
    let mut view = status();
    let boot = view["boot_id"].as_str().unwrap();
    view["boot_id"] = json!(format!(
        "{}{}",
        if boot.starts_with('0') { "1" } else { "0" },
        &boot[1..]
    ));
    let script = Script::start(vec![Action::reply(&view)]);
    let mut client = script.client();
    let grant = client.latest_status().grant.clone();
    assert_eq!(client.bind(&grant), Err(Refusal::Grant));
}
#[test]
fn bind_refuses_a_stale_status_observation() {
    let view = status();
    let script = Script::start(vec![Action::reply(&view)]);
    let now = Arc::new(AtomicU64::new(1));
    let clock = now.clone();
    let mut client = BusinessSignerClient::bootstrap_at_with_clock(
        &script.path,
        policy(),
        Arc::new(move || Ok(clock.load(Ordering::SeqCst))),
    )
    .unwrap();
    now.store(
        2 + SIGNER_IDLE_DEADLINE_MS as u64 * NS_PER_MS,
        Ordering::SeqCst,
    );
    let grant = client.latest_status().grant.clone();
    assert_eq!(client.bind(&grant), Err(Refusal::Expired));
}
