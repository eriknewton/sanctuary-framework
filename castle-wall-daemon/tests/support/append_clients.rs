// fail-before-exempt: checkpoint timeout and repeated ownership assertions use native authenticated sockets and shared fixtures.
// fail-before-exempt: authenticated client and WAL fact fixtures use isolated native sockets, process pins and shared data.
// W-CLIENT-CONTRACT
// W-CHECKPOINT
use castle_wall_daemon::business_profile::{
    append_checkpoint as cp,
    append_clients::*,
    append_contract, drain_protocol as d,
    signer_peer::{self, PeerPolicy},
    writer_protocol as p,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::fs::PermissionsExt,
    },
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};
const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SESSION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NS: u64 = 1_000_000;
struct Hooks(Arc<AtomicUsize>);
impl ClientHooks for Hooks {
    fn before_send(&mut self) -> Result<()> {
        Ok(())
    }
    fn closed(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
struct Fixture {
    root: tempfile::TempDir,
    held: HeldSocketRoot,
    listener: OwnedFd,
    now: Arc<AtomicU64>,
    closes: Arc<AtomicUsize>,
}
fn policy() -> PeerPolicy {
    static POLICY: std::sync::OnceLock<PeerPolicy> = std::sync::OnceLock::new();
    POLICY
        .get_or_init(|| PeerPolicy {
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            executable_sha256: hex::encode(Sha256::digest(fs::read("/proc/self/exe").unwrap())),
            cgroup: fs::read_to_string("/proc/self/cgroup")
                .unwrap()
                .trim()
                .into(),
        })
        .clone()
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("server");
        let listener = signer_peer::listen(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let held = HeldSocketRoot::checked(fs::File::open(root.path()).unwrap(), unsafe {
            libc::geteuid()
        })
        .unwrap();
        Self {
            root,
            held,
            listener,
            now: Arc::new(AtomicU64::new(NS)),
            closes: Arc::default(),
        }
    }
    fn clock(&self) -> castle_wall_daemon::business_profile::writer_peer::Clock {
        let n = self.now.clone();
        Arc::new(move || Ok(n.load(Ordering::SeqCst)))
    }
    fn pins(&self) -> ServerPins {
        ServerPins {
            writer: policy(),
            drain: policy(),
        }
    }
    fn drain(&self) -> (DrainClient, OwnedFd) {
        let c = DrainClient::connect(
            &self.held,
            "server",
            self.pins(),
            self.clock(),
            Box::new(Hooks(self.closes.clone())),
        )
        .unwrap();
        let s = signer_peer::accept(self.listener.as_raw_fd()).unwrap();
        (c, s)
    }
    fn writer(&self) -> (WriterClient, OwnedFd) {
        let mut c = WriterClient::connect(
            &self.held,
            "server",
            self.pins(),
            self.clock(),
            Box::new(Hooks(self.closes.clone())),
        )
        .unwrap();
        let s = signer_peer::accept(self.listener.as_raw_fd()).unwrap();
        send(
            &s,
            &p::encode(p::Direction::ToWall, SESSION, &p::Operation::Hello, &[]).unwrap(),
        );
        assert!(matches!(c.poll().unwrap(), Some(WriterReply::Ready)));
        let bytes = receive(&s);
        assert!(matches!(
            p::decode(&bytes, p::Direction::ToWriter, SESSION)
                .unwrap()
                .operation,
            p::Operation::HelloAck
        ));
        (c, s)
    }
}
fn send(s: &OwnedFd, bytes: &[u8]) {
    signer_peer::send(s.as_raw_fd(), bytes, &[]).unwrap();
}
fn receive(s: &OwnedFd) -> Vec<u8> {
    signer_peer::receive(s.as_raw_fd(), d::D_REQUEST_MAX_BYTES)
        .unwrap()
        .bytes
}
fn read_reply(id: &str, latched: bool, uncertain: bool) -> Vec<u8> {
    let a = append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"]["d_observation"]
        ["anchor"]
        .clone();
    let payload = castle_wall_daemon::smb::jcs::encode(&a).unwrap();
    let mut h = d::header("READ_REPLY", id, d::DRAIN_SLOTS[0].1);
    h["state"] = json!("PRESENT");
    h["latched"] = json!(latched);
    h["uncertain"] = json!(uncertain);
    h["anchor_digest"] =
        json!(castle_wall_daemon::business_profile::activation_anchor::anchor_digest(&a).unwrap());
    h["payload_length"] = json!(payload.len());
    d::encode(&h, payload.as_bytes(), d::Direction::FromDrain).unwrap()
}
#[test]
fn read_reply_alone_renews_lease_and_empty_poll_does_not_block() {
    let f = Fixture::new();
    let (mut c, s) = f.drain();
    assert!(f.root.path().exists());
    c.read(ID, u64::MAX).unwrap();
    let bytes = receive(&s);
    assert!(matches!(
        d::decode(&bytes, d::Direction::ToDrain).unwrap().operation,
        d::Operation::Read
    ));
    let start = std::time::Instant::now();
    assert!(c.poll().unwrap().is_none());
    assert!(start.elapsed().as_millis() < 10);
    assert!(!c.lease_live(NS));
    assert!(c.read_due(NS));
    send(&s, &read_reply(ID, false, true));
    let Some(DrainReply::Read(o)) = c.poll().unwrap() else {
        panic!("correlated observation");
    };
    assert_eq!(o.pending(), Some(0));
    assert!(!o.ordinary_room());
    assert!(c.lease_live(NS));
    assert!(!c.read_due(NS));
    assert!(c.read_due(NS + d::D_HEARTBEAT_MS as u64 * NS));
    f.now.store(2 * NS, Ordering::SeqCst);
    c.read(ID, u64::MAX).unwrap();
    receive(&s);
    send(
        &s,
        &d::encode(
            &d::header("REFUSED", ID, d::DRAIN_SLOTS[0].1),
            &[],
            d::Direction::FromDrain,
        )
        .unwrap(),
    );
    assert!(matches!(c.poll().unwrap(), Some(DrainReply::Refused)));
    assert!(!c.lease_live(NS + d::D_LEASE_MS as u64 * NS));
}
#[test]
fn client_refuses_wrong_correlation_duplicate_rights_and_deadline() {
    for case in ["id", "duplicate", "rights", "deadline"] {
        let f = Fixture::new();
        let (mut c, s) = f.drain();
        c.read(ID, u64::MAX).unwrap();
        receive(&s);
        let bytes = read_reply(if case == "id" { SESSION } else { ID }, false, false);
        if case == "rights" {
            let file = fs::File::open(f.root.path()).unwrap();
            signer_peer::send(s.as_raw_fd(), &bytes, &[file.as_raw_fd()]).unwrap();
        } else {
            send(&s, &bytes);
        }
        if case == "duplicate" {
            send(&s, &bytes);
        }
        if case == "deadline" {
            f.now
                .fetch_add(d::D_REQUEST_DEADLINE_MS as u64 * NS, Ordering::SeqCst);
        }
        assert!(
            c.poll().is_err(),
            "{case} refuses before observation authority"
        );
        assert!(!c.lease_live(f.now.load(Ordering::SeqCst)));
        assert_eq!(f.closes.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn checkpoint_sender_keeps_one_owned_report_until_correlated_ack() {
    let f = Fixture::new();
    let (mut c, s) = f.writer();
    let mut report = append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"].clone();
    c.checkpoint_query(ID, 3000 * NS).unwrap();
    receive(&s);
    let status=serde_json::from_value::<castle_wall_daemon::business_profile::signer_client::StatusReply>(json!({
        "op":"STATUS","state":"LOCKED","grant":{"role":report["wal_checkpoint"]["join_state"]["pin"]["role"],
        "epoch":1,"kid":report["wal_checkpoint"]["join_state"]["pin"]["kid"],"public_key":report["wal_checkpoint"]["join_state"]["pin"]["public_key"],
        "identity_id":ID,"machine_id":ID,"activation_id":ID,"lease_id":ID,"generation":1},
        "started_boottime_ns":"0","expires_boottime_ns":"0","boot_id":ID,"anchor_revision":null,"anchor_digest":null})).unwrap();
    let payload = cp::status_bytes(&status).unwrap();
    send(
        &s,
        &p::encode(
            p::Direction::ToWall,
            SESSION,
            &p::Operation::CheckpointChallenge {
                request_id: ID.into(),
                nonce: ID.into(),
                issued_boottime_ns: NS,
            },
            &payload,
        )
        .unwrap(),
    );
    let Some(WriterReply::Challenge(challenge)) = c.poll().unwrap() else {
        panic!("challenge");
    };
    report["session_id"] = json!(challenge.session);
    report["request_id"] = json!(ID);
    report["nonce"] = json!(ID);
    let raw = castle_wall_daemon::smb::jcs::encode(&report)
        .unwrap()
        .into_bytes();
    let digest = cp::digest(&raw);
    c.checkpoint_report(raw.clone()).unwrap();
    assert!(matches!(c.status(ID, u64::MAX), Err(Refusal::Busy)));
    // Fill the actual outbound queue without consuming the report's first part.
    let fd = test_support::checkpoint_socket(&c);
    let filler = vec![0_u8; 1];
    let mut queued = 0;
    loop {
        let n = unsafe {
            libc::send(
                fd,
                filler.as_ptr() as _,
                filler.len(),
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            )
        };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
        queued += 1;
    }
    assert!(queued > 0);
    assert!(
        c.poll().unwrap().is_none(),
        "EAGAIN retains the pending report"
    );
    let retained = test_support::pending_packet(&c).expect("EAGAIN retains exact packet");
    assert!(
        c.poll().unwrap().is_none(),
        "repeated EAGAIN retains ownership"
    );
    assert_eq!(
        test_support::pending_packet(&c).as_ref(),
        Some(&retained),
        "EAGAIN cannot reconstruct or advance the packet"
    );
    for _ in 0..queued {
        assert_eq!(receive(&s), filler);
    }
    assert!(c.poll().unwrap().is_none());
    let packet = receive(&s);
    assert_eq!(packet, retained, "retry sends identical packet bytes");
    let decoded = p::decode(&packet, p::Direction::ToWriter, SESSION).unwrap();
    assert_eq!(decoded.payload, raw);
    assert!(matches!(decoded.operation, p::Operation::CheckpointPart(_)));
    send(
        &s,
        &p::encode(
            p::Direction::ToWall,
            SESSION,
            &p::Operation::CheckpointAck {
                request_id: ID.into(),
                checkpoint_digest: digest.clone(),
            },
            &[],
        )
        .unwrap(),
    );
    assert!(matches!(c.poll().unwrap(),Some(WriterReply::CheckpointAcknowledged(d)) if d==digest));
}

pub(super) fn authenticated_read(anchor: &serde_json::Value) -> DrainObservation {
    authenticated_read_flags(anchor, false, false)
}
pub(super) fn authenticated_read_flags(
    anchor: &serde_json::Value,
    latched: bool,
    uncertain: bool,
) -> DrainObservation {
    let mut anchor = anchor.clone();
    if latched {
        anchor["recovery_required"] = json!(true);
        anchor["recovery_reason"] = json!("integrity");
        anchor["recovery_revision"] = json!(1);
    }
    let anchor = &anchor;
    let f = Fixture::new();
    let (mut c, s) = f.drain();
    c.read(ID, u64::MAX).unwrap();
    receive(&s);
    let payload = castle_wall_daemon::smb::jcs::encode(anchor).unwrap();
    let mut h = d::header("READ_REPLY", ID, d::DRAIN_SLOTS[0].1);
    h["state"] = json!("PRESENT");
    h["latched"] = json!(latched);
    h["uncertain"] = json!(uncertain);
    h["anchor_digest"] = json!(
        castle_wall_daemon::business_profile::activation_anchor::anchor_digest(anchor).unwrap()
    );
    h["payload_length"] = json!(payload.len());
    send(
        &s,
        &d::encode(&h, payload.as_bytes(), d::Direction::FromDrain).unwrap(),
    );
    let Some(DrainReply::Read(observation)) = c.poll().unwrap() else {
        panic!("correlated READ")
    };
    observation
}
pub(super) fn authenticated_original(envelope: &[u8]) -> DrainReleaseFact {
    let f = Fixture::new();
    let (mut c, s) = f.drain();
    c.original(ID, envelope, u64::MAX).unwrap();
    receive(&s);
    let identity = append_contract::identity(envelope).unwrap();
    let mut h = d::header("ORIGINAL_ACK", ID, d::DRAIN_SLOTS[0].1);
    h["sequence"] = identity["sequence"].clone();
    h["drained_digest"] = identity["commitment"].clone();
    send(&s, &d::encode(&h, &[], d::Direction::FromDrain).unwrap());
    let Some(DrainReply::Released(fact)) = c.poll().unwrap() else {
        panic!("correlated ORIGINAL_ACK")
    };
    fact
}

fn frozen_reserve(id: &str) -> FrozenMutation {
    let expected = append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"]
        ["d_observation"]["anchor"]
        .clone();
    let mut next = expected.clone();
    let digest = format!("sha256:{}", "a".repeat(64));
    next["reserved_sequence"] = json!(1);
    next["reserved_body_digest"] = json!(digest);
    let message = json!({"version":1,"op":"RESERVE","request_id":id,"expected":expected,"next":next,"body_digest":digest});
    let bytes = castle_wall_daemon::smb::jcs::encode(&message).unwrap();
    let mut header = d::header("ANCHOR", id, d::DRAIN_SLOTS[0].1);
    header["message_length"] = json!(bytes.len());
    header["envelope_length"] = json!(0);
    FrozenMutation::checked(d::encode(&header, bytes.as_bytes(), d::Direction::ToDrain).unwrap())
        .unwrap()
}
fn anchor_reply(op: &str, anchor: &serde_json::Value, uncertain: bool) -> Vec<u8> {
    let bytes = castle_wall_daemon::smb::jcs::encode(anchor).unwrap();
    let mut header = d::header(op, ID, d::DRAIN_SLOTS[0].1);
    header["anchor_digest"] = json!(
        castle_wall_daemon::business_profile::activation_anchor::anchor_digest(anchor).unwrap()
    );
    header["payload_length"] = json!(bytes.len());
    if op == "READ_REPLY" {
        header["state"] = json!("PRESENT");
        header["latched"] = json!(false);
        header["uncertain"] = json!(uncertain);
    }
    d::encode(&header, bytes.as_bytes(), d::Direction::FromDrain).unwrap()
}
#[test]
fn mutation_ownership_survives_refusal_ack_and_forty_late_waves() {
    let proposal = frozen_reserve(ID);
    for outcome in ["REFUSED", "ANCHOR_ACK", "timeout", "disconnect"] {
        for _ in 0..40 {
            let f = Fixture::new();
            let (mut c, s) = f.drain();
            c.mutation(&proposal, u64::MAX).unwrap();
            assert_eq!(receive(&s), proposal.bytes());
            match outcome {
                "REFUSED" => send(
                    &s,
                    &d::encode(
                        &d::header("REFUSED", ID, d::DRAIN_SLOTS[0].1),
                        &[],
                        d::Direction::FromDrain,
                    )
                    .unwrap(),
                ),
                "ANCHOR_ACK" => send(&s, &anchor_reply("ANCHOR_ACK", proposal.next(), false)),
                "timeout" => {
                    f.now
                        .fetch_add(d::D_REQUEST_DEADLINE_MS as u64 * NS, Ordering::SeqCst);
                    send(&s, &anchor_reply("ANCHOR_ACK", proposal.next(), false));
                }
                "disconnect" => unsafe {
                    libc::shutdown(s.as_raw_fd(), libc::SHUT_RDWR);
                },
                _ => unreachable!(),
            }
            let reply = c.poll();
            if matches!(outcome, "timeout" | "disconnect") {
                assert!(reply.is_err());
            } else {
                assert!(reply.unwrap().is_some());
            }
            assert!(
                c.retained_mutation().is_some(),
                "non-READ completion retains exact mutation"
            );
            assert_eq!(
                c.retained_mutation().unwrap().bytes(),
                proposal.bytes(),
                "non-READ completion retains exact mutation"
            );
            assert!(
                !c.lease_live(f.now.load(Ordering::SeqCst)),
                "only READ renews D liveness"
            );
            if !matches!(outcome, "timeout" | "disconnect") {
                assert_eq!(
                    c.mutation(&frozen_reserve(SESSION), u64::MAX),
                    Err(Refusal::Busy),
                    "changed request cannot replace owned mutation"
                );
                c.read(ID, u64::MAX).unwrap();
                receive(&s);
                send(&s, &anchor_reply("READ_REPLY", proposal.next(), true));
                assert!(matches!(c.poll().unwrap(), Some(DrainReply::Read(_))));
                assert!(
                    c.retained_mutation().is_some(),
                    "uncertain READ retains mutation"
                );
                c.read(ID, u64::MAX).unwrap();
                receive(&s);
                send(&s, &anchor_reply("READ_REPLY", proposal.expected(), false));
                assert!(matches!(c.poll().unwrap(), Some(DrainReply::Read(_))));
                assert!(
                    c.retained_mutation().is_some(),
                    "whole anchor equality settles mutation"
                );
                c.read(ID, u64::MAX).unwrap();
                receive(&s);
                send(&s, &anchor_reply("READ_REPLY", proposal.next(), false));
                assert!(matches!(c.poll().unwrap(), Some(DrainReply::Read(_))));
                assert!(c.retained_mutation().is_none());
            }
        }
    }
}
#[test]
fn drain_slots_roles_operations_and_original_facts_are_correlated() {
    for field in ["role", "operation", "slot"] {
        let f = Fixture::new();
        let (mut c, s) = f.drain();
        c.read(ID, u64::MAX).unwrap();
        receive(&s);
        if field == "slot" {
            assert_eq!(
                c.read(SESSION, u64::MAX),
                Err(Refusal::Busy),
                "one pending D request owns its slot"
            );
            send(&s, &read_reply(ID, false, false));
            assert!(matches!(c.poll().unwrap(), Some(DrainReply::Read(_))));
        } else {
            let bytes = if field == "role" {
                {
                    let header = d::header("REFUSED", ID, "linux-business-retrospective");
                    let bytes = castle_wall_daemon::smb::jcs::encode(&header).unwrap();
                    [&(bytes.len() as u32).to_be_bytes()[..], bytes.as_bytes()].concat()
                }
            } else {
                anchor_reply("ANCHOR_ACK", frozen_reserve(ID).next(), false)
            };
            send(&s, &bytes);
            assert!(c.poll().is_err(), "role and operation bind the D reply");
        }
    }
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    let record = &vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == "listener-accept")
        .unwrap()["records"][0];
    let envelope = castle_wall_daemon::smb::jcs::encode(record).unwrap();
    let identity = append_contract::identity(envelope.as_bytes()).unwrap();
    for field in ["sequence", "commitment", "positive"] {
        let f = Fixture::new();
        let (mut c, s) = f.drain();
        c.original(ID, envelope.as_bytes(), u64::MAX).unwrap();
        receive(&s);
        let mut h = d::header("ORIGINAL_ACK", ID, d::DRAIN_SLOTS[0].1);
        h["sequence"] = if field == "sequence" {
            json!(2)
        } else {
            identity["sequence"].clone()
        };
        h["drained_digest"] = if field == "commitment" {
            json!(format!("sha256:{}", "a".repeat(64)))
        } else {
            identity["commitment"].clone()
        };
        send(&s, &d::encode(&h, &[], d::Direction::FromDrain).unwrap());
        if field == "positive" {
            assert!(matches!(c.poll().unwrap(), Some(DrainReply::Released(_))));
        } else {
            assert!(
                c.poll().is_err(),
                "ORIGINAL_ACK matches the whole frozen identity"
            );
        }
        assert!(!c.lease_live(NS));
    }
}
#[test]
fn writer_waits_for_hello_and_preserves_one_correlated_request() {
    for field in ["hello", "slot", "id", "session"] {
        let f = Fixture::new();
        if field == "hello" {
            let mut c = WriterClient::connect(
                &f.held,
                "server",
                f.pins(),
                f.clock(),
                Box::new(Hooks(f.closes.clone())),
            )
            .unwrap();
            let s = signer_peer::accept(f.listener.as_raw_fd()).unwrap();
            assert!(c.poll().unwrap().is_none());
            send(
                &s,
                &p::encode(
                    p::Direction::ToWall,
                    SESSION,
                    &p::Operation::Refused {
                        request_id: ID.into(),
                    },
                    &[],
                )
                .unwrap(),
            );
            assert!(
                c.poll().is_err(),
                "only P HELLO establishes the writer session"
            );
        } else {
            let (mut c, s) = f.writer();
            c.status(ID, u64::MAX).unwrap();
            receive(&s);
            if field == "slot" {
                assert_eq!(
                    c.status(SESSION, u64::MAX),
                    Err(Refusal::Busy),
                    "one pending writer request owns its slot"
                );
            }
            send(
                &s,
                &p::encode(
                    p::Direction::ToWall,
                    if field == "session" { ID } else { SESSION },
                    &p::Operation::Refused {
                        request_id: if field == "id" { SESSION } else { ID }.into(),
                    },
                    &[],
                )
                .unwrap(),
            );
            if field == "slot" {
                assert!(matches!(c.poll().unwrap(), Some(WriterReply::Refused)));
            } else {
                assert!(
                    c.poll().is_err(),
                    "writer reply uses the captured session and request"
                );
            }
        }
    }
}

#[test]
fn checkpoint_deadlines_refuse_only_the_checkpoint_and_keep_the_session() {
    for phase in ["query", "report", "parts", "ack"] {
        let f = Fixture::new();
        let (mut c, s) = f.writer();
        if phase == "query" {
            c.checkpoint_query(ID, 3000 * NS).unwrap();
            receive(&s);
        } else {
            let mut report =
                append_contract::contract().unwrap()["checkpoint_vectors"][0]["value"].clone();
            c.checkpoint_query(ID, 3000 * NS).unwrap();
            receive(&s);
            let status=serde_json::from_value::<castle_wall_daemon::business_profile::signer_client::StatusReply>(json!({
        "op":"STATUS","state":"LOCKED","grant":{"role":report["wal_checkpoint"]["join_state"]["pin"]["role"],
        "epoch":1,"kid":report["wal_checkpoint"]["join_state"]["pin"]["kid"],"public_key":report["wal_checkpoint"]["join_state"]["pin"]["public_key"],
        "identity_id":ID,"machine_id":ID,"activation_id":ID,"lease_id":ID,"generation":1},
        "started_boottime_ns":"0","expires_boottime_ns":"0","boot_id":ID,"anchor_revision":null,"anchor_digest":null})).unwrap();
            let payload = cp::status_bytes(&status).unwrap();
            send(
                &s,
                &p::encode(
                    p::Direction::ToWall,
                    SESSION,
                    &p::Operation::CheckpointChallenge {
                        request_id: ID.into(),
                        nonce: ID.into(),
                        issued_boottime_ns: NS,
                    },
                    &payload,
                )
                .unwrap(),
            );
            let Some(WriterReply::Challenge(challenge)) = c.poll().unwrap() else {
                panic!("challenge");
            };
            report["session_id"] = json!(challenge.session);
            report["request_id"] = json!(ID);
            report["nonce"] = json!(ID);
            let raw = castle_wall_daemon::smb::jcs::encode(&report)
                .unwrap()
                .into_bytes();

            if phase != "report" {
                c.checkpoint_report(raw).unwrap();
            }
            if phase == "ack" {
                assert!(c.poll().unwrap().is_none());
                receive(&s);
            }
        }
        f.now
            .store((cp::CHECKPOINT_CHALLENGE_MS + 1) * NS, Ordering::SeqCst);
        assert!(
            matches!(c.poll(), Ok(Some(WriterReply::Refused))),
            "checkpoint deadline is a checkpoint-only refusal: {phase}"
        );
        assert_eq!(
            f.closes.load(Ordering::SeqCst),
            0,
            "checkpoint timeout keeps the session"
        );
        c.checkpoint_query(SESSION, u64::MAX).unwrap();
        let q = receive(&s);
        assert!(matches!(
            p::decode(&q, p::Direction::ToWriter, SESSION)
                .unwrap()
                .operation,
            p::Operation::CheckpointQuery { .. }
        ));
    }
    let f = Fixture::new();
    let (mut c, s) = f.writer();
    c.status(ID, u64::MAX).unwrap();
    receive(&s);
    f.now
        .store((cp::CHECKPOINT_CHALLENGE_MS + 1) * NS, Ordering::SeqCst);
    assert!(
        matches!(c.poll(), Err(Refusal::Deadline)),
        "ordinary deadline stays terminal"
    );
    assert_eq!(f.closes.load(Ordering::SeqCst), 1);
}
