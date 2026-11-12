#![allow(dead_code)]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::business_profile::{
    signer_client::{CurrentGrantView, SignedReply, StatusReply},
    signer_contract::SIGNER_PROTOCOL,
    signer_service::Header,
    writer_peer::Clock,
    writer_service::{test_support::*, *},
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex,
};
pub const NOW: u64 = 1_000_000_000; // One second on the injected boottime clock.
pub const NS_PER_MS: u64 = 1_000_000;
// Twenty independently settled writers are the required repeated-admission policy sample.
pub const HEARTBEAT_WAVES: usize = 20;
// Ten watchdog ticks leave scheduling margin around the fixed bus handshake deadline.
pub const BUS_SCHEDULING_SLACK_MS: u64 =
    10 * castle_wall_daemon::business_profile::signer_watchdog::WATCHDOG_TICK_MS as u64;
pub struct Fixture {
    pub now: Arc<AtomicU64>,
    pub view: Arc<Mutex<StatusReply>>,
    pub signs: Arc<AtomicUsize>,
    pub binds: Arc<AtomicUsize>,
    pub reconciles: Arc<AtomicUsize>,
    pub statuses: Arc<AtomicUsize>,
    pub closes: Arc<AtomicUsize>,
    pub body: Vec<u8>,
    pub signature: Arc<Mutex<[u8; 64]>>,
    pub delay: Arc<AtomicU64>,
    pub status_delay: Arc<AtomicU64>,
    pub events: Arc<Mutex<Vec<String>>>,
}
impl Fixture {
    pub fn new() -> Self {
        let corpus: Value = serde_json::from_str(include_str!(
            "../../src/business_profile/record_join_vectors.json"
        ))
        .unwrap();
        let c = &corpus["cases"][0];
        let b = &c["records"][0]["body"];
        let mut grant = c["initial"]["pin"].clone();
        for field in ["activation_id", "lease_id", "generation"] {
            grant[field] = b[field].clone();
        }
        let view:StatusReply=serde_json::from_value(json!({"op":"STATUS","state":"LOCKED","grant":grant,"started_boottime_ns":"0","expires_boottime_ns":"0","boot_id":"a".repeat(32),"anchor_revision":1,"anchor_digest":format!("sha256:{}","b".repeat(64))})).unwrap();
        let signature = URL_SAFE_NO_PAD
            .decode(c["records"][0]["outer"]["signature"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        Self {
            now: Arc::new(AtomicU64::new(NOW)),
            view: Arc::new(Mutex::new(view)),
            signs: Arc::default(),
            binds: Arc::default(),
            reconciles: Arc::default(),
            statuses: Arc::default(),
            closes: Arc::default(),
            body: serde_json::to_vec(b).unwrap(),
            signature: Arc::new(Mutex::new(signature)),
            delay: Arc::default(),
            status_delay: Arc::default(),
            events: Arc::default(),
        }
    }
    pub fn clock(&self) -> Clock {
        let now = self.now.clone();
        Arc::new(move || Ok(now.load(Ordering::SeqCst)))
    }
    pub fn signer(&self) -> ScriptedSigner {
        let view = self.view.clone();
        let statuses = self.statuses.clone();
        let now = self.now.clone();
        let status_delay = self.status_delay.clone();
        let events = self.events.clone();
        let signs = self.signs.clone();
        let signature = self.signature.clone();
        let sign_now = self.now.clone();
        let delay = self.delay.clone();
        let sign_events = self.events.clone();
        let binds = self.binds.clone();
        let closes = self.closes.clone();
        ScriptedSigner {
            initial: self.view.lock().unwrap().clone(),
            status: Box::new(move || {
                statuses.fetch_add(1, Ordering::SeqCst);
                events.lock().unwrap().push("status".into());
                now.fetch_add(status_delay.load(Ordering::SeqCst), Ordering::SeqCst);
                Ok(view.lock().unwrap().clone())
            }),
            bind: Box::new(move |_: &CurrentGrantView| {
                binds.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }),
            sign: Box::new(move |h, _| {
                signs.fetch_add(1, Ordering::SeqCst);
                sign_events.lock().unwrap().push("sign".into());
                sign_now.fetch_add(delay.load(Ordering::SeqCst), Ordering::SeqCst);
                Ok(SignedReply {
                    request_id: h.request_id,
                    kid: serde_json::from_str::<Value>(include_str!(
                        "../../src/business_profile/record_join_vectors.json"
                    ))
                    .unwrap()["cases"][0]["initial"]["pin"]["kid"]
                        .as_str()
                        .unwrap()
                        .into(),
                    signature: *signature.lock().unwrap(),
                })
            }),
            close: Box::new(move || {
                closes.fetch_add(1, Ordering::SeqCst);
            }),
        }
    }
    pub fn reconciler(&self) -> TestReconciler {
        let calls = self.reconciles.clone();
        TestReconciler {
            reconcile: Box::new(move |e| {
                calls.fetch_add(1, Ordering::SeqCst);
                Reconciliation::Reconciled(Box::new(e.observation.clone()))
            }),
        }
    }
    pub fn machine(&self) -> WriterMachine<ScriptedSigner, TestReconciler> {
        WriterMachine::isolated(
            self.signer(),
            self.reconciler(),
            "a".repeat(32),
            self.clock(),
        )
        .unwrap()
    }
    pub fn state(&self, state: &str) {
        self.view.lock().unwrap().state = state.into();
    }
    pub fn unlock(&self) {
        let mut v = self.view.lock().unwrap();
        v.state = "UNLOCKED".into();
        v.started_boottime_ns = self.now.load(Ordering::SeqCst).to_string();
        v.expires_boottime_ns = (NOW + 300_000 * NS_PER_MS).to_string();
    }
    pub fn grant(&self, m: &mut WriterMachine<ScriptedSigner, TestReconciler>) {
        assert_eq!(m.state(), WriterState::ClosedLocked);
        m.captured_wall_for_test().unwrap();
        assert_eq!(m.state(), WriterState::WallBound);
        self.unlock();
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::Reconciled);
        m.heartbeat().unwrap();
        assert_eq!(m.state(), WriterState::Granted);
        assert_eq!(self.binds.load(Ordering::SeqCst), 1);
    }
    pub fn header(&self) -> Header {
        let v = self.view.lock().unwrap();
        Header {
            v: 1,
            protocol: SIGNER_PROTOCOL.into(),
            request_id: "d".repeat(32),
            activation_id: v.grant.activation_id.clone(),
            lease_id: v.grant.lease_id.clone(),
            generation: v.grant.generation,
            epoch: v.grant.epoch,
            role: v.grant.role.clone(),
            deadline_boottime_ns: (self.now.load(Ordering::SeqCst)
                + castle_wall_daemon::business_profile::writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS
                    * NS_PER_MS)
                .to_string(),
            preimage_length: self.body.len(),
        }
    }
}
