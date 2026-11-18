//! Explicit isolated composition. Installed selection remains closed at daemon boot.
use super::{
    append_actor::{AppendActor, Dependencies},
    business_wal::Result,
};
/// Consume the selector's sealed Business capability and all required actor dependencies.
pub fn compose(
    _selection: crate::config::BusinessSelection,
    dependencies: Dependencies,
) -> Result<AppendActor> {
    AppendActor::new(dependencies)
}

#[cfg(feature = "test-isolation")]
mod isolated {
    use super::*;
    use crate::business_profile::{
        append_actor::{EvidenceSource, LocalEvidence, State},
        append_clients::{
            ClientHooks, DrainClient, DrainReply, HeldSocketRoot, ServerPins, WriterClient,
        },
        business_wal::{
            original_request_id, CheckpointSeed, RecoveryAction, Refusal, WalHooks, WalStep,
        },
        effect_permit::{EffectIntent, EffectPermit, EffectSink},
        signer_peer::PeerPolicy,
        signer_watchdog,
        wal_executor::{Operation, Output, WalExecutor},
        writer_peer::NS_PER_MS,
    };
    use serde::Deserialize;
    use serde_json::Value;
    use std::{
        fs::File,
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Configuration {
        fortress: String,
        revision: u64,
        writer_root: PathBuf,
        writer_leaf: String,
        drain_root: PathBuf,
        drain_leaf: String,
        writer_pin: PeerPolicy,
        drain_pin: PeerPolicy,
        wal_root: PathBuf,
        anchor: Value,
        join: Value,
        h_expiry_ns: u64,
        policy_digest: String,
        runtime_digest: String,
        config_digest: String,
        body: Value,
        effect: Option<EffectIntent>,
        flows: u64,
        clock_boottime_ns: Option<u64>,
    }
    struct Local {
        file: File,
        bytes: Vec<u8>,
        evidence: LocalEvidence,
    }
    impl EvidenceSource for Local {
        fn observe(&mut self) -> Result<LocalEvidence> {
            use std::os::unix::fs::FileExt;
            let mut bytes = vec![0; self.bytes.len() + 1];
            let n = self.file.read_at(&mut bytes, 0).map_err(|_| Refusal::Io)?;
            if bytes[..n] != self.bytes {
                return Err(Refusal::Authority);
            }
            Ok(self.evidence.clone())
        }
    }
    struct Hooks;
    impl ClientHooks for Hooks {
        fn before_send(&mut self) -> crate::business_profile::append_clients::Result<()> {
            Ok(())
        }
        fn closed(&mut self) {}
    }
    impl WalHooks for Hooks {
        fn before(&mut self, _: WalStep) -> Result<()> {
            Ok(())
        }
    }
    struct Sink(Arc<AtomicUsize>);
    impl EffectSink for Sink {
        fn deliver(&mut self, _permit: EffectPermit) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn startup_disk(
        store: &mut WalExecutor,
        drain: &mut DrainClient,
        operation: Operation,
        clock: &crate::business_profile::writer_peer::Clock,
        end: Instant,
    ) -> Result<Output> {
        let now = clock().map_err(|_| Refusal::Deadline)?;
        let id = store.submit(
            operation,
            now,
            now + crate::business_profile::append_budget::APPEND_BUDGET_MS * NS_PER_MS,
        )?;
        loop {
            drain.recheck_transport().map_err(|_| Refusal::Authority)?;
            if store
                .poll(clock().map_err(|_| Refusal::Deadline)?)?
                .is_some()
            {
                return store.settle(id)?.result;
            }
            if Instant::now() >= end {
                store.disconnect();
                return Err(Refusal::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn startup_reply(drain: &mut DrainClient, end: Instant) -> Result<DrainReply> {
        loop {
            if let Some(reply) = drain.poll().map_err(|_| Refusal::Authority)? {
                return Ok(reply);
            }
            if Instant::now() >= end {
                return Err(Refusal::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn settle_startup(
        store: &mut WalExecutor,
        drain: &mut DrainClient,
        clock: &crate::business_profile::writer_peer::Clock,
        end: Instant,
    ) -> Result<()> {
        let mut serial = 0u64;
        loop {
            if Instant::now() >= end {
                return Err(Refusal::Deadline);
            }
            serial = serial.checked_add(1).ok_or(Refusal::Capacity)?;
            // Startup READ ids occupy a separate namespace from live append ids; retry mutations preserve their stored id.
            let id = format!("eeeeeeeeeeeeeeee{serial:016x}");
            let limit = clock().map_err(|_| Refusal::Deadline)?
                + crate::business_profile::drain_protocol::D_REQUEST_DEADLINE_MS as u64 * NS_PER_MS;
            drain.read(&id, limit).map_err(|_| Refusal::Held)?;
            let DrainReply::Read(observation) = startup_reply(drain, end)? else {
                return Err(Refusal::Held);
            };
            let Output::Recovery(action) = startup_disk(
                store,
                drain,
                Operation::Recover {
                    observation,
                    clock: clock.clone(),
                },
                clock,
                end,
            )?
            else {
                return Err(Refusal::Shape);
            };
            let limit = clock().map_err(|_| Refusal::Deadline)?
                + crate::business_profile::drain_protocol::D_REQUEST_DEADLINE_MS as u64 * NS_PER_MS;
            match action {
                RecoveryAction::Held(report) => {
                    // SAFETY: the bounded hold diagnostic exposes sequence and request hashes, never record bytes.
                    eprintln!("{report}");
                    return Err(Refusal::Held);
                }
                RecoveryAction::Ready => return Ok(()),
                RecoveryAction::Observe => {}
                RecoveryAction::Retry(proposal) => {
                    drain
                        .mutation(&proposal, limit)
                        .map_err(|_| Refusal::Held)?;
                    // ACK and REFUSED both require a fresh correlated READ before any durable settlement.
                    let _ = startup_reply(drain, end)?;
                }
                RecoveryAction::Original { sequence, envelope } => {
                    // A drain under a frozen COMMIT would stale its predecessor, and no proved renewal exists.
                    drain
                        .original(&original_request_id(&envelope), &envelope, limit)
                        .map_err(|_| Refusal::Held)?;
                    let DrainReply::Released(fact) = startup_reply(drain, end)? else {
                        return Err(Refusal::Held);
                    };
                    startup_disk(
                        store,
                        drain,
                        Operation::DFact { sequence, fact },
                        clock,
                        end,
                    )?;
                }
            }
        }
    }
    /// Fixture-only entry requires an owned bounded configuration and real authenticated P/D endpoints.
    pub fn run(selection: crate::config::BusinessSelection, root: &Path) -> Result<usize> {
        run_at(selection, root, Arc::new(signer_watchdog::boottime_ns))
    }
    /// Deterministic isolated schedules supply the same independent clock to W and P.
    pub fn run_at(
        selection: crate::config::BusinessSelection,
        root: &Path,
        clock: crate::business_profile::writer_peer::Clock,
    ) -> Result<usize> {
        run_driven(selection, root, clock, Box::new(Hooks), &mut |_, _| Ok(()))
    }
    /// Test schedules observe the real actor and supply owned disk hooks without replacing its clients.
    pub fn run_driven(
        selection: crate::config::BusinessSelection,
        root: &Path,
        clock: crate::business_profile::writer_peer::Clock,
        hooks: Box<dyn WalHooks>,
        drive: &mut dyn FnMut(&mut AppendActor, usize) -> Result<()>,
    ) -> Result<usize> {
        const CONFIG_MAX: u64 = 65_536;
        let owner = unsafe { libc::geteuid() };
        let metadata = std::fs::symlink_metadata(root).map_err(|_| Refusal::Root)?;
        if !root.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != owner
            || metadata.mode() & 0o7777 != 0o700
        {
            return Err(Refusal::Root);
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(root.join("compose.json"))
            .map_err(|_| Refusal::Missing)?;
        let metadata = file.metadata().map_err(|_| Refusal::Root)?;
        if !metadata.is_file()
            || metadata.uid() != owner
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
            || metadata.len() > CONFIG_MAX
        {
            return Err(Refusal::Root);
        }
        let mut bytes = Vec::new();
        (&file)
            .take(CONFIG_MAX + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Refusal::Io)?;
        crate::smb::strict_json::parse(&bytes, CONFIG_MAX as usize).map_err(|_| Refusal::Shape)?;
        let config: Configuration = serde_json::from_slice(&bytes).map_err(|_| Refusal::Shape)?;
        let startup_ns = 2 * crate::business_profile::append_budget::APPEND_BUDGET_MS * NS_PER_MS;
        // The explicit isolated entry can replay a shared deterministic peer clock; installed code has no fixture configuration.
        let clock = match config.clock_boottime_ns {
            Some(now) if now > 0 && now.checked_add(startup_ns).is_some() => {
                Arc::new(move || Ok(now)) as crate::business_profile::writer_peer::Clock
            }
            Some(_) => return Err(Refusal::Shape),
            None => clock,
        };
        let pins = || ServerPins {
            writer: config.writer_pin.clone(),
            drain: config.drain_pin.clone(),
        };
        let writer_root = HeldSocketRoot::checked(
            File::open(config.writer_root).map_err(|_| Refusal::Root)?,
            owner,
        )
        .map_err(|_| Refusal::Root)?;
        let drain_root = HeldSocketRoot::checked(
            File::open(config.drain_root).map_err(|_| Refusal::Root)?,
            owner,
        )
        .map_err(|_| Refusal::Root)?;
        let mut drain = DrainClient::connect(
            &drain_root,
            &config.drain_leaf,
            pins(),
            clock.clone(),
            Box::new(Hooks),
        )
        .map_err(|_| Refusal::Authority)?;
        let end = Instant::now() + Duration::from_nanos(startup_ns);
        let now = clock().map_err(|_| Refusal::Deadline)?;
        // Recovery authority comes from D before disk interpretation; storage bytes cannot grant it.
        drain
            .read(
                "ffffffffffffffffffffffffffffffff",
                now + crate::business_profile::drain_protocol::D_REQUEST_DEADLINE_MS as u64
                    * NS_PER_MS,
            )
            .map_err(|_| Refusal::Authority)?;
        let observation = loop {
            if let Some(reply) = drain.poll().map_err(|_| Refusal::Authority)? {
                let DrainReply::Read(observation) = reply else {
                    return Err(Refusal::Authority);
                };
                break observation;
            }
            if Instant::now() >= end {
                return Err(Refusal::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut store = WalExecutor::start()?;
        let now = clock().map_err(|_| Refusal::Deadline)?;
        let id = store.submit(
            Operation::OpenRecovering {
                path: config.wal_root,
                owner,
                hooks,
                observation,
                clock: clock.clone(),
                seed: Some(CheckpointSeed::checked(
                    config.anchor,
                    crate::smb::jcs::encode(&config.join)
                        .map_err(|_| Refusal::Shape)?
                        .into_bytes(),
                )?),
            },
            now,
            now + startup_ns,
        )?;
        while store
            .poll(clock().map_err(|_| Refusal::Deadline)?)?
            .is_none()
        {
            if Instant::now() >= end {
                store.disconnect();
                return Err(Refusal::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        store.settle(id)?.result?;
        if root.join("settlement.json").exists() {
            let fixture = super::super::append_clients::SettlementFixture::load(
                &root.join("settlement.json"),
            )
            .map_err(|_| Refusal::Root)?;
            drain
                .settlement_fixture_for_test(fixture)
                .map_err(|_| Refusal::Held)?;
        }
        settle_startup(&mut store, &mut drain, &clock, end)?;
        let writer = WriterClient::connect(
            &writer_root,
            &config.writer_leaf,
            pins(),
            clock.clone(),
            Box::new(Hooks),
        )
        .map_err(|_| Refusal::Authority)?;
        let count = Arc::new(AtomicUsize::new(0));
        let mut actor = compose(
            selection,
            Dependencies {
                writer,
                drain,
                store,
                clock: clock.clone(),
                evidence: Box::new(Local {
                    file,
                    bytes,
                    evidence: LocalEvidence {
                        h_expiry_ns: config.h_expiry_ns,
                        policy_digest: config.policy_digest,
                        runtime_digest: config.runtime_digest,
                        config_digest: config.config_digest,
                    },
                }),
                sink: Box::new(Sink(count.clone())),
                fortress: config.fortress,
                revision: config.revision,
            },
        )?;
        let mut body = Some(
            crate::smb::jcs::encode(&config.body)
                .map_err(|_| Refusal::Shape)?
                .into_bytes(),
        );
        let mut effect = config.effect;
        loop {
            let before = actor.state();
            if let Err(error) = actor.poll() {
                drive(&mut actor, count.load(Ordering::SeqCst))?;
                if actor.state() != State::Held {
                    continue;
                }
                if let Some(report) = actor.commit_hold() {
                    // SAFETY: the bounded hold diagnostic exposes sequence and request hashes, never record bytes.
                    eprintln!("{report}");
                }
                // SAFETY: isolated diagnostics expose only bounded state and refusal names, never record data.
                eprintln!("isolated append refused in {before:?}: {error:?}");
                return Err(error);
            }
            drive(&mut actor, count.load(Ordering::SeqCst))?;
            if actor.state() == State::Ready {
                if let Some(bytes) = body.take() {
                    actor.begin(
                        bytes,
                        effect.take(),
                        clock().map_err(|_| Refusal::Deadline)? + startup_ns,
                        config.flows,
                    )?;
                } else {
                    return Ok(count.load(Ordering::SeqCst));
                }
            }
            if Instant::now() >= end {
                actor.disconnect();
                return Err(Refusal::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
#[cfg(feature = "test-isolation")]
pub use isolated::run as compose_for_test;

#[cfg(feature = "test-isolation")]
pub use isolated::run_at as compose_for_test_at;

#[cfg(feature = "test-isolation")]
pub use isolated::run_driven as compose_for_test_driven;
