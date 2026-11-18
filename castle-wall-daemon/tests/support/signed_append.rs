// fail-before-exempt: authenticated delivery schedules inspect isolated WAL cursors and execute private process fixtures.
// W-APPEND
// W-JOIN-FIXTURE
use super::{drain_run, writer_bus};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use castle_wall_daemon::business_profile::{
    activation_anchor,
    append_actor::{
        AppendActor, EvidenceSource, LocalEvidence, PendingCount, State, TestObservations,
        VerifiedObservers,
    },
    append_contract,
    business_wal::{Refusal, Result as WalResult, WalHooks, WalStep},
    compose::compose_for_test_driven,
    join_lifecycle,
    signer_client::StatusReply,
    signer_peer, signer_service, signer_watchdog, writer_peer, writer_protocol,
};
use ed25519_dalek::Signer;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
fn canonical(value: &Value) -> Vec<u8> {
    drain_run::canonical(value)
}
struct Threads {
    stop: Arc<AtomicBool>,
    handles: Vec<std::thread::JoinHandle<()>>,
    children: Vec<std::process::Child>,
}
impl Drop for Threads {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
        for handle in self.handles.drain(..) {
            let _ = handle.join();
        }
    }
}
fn private(path: &std::path::Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
// Each completed wait has a separately selectable observation and assertion.
macro_rules! postwait_observations {
    ($module:ident, $field:literal) => {
        mod $module {
            use super::graph;
            #[test]
            fn reserve() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:Reserve:", $field)),
                );
            }
            #[test]
            fn signmarker() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:SignMarker:", $field)),
                );
            }
            #[test]
            fn sign() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:Sign:", $field)),
                );
            }
            #[test]
            fn commitfreeze() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:CommitFreeze:", $field)),
                );
            }
            #[test]
            fn commitsend() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:CommitSend:", $field)),
                );
            }
            #[test]
            fn confirm() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:Confirm:", $field)),
                );
            }
            #[test]
            fn effectmarker() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:EffectMarker:", $field)),
                );
            }
            #[test]
            fn deliver() {
                graph(
                    false,
                    false,
                    false,
                    false,
                    Some(concat!("observe:Deliver:", $field)),
                );
            }
        }
    };
}
postwait_observations!(postwait_policy, "Policy");
postwait_observations!(postwait_runtime, "Runtime");
postwait_observations!(postwait_config, "Config");
postwait_observations!(postwait_h, "H");
postwait_observations!(postwait_status, "Status");
postwait_observations!(postwait_grant, "Grant");
postwait_observations!(postwait_missinggrant, "MissingGrant");
postwait_observations!(postwait_leaseid, "LeaseId");
postwait_observations!(postwait_lease, "Lease");
postwait_observations!(postwait_certain, "Certain");
postwait_observations!(postwait_latch, "Latch");
postwait_observations!(postwait_role, "Role");
postwait_observations!(postwait_epoch, "Epoch");
postwait_observations!(postwait_publickey, "PublicKey");
postwait_observations!(postwait_kid, "Kid");
postwait_observations!(postwait_identity, "Identity");
postwait_observations!(postwait_machine, "Machine");
postwait_observations!(postwait_activation, "Activation");
postwait_observations!(postwait_started, "Started");
postwait_observations!(postwait_expires, "Expires");
postwait_observations!(postwait_anchorrevision, "AnchorRevision");
postwait_observations!(postwait_anchordigest, "AnchorDigest");
postwait_observations!(postwait_state, "State");
postwait_observations!(postwait_absent, "Absent");
postwait_observations!(postwait_anchor, "Anchor");
postwait_observations!(postwait_writertransport, "WriterTransport");
postwait_observations!(postwait_draintransport, "DrainTransport");
postwait_observations!(postwait_writerprocess, "WriterProcess");
postwait_observations!(postwait_writerdevice, "WriterDevice");
postwait_observations!(postwait_writerinode, "WriterInode");
postwait_observations!(postwait_writerliveness, "WriterLiveness");
postwait_observations!(postwait_drainprocess, "DrainProcess");
postwait_observations!(postwait_draindevice, "DrainDevice");
postwait_observations!(postwait_draininode, "DrainInode");
postwait_observations!(postwait_drainliveness, "DrainLiveness");
postwait_observations!(postwait_windowbudget, "WindowBudget");
postwait_observations!(postwait_windowgrant, "WindowGrant");
postwait_observations!(postwait_windowproducer, "WindowProducer");
postwait_observations!(postwait_windowh, "WindowH");
#[test]
fn complete_status_and_transport_observations_at_final_constructor() {
    for field in [
        "Role",
        "Epoch",
        "PublicKey",
        "Kid",
        "Identity",
        "Machine",
        "Activation",
        "Started",
        "Expires",
        "AnchorRevision",
        "AnchorDigest",
        "State",
        "Absent",
        "WriterTransport",
        "DrainTransport",
        "WriterProcess",
        "WriterDevice",
        "WriterInode",
        "WriterLiveness",
        "DrainProcess",
        "DrainDevice",
        "DrainInode",
        "DrainLiveness",
        "Anchor",
    ] {
        graph(
            false,
            false,
            false,
            false,
            Some(&format!("observe:Deliver:{field}")),
        );
    }
}
#[test]
fn reserve_reply_matrix_counts_both_sign_admissions() {
    for field in [
        "ReserveRefused",
        "ReserveMissing",
        "ReserveWrongId",
        "ReserveUncertain",
        "ReserveSuperseding",
    ] {
        graph(
            false,
            false,
            false,
            false,
            Some(&format!("observe:SignMarker:{field}")),
        );
    }
    graph(false, false, false, false, Some("observe:SignMarker:Lease"));
    graph(
        false,
        false,
        false,
        false,
        Some("observe:SignMarker:Anchor"),
    );
}
#[test]
fn isolated_final_lease_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Lease"));
}
#[test]
fn isolated_final_latch_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Latch"));
}
#[test]
fn isolated_final_status_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Status"));
}
#[test]
fn isolated_final_grant_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Grant"));
}
#[test]
fn isolated_final_anchor_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Anchor"));
}
#[test]
fn isolated_final_absent_observation() {
    graph(false, false, false, false, Some("observe:Deliver:Absent"));
}
#[test]
fn isolated_final_writerprocess_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WriterProcess"),
    );
}
#[test]
fn isolated_final_writerdevice_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WriterDevice"),
    );
}
#[test]
fn isolated_final_writerinode_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WriterInode"),
    );
}
#[test]
fn isolated_final_writerliveness_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WriterLiveness"),
    );
}
#[test]
fn isolated_final_drainprocess_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:DrainProcess"),
    );
}
#[test]
fn isolated_final_draindevice_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:DrainDevice"),
    );
}
#[test]
fn isolated_final_draininode_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:DrainInode"),
    );
}
#[test]
fn isolated_final_drainliveness_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:DrainLiveness"),
    );
}
#[test]
fn isolated_final_markersequence_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:MarkerSequence"),
    );
}
#[test]
fn isolated_final_markercommitment_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:MarkerCommitment"),
    );
}
#[test]
fn isolated_final_markerenvelope_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:MarkerEnvelope"),
    );
}
#[test]
fn isolated_final_windowbudget_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WindowBudget"),
    );
}
#[test]
fn isolated_final_windowgrant_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WindowGrant"),
    );
}
#[test]
fn isolated_final_windowproducer_observation() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:WindowProducer"),
    );
}
#[test]
fn isolated_final_windowh_observation() {
    graph(false, false, false, false, Some("observe:Deliver:WindowH"));
}
#[test]
fn uncertain_final_observation_has_no_other_invalid_predicate() {
    graph(false, false, false, false, Some("observe:Deliver:Certain"));
}
#[test]
fn expired_final_constructor_has_no_other_invalid_predicate() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Deliver:PermitTime"),
    );
}
#[test]
fn decoded_same_body_append_identity_rejects_second_envelope_and_accepts_replay() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:CommitFreeze:AppendIdentity"),
    );
    graph(
        false,
        false,
        false,
        false,
        Some("observe:CommitFreeze:AppendReplay"),
    );
}
#[test]
fn decoded_same_body_commit_identity_rejects_second_envelope_and_accepts_replay() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:CommitSend:CommitIdentity"),
    );
    graph(
        false,
        false,
        false,
        false,
        Some("observe:CommitSend:CommitReplay"),
    );
}
#[test]
fn exact_envelope_at_append_commit_original_and_permit_boundaries() {
    graph(false, false, false, false, Some("observe:Deliver:Trace"));
}
#[test]
fn independently_decoded_marker_identity_fields_refuse_permit() {
    for field in ["MarkerSequence", "MarkerCommitment", "MarkerEnvelope"] {
        graph(
            false,
            false,
            false,
            false,
            Some(&format!("observe:Deliver:{field}")),
        );
    }
}
#[test]
fn delayed_verified_preserves_w_and_p_ownership_for_forty_waves() {
    graph(false, false, false, false, Some("reply-delayed"));
}
#[test]
fn late_verified_retains_missing_envelope_without_signing_again() {
    graph(false, false, false, false, Some("reply-late"));
}
#[test]
fn delayed_locking_status_prevents_verified_and_preserves_sign_owner() {
    graph(false, false, false, false, Some("reply-locking"));
}
#[test]
fn malformed_oversized_verified_is_refused_by_real_w_receive_graph() {
    graph(false, false, false, false, Some("oversized"));
}
#[test]
fn reopened_graph_row_cannot_create_an_old_effect_capability() {
    graph(false, false, true, false, Some("process-old-capability"));
}
#[test]
fn real_wall_writer_drain_commit_and_original_with_synthetic_signer() {
    graph(false, false, false, false, None);
}
#[test]
fn one_wall_owner_retains_forty_disconnect_waves_while_store_is_held() {
    graph(true, false, false, false, None);
}
#[test]
fn unknown_marker_readback_precedes_graph_permit_delivery() {
    graph(false, true, false, false, None);
}
#[test]
fn selected_business_value_flag_enters_the_real_composed_graph() {
    graph(false, false, true, false, None);
}
#[test]
fn absent_ts_retains_one_token_while_next_append_commits_and_persists_original() {
    graph(false, false, false, true, None);
}
#[test]
fn final_policy_recheck_prevents_permit_after_marker_readback() {
    graph(false, true, false, false, Some("policy"));
}
#[test]
fn final_runtime_recheck_prevents_permit_after_marker_readback() {
    graph(false, true, false, false, Some("runtime"));
}
#[test]
fn final_config_recheck_prevents_permit_after_marker_readback() {
    graph(false, true, false, false, Some("config"));
}
#[test]
fn refused_effect_commits_authorized_cut_without_permit() {
    graph(false, false, false, false, Some("cut"));
}
#[test]
fn refused_effect_cut_cannot_reset_the_original_append_end() {
    graph(false, false, false, false, Some("cut-expired"));
}
#[test]
fn typed_pending_count_at_512_refuses_before_reserve_or_sign() {
    graph(false, false, false, false, Some("cap"));
}
#[test]
fn typed_pending_count_at_511_keeps_the_legal_graph_path() {
    graph(false, false, false, false, Some("below-cap"));
}
#[test]
fn same_d_child_commit_readback_held_has_zero_permits_then_one() {
    graph(false, false, false, false, Some("commit-hold"));
}
#[test]
fn refused_commit_retries_exact_request_then_settles() {
    graph(false, false, false, false, Some("commit-refused"));
}
#[test]
fn uncertain_commit_retains_ownership_and_holds_without_permit() {
    graph(false, false, false, false, Some("commit-uncertain"));
}
#[test]
fn final_h_completion_recheck_prevents_permit_after_marker_readback() {
    graph(false, true, false, false, Some("h"));
}
#[test]
fn confirming_read_after_original_expiry_never_revives_a_permit() {
    graph(false, false, false, false, Some("commit-expired"));
}
#[test]
fn journal_fault_before_durability_precedes_guarded_payload_mutation() {
    graph(false, false, false, false, Some("journal-before"));
}
#[test]
fn journal_fault_after_durability_retains_proof_without_reserve_or_sign() {
    graph(false, false, false, false, Some("journal-after"));
}
#[test]
fn lost_local_envelope_after_each_durable_phase_refuses_process_restart() {
    for phase in [5, 6, 7, 8] {
        graph(
            false,
            false,
            true,
            false,
            Some(&format!("process-lost-{phase}")),
        );
    }
}
#[test]
fn process_crash_after_unknown_marker_restarts_settlement_and_next_append() {
    graph(false, false, true, false, Some("process-restart"));
}
#[test]
fn process_crash_restart_covers_marker_and_exact_envelope_settlement_phases() {
    for phase in [3, 4, 5, 6, 7] {
        let mode = format!("process-{phase}");
        graph(false, false, true, false, Some(&mode));
    }
}
#[test]
fn process_restart_child() {
    let Some(root) = std::env::var_os("APPEND_PROCESS_ROOT") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let selector = std::path::PathBuf::from(std::env::var_os("APPEND_PROCESS_SELECTOR").unwrap());
    let end = std::time::Instant::now() + Duration::from_secs(15);
    while !root.join("process-start").exists() {
        assert!(std::time::Instant::now() < end);
        std::thread::sleep(Duration::from_millis(1));
    }
    let selection = match castle_wall_daemon::config::select_profile(
        &castle_wall_daemon::config::SelectorRoots::isolated_under(&selector),
        &[],
    ) {
        castle_wall_daemon::config::ProfileSelection::Business(selection) => selection,
        _ => panic!("isolated child selection"),
    };
    struct Pause {
        root: std::path::PathBuf,
        count: usize,
        enabled: bool,
        at: usize,
    }
    impl WalHooks for Pause {
        fn before(&mut self, step: WalStep) -> WalResult<()> {
            if step == WalStep::Delete
                && std::env::var("APPEND_PROCESS_BUSINESS").ok().as_deref() == Some("lag")
            {
                let cp: Value = serde_json::from_slice(
                    &fs::read(self.root.join("wal/checkpoint.json")).unwrap(),
                )
                .unwrap();
                assert!(
                    cp["payload"]["delivered"].is_object(),
                    "lagging cursor forbids deletion"
                );
            }
            if step == WalStep::Readback && self.root.join("hold-first-ts-fact").exists() {
                let path = self.root.join("wal/row-00000000000000000001.json");
                if let Ok(bytes) = fs::read(path) {
                    let row: Value = serde_json::from_slice(&bytes).unwrap();
                    let cp: Value = serde_json::from_slice(
                        &fs::read(self.root.join("wal/checkpoint.json")).unwrap(),
                    )
                    .unwrap();
                    if row["payload"]["ts_fact"].is_object() && cp["payload"]["delivered"].is_null()
                    {
                        private(&self.root.join("fact.held"), b"held");
                        let end = std::time::Instant::now() + Duration::from_secs(15);
                        while !self.root.join("process-release").exists() {
                            if std::time::Instant::now() >= end {
                                return Err(Refusal::Deadline);
                            }
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    }
                }
            }
            if step == WalStep::Readback {
                self.count += 1;
                // Startup republishes its drained checkpoint before the append's phase-indexed publications.
                const STARTUP_REFRESH_PUBLICATIONS: usize = 1;
                if self.enabled && self.count == self.at + STARTUP_REFRESH_PUBLICATIONS {
                    private(&self.root.join("process-reached"), b"marker");
                    let end = std::time::Instant::now() + Duration::from_secs(15);
                    while !self.root.join("process-release").exists() {
                        if std::time::Instant::now() >= end {
                            return Err(Refusal::Deadline);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            Ok(())
        }
    }
    let business_order = std::env::var("APPEND_PROCESS_BUSINESS").ok();
    let pause = std::env::var_os("APPEND_PROCESS_PAUSE").is_some();
    let mut first_fact = false;
    let mut published_count = 0usize;
    private(
        &root.join("process-permits"),
        published_count.to_string().as_bytes(),
    );
    let mut observe = |actor: &mut AppendActor, count: usize| {
        if let Some(order) = &business_order {
            if !first_fact
                && actor.pending_delivery().is_some()
                && if pause && order == "ts" {
                    actor.state() == State::CommittedDeliveryReady
                } else {
                    actor.state() == State::Ready
                }
            {
                first_fact = true;
                let config: Value =
                    serde_json::from_slice(&fs::read(root.join("compose.json")).unwrap()).unwrap();
                if matches!(order.as_str(), "held" | "lag") && pause {
                    private(&root.join("hold-first-ts-fact"), b"hold");
                    private(
                        &root.join("first-consumer.json"),
                        &canonical(&config["join"]),
                    );
                }
                if order == "held"
                    || pause && matches!(order.as_str(), "ts" | "lag")
                    || !pause && order == "d"
                {
                    // Restarted TS acceptance starts from its durable preceding checkpoint, not the new append's join.
                    let initial = if pause {
                        config["join"].clone()
                    } else {
                        serde_json::from_slice(&fs::read(root.join("first-consumer.json")).unwrap())
                            .unwrap()
                    };
                    deliver_business_graph(
                        actor,
                        &root,
                        &initial,
                        &root.join("wal"),
                        pause && order == "ts",
                        false,
                        None,
                    );
                }
                if pause {
                    private(
                        &root.join("first-consumer.json"),
                        &canonical(&config["join"]),
                    );
                    private(&root.join("process-reached"), b"first-fact");
                    let end = std::time::Instant::now() + Duration::from_secs(15);
                    while !root.join("process-release").exists() {
                        assert!(
                            std::time::Instant::now() < end,
                            "parent kills first-fact owner"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        // A paused child's parent reads this counter concurrently; unchanged values must remain stable.
        if count != published_count {
            private(&root.join("process-permits"), count.to_string().as_bytes());
            published_count = count;
        }
        Ok(())
    };
    let result = compose_for_test_driven(
        selection,
        &root,
        Arc::new(signer_watchdog::boottime_ns),
        Box::new(Pause {
            root: root.clone(),
            count: 0,
            enabled: pause && business_order.is_none(),
            at: std::env::var("APPEND_PROCESS_PHASE")
                .unwrap()
                .parse()
                .unwrap(),
        }),
        &mut observe,
    );
    if std::env::var_os("APPEND_PROCESS_EXPECT_LOST").is_some() {
        assert!(
            result.is_err(),
            "lost local exact E cannot recover an append owner"
        );
        private(&root.join("process-result"), b"held");
    } else if std::env::var_os("APPEND_PROCESS_EXPECT_HELD").is_some() {
        assert_eq!(
            result,
            Err(Refusal::Held),
            "restart without exact E retains the outstanding intent"
        );
        private(&root.join("process-result"), b"held");
    } else {
        assert!(
            result.is_ok(),
            "restarted child completes exact settlement and next append: {result:?}"
        );
        private(
            &root.join("process-result"),
            result.unwrap().to_string().as_bytes(),
        );
    }
}
#[test]
fn post_p_verified_substitution_stops_before_client_append_attempt() {
    graph(false, false, false, false, Some("body-client"));
}
#[test]
fn post_client_substitution_stops_before_actor_append_attempt() {
    graph(false, false, false, false, Some("body-actor"));
}
#[test]
fn composed_entry_requires_independent_h_evidence_before_any_append() {
    graph(false, false, false, false, Some("dependency"));
}
struct Evidence(LocalEvidence);
impl EvidenceSource for Evidence {
    fn observe(&mut self) -> WalResult<LocalEvidence> {
        Ok(self.0.clone())
    }
}
struct HoldBody {
    release_root: Option<std::path::PathBuf>,
    journal: Option<WalStep>,
    journal_calls: usize,
    hold: bool,
    syncs: usize,
    marker: bool,
    entered: Arc<AtomicBool>,
    released: Arc<AtomicBool>,
}
impl WalHooks for HoldBody {
    fn before(&mut self, step: WalStep) -> WalResult<()> {
        if let Some(root) = &self.release_root {
            if step == WalStep::Delete {
                let wal = root.join("wal");
                let row: Value = serde_json::from_slice(
                    &fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                )
                .unwrap();
                let cp: Value =
                    serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap())
                        .unwrap();
                assert!(
                    row["payload"]["d_fact"].is_object() && row["payload"]["ts_fact"].is_object(),
                    "release requires both exact facts"
                );
                assert_eq!(
                    row["payload"]["d_fact"], row["payload"]["ts_fact"],
                    "release facts name identical E"
                );
                assert_eq!(
                    cp["payload"]["released"], row["payload"]["d_fact"],
                    "deletion follows durable released checkpoint"
                );
                private(&root.join("release.observed"), b"observed");
            }
            if step == WalStep::Readback && root.join("fail-ts-fact").exists() {
                let row: Value = serde_json::from_slice(
                    &fs::read(root.join("wal/row-00000000000000000001.json")).unwrap(),
                )
                .unwrap();
                if row["payload"]["ts_fact"].is_object() {
                    return Err(Refusal::Io);
                }
            }
            if step == WalStep::Readback && root.join("hold-cursor").exists() {
                let cp: Value =
                    serde_json::from_slice(&fs::read(root.join("wal/checkpoint.json")).unwrap())
                        .unwrap();
                if cp["payload"]["delivered"]["sequence"] == 1 {
                    private(&root.join("cursor.held"), b"held");
                    let end = std::time::Instant::now() + Duration::from_secs(10);
                    while !root.join("cursor.release").exists() {
                        if std::time::Instant::now() >= end {
                            return Err(Refusal::Deadline);
                        }
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
        }
        if self.journal == Some(step) {
            self.journal_calls += 1;
            // Initialization publishes first; the second journal guards the live body's first publication.
            if self.journal_calls == 2 {
                return Err(Refusal::Io);
            }
        }
        if step
            == if self.marker {
                WalStep::Readback
            } else {
                WalStep::FileSync
            }
        {
            self.syncs += 1;
            // Initialization and drained refresh each publish before the first body publication.
            const STARTUP_PUBLICATIONS: usize = 2;
            const BODY_PUBLICATION: usize = STARTUP_PUBLICATIONS + 1;
            const MARKER_PUBLICATION: usize = STARTUP_PUBLICATIONS + 7;
            if self.hold
                && self.syncs
                    == if self.marker {
                        MARKER_PUBLICATION
                    } else {
                        BODY_PUBLICATION
                    }
            {
                self.entered.store(true, Ordering::SeqCst);
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                while !self.released.load(Ordering::SeqCst) {
                    if std::time::Instant::now() >= deadline {
                        return Err(Refusal::Deadline);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
        Ok(())
    }
}
struct Release(Arc<AtomicBool>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
#[test]
fn continuation_cas_identity_at_earliest_w_send() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:Confirm:CasIdentity"),
    );
}
#[test]
fn continuation_second_envelope_at_earliest_w_commit_send() {
    graph(
        false,
        false,
        false,
        false,
        Some("observe:CommitFreeze:SendSecondEnvelope"),
    );
}
fn invariant_zero(anchor: &Value, wal: &std::path::Path) {
    let committed = anchor["committed_sequence"].as_u64().unwrap();
    assert_eq!(
        committed - anchor["drained_sequence"].as_u64().unwrap(),
        0,
        "admission and active reopen have zero D pending"
    );
    let checkpoint: Value =
        serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(
        checkpoint["payload"]["originals"]["sequence"]
            .as_u64()
            .unwrap_or(0),
        committed,
        "local originals equal committed at admission and active reopen"
    );
}
fn fresh_s_anchor(d: &mut drain_run::Fixture) -> Value {
    use castle_wall_daemon::business_profile::drain_protocol as protocol;
    d.s.connect(&d.socket());
    d.s.send(
        &protocol::encode(
            &protocol::header("READ", &"d".repeat(32), drain_run::ROLE),
            &[],
            protocol::Direction::ToDrain,
        )
        .unwrap(),
    );
    let bytes = d.s.receive(drain_run::WAIT_MS).unwrap();
    match protocol::decode(&bytes, protocol::Direction::FromDrain)
        .unwrap()
        .operation
    {
        protocol::Operation::ReadReply {
            anchor: Some(anchor),
            uncertain: false,
            ..
        } => anchor,
        _ => panic!("fresh authenticated D observation"),
    }
}
#[test]
fn continuation_resume_expected_retries_identical_c0() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-resume-expected"),
    );
}
#[test]
fn continuation_resume_next_active_confirms() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-resume-active"),
    );
}
#[test]
fn continuation_resume_next_confirmed_reaches_original_without_restart() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-resume-confirmed"),
    );
}
#[test]
fn continuation_admission_drained_hold() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-admission-drained"),
    );
}
#[test]
fn continuation_admission_authority_hold() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-admission-authority"),
    );
}
#[test]
fn continuation_resume_drained_hold() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-resume-drained"),
    );
}
#[test]
fn continuation_resume_authority_hold() {
    graph(
        false,
        false,
        false,
        false,
        Some("continuation-resume-authority"),
    );
}
#[test]
fn continuation_admit_zero_forty_waves_and_reconnect() {
    graph(false, false, false, false, Some("continuation-admit-zero"));
}
#[test]
fn continuation_admit_zero_actual_kill_and_reopen() {
    graph(false, false, true, false, Some("process-6"));
}
#[test]
fn continuation_startup_drained_hold() {
    graph(
        false,
        false,
        true,
        false,
        Some("process-continuation-drained"),
    );
}
#[test]
fn continuation_startup_authority_hold() {
    graph(
        false,
        false,
        true,
        false,
        Some("process-continuation-authority"),
    );
}
#[test]
#[ignore = "explicit unprivileged Business consumer fixture"]
fn business_ipc_durable_ts_fact_after_real_d_original() {
    graph(false, false, false, false, Some("business-delivery"));
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_ts_fact_before_original_and_live_compaction() {
    graph(false, false, false, false, Some("business-ts-first"));
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_ts_cursor_readback_holds_next_delivery() {
    graph(false, false, false, true, Some("business-cursor"));
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_restart_after_first_fact_in_each_order() {
    for order in ["d", "ts", "held"] {
        graph(
            false,
            false,
            true,
            false,
            Some(&format!("process-business-{order}")),
        );
    }
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_missing_d_fact_retains_exact_row() {
    graph(false, false, false, false, Some("business-missing-d"));
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_missing_ts_fact_retains_exact_row() {
    graph(false, false, false, false, Some("business-missing-ts"));
}
#[test]
#[ignore = "unprivileged Business delivery integration"]
fn business_local_fact_failure_retains_one_delivery() {
    graph(false, false, false, true, Some("business-fact-failure"));
}
#[test]
#[ignore = "real authenticated delivery schedule"]
fn delivery_submit_deadline_reconnect_retains_exact_envelope() {
    graph(false, false, false, false, Some("business-submit-failure"));
}
#[test]
#[ignore = "real authenticated delivery schedule"]
fn delivery_resume_during_fact_retires_completed_token() {
    graph(false, false, false, false, Some("business-resume-fact"));
}
#[test]
#[ignore = "real authenticated delivery schedule"]
fn delivery_cursor_lag_after_process_kill_allows_next_append() {
    graph(false, false, true, false, Some("process-business-lag"));
}
#[test]
fn delivery_fact_wait_stays_outside_recheck_and_original_windows() {
    graph(false, false, false, false, Some("delivery-window"));
}
fn graph(hold_store: bool, marker: bool, entry: bool, second: bool, changed_field: Option<&str>) {
    let process_business = changed_field.and_then(|s| s.strip_prefix("process-business-"));
    let business = changed_field.is_some_and(|s| s.starts_with("business-"));
    let missing_fact = changed_field.and_then(|s| s.strip_prefix("business-missing-"));
    let ts_first = matches!(
        changed_field,
        Some("business-ts-first" | "business-submit-failure" | "business-resume-fact")
    ) || missing_fact.is_some();
    let continuation = changed_field.is_some_and(|s| s.starts_with("continuation-"));
    let continuation_startup =
        changed_field.is_some_and(|s| s.starts_with("process-continuation-"));
    let continuation_hold =
        changed_field.is_some_and(|s| s.ends_with("drained") || s.ends_with("authority"));
    let continuation_reason = if changed_field.is_some_and(|s| s.ends_with("drained")) {
        "invariant breach (unreachable by construction)"
    } else {
        "superseding authority, owner 2g"
    };
    let observation = changed_field
        .and_then(|s| s.strip_prefix("observe:"))
        .map(|s| s.split_once(':').unwrap());
    let delayed = changed_field.is_some_and(|s| s.starts_with("reply-"));
    let locking_reply = changed_field == Some("reply-locking");
    let lost_local = changed_field.is_some_and(|s| s.starts_with("process-lost-"));
    let process = changed_field.is_some_and(|s| s.starts_with("process-"));
    let process_phase = changed_field
        .and_then(|s| s.strip_prefix("process-"))
        .and_then(|s| s.strip_prefix("lost-").unwrap_or(s).parse::<usize>().ok())
        .unwrap_or(if process_business.is_some() {
            11
        } else if continuation_startup {
            6
        } else if changed_field == Some("process-old-capability") {
            7
        } else {
            8
        });
    let body_substitution = matches!(changed_field, Some("body-client" | "body-actor"));
    let cut = matches!(changed_field, Some("cut" | "cut-expired"));
    let mut d = drain_run::Fixture::new();
    d.bus.unit.lock().unwrap().pid = std::process::id();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let now = signer_watchdog::boottime_ns().unwrap();
    const GRANT_MS: u64 = 300_000;
    let expires = now + GRANT_MS * writer_peer::NS_PER_MS;
    let clock = Arc::new(AtomicU64::new(now));
    let boot = signer_service::parse_boot_id(&fs::read("/proc/sys/kernel/random/boot_id").unwrap())
        .unwrap();
    d.anchor["boot_id"] = json!(boot);
    let vectors: Value = serde_json::from_str(include_str!(
        "../../src/business_profile/record_join_vectors.json"
    ))
    .unwrap();
    let case = vectors["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| {
            if cut {
                c["records"][0]["body"]["record_kind"] == "control"
                    && c["records"][0]["body"]["payload"]["unresolved_flows"] == 1
            } else {
                c["id"] == "listener-accept"
            }
        })
        .unwrap();
    let mut body = case["records"][0]["body"].clone();
    let mut join = case["initial"].clone();
    body["kid"] = d.body["kid"].clone();
    body["boot_id"] = json!(boot);
    body["captured_at_boottime_ns"] = json!(now.to_string());
    if !cut {
        body["payload"]["context"]["flow"]["boot_id"] = json!(boot);
    }
    join["pin"]["kid"] = body["kid"].clone();
    join["pin"]["public_key"] = json!(URL_SAFE_NO_PAD.encode(d.key.verifying_key().to_bytes()));
    join["grant"]["boot_id"] = json!(boot);
    join["grant"]["expires_ns"] = json!(expires.to_string());
    let mut grant = join["pin"].clone();
    for field in ["activation_id", "lease_id", "generation"] {
        grant[field] = join["grant"][field].clone();
    }
    let view: StatusReply = serde_json::from_value(json!({"op":"STATUS","state":"UNLOCKED","grant":grant,"started_boottime_ns":now.to_string(),"expires_boottime_ns":expires.to_string(),"boot_id":boot,"anchor_revision":1,"anchor_digest":activation_anchor::anchor_digest(&d.anchor).unwrap()})).unwrap();
    d.start();
    d.prepare();
    let original_d_records = d
        .events()
        .iter()
        .filter(|e| e["event"] == "StoreEntered" && e["publication"] == "record")
        .count();
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let wal = root.path().join("wal");
    fs::create_dir(&wal).unwrap();
    fs::set_permissions(&wal, fs::Permissions::from_mode(0o700)).unwrap();
    let signer_path = root.path().join("signer");
    let signer_listener = (!entry).then(|| signer_peer::listen(&signer_path).unwrap());
    let helper = std::env::var_os("WRITER_TEST_HELPER")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(env!("CARGO_BIN_EXE_writer-standin")));
    let policy = signer_peer::PeerPolicy {
        uid,
        gid,
        executable_sha256: hex::encode(Sha256::digest(fs::read(&helper).unwrap())),
        cgroup: fs::read_to_string("/proc/self/cgroup").unwrap(),
    };
    let lifecycle = Arc::new(Mutex::new(
        join_lifecycle::step(
            &join_lifecycle::initial(),
            &json!({"type":"Checkpoint","checkpoint":join}),
        )
        .unwrap(),
    ));
    let mut threads = Threads {
        stop: Arc::new(AtomicBool::new(false)),
        handles: vec![],
        children: vec![],
    };
    let stop = threads.stop.clone();
    let key = d.key.clone();
    let model = lifecycle.clone();
    let s_admissions = Arc::new(AtomicU64::new(0));
    let s_count = s_admissions.clone();
    let reply_released = Arc::new(AtomicBool::new(!delayed));
    let reply_release = Release(reply_released.clone());
    let s_release = reply_released.clone();
    let locking_seen = Arc::new(AtomicBool::new(false));
    let s_locking = locking_seen.clone();
    let entry_view = view.clone();
    if let Some(signer_listener) = signer_listener {
        threads.handles.push(std::thread::spawn(move || {
        let socket = loop {
            if stop.load(Ordering::SeqCst) { return; }
            if let Ok(s) = signer_peer::accept(signer_listener.as_raw_fd()) { break s; }
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut first_status = true;
        while !stop.load(Ordering::SeqCst) {
            let mut p = libc::pollfd { fd: socket.as_raw_fd(), events: libc::POLLIN, revents: 0 };
            if unsafe { libc::poll(&mut p, 1, 10) } != 1 { continue; }
            let Ok(packet) = signer_peer::receive(socket.as_raw_fd(), writer_protocol::WRITER_SIGN_PACKET_MAX_BYTES) else { return; };
            if packet.bytes.is_empty() { return; }
            let response = if packet.bytes == b"{\"op\":\"STATUS\"}" { {
                let mut status = view.clone();
                if first_status { status.state = "LOCKED".into(); status.started_boottime_ns = "0".into(); status.expires_boottime_ns = "0".into(); first_status = false; }
                if locking_reply && s_count.load(Ordering::SeqCst) > 0 {
                    status.state = "LOCKING".into();
                    s_locking.store(true, Ordering::SeqCst);
                }
                serde_json::to_value(&status).unwrap()
            } } else {
                let (header, body) = signer_service::decode(&packet.bytes).unwrap();
                s_count.fetch_add(1, Ordering::SeqCst);
                while !s_release.load(Ordering::SeqCst) && !stop.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let domain = castle_wall_daemon::business_profile::signer_contract::ROLE_REGISTRY[0].1;
                let signature = key.sign(&[domain.as_bytes(), body].concat()).to_bytes();
                let envelope = writer_protocol::envelope(body, &signature).unwrap(); let record: Value = serde_json::from_slice(&envelope).unwrap();
                let identity = append_contract::identity(&envelope).unwrap();
                let mut state = model.lock().unwrap();
                *state = join_lifecycle::step(&state, &json!({"type":"SignAdmitted","record":record})).unwrap();
                *state = join_lifecycle::step(&state, &json!({"type":"Signed","identity":identity})).unwrap();
                json!({"op":"SIGNED","request_id":header.request_id,"kid":view.grant.kid,"signature":URL_SAFE_NO_PAD.encode(signature)})
            };
            if signer_peer::send(socket.as_raw_fd(), &signer_service::encode(&response, &[]).unwrap(), &[]).is_err() { return; }
        }
    }));
    }
    let mut alternate = body.clone();
    alternate["captured_at_unix_ms"] = json!(body["captured_at_unix_ms"].as_u64().unwrap() + 1);
    let alternate_body = canonical(&alternate);
    let alternate_signature = d
        .key
        .sign(
            &[
                castle_wall_daemon::business_profile::signer_contract::ROLE_REGISTRY[0]
                    .1
                    .as_bytes(),
                &alternate_body,
            ]
            .concat(),
        )
        .to_bytes();
    let alternate_envelope =
        writer_protocol::envelope(&alternate_body, &alternate_signature).unwrap();
    if body_substitution {
        private(&root.path().join("verified.reply"), &alternate_envelope);
    }
    private(
        &root.path().join("sign.reply"),
        if changed_field == Some("oversized") {
            b"oversized-verified"
        } else {
            b"sign-admissions"
        },
    );
    let mut bus = writer_bus::Fixture::new();
    bus.config.fortress_id = drain_run::FORTRESS.into();
    let writer_config = bus.config_path();
    let wall_unit = bus.unit.clone();
    let mut signer_policy = policy.clone();
    if !entry {
        signer_policy.executable_sha256 =
            hex::encode(Sha256::digest(fs::read("/proc/self/exe").unwrap()));
    }
    {
        use std::process::{Command, Stdio};
        private(
            &root.path().join("peers.json"),
            &canonical(
                &json!({"status":entry_view,"join":join,"peer_policy":signer_policy,"writer_config":writer_config,"bus":{"socket":bus.root.path().join("bus"),"socket_owner_uid":uid,"expected_manager_uid":uid,"expected_manager_pid":std::process::id(),"wall_unit":bus.config.wall_unit},"boot":boot,"fortress":drain_run::FORTRESS,"clock_boottime_ns":now,"verified_reply":if changed_field == Some("body-client") { Some(root.path().join("verified.reply")) } else { Some(root.path().join("sign.reply")) }}),
            ),
        );
        for (mode, ready) in [
            ("composed-signer", "signer"),
            ("composed-writer", "writer-ready"),
        ] {
            if mode == "composed-signer" && !entry {
                continue;
            }
            let stderr = fs::File::create(root.path().join(format!("{mode}-stderr"))).unwrap();
            threads.children.push(
                Command::new(&helper)
                    .args([mode, root.path().to_str().unwrap(), "composed"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::from(stderr))
                    .spawn()
                    .unwrap(),
            );
            let end = std::time::Instant::now() + Duration::from_secs(10);
            while !root.path().join(ready).exists() {
                assert!(
                    std::time::Instant::now() < end,
                    "isolated peer startup: {mode}: {:?}",
                    fs::read_to_string(root.path().join(format!("{mode}-stderr")))
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    let d_pin = signer_peer::PeerPolicy {
        uid,
        gid,
        executable_sha256: hex::encode(Sha256::digest(
            fs::read(drain_run::native("sanctuary-business-drain")).unwrap(),
        )),
        cgroup: fs::read_to_string(format!("/proc/{}/cgroup", d.child.as_ref().unwrap().id()))
            .unwrap(),
    };
    private(
        &root.path().join("compose.json"),
        &canonical(
            &json!({"fortress":drain_run::FORTRESS,"revision":1,"writer_root":root.path(),"writer_leaf":"writer","drain_root":d.root.join("runtime"),"drain_leaf":"drain.sock","writer_pin":policy,"drain_pin":d_pin,"wal_root":wal,"anchor":d.anchor,"join":join,"h_expiry_ns":expires,"policy_digest":body["policy_digest"],"runtime_digest":body["runtime_digest"],"config_digest":body["config_digest"],"body":body,"effect":if cut || process_business.is_some() { Value::Null } else {json!({"OpenAdmission":{"flow":body["payload"]["context"]["flow"],"payload":body["payload"]}})},"flows":0,"clock_boottime_ns":if entry {Some(now)} else {None}}),
        ),
    );
    if changed_field == Some("dependency") {
        let path = root.path().join("compose.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        config.as_object_mut().unwrap().remove("h_expiry_ns");
        private(&path, &canonical(&config));
    }
    let selector = tempfile::tempdir().unwrap();
    fs::set_permissions(selector.path(), fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(selector.path().join("etc")).unwrap();
    // Profile selector fixtures use the same explicit isolated root contract as the daemon entry.
    let roots = castle_wall_daemon::config::SelectorRoots::isolated_under(selector.path());
    let selection = select_business(&roots, selector.path());
    let entered = Arc::new(AtomicBool::new(false));
    let released = Arc::new(AtomicBool::new(false));
    let release = Release(released.clone());
    let mut waves = Vec::new();
    let mut marker_polls = 0;
    let mut second_started = false;
    let mut refused = false;
    let mut commit_fault = false;
    let mut commit_polls = 0;
    let mut commit_bytes: Option<Vec<u8>> = None;
    let d_pid = d.child.as_ref().unwrap().id();
    let mut resumed = false;
    let after_client = Arc::new(Mutex::new(None::<Vec<u8>>));
    let after_actor = Arc::new(Mutex::new(None::<Vec<u8>>));
    let mut observing = false;
    let mut observation_installed = false;
    let mut observed_permits = 0;
    let mut reply_waves = 0;
    let mut refused_reserve_gap = false;
    let mut continuation_started = false;
    let mut continuation_snapshot: Option<Vec<u8>> = None;
    let mut continuation_report = None;
    let mut expired_hold = None;
    let mut reserve_observations = 0;

    if let Some((point, field)) = observation {
        private(
            &root.path().join("observation.json"),
            &canonical(&json!({"point":point,"field":field})),
        );
    }
    let mut delivery_windows = [false; 3];
    let mut business_delivered = false;
    let mut fact_removed = false;
    let mut drive = |actor: &mut AppendActor, count: usize| -> WalResult<()> {
        observed_permits = count;
        if changed_field == Some("delivery-window") && actor.pending_delivery().is_some() {
            if actor.state() == State::Checking && count == 0 {
                assert!(
                    !actor.can_complete_delivery(),
                    "eligible recheck evaluates before a TS disk wait"
                );
                delivery_windows[0] = true;
            }
            if actor.state() == State::Original {
                assert!(
                    !actor.can_complete_delivery(),
                    "ORIGINAL reply is polled before a TS disk wait"
                );
                delivery_windows[1] = true;
            }
            if actor.state() == State::Ready {
                assert!(
                    actor.can_complete_delivery(),
                    "settled delivery can persist its fact"
                );
                delivery_windows[2] = true;
            }
        }
        if business
            && !business_delivered
            && actor.pending_delivery().is_some()
            && if ts_first {
                actor.state() == State::CommittedDeliveryReady
            } else {
                actor.state() == State::Ready && (!second || second_started)
            }
        {
            if changed_field == Some("business-fact-failure") {
                let checkpoint: Value =
                    serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap())
                        .unwrap();
                assert_eq!(
                    checkpoint["payload"]["anchor"]["committed_sequence"], 2,
                    "successor is committed before the failed fact"
                );
                assert!(
                    wal.join("row-00000000000000000002.json").exists(),
                    "committed successor remains charged"
                );
                private(&root.path().join("fail-ts-fact"), b"fail");
            }
            if changed_field == Some("business-resume-fact") {
                private(&root.path().join("resume-fact"), b"resume");
            }
            if changed_field == Some("business-submit-failure") {
                private(&root.path().join("fail-submit"), b"deadline");
            }
            deliver_business_graph(
                actor,
                root.path(),
                &join,
                &wal,
                ts_first,
                second && changed_field != Some("business-fact-failure"),
                (changed_field == Some("business-submit-failure")).then(|| clock.clone()),
            );
            business_delivered = true;
            if matches!(
                changed_field,
                Some("business-fact-failure" | "business-submit-failure")
            ) {
                return Err(Refusal::Io);
            }
        }
        if let Some(fact) = missing_fact {
            if business_delivered && !fact_removed && actor.state() == State::Checking {
                let path = wal.join("row-00000000000000000001.json");
                let mut row: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let cp: Value =
                    serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap())
                        .unwrap();
                if cp["payload"]["originals"]["sequence"] == 1
                    && cp["payload"]["delivered"]["sequence"] == 1
                {
                    // Loss of one locally checksummed fact leaves the two cursor observations intact.
                    row["payload"][format!("{fact}_fact")] = Value::Null;
                    row["storage_checksum"] = json!(format!(
                        "sha256:{}",
                        hex::encode(Sha256::digest(canonical(&row["payload"])))
                    ));
                    private(&path, &canonical(&row));
                    fact_removed = true;
                }
            }
        }
        if changed_field == Some("commit-expired") && resumed && actor.state() == State::Held {
            expired_hold = actor.commit_hold().map(ToString::to_string);
        }
        if actor.state() == State::Reserve {
            invariant_zero(&actor.drain_observation_for_test().unwrap()["anchor"], &wal);
            reserve_observations += 1;
        }
        if continuation
            && !continuation_started
            && actor.state() == State::Checking
            && actor.continuation_for_test()
                == match changed_field {
                    Some("continuation-resume-active") => "Confirm",
                    Some("continuation-resume-confirmed") => "EffectMarker",
                    _ => "CommitSend",
                }
        {
            let kind = if !continuation_hold {
                "Observe"
            } else if changed_field.unwrap().ends_with("drained") {
                "DrainedOnly"
            } else {
                "Authority"
            };
            private(
                &root.path().join("continuation.json"),
                &canonical(&json!(kind)),
            );
            actor.settlement_fixture_for_test(
                castle_wall_daemon::business_profile::append_clients::SettlementFixture::load(
                    &root.path().join("continuation.json"),
                )
                .unwrap(),
            )?;
            continuation_snapshot =
                Some(fs::read(wal.join("row-00000000000000000001.json")).unwrap());
            if changed_field == Some("continuation-admit-zero") {
                let anchor = fresh_s_anchor(&mut d);
                for _ in 0..40 {
                    invariant_zero(&anchor, &wal);
                    assert_eq!(
                        actor.begin(alternate_body.clone(), None, expires, 0),
                        Err(Refusal::Held)
                    );
                    assert_eq!(
                        fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                        *continuation_snapshot.as_ref().unwrap()
                    );
                }
            }
            if !changed_field
                .unwrap()
                .starts_with("continuation-admission-")
            {
                actor.disconnect();
                actor.resume_settlement()?;
                let sends = fs::read_to_string(root.path().join("continuation.sends")).unwrap();
                let first: Value = serde_json::from_str(sends.lines().next().unwrap()).unwrap();
                assert_eq!(
                    first["op"], "READ",
                    "reconnect reads before any COMMIT send"
                );
                resumed = true;
            }
            continuation_started = true;
        }
        if continuation && continuation_hold && actor.state() == State::Held {
            assert_eq!(count, 0, "held predecessor grants no permit");
            let report = actor
                .commit_hold()
                .expect("changed predecessor has bounded hold report")
                .clone();
            continuation_report = Some(report.to_string());
            let cut = actor.pending_cut();
            for _ in 0..40 {
                assert_eq!(
                    actor.resume_settlement(),
                    Err(Refusal::Held),
                    "changed predecessor retries nothing"
                );
                assert_eq!(
                    actor.begin(alternate_body.clone(), None, expires, 0),
                    Err(Refusal::Held)
                );
                assert!(actor.ownership_for_test().0 && actor.ownership_for_test().2);
                actor.poll()?;
                assert_eq!(actor.pending_cut(), cut, "hold retains the cut obligation");
                assert_eq!(
                    fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                    *continuation_snapshot.as_ref().unwrap(),
                    "held row and all charges remain exact"
                );
            }
        }

        if delayed
            && actor.state() == State::Sign
            && s_admissions.load(Ordering::SeqCst) == 1
            && reply_waves < 40
        {
            assert_eq!(count, 0, "held SIGN has no effect");
            assert_eq!(
                fs::read(root.path().join("sign.observed")).unwrap().len(),
                1,
                "one P admission while S owns reply"
            );
            assert!(
                actor.ownership_for_test().0 && !actor.ownership_for_test().2,
                "delayed reply retains unresolved W owner"
            );
            let owned_row = fs::read(wal.join("row-00000000000000000001.json")).unwrap();
            let owned: Value = serde_json::from_slice(&owned_row).unwrap();
            assert_eq!(
                URL_SAFE_NO_PAD
                    .decode(owned["payload"]["body"].as_str().unwrap())
                    .unwrap(),
                canonical(&body)
            );
            assert_eq!(
                actor.begin(alternate_body.clone(), None, expires, 0),
                Err(Refusal::Held),
                "changed body cannot reuse outstanding request"
            );
            assert_eq!(
                fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                owned_row,
                "changed B preserves the complete owned row and exact reserve request"
            );
            reply_waves += 1;
            if reply_waves == 40 {
                if changed_field == Some("reply-late") {
                    clock.store(
                        now + (writer_protocol::WRITER_SIGN_DEADLINE_MAX_MS + 1)
                            * writer_peer::NS_PER_MS,
                        Ordering::SeqCst,
                    );
                }
                if locking_reply {
                    private(
                        &root.path().join("writer-clock"),
                        (now + writer_protocol::WRITER_HEARTBEAT_MS * writer_peer::NS_PER_MS)
                            .to_string()
                            .as_bytes(),
                    );
                }
                reply_release.0.store(true, Ordering::SeqCst);
            }
        }
        if observation == Some(("SignMarker", "ReserveRefused"))
            && !refused_reserve_gap
            && root.path().join("observation.observed").exists()
        {
            refused_reserve_gap = true;
            assert_eq!(
                actor.state(),
                State::Checking,
                "reasonless reserve refusal awaits independent READ"
            );
            assert_eq!(
                fs::read(root.path().join("sign.observed"))
                    .unwrap_or_default()
                    .len(),
                0,
                "reserve refusal alone admits no W-to-P SIGN"
            );
            assert_eq!(
                s_admissions.load(Ordering::SeqCst),
                0,
                "reserve refusal alone admits no P-to-S SIGN"
            );
        }
        if observation == Some(("SignMarker", "ReserveMissing"))
            && root.path().join("observation.observed").exists()
        {
            clock.store(
                now + castle_wall_daemon::business_profile::append_budget::APPEND_BUDGET_MS
                    * writer_peer::NS_PER_MS,
                Ordering::SeqCst,
            );
        }
        if observation.is_some() && !observation_installed {
            actor.observations_for_test(
                TestObservations::load(&root.path().join("observation.json")).unwrap(),
            );
            observation_installed = true;
        }
        if body_substitution && !observing {
            let client = after_client.clone();
            let wall = after_actor.clone();
            actor.verified_observers_for_test(VerifiedObservers {
                after_client: Box::new(move |bytes| {
                    let mut owned = client.lock().unwrap();
                    assert!(owned.is_none());
                    *owned = Some(bytes.to_vec());
                }),
                after_actor: Box::new(move |bytes| {
                    let mut owned = wall.lock().unwrap();
                    assert!(owned.is_none());
                    *owned = Some(bytes.to_vec());
                }),
                actor_reply: (changed_field == Some("body-actor"))
                    .then(|| alternate_envelope.clone()),
            })?;
            observing = true;
        }
        if matches!(
            changed_field,
            Some("commit-hold" | "commit-expired" | "commit-refused" | "commit-uncertain")
        ) {
            if actor.state() == State::Sign && !commit_fault {
                let (step, action) = match changed_field {
                    Some("commit-hold" | "commit-expired") => ("Readback", "hold"),
                    Some("commit-refused") => ("Stage", "fail"),
                    _ => ("DirSync", "fail"),
                };
                d.fault("record", step, action, json!("b2commit"), 1);
                commit_fault = true;
            }
            if let Some(commit) = actor.commit_for_test() {
                if let Some(bytes) = &commit_bytes {
                    assert_eq!(
                        commit.bytes(),
                        bytes,
                        "refused or uncertain settlement preserves exact COMMIT bytes and id"
                    );
                } else {
                    commit_bytes = Some(commit.bytes().to_vec());
                }
                let frame = castle_wall_daemon::business_profile::drain_protocol::decode(
                    commit.bytes(),
                    castle_wall_daemon::business_profile::drain_protocol::Direction::ToDrain,
                )
                .unwrap();
                let events = d.events();
                let entered = events.iter().any(|e| {
                    e["event"] == "StoreEntered"
                        && e["publication"] == "record"
                        && e["request_id"] == frame.request_id
                });
                let synced = events.iter().any(|e| {
                    e["event"] == "StepCompleted"
                        && e["publication"] == "record"
                        && e["request_id"] == frame.request_id
                        && e["step"] == "DirSync"
                });
                if matches!(changed_field, Some("commit-hold" | "commit-expired"))
                    && entered
                    && synced
                    && commit_polls < 40
                {
                    assert_eq!(
                        d.child.as_ref().unwrap().id(),
                        d_pid,
                        "COMMIT hold belongs to the same D child"
                    );
                    assert_eq!(count, 0, "same-child held COMMIT readback has zero permits");
                    commit_polls += 1;
                    if commit_polls == 40 {
                        private(&d.root.join("release-b2commit"), b"");
                        if changed_field == Some("commit-expired") {
                            clock.store(now + (castle_wall_daemon::business_profile::append_budget::APPEND_BUDGET_MS + 1) * writer_peer::NS_PER_MS, Ordering::SeqCst);
                        }
                    }
                }
            }
            if actor.state() == State::Held
                && matches!(
                    changed_field,
                    Some("commit-uncertain" | "commit-refused" | "commit-expired")
                )
                && !resumed
            {
                assert_eq!(count, 0, "uncertain confirming state has zero permits");
                assert!(
                    actor.ownership_for_test().0 && actor.ownership_for_test().2,
                    "uncertain settlement retains exact envelope ownership"
                );
                d.clear();
                actor.resume_settlement()?;
                resumed = true;
            }
        }
        if matches!(changed_field, Some("cap" | "below-cap"))
            && actor.state() == State::Ready
            && !refused
        {
            let cap = castle_wall_daemon::business_profile::drain_store::D_UNDRAINED_MAX as u64;
            actor.pending_count_for_test(
                PendingCount::checked(if changed_field == Some("cap") {
                    cap
                } else {
                    cap - 1
                })
                .unwrap(),
            );
            refused = true;
            if changed_field == Some("cap") {
                assert_eq!(
                    actor.begin(canonical(&body), None, expires, 0),
                    Err(Refusal::Capacity),
                    "typed W pending count refuses row 513 before reserve or SIGN"
                );
                assert_eq!(actor.ownership_for_test(), (false, false, false));
                assert_eq!(count, 0);
                return Err(Refusal::Capacity);
            }
        }
        if cut && !refused && actor.state() == State::Ready {
            let mut wrong = vectors["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] == "listener-accept")
                .unwrap()["records"][0]["body"]
                .clone();
            wrong["policy_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
            assert_eq!(
                actor.begin(canonical(&wrong), Some(castle_wall_daemon::business_profile::effect_permit::EffectIntent::OpenAdmission { flow: wrong["payload"]["context"]["flow"].clone(), payload: wrong["payload"].clone() }), expires, 0),
                Err(Refusal::Authority)
            );
            assert_eq!(
                actor.pending_cut().map(|(_, n)| n),
                Some(1),
                "refusal retains one checked cut obligation"
            );
            refused = true;
            if changed_field == Some("cut-expired") {
                clock.store(
                    now + (castle_wall_daemon::business_profile::append_budget::APPEND_BUDGET_MS
                        + 1)
                        * writer_peer::NS_PER_MS,
                    Ordering::SeqCst,
                );
                assert_eq!(
                    actor.begin(canonical(&body), None, expires, 0),
                    Err(Refusal::Deadline),
                    "cut cannot reset the original append end"
                );
                assert_eq!(
                    actor.pending_cut().map(|(_, n)| n),
                    Some(1),
                    "failed cut retains the original count"
                );
                assert_eq!(actor.ownership_for_test(), (false, false, false));
                assert_eq!(count, 0);
                return Err(Refusal::Deadline);
            }
        } else if cut && refused && actor.state() == State::Ready {
            assert_eq!(
                actor.pending_cut(),
                None,
                "committed cut discharges only after durable confirmation"
            );
            assert_eq!(
                count, 0,
                "committed control never permits the refused effect"
            );
        }
        if second
            && !second_started
            && actor.state() == State::Ready
            && actor.pending_delivery().is_some()
        {
            assert!(
                !actor.ownership_for_test().1,
                "absent TS owns no store slot"
            );
            let state = lifecycle.lock().unwrap().clone();
            let checkpoint = state["provisional"]["state"].clone();
            let identity = state["provisional"]["identity"].clone();
            *lifecycle.lock().unwrap() = join_lifecycle::step(
                &state,
                &json!({"type":"Committed","identity":identity,"checkpoint":checkpoint}),
            )
            .unwrap();
            let mut next = case["records"][1]["body"].clone();
            next["kid"] = body["kid"].clone();
            next["boot_id"] = body["boot_id"].clone();
            next["captured_at_boottime_ns"] = body["captured_at_boottime_ns"].clone();
            next["payload"]["context"]["flow"]["boot_id"] = body["boot_id"].clone();
            next["payload"]["link"]["agent_flow"]["boot_id"] = body["boot_id"].clone();
            next["prior_commitment"] = identity["commitment"].clone();
            actor.begin(canonical(&next), None, expires, 1)?;
            second_started = true;
        }
        if marker && entered.load(Ordering::SeqCst) && !release.0.load(Ordering::SeqCst) {
            marker_polls += 1;
            if marker_polls == 40 {
                if let Some(field) = changed_field {
                    let mut evidence = LocalEvidence {
                        h_expiry_ns: expires,
                        policy_digest: body["policy_digest"].as_str().unwrap().into(),
                        runtime_digest: body["runtime_digest"].as_str().unwrap().into(),
                        config_digest: body["config_digest"].as_str().unwrap().into(),
                    };
                    let changed = format!("sha256:{}", "c".repeat(64));
                    match field {
                        // Flipping the low nanosecond bit preserves the rounded millisecond budget input.
                        "h" => evidence.h_expiry_ns ^= 1,
                        "policy" => evidence.policy_digest = changed,
                        "runtime" => evidence.runtime_digest = changed,
                        "config" => evidence.config_digest = changed,
                        _ => unreachable!(),
                    }
                    actor.evidence_for_test(Box::new(Evidence(evidence)));
                }
                release.0.store(true, Ordering::SeqCst);
            }
            assert_eq!(count, 0, "held marker readback has zero sink calls");
            assert!(
                actor.ownership_for_test().1,
                "marker publication retains the store owner"
            );
        }
        if hold_store && entered.load(Ordering::SeqCst) {
            for _ in 0..40 {
                actor.disconnect();
                let monitored = actor.poll().is_ok();
                let admission = actor.begin(canonical(&body), None, expires, 0);
                waves.push((actor.ownership_for_test(), admission, monitored, count));
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                d.events()
                    .iter()
                    .filter(|e| e["event"] == "StoreEntered" && e["publication"] == "record")
                    .count(),
                original_d_records,
                "freeze_body checkpoint readback precedes every D RESERVE store entry"
            );
            release.0.store(true, Ordering::SeqCst);
            return Err(Refusal::Held);
        }
        if actor.state() == State::Commit && changed_field != Some("commit-hold") {
            assert_eq!(
                count,
                usize::from(second_started),
                "WAL durable alone grants no effect"
            );
        }
        Ok(())
    };
    let outcome = if process {
        use std::process::{Command, Stdio};
        // Child libtest executes a private capability-free copy outside the build tree, with stdout discarded.
        let binary = root.path().join("private-test");
        fs::copy(std::env::current_exe().unwrap(), &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o700)).unwrap();
        for attempt in 0..2 {
            if attempt == 1 {
                for child in &mut threads.children {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                threads.children.clear();
                for name in [
                    "writer",
                    "signer",
                    "writer-ready",
                    "process-start",
                    "hold-first-ts-fact",
                    "fact.held",
                ] {
                    if root.path().join(name).exists() {
                        fs::remove_file(root.path().join(name)).unwrap();
                    }
                }
                let checkpoint: Value =
                    serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap())
                        .unwrap();
                if !checkpoint["payload"]["active"].is_null() {
                    invariant_zero(&fresh_s_anchor(&mut d), &wal);
                }
                if continuation_startup {
                    private(
                        &root.path().join("settlement.json"),
                        &canonical(&json!(if changed_field.unwrap().ends_with("drained") {
                            "DrainedOnly"
                        } else {
                            "Authority"
                        })),
                    );
                }
                let mut next_join: Value = serde_json::from_slice(
                    &URL_SAFE_NO_PAD
                        .decode(checkpoint["payload"]["join_state"].as_str().unwrap())
                        .unwrap(),
                )
                .unwrap();
                let mut anchor = checkpoint["payload"]["anchor"].clone();
                if process_phase >= 5 {
                    let model: Value = serde_json::from_slice(
                        &fs::read(root.path().join("join-model.json")).unwrap(),
                    )
                    .unwrap();
                    next_join = model["provisional"]["state"].clone();
                    anchor["committed_sequence"] =
                        model["provisional"]["identity"]["sequence"].clone();
                    anchor["committed_digest"] =
                        model["provisional"]["identity"]["commitment"].clone();
                    anchor["reserved_sequence"] = anchor["committed_sequence"].clone();
                    anchor["reserved_body_digest"] = Value::Null;
                }
                anchor["drained_sequence"] = anchor["committed_sequence"].clone();
                anchor["drained_digest"] = anchor["committed_digest"].clone();
                let mut peers: Value =
                    serde_json::from_slice(&fs::read(root.path().join("peers.json")).unwrap())
                        .unwrap();
                peers["join"] = next_join.clone();
                peers["status"]["anchor_digest"] =
                    json!(activation_anchor::anchor_digest(&anchor).unwrap());
                private(&root.path().join("peers.json"), &canonical(&peers));
                let mut next = case["records"][1]["body"].clone();
                for field in ["kid", "boot_id", "captured_at_boottime_ns"] {
                    next[field] = body[field].clone();
                }
                next["payload"]["context"]["flow"]["boot_id"] = body["boot_id"].clone();
                next["payload"]["link"]["agent_flow"]["boot_id"] = body["boot_id"].clone();
                next["prior_commitment"] = next_join["anchor"]["commitment"].clone();
                let mut config: Value =
                    serde_json::from_slice(&fs::read(root.path().join("compose.json")).unwrap())
                        .unwrap();
                config["body"] = next;
                config["effect"] = Value::Null;
                config["flows"] = json!(1);
                private(&root.path().join("compose.json"), &canonical(&config));
                for (mode, ready) in [
                    ("composed-signer", "signer"),
                    ("composed-writer", "writer-ready"),
                ] {
                    let stderr =
                        fs::File::create(root.path().join(format!("restart-{mode}-stderr")))
                            .unwrap();
                    threads.children.push(
                        Command::new(&helper)
                            .args([mode, root.path().to_str().unwrap(), "composed"])
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::from(stderr))
                            .spawn()
                            .unwrap(),
                    );
                    let end = std::time::Instant::now() + Duration::from_secs(10);
                    while !root.path().join(ready).exists() {
                        assert!(std::time::Instant::now() < end);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            }
            let diagnostic = root.path().join(format!("process-{attempt}-stderr"));
            let mut command = Command::new(&binary);
            command
                .args([
                    "signed_append::process_restart_child",
                    "--exact",
                    "--test-threads=1",
                ])
                .arg("--nocapture")
                .env("APPEND_PROCESS_PHASE", process_phase.to_string())
                .env("APPEND_PROCESS_ROOT", root.path())
                .env("APPEND_PROCESS_SELECTOR", selector.path())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::from(fs::File::create(&diagnostic).unwrap()));
            if let Some(order) = process_business {
                command.env("APPEND_PROCESS_BUSINESS", order);
            }
            if attempt == 0 {
                command.env("APPEND_PROCESS_PAUSE", "1");
            } else if lost_local {
                command.env("APPEND_PROCESS_EXPECT_LOST", "1");
            } else if process_phase < 5 || continuation_startup {
                command.env("APPEND_PROCESS_EXPECT_HELD", "1");
            }
            let child = command.spawn().unwrap();
            wall_unit.lock().unwrap().pid = child.id();
            d.bus.unit.lock().unwrap().pid = child.id();
            threads.children.push(child);
            private(&root.path().join("process-start"), b"start");
            let end = std::time::Instant::now() + Duration::from_secs(15);
            loop {
                let child = threads.children.last_mut().unwrap();
                if attempt == 0 && root.path().join("process-reached").exists() {
                    assert_eq!(fs::read(root.path().join("process-permits")).unwrap(), b"0");
                    child.kill().unwrap();
                    child.wait().unwrap();
                    let row: Value = serde_json::from_slice(
                        &fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                    )
                    .unwrap();
                    assert_eq!(
                        row["payload"]["effect_status"],
                        if process_phase == 8 {
                            json!("unknown")
                        } else {
                            Value::Null
                        },
                        "process crash retains exactly the marker state reached"
                    );
                    if changed_field == Some("process-old-capability") {
                        use castle_wall_daemon::business_profile::{
                            business_wal::{test_support, BusinessSequence, BusinessWal},
                            effect_permit::{EffectIntent, EffectPermit},
                        };
                        struct Plain;
                        impl WalHooks for Plain {
                            fn before(&mut self, _: WalStep) -> WalResult<()> {
                                Ok(())
                            }
                        }
                        let mut reopened =
                            BusinessWal::open_isolated(&wal, uid, Box::new(Plain), None).unwrap();
                        let checkpoint: Value =
                            serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap())
                                .unwrap();
                        assert_eq!(checkpoint["payload"]["anchor"]["committed_sequence"], 1);
                        assert!(checkpoint["payload"]["active"].is_null());
                        assert!(row["payload"]["effect_status"].is_null());
                        let marker = test_support::mark_effect(&mut reopened, BusinessSequence(1));
                        let envelope = URL_SAFE_NO_PAD
                            .decode(row["payload"]["envelope"].as_str().unwrap())
                            .unwrap();
                        let intent = EffectIntent::OpenAdmission {
                            flow: body["payload"]["context"]["flow"].clone(),
                            payload: body["payload"].clone(),
                        };
                        let permit = marker.ok().and_then(|marker| {
                            EffectPermit::from_marker_for_test(
                                marker,
                                &intent,
                                &envelope,
                                "e".repeat(32),
                                now,
                                expires,
                            )
                        });
                        assert!(
                            permit.is_none(),
                            "reopened graph row cannot redeliver old effect capability"
                        );
                    }
                    if let Some(order) = process_business {
                        assert_eq!(
                            row["payload"]["d_fact"].is_object(),
                            order != "ts",
                            "restart retains exactly the first D fact"
                        );
                        assert_eq!(
                            row["payload"]["ts_fact"].is_object(),
                            order != "d",
                            "restart retains exactly the first TS fact"
                        );
                        if matches!(order, "held" | "lag") {
                            let cp: Value = serde_json::from_slice(
                                &fs::read(wal.join("checkpoint.json")).unwrap(),
                            )
                            .unwrap();
                            assert!(
                                cp["payload"]["delivered"].is_null(),
                                "killed TS fact readback has not advanced n's cursor"
                            );
                        }
                        private(&root.path().join("first-fact.snapshot"), &canonical(&row));
                    }
                    if continuation_startup {
                        continuation_snapshot =
                            Some(fs::read(wal.join("row-00000000000000000001.json")).unwrap());
                    }
                    if lost_local {
                        fs::remove_file(wal.join("row-00000000000000000001.json")).unwrap();
                    }
                    break;
                }
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(
                        attempt == 1 && status.success(),
                        "process restart graph child {attempt}: {status:?}; {:?}",
                        fs::read_to_string(&diagnostic)
                    );
                    assert_eq!(
                        fs::read(root.path().join("process-result")).unwrap(),
                        if process_phase < 5 || lost_local || continuation_startup {
                            b"held".as_slice()
                        } else {
                            b"0".as_slice()
                        },
                        "process restart never redelivers the old effect"
                    );
                    break;
                }
                assert!(
                    std::time::Instant::now() < end,
                    "bounded process restart graph: {:?}",
                    fs::read_to_string(&diagnostic)
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        if process_phase >= 5 && !lost_local && !continuation_startup {
            let next: Value = serde_json::from_slice(
                &fs::read(wal.join("row-00000000000000000002.json")).unwrap(),
            )
            .unwrap();
            assert!(
                next["payload"]["d_fact"].is_object(),
                "clean restarted W signs and commits the fresh next append"
            );
        } else {
            assert!(
                !wal.join("row-00000000000000000002.json").exists(),
                "missing E never admits a replacement after process restart"
            );
        }
        Ok(0)
    } else if entry {
        use std::process::{Command, Stdio};
        private(
            &selector.path().join("compose.json"),
            &fs::read(root.path().join("compose.json")).unwrap(),
        );
        let mut closed = Command::new(drain_run::native("castle-wall-daemon"))
            .args(["--test-profile-root", selector.path().to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        wall_unit.lock().unwrap().pid = closed.id();
        d.bus.unit.lock().unwrap().pid = closed.id();
        let end = std::time::Instant::now() + Duration::from_secs(15);
        let closed_status = loop {
            if let Some(status) = closed.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= end {
                let _ = closed.kill();
                let _ = closed.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(
            closed_status.and_then(|s| s.code()),
            Some(78),
            "business selection without the value flag never enters the prepared graph"
        );
        assert!(lifecycle.lock().unwrap()["provisional"].is_null());
        let diagnostic = root.path().join("wall-stderr");
        let stderr = fs::File::create(&diagnostic).unwrap();
        let mut child = Command::new(drain_run::native("castle-wall-daemon"))
            .args([
                "--test-profile-root",
                selector.path().to_str().unwrap(),
                "--test-business-compose",
                root.path().to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        wall_unit.lock().unwrap().pid = child.id();
        d.bus.unit.lock().unwrap().pid = child.id();
        let end = std::time::Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if std::time::Instant::now() >= end {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(
            status.is_some_and(|s| s.success()),
            "explicit main entry reaches COMMIT and ORIGINAL: {status:?}; D stages {:?}",
            (d.stages(), fs::read_to_string(&diagnostic).unwrap())
        );
        Ok(0)
    } else {
        compose_for_test_driven(
            selection,
            root.path(),
            {
                let clock = clock.clone();
                Arc::new(move || Ok(clock.load(Ordering::SeqCst)))
            },
            Box::new(HoldBody {
                release_root: business.then(|| root.path().to_path_buf()),
                journal: match changed_field {
                    Some("journal-before") => Some(WalStep::JournalPrepare),
                    Some("journal-after") => Some(WalStep::JournalDurable),
                    _ => None,
                },
                journal_calls: 0,
                hold: hold_store || marker,
                marker,
                syncs: 0,
                entered: entered.clone(),
                released,
            }),
            &mut drive,
        )
    };
    if changed_field == Some("delivery-window") {
        assert_eq!(outcome, Ok(1));
        assert_eq!(
            delivery_windows, [true; 3],
            "all delivery admission windows execute"
        );
        return;
    }
    if matches!(
        changed_field,
        Some("business-fact-failure" | "business-submit-failure")
    ) {
        assert_eq!(outcome, Err(Refusal::Io));
        assert!(
            business_delivered && wal.join("row-00000000000000000001.json").exists(),
            "failed local fact retains charged row"
        );
        let cp: Value =
            serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap()).unwrap();
        assert!(
            cp["payload"]["delivered"].is_null() && cp["payload"]["released"].is_null(),
            "failed fact cannot advance either cursor"
        );
        return;
    }
    if process_business == Some("lag") {
        assert_eq!(outcome, Ok(0), "lagging cursor permits append settlement");
        let cp: Value =
            serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap()).unwrap();
        assert_eq!(cp["payload"]["anchor"]["committed_sequence"], 2);
        assert_eq!(cp["payload"]["originals"]["sequence"], 2);
        assert!(
            cp["payload"]["delivered"].is_null() && cp["payload"]["released"].is_null(),
            "lagging cursor forbids deletion"
        );
        assert!(
            wal.join("row-00000000000000000001.json").exists()
                && wal.join("row-00000000000000000002.json").exists()
        );
        return;
    }
    if process_business.is_some() {
        assert_eq!(outcome, Ok(0));
        let first: Value =
            serde_json::from_slice(&fs::read(root.path().join("first-fact.snapshot")).unwrap())
                .unwrap();
        let saved: Value = serde_json::from_slice(
            &fs::read(root.path().join("consumer/business.accepted.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            saved["envelope"], first["payload"]["envelope"],
            "restart replays the exact original n without another history advance"
        );
        assert!(
            !wal.join("row-00000000000000000001.json").exists(),
            "restarted actor compacts exact first row"
        );
        let cp: Value =
            serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap()).unwrap();
        assert_eq!(
            cp["payload"]["released"]["sequence"], 1,
            "restart keeps durable release sequence"
        );
        assert_eq!(
            cp["payload"]["anchor"]["committed_sequence"], 2,
            "restart appends n+1 without sequence reset"
        );
        return;
    }
    if let Some(fact) = missing_fact {
        assert!(
            fact_removed,
            "exactly one fact was removed after cursor readback"
        );
        assert_eq!(outcome, Ok(1));
        let row: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
                .unwrap();
        assert!(
            row["payload"][format!("{fact}_fact")].is_null(),
            "missing fact never reconstructed from a cursor"
        );
        assert!(
            row["payload"]["envelope"].is_string(),
            "one missing fact retains charged exact E"
        );
        assert!(
            !root.path().join("release.observed").exists(),
            "one missing fact never reaches deletion"
        );
        return;
    }
    if business {
        assert!(
            business_delivered,
            "real native adapter reached the live TS loop"
        );
        assert_eq!(
            outcome,
            Ok(if changed_field == Some("business-resume-fact") {
                0
            } else {
                1
            })
        );
        if second {
            assert!(
                wal.join("row-00000000000000000001.json").exists(),
                "delivery advance does not replace a missing D release fact"
            );
            assert!(
                root.path().join("next.served").exists(),
                "real Business socket serves n+1 after local readback"
            );
            assert!(
                !root.path().join("release.observed").exists(),
                "cursor advance alone cannot delete E"
            );
            return;
        }
        assert!(
            !wal.join("row-00000000000000000001.json").exists(),
            "live compaction deletes only the released row"
        );
        let checkpoint: Value =
            serde_json::from_slice(&fs::read(wal.join("checkpoint.json")).unwrap()).unwrap();
        assert_eq!(
            checkpoint["payload"]["released"]["sequence"], 1,
            "released checkpoint survives compaction"
        );
        assert_eq!(
            checkpoint["payload"]["anchor"]["committed_sequence"],
            if second { 2 } else { 1 },
            "compaction never resets sequence"
        );
        assert!(
            root.path().join("release.observed").exists(),
            "deletion traverses the exact fact and durable checkpoint observer"
        );
        return;
    }
    if matches!(observation, Some((_, "CasIdentity" | "SendSecondEnvelope"))) {
        assert!(
            root.path().join("observation.observed").exists(),
            "identity probe reached the real owned graph boundary"
        );
        let extension = if observation.unwrap().1 == "CasIdentity" {
            "candidate"
        } else {
            "commit"
        };
        assert!(
            !root
                .path()
                .join(format!("observation.{extension}"))
                .exists(),
            "changed identity stops before earliest W send"
        );
        assert_eq!(outcome, Err(Refusal::Conflict));
        assert_eq!(observed_permits, 0);
        assert_eq!(s_admissions.load(Ordering::SeqCst), 1);
        return;
    }
    if continuation || continuation_startup {
        let log_path = root.path().join(if continuation_startup {
            "settlement.sends"
        } else {
            "continuation.sends"
        });
        let sends: Vec<Value> = fs::read_to_string(log_path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(continuation_startup || continuation_started);
        if resumed || continuation_startup {
            assert_eq!(
                sends.first().unwrap()["op"],
                "READ",
                "reconnect reads before any COMMIT send"
            );
        }
        if continuation_hold {
            assert!(
                !sends.iter().any(|s| s["op"] == "COMMIT"),
                "changed predecessor sends no COMMIT under any id"
            );
            assert_eq!(observed_permits, 0);
            if continuation_startup {
                let report = fs::read_to_string(root.path().join("process-1-stderr")).unwrap();
                assert!(report.contains("COMMIT held; effects disabled"));
                assert!(report.contains(continuation_reason));
                assert!(report.contains("proof_stage=startup READ"));
                assert_eq!(
                    fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                    *continuation_snapshot.as_ref().unwrap(),
                    "restart hold retains exact row, marker, requests and charges"
                );
                assert_eq!(
                    fs::read(root.path().join("sign.observed")).unwrap().len(),
                    1,
                    "restart hold never re-signs"
                );
                let row: Value =
                    serde_json::from_slice(continuation_snapshot.as_ref().unwrap()).unwrap();
                for field in ["reserve", "commit"] {
                    let bytes = URL_SAFE_NO_PAD
                        .decode(row["payload"][field].as_str().unwrap())
                        .unwrap();
                    assert!(report.contains(&format!(
                        "{field}_sha256={}",
                        hex::encode(Sha256::digest(bytes))
                    )));
                }
                assert!(report.contains("sequence=1;"));
            } else {
                assert_eq!(outcome, Err(Refusal::Held));
                let row: Value =
                    serde_json::from_slice(continuation_snapshot.as_ref().unwrap()).unwrap();
                let payload = &row["payload"];
                let reserve = URL_SAFE_NO_PAD
                    .decode(payload["reserve"].as_str().unwrap())
                    .unwrap();
                let commit = URL_SAFE_NO_PAD
                    .decode(payload["commit"].as_str().unwrap())
                    .unwrap();
                assert_eq!(continuation_report.unwrap(), format!("COMMIT held; effects disabled; {}; sequence=1; reserve_sha256={}; commit_sha256={}; proof_stage={}", continuation_reason, hex::encode(Sha256::digest(reserve)), hex::encode(Sha256::digest(commit)), if resumed { "resume READ" } else { "live READ" }));
                assert_eq!(
                    s_admissions.load(Ordering::SeqCst),
                    1,
                    "held predecessor never re-signs"
                );
                assert_eq!(
                    fs::read(root.path().join("sign.observed")).unwrap().len(),
                    1
                );
            }
        } else {
            assert_eq!(outcome, Ok(0), "reconnect settles without a permit");
            assert!(
                sends.iter().any(|s| s["op"] == "ORIGINAL"),
                "post-confirm continuation reaches ORIGINAL without restart"
            );
            if matches!(
                changed_field,
                Some("continuation-resume-expected" | "continuation-admit-zero")
            ) {
                let row: Value =
                    serde_json::from_slice(continuation_snapshot.as_ref().unwrap()).unwrap();
                let commit = URL_SAFE_NO_PAD
                    .decode(row["payload"]["commit"].as_str().unwrap())
                    .unwrap();
                assert_eq!(
                    sends.iter().find(|s| s["op"] == "COMMIT").unwrap()["sha256"],
                    hex::encode(Sha256::digest(commit)),
                    "unchanged predecessor sends exact C0 bytes and id"
                );
            } else if !continuation_startup {
                assert!(!sends.iter().any(|s| s["op"] == "COMMIT"));
            }
        }
        if continuation {
            assert!(reserve_observations > 0);
        }
        return;
    }
    if changed_field == Some("commit-expired") {
        assert_eq!(commit_polls, 40);
        assert_eq!(
            observed_permits, 0,
            "expired original window never revives a permit"
        );
        assert_eq!(s_admissions.load(Ordering::SeqCst), 1);
        let row: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
                .unwrap();
        assert!(row["payload"]["effect_status"].is_null());
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(row["payload"]["commit"].as_str().unwrap())
                .unwrap(),
            commit_bytes.unwrap()
        );
        // An expired in-flight reply can leave D uncertain; only a certain next anchor may finish settlement.
        if outcome == Ok(0) {
            assert!(row["payload"]["d_fact"].is_object());
        } else {
            assert_eq!(outcome, Err(Refusal::Held));
            assert!(expired_hold
                .unwrap()
                .contains("COMMIT held; effects disabled; unresolved settlement, owner 2g;"));
        }
        return;
    }
    if changed_field == Some("commit-uncertain") {
        assert_eq!(
            outcome,
            Err(Refusal::Held),
            "uncertain reconnect READ holds without a blind COMMIT retry"
        );
        assert!(resumed && commit_fault && commit_bytes.is_some());
        assert_eq!(observed_permits, 0);
        assert_eq!(s_admissions.load(Ordering::SeqCst), 1);
        let row: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
                .unwrap();
        assert!(row["payload"]["commit"].is_string());
        assert!(row["payload"]["effect_status"].is_null());
        return;
    }
    if changed_field == Some("oversized") {
        assert!(
            root.path().join("sign.observed").exists(),
            "malformed oversized reply passed P's own verification before injection"
        );
        assert!(outcome.is_err(), "W rejects malformed oversized VERIFIED");
        assert_eq!(observed_permits, 0);
        assert_eq!(s_admissions.load(Ordering::SeqCst), 1);
        let row: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
                .unwrap();
        assert!(
            row["payload"]["envelope"].is_null(),
            "oversized reply cannot reach WAL envelope publication"
        );
        return;
    }
    if delayed {
        assert_eq!(
            reply_waves, 40,
            "forty same-owner delayed reply waves completed"
        );
        assert_eq!(
            s_admissions.load(Ordering::SeqCst),
            1,
            "no repeated P-to-S SIGN after delayed reply"
        );
        assert_eq!(
            fs::read(root.path().join("sign.observed")).unwrap().len(),
            1,
            "no repeated W-to-P SIGN after delayed reply"
        );
        if changed_field == Some("reply-delayed") {
            assert_eq!(outcome, Ok(1), "live delayed VERIFIED completes once");
        } else {
            assert!(outcome.is_err());
            assert_eq!(observed_permits, 0, "late or LOCKING reply has no effect");
            if locking_reply {
                assert!(
                    locking_seen.load(Ordering::SeqCst),
                    "LOCKING traversed real P heartbeat"
                );
            }
            let row: Value = serde_json::from_slice(
                &fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
            )
            .unwrap();
            assert!(
                row["payload"]["envelope"].is_null(),
                "missing E remains held after may-have-sent"
            );
        }
        return;
    }
    if let Some((
        _,
        field @ ("AppendIdentity" | "AppendReplay" | "CommitIdentity" | "CommitReplay"),
    )) = observation
    {
        assert!(
            root.path().join("observation.observed").exists(),
            "decoded identity probe reached its owned WAL operation"
        );
        if field.ends_with("Identity") {
            assert_eq!(
                outcome,
                Err(Refusal::Conflict),
                "first exact envelope identity refuses decoded same-body replacement"
            );
            assert_eq!(observed_permits, 0);
        } else {
            assert_eq!(
                outcome,
                Ok(1),
                "exact envelope replay preserves the live continuation"
            );
        }
        assert_eq!(s_admissions.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read(root.path().join("sign.observed")).unwrap().len(),
            1
        );
        return;
    }
    if observation == Some(("Deliver", "Trace")) {
        let envelope = fs::read(root.path().join("observation.append")).unwrap();
        assert_eq!(
            writer_protocol::decode_envelope(&envelope).unwrap()["body"],
            body
        );
        use castle_wall_daemon::business_profile::drain_protocol as protocol;
        let commit = fs::read(root.path().join("observation.commit")).unwrap();
        let frame = protocol::decode(&commit, protocol::Direction::ToDrain)
            .expect("COMMIT send framing preserves both exact lengths");
        let protocol::Operation::Anchor {
            message,
            envelope: sent,
        } = frame.operation
        else {
            panic!("COMMIT send operation");
        };
        assert_eq!(message["op"], "COMMIT");
        assert_eq!(sent, envelope, "COMMIT send carries exact E");
        let original = fs::read(root.path().join("observation.original")).unwrap();
        let frame = protocol::decode(&original, protocol::Direction::ToDrain).unwrap();
        let protocol::Operation::Original { envelope: sent, .. } = frame.operation else {
            panic!("ORIGINAL send operation");
        };
        assert_eq!(sent, envelope, "ORIGINAL send carries exact E");
        assert_eq!(
            fs::read(root.path().join("observation.permit")).unwrap(),
            envelope,
            "permit consumes first exact E"
        );
        assert_eq!(outcome, Ok(1));
        return;
    }
    if let Some((point, field)) = observation {
        if field == "ReserveRefused" {
            assert!(
                refused_reserve_gap,
                "reserve refusal gap was observed before certain READ continuation"
            );
        }
        assert!(
            root.path().join("observation.observed").exists(),
            "selected independent observation was reached: {point}/{field}"
        );
        assert_eq!(
            observed_permits,
            usize::from(field == "ReserveRefused"),
            "isolated observation forbids permit: {point}/{field}"
        );
        if let Ok(count) = outcome {
            assert_eq!(
                count,
                usize::from(field == "ReserveRefused"),
                "isolated observation forbids completed permit: {point}/{field}"
            );
        }
        let expected = u64::from(
            field == "ReserveRefused" || !matches!(point, "Reserve" | "SignMarker" | "Sign"),
        );
        let p_admissions = fs::read(root.path().join("sign.observed"))
            .unwrap_or_default()
            .len() as u64;
        assert_eq!(
            p_admissions, expected,
            "independent W-to-P SIGN admission count: {point}/{field}"
        );
        assert_eq!(
            s_admissions.load(Ordering::SeqCst),
            expected,
            "independent P-to-S SIGN admission count: {point}/{field}"
        );
        return;
    }
    if !entry
        && !body_substitution
        && !matches!(
            changed_field,
            Some("journal-before" | "journal-after" | "dependency" | "cap" | "cut-expired")
        )
        && !hold_store
    {
        let expected = if second { 2 } else { 1 };
        assert_eq!(
            fs::read(root.path().join("sign.observed"))
                .unwrap_or_default()
                .len(),
            expected,
            "W-to-P admitted SIGN count"
        );
        assert_eq!(
            s_admissions.load(Ordering::SeqCst),
            expected as u64,
            "P-to-S admitted SIGN count"
        );
    }
    if changed_field == Some("dependency") {
        assert_eq!(
            outcome,
            Err(Refusal::Shape),
            "entry refuses missing independent H evidence instead of deriving it from the signer"
        );
        assert!(
            fs::read_dir(&wal).unwrap().next().is_none(),
            "missing evidence cannot open a store"
        );
        assert!(lifecycle.lock().unwrap()["provisional"].is_null());
        return;
    }
    if body_substitution {
        if changed_field == Some("body-client") {
            assert!(
                root.path().join("verified.observed").exists(),
                "substitution ran after P's passing exact-body verification"
            );
            if let Some(bytes) = after_client.lock().unwrap().as_ref() {
                assert_eq!(
                    bytes, &alternate_envelope,
                    "client downstream observer sees exact substituted E"
                );
            }
            assert!(
                after_client.lock().unwrap().is_none(),
                "client equality prevents the downstream append attempt for substituted body"
            );
        } else {
            let received = after_client.lock().unwrap();
            assert_eq!(
                writer_protocol::decode_envelope(received.as_ref().unwrap()).unwrap()["body"],
                body,
                "client independently passed the original body"
            );
            if let Some(bytes) = after_actor.lock().unwrap().as_ref() {
                assert_eq!(
                    bytes, &alternate_envelope,
                    "actor downstream observer sees exact substituted E"
                );
            }
            assert!(
                after_actor.lock().unwrap().is_none(),
                "actor equality prevents the downstream append attempt for substituted body"
            );
        }
        assert!(outcome.is_err());
        assert!(lifecycle.lock().unwrap()["provisional"]["signed"] == true);
        let row: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
                .unwrap();
        assert!(
            row["payload"]["envelope"].is_null(),
            "WAL never persisted the substituted body"
        );
        return;
    }
    if matches!(changed_field, Some("journal-before" | "journal-after")) {
        assert_eq!(outcome, Err(Refusal::Io));
        assert!(
            !wal.join("publication.stage").exists(),
            "journal proof precedes guarded payload staging"
        );
        assert!(!wal.join("row-00000000000000000001.json").exists());
        assert_eq!(
            wal.join("publication.journal").exists(),
            changed_field == Some("journal-after")
        );
        assert!(
            lifecycle.lock().unwrap()["provisional"].is_null(),
            "journal fault cannot reach SIGN"
        );
        return;
    }
    if changed_field == Some("cap") {
        assert_eq!(outcome, Err(Refusal::Capacity));
        assert!(refused);
        assert!(
            !wal.join("row-00000000000000000001.json").exists(),
            "cap refusal publishes no row"
        );
        assert!(
            lifecycle.lock().unwrap()["provisional"].is_null(),
            "cap refusal reaches no signer"
        );
        return;
    }
    if changed_field == Some("cut-expired") {
        assert_eq!(outcome, Err(Refusal::Deadline));
        assert!(refused);
        assert!(
            !wal.join("row-00000000000000000001.json").exists(),
            "expired cut publishes no row"
        );
        return;
    }
    if hold_store {
        assert_eq!(outcome, Err(Refusal::Held));
        assert_eq!(waves.len(), 40);
        for (wave, (ownership, admission, monitored, count)) in waves.into_iter().enumerate() {
            assert!(
                ownership.0 && ownership.1,
                "wave {wave} retains actor and disk ownership"
            );
            assert_eq!(
                admission,
                Err(Refusal::Held),
                "wave {wave} admits no second append"
            );
            assert!(
                monitored,
                "wave {wave} monitors pinned peers without blocking on disk"
            );
            assert_eq!(count, 0);
        }
        assert!(
            lifecycle.lock().unwrap()["provisional"].is_null(),
            "held freeze_body never reaches SIGN"
        );
        return;
    }
    assert!(
        outcome.is_ok(),
        "real composed append reaches settlement: {outcome:?}; D stages {:?}",
        d.stages()
    );
    if matches!(changed_field, Some("commit-hold" | "commit-expired")) {
        assert_eq!(
            commit_polls, 40,
            "matched COMMIT StoreEntered and pre-readback hold were exercised"
        );
    }
    if matches!(changed_field, Some("commit-refused" | "commit-uncertain")) {
        assert!(commit_fault && commit_bytes.is_some());
        assert!(
            resumed,
            "faulted COMMIT settled through retained-identity reconnect"
        );
    }
    if marker {
        assert_eq!(
            marker_polls, 40,
            "marker readback was held at the live graph boundary"
        );
    }
    if !entry {
        assert_eq!(
            outcome.unwrap(),
            usize::from(
                changed_field.is_none()
                    || matches!(changed_field, Some("below-cap" | "commit-hold"))
                    || (matches!(
                        changed_field,
                        Some("commit-uncertain" | "commit-refused" | "commit-expired")
                    ) && !resumed)
            ),
            "only unchanged independently observed digests permit delivery"
        );
    }
    if process {
        return;
    }
    let row: Value =
        serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
            .unwrap();
    assert_eq!(
        row["payload"]["effect_status"],
        if cut || resumed {
            Value::Null
        } else {
            json!("unknown")
        }
    );
    assert!(row["payload"]["d_fact"].is_object());
    assert!(
        row["payload"]["ts_fact"].is_null(),
        "TS absence retains E without holding the WAL slot"
    );
    if second {
        assert!(
            second_started,
            "same W admits a second append with first TS token outstanding"
        );
        let next: Value =
            serde_json::from_slice(&fs::read(wal.join("row-00000000000000000002.json")).unwrap())
                .unwrap();
        assert!(
            next["payload"]["d_fact"].is_object(),
            "second ORIGINAL fact reaches disk while TS is absent"
        );
        assert!(next["payload"]["ts_fact"].is_null());
        assert!(next["payload"]["effect_status"].is_null());
        assert_eq!(
            lifecycle.lock().unwrap()["committed"]["anchor"]["sequence"],
            1
        );
        return;
    }
    if process {
        return;
    }
    if entry {
        *lifecycle.lock().unwrap() =
            serde_json::from_slice(&fs::read(root.path().join("join-model.json")).unwrap())
                .unwrap();
    }
    let state = lifecycle.lock().unwrap();
    assert!(state["committed"]["anchor"]["sequence"] == 0);
    assert_eq!(state["provisional"]["signed"], true);
    let checkpoint = state["provisional"]["state"].clone();
    let identity = state["provisional"]["identity"].clone();
    let lost = join_lifecycle::step(&state, &json!({"type":"LostOrUnmatched"})).unwrap();
    assert_eq!(
        lost,
        json!({"committed":join,"provisional":null,"tombstone":identity,"needs_checkpoint":true}),
        "lost reply retains tombstone and drops provisional view"
    );
    let next = join_lifecycle::step(&lost, &json!({"type":"NextGrant"})).unwrap();
    assert_eq!(next, lost, "new grant preserves the unresolved tombstone");
    let restored =
        join_lifecycle::step(&next, &json!({"type":"Checkpoint","checkpoint":checkpoint})).unwrap();
    assert_eq!(
        restored,
        json!({"committed":checkpoint,"provisional":null,"tombstone":null,"needs_checkpoint":false})
    );
    let committed = join_lifecycle::step(
        &state,
        &json!({"type":"Committed","identity":identity,"checkpoint":checkpoint}),
    )
    .unwrap();
    assert_eq!(
        committed, restored,
        "only matched commit advances the fixture's committed join state"
    );
}
fn select_business(
    roots: &castle_wall_daemon::config::SelectorRoots,
    root: &std::path::Path,
) -> castle_wall_daemon::config::BusinessSelection {
    fs::create_dir(root.join("etc/sanctuary")).unwrap();
    private(
        &root.join("etc/sanctuary/business-profile.json"),
        &canonical(
            &json!({"version":1,"profile":"business","fortress_id":"a".repeat(32),"machine_id":"a".repeat(32),"enrollment_revision":1,"digests":{"custody_envelope_digest":format!("sha256:{}","a".repeat(64)),"roster_digest":format!("sha256:{}","b".repeat(64)),"anchor_digest":format!("sha256:{}","c".repeat(64))}}),
        ),
    );
    match castle_wall_daemon::config::select_profile(roots, &[]) {
        castle_wall_daemon::config::ProfileSelection::Business(selection) => selection,
        _ => panic!("isolated business selection"),
    }
}

fn deliver_business_graph(
    actor: &mut AppendActor,
    root: &std::path::Path,
    join: &Value,
    wal: &std::path::Path,
    ts_first: bool,
    hold_cursor: bool,
    submit_clock: Option<Arc<AtomicU64>>,
) {
    use castle_wall_daemon::{
        audit::AuditRingBuffer,
        business_profile::business_delivery::BusinessDeliveryHandle,
        config::{DaemonConfig, LinuxRuntimePaths},
        ipc::server::{BusinessIpcConfig, BusinessIpcLifecycle, IpcServer},
    };
    use std::process::{Command, Stdio};
    let expected = actor.pending_delivery().unwrap().envelope().to_vec();
    let before: Value =
        serde_json::from_slice(&fs::read(wal.join("row-00000000000000000001.json")).unwrap())
            .unwrap();
    let replay = root.join("consumer/business.accepted.json").exists();
    assert!(
        before["payload"]["d_fact"].is_object() != ts_first
            && (before["payload"]["ts_fact"].is_null() || replay),
        "each order retains E before TS acceptance"
    );
    if hold_cursor {
        let mut row = before.clone();
        row["payload"]["d_fact"] = Value::Null;
        row["storage_checksum"] = json!(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(canonical(&row["payload"])))
        ));
        private(&wal.join("row-00000000000000000001.json"), &canonical(&row));
        private(&root.join("hold-cursor"), b"hold");
    }
    let (mut delivery, endpoint) = BusinessDeliveryHandle::channel();
    delivery.offer(actor.pending_delivery().unwrap()).unwrap();
    let mut config = DaemonConfig::defaults_for_fortress("deadbeef");
    config.socket_path = root.join("delivery.sock");
    config.trusted_service_uid = Some(unsafe { libc::geteuid() });
    config.linux_runtime_paths = LinuxRuntimePaths::isolated_under(root);
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    let audit = Arc::new(Mutex::new(AuditRingBuffer::new(
        1024 * 1024,
        Duration::from_secs(60),
    )));
    let lifecycle = BusinessIpcLifecycle::for_isolated_test("deadbeef", audit);
    let legacy_root = tempfile::tempdir().unwrap();
    let legacy = match castle_wall_daemon::config::select_profile(
        &castle_wall_daemon::config::SelectorRoots::isolated_under(legacy_root.path()),
        &[],
    ) {
        castle_wall_daemon::config::ProfileSelection::LegacyV1(selection) => selection,
        other => panic!("isolated Legacy selection required: {other:?}"),
    };
    let probe = Arc::new(
        castle_wall_daemon::ipc::producer_sig::ProducerSigner::load_or_generate(
            &legacy,
            &legacy_root.path().join("probe.key"),
            &legacy_root.path().join("probe.pub"),
        )
        .unwrap(),
    );
    let server = IpcServer::start_business_with_probe(
        BusinessIpcConfig::checked(
            &config,
            fs::File::open(root).unwrap(),
            key.verifying_key().to_bytes().to_vec(),
            endpoint,
            lifecycle,
        )
        .unwrap(),
        probe.clone(),
    )
    .unwrap();
    let server_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("server");
    let consumer_root = root.join("consumer");
    if !consumer_root.exists() {
        fs::create_dir(&consumer_root).unwrap();
    }
    for name in [
        "ack.probed",
        "ack.checked",
        "negative.probed",
        "negative.checked",
        "lost.probed",
        "lost.checked",
        "consumer.done",
    ] {
        if root.join(name).exists() {
            fs::remove_file(root.join(name)).unwrap();
        }
    }
    fs::set_permissions(&consumer_root, fs::Permissions::from_mode(0o700)).unwrap();
    private(&root.join("consumer.json"), &canonical(join));
    private(&root.join("expected-envelope.json"), &expected);
    let imports = server_root.join("src").to_str().unwrap().to_string();
    let script = r#"
import net from 'node:net';
import fs from 'node:fs/promises';
import {IpcClient} from 'SOURCE/castle-wall/runtime/ipc-client.ts';
import {startLinuxAuditDrainLoop} from 'SOURCE/castle-wall/runtime/linux-audit-drain.ts';
import {createBusinessDurableSink} from 'SOURCE/castle-wall/runtime/business-durable-sink.ts';
import {encrypt} from 'SOURCE/core/encryption.ts';
import {createBusinessRecordConsumer} from 'SOURCE/castle-wall/runtime/business-record-consumer.ts';
import {deliveryIdentity} from 'SOURCE/signing/business-append-contract.ts';
const root=process.argv[2];const checkpoint=JSON.parse(await fs.readFile(root+'/consumer.json','utf8'));
function connectClient(){
const socket=net.createConnection(root+'/delivery.sock');
const transport={send:bytes=>new Promise((resolve,reject)=>socket.write(bytes,error=>error?reject(error):resolve())),onData:fn=>{socket.on('data',fn);return()=>socket.off('data',fn);},onClose:fn=>{const close=()=>fn(Error('closed'));socket.on('close',close);return()=>socket.off('close',close);},close:async()=>{socket.destroy();}};
const encryptionKey=new Uint8Array(32).fill(9);
return IpcClient.createBusiness(transport,{fortressId:'deadbeef',signingKeyId:'test',encryptedPrivateKey:encrypt(new Uint8Array(32).fill(7),encryptionKey),encryptionKey});}
let client=connectClient();
const sink=await createBusinessDurableSink(root+'/consumer');let loop;
try {await client.start();
const exact=await fs.readFile(root+'/expected-envelope.json');
let refused=false;try{await client.sendBusinessAck({version:1,identity:deliveryIdentity(exact,JSON.parse(exact.toString()))});}catch{refused=true;}
await fs.writeFile(root+'/ack.probed.pending',JSON.stringify(refused));await fs.rename(root+'/ack.probed.pending',root+'/ack.probed');
const checkEnd=Date.now()+10000;while(!(await fs.stat(root+'/ack.checked').catch(()=>null))){if(Date.now()>checkEnd)throw Error('ACK probe deadline');await new Promise(r=>setTimeout(r,5));}
if(!refused)throw Error('unserved connection cannot acknowledge computable identity');
const offered=await client.businessDrainRequest();if(!offered.event)throw Error('exact offer missing');
const rejecting=await createBusinessRecordConsumer({kind:'Business',pin:{...checkpoint.pin,...checkpoint.grant},committed_state:checkpoint,durable_sink:{load:async()=>null,persist:async()=>{throw Error('held persistence');}}});
let rejected=false;try{await rejecting.accept(offered.event);}catch{rejected=true;}if(!rejected)throw Error('failed persistence accepted');
const wrong={version:1,identity:{...deliveryIdentity(exact,JSON.parse(exact.toString())),commitment:'sha256:'+ '0'.repeat(64)}};
let wrongRefused=false;try{await client.sendBusinessAck(wrong);}catch{wrongRefused=true;}if(!wrongRefused)throw Error('wrong ACK accepted');
await fs.writeFile(root+'/negative.probed','checked');
const negativeEnd=Date.now()+10000;while(!(await fs.stat(root+'/negative.checked').catch(()=>null))){if(Date.now()>negativeEnd)throw Error('negative deadline');await new Promise(r=>setTimeout(r,5));}
const firstAcceptance=await createBusinessRecordConsumer({kind:'Business',pin:{...checkpoint.pin,...checkpoint.grant},committed_state:checkpoint,durable_sink:sink});
await firstAcceptance.accept(offered.event);
let legacyRefused=false;try{await client.sendDrainAck(1);}catch{legacyRefused=true;}if(!legacyRefused)throw Error('Legacy ACK did not refuse');
await fs.writeFile(root+'/lost.probed','persisted without Business ACK');
const lostEnd=Date.now()+10000;while(!(await fs.stat(root+'/lost.checked').catch(()=>null))){if(Date.now()>lostEnd)throw Error('lost ACK deadline');await new Promise(r=>setTimeout(r,5));}
await client.close();client=connectClient();await client.start();
loop=startLinuxAuditDrainLoop(client,null,{mode:{kind:'Business',pin:{...checkpoint.pin,...checkpoint.grant},committed_state:checkpoint,durable_sink:sink},pollIntervalMs:10,onDrainFault:error=>{throw error;}});
const end=Date.now()+10000;while(loop.lastAckedSeq()!==1){if(Date.now()>end)throw Error('delivery deadline');await new Promise(r=>setTimeout(r,5));}
await loop.stop();
if(await fs.stat(root+'/fail-ts-fact').catch(()=>null) || await fs.stat(root+'/fail-submit').catch(()=>null)) {
 const failedEnd=Date.now()+10000;while(!(await fs.stat(root+'/fact.failed').catch(()=>null))){if(Date.now()>failedEnd)throw Error('fact failure deadline');await new Promise(r=>setTimeout(r,5));}
 await client.close();client=connectClient();await client.start();
 const rebound=await client.businessDrainRequest();
 await fs.writeFile(root+'/fact.rebound.pending',JSON.stringify(rebound));await fs.rename(root+'/fact.rebound.pending',root+'/fact.rebound');
 const reboundEnd=Date.now()+10000;while(!(await fs.stat(root+'/fact.rebound.checked').catch(()=>null))){if(Date.now()>reboundEnd)throw Error('rebound check deadline');await new Promise(r=>setTimeout(r,5));}
 await client.sendBusinessAck({version:1,identity:deliveryIdentity(exact,JSON.parse(exact.toString()))});
 await fs.writeFile(root+'/fact.reacked','acknowledged');
}
if(await fs.stat(root+'/hold-cursor').catch(()=>null)) {
 const nextEnd=Date.now()+10000;let next;
 while(true) {
  next=await client.businessDrainRequest();
  if(next.event && next.event.seq!==1)break;
  // An unread-back acceptance can re-serve only the exact retained original.
  if(next.event && next.event.business_envelope!==exact.toString('base64url'))throw Error('changed pending replay');
  if(Date.now()>nextEnd)throw Error('next offer deadline');await new Promise(r=>setTimeout(r,5));
 }
 if(next.event.seq!==2)throw Error('next exact sequence');
 await fs.writeFile(root+'/next.served.pending',JSON.stringify(next.event));await fs.rename(root+'/next.served.pending',root+'/next.served');
}
await fs.writeFile(root+'/consumer.done','accepted');
} finally {if(loop)await loop.stop();await client.close();await sink.close();}
"#.replace("SOURCE", &imports);
    private(&root.join("consumer.mts"), script.as_bytes());
    let error_path = root.join("consumer.stderr");
    let child = Command::new(server_root.join("node_modules/.bin/tsx"))
        .arg(root.join("consumer.mts"))
        .arg(root)
        .current_dir(&server_root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(fs::File::create(&error_path).unwrap()))
        .spawn()
        .unwrap();
    let mut children = Threads {
        stop: Arc::new(AtomicBool::new(false)),
        handles: Vec::new(),
        children: vec![child],
    };
    let end = std::time::Instant::now() + Duration::from_secs(15);
    let mut unserved_checked = false;
    let mut cursor_waves = 0;
    let fact_failure = root.join("fail-ts-fact").exists() || submit_clock.is_some();
    let mut fact_failed = false;
    let mut fact_resumed = false;
    let mut failed_snapshot = None;
    loop {
        // Keep the post-COMMIT state observable until the independent TS fact has completed.
        if !fact_failed && (!ts_first || actor.state() != State::CommittedDeliveryReady) {
            match actor.poll() {
                Err(Refusal::Io) if fact_failure => {
                    fact_failed = true;
                    delivery.pump(actor).unwrap();
                    private(&root.join("fact.failed"), b"failed");
                }
                result => result.unwrap(),
            }
        }
        if fact_resumed && actor.state() == State::SettlementRead {
            assert!(
                actor.pending_delivery().is_none(),
                "resumed TS completion retires the exact delivery token"
            );
        }
        if hold_cursor && root.join("next.served").exists() {
            assert!(
                root.join("cursor.release").exists(),
                "n+1 is served only after local TS cursor readback"
            );
        }
        if hold_cursor && root.join("cursor.held").exists() && !root.join("cursor.release").exists()
        {
            assert_eq!(
                actor.pending_delivery().map(|t| t.envelope()),
                Some(expected.as_slice()),
                "held local readback retains n's exact token"
            );
            assert!(
                actor.ownership_for_test().1,
                "held TS readback retains one store operation"
            );
            assert!(
                wal.join("row-00000000000000000001.json").exists()
                    && wal.join("row-00000000000000000002.json").exists(),
                "held cursor retains both charged envelopes"
            );
            cursor_waves += 1;
            if cursor_waves == 40 {
                private(&root.join("cursor.release"), b"release");
            }
        }
        if !unserved_checked && root.join("ack.probed").exists() {
            assert!(
                delivery.complete().unwrap().is_none(),
                "unserved ACK mints no TsReleaseFact"
            );
            assert_eq!(fs::read(root.join("ack.probed")).unwrap(), b"true");
            private(&root.join("ack.checked"), b"checked");
            unserved_checked = true;
        }
        if root.join("negative.probed").exists() && !root.join("negative.checked").exists() {
            assert!(
                delivery.complete().unwrap().is_none(),
                "rejection and wrong identity mint no release fact"
            );
            let row: Value = serde_json::from_slice(
                &fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
            )
            .unwrap();
            assert!(
                row["payload"]["ts_fact"] == before["payload"]["ts_fact"],
                "copy and rejected persistence retain exact E"
            );
            private(&root.join("negative.checked"), b"checked");
        }
        if root.join("lost.probed").exists() && !root.join("lost.checked").exists() {
            assert!(
                delivery.complete().unwrap().is_none(),
                "Legacy ACK and disconnect cannot replace a Business fact"
            );
            assert_eq!(
                actor.pending_delivery().unwrap().envelope(),
                expected,
                "lost ACK retains exactly one envelope"
            );
            private(&root.join("lost.checked"), b"checked");
        }
        let previous_clock = submit_clock.as_ref().map(|clock| {
            let old = clock.load(Ordering::SeqCst);
            clock.store(old + 60_000_000_000, Ordering::SeqCst);
            old
        });
        let pump_result = if unserved_checked {
            delivery.pump(actor)
        } else {
            Ok(())
        };
        if let Some(old) = previous_clock {
            submit_clock.as_ref().unwrap().store(old, Ordering::SeqCst);
        }
        match pump_result {
            Ok(()) | Err(Refusal::Held) => {}
            Err(Refusal::Deadline) if submit_clock.is_some() => {
                fact_failed = true;
                private(&root.join("fact.failed"), b"failed");
            }
            other => panic!("native delivery pump: {other:?}"),
        }
        if !fact_resumed
            && root.join("resume-fact").exists()
            && actor.state() == State::DeliveryFact
        {
            actor.disconnect();
            actor.resume_settlement().unwrap();
            fact_resumed = true;
        }
        if fact_failed && root.join("fact.rebound").exists() {
            let rebound: Value =
                serde_json::from_slice(&fs::read(root.join("fact.rebound")).unwrap()).unwrap();
            assert_eq!(
                rebound["event"]["business_envelope"].as_str(),
                Some(URL_SAFE_NO_PAD.encode(&expected).as_str()),
                "failed fact re-serves the exact envelope before n+1"
            );
            assert_eq!(
                rebound["event"]["seq"], 1,
                "first rebound offer is exactly the retained sequence"
            );
            let row = wal.join("row-00000000000000000001.json");
            let checkpoint = wal.join("checkpoint.json");
            if failed_snapshot.is_none() {
                failed_snapshot = Some((fs::read(&row).unwrap(), fs::read(&checkpoint).unwrap()));
                private(&root.join("fact.rebound.checked"), b"checked");
            }
            if root.join("fact.reacked").exists() {
                assert!(
                    delivery.complete().unwrap().is_none(),
                    "one envelope cannot issue a second fact after rebound ACK"
                );
                let (saved_row, saved_checkpoint) = failed_snapshot.as_ref().unwrap();
                assert_eq!(
                    &fs::read(row).unwrap(),
                    saved_row,
                    "rebound ACK leaves the retained row unchanged"
                );
                assert_eq!(
                    &fs::read(checkpoint).unwrap(),
                    saved_checkpoint,
                    "rebound ACK leaves the durable cursor unchanged"
                );
                break;
            }
        }
        if root.join("consumer.done").exists()
            && if fact_resumed {
                actor.pending_delivery().is_none() && actor.state() == State::Ready
            } else if ts_first {
                actor.pending_delivery().is_none() && actor.state() == State::CommittedDeliveryReady
            } else {
                actor.state() == State::Ready
                    && actor.pending_delivery().map(|t| t.envelope()) != Some(expected.as_slice())
            }
        {
            if ts_first && !fact_resumed {
                let row: Value = serde_json::from_slice(
                    &fs::read(wal.join("row-00000000000000000001.json")).unwrap(),
                )
                .unwrap();
                assert!(
                    row["payload"]["d_fact"].is_null() && row["payload"]["ts_fact"].is_object(),
                    "TS first retains E without D release"
                );
            }
            break;
        }
        assert!(
            std::time::Instant::now() < end,
            "native-to-TS delivery completes: {:?}",
            fs::read_to_string(&error_path)
        );
        if let Some(status) = children.children[0].try_wait().unwrap() {
            assert!(
                status.success(),
                "TS child {status}: {:?}",
                fs::read_to_string(&error_path)
            );
            if root.join("fact.held").exists() {
                // The consumer child is reaped before the parent kills this wall process.
                private(&root.join("process-reached"), b"held-first-fact");
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    if fact_failure {
        assert!(fact_failed, "local fact persistence failure is observed");
        if submit_clock.is_none() {
            assert_eq!(actor.state(), State::Held);
        }
        assert_eq!(
            actor.pending_delivery().unwrap().envelope(),
            expected,
            "fact failure retains one exact delivery"
        );
    }
    if hold_cursor {
        assert_eq!(cursor_waves, 40, "forty held cursor waves execute");
    }
    let saved: Value =
        serde_json::from_slice(&fs::read(consumer_root.join("business.accepted.json")).unwrap())
            .unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(saved["envelope"].as_str().unwrap())
            .unwrap(),
        expected,
        "real TS sink preserves exact E"
    );
    assert_eq!(
        probe.raw_sign_calls_for_test(),
        0,
        "Business output invokes no production raw signer"
    );
    server.stop_and_join();
}
