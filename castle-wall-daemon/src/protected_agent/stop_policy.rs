//! Stop-authority decisions, separated from the Linux-only owner that acts on
//! them. Three different sites ask the same three questions (is a stop signal
//! owed for this release, may this cgroup still be acted on, and is this open
//! record owed a resumed stop), and each answer is a named state rather than a
//! bare boolean so the acting site reads as the decision it implements. Keeping
//! them here also makes every polarity provable on any host, while the code
//! that performs the stop remains Linux-only.
use super::{
    ledger::GenerationState,
    receipt::{Generation, ManagerIdentity},
};

/// Named routing states for the daemon-side stop hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookRoute {
    /// Nothing is owed to the owner, and the daemon sends no signed request.
    NoSignal,
    /// Sign a stop-failure receipt for the unresolved release and send it.
    Send,
}

/// A stop-failure signal is owed only when the ACCOUNT of the unresolved
/// release is one the safety net just attempted to deny, that is a uid in
/// sources (a) union (b). An authentic release row for a different account is
/// true evidence about a different agent: acting on it would have the owner
/// stop whichever generation its ledger happens to hold rather than the one the
/// failed install named, so a non-empty kill set is not on its own a reason to
/// send. An empty kill set, a kill set without the released account, and an
/// absent release all stay no-signal, which is the conservative direction: the
/// release simply remains unresolved and INHIBIT.
///
/// `kill_set` MUST MATCH the `resolution.kill_set` the caller passes at the six
/// hook sites in `crate::runtime_providers`, which is sources (a) and (b) only
/// and never the live table's bindings.
pub fn hook_route(kill_set: &[u32], released_account_uid: Option<u32>) -> HookRoute {
    match released_account_uid {
        Some(uid) if kill_set.contains(&uid) => HookRoute::Send,
        _ => HookRoute::NoSignal,
    }
}

/// Named states of a producer's original main process at stop time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainProcessAuthority {
    /// The unit's main process is still the exact durable (pid, start time).
    SameMain,
    /// No main process remains under this unit. Descendants may still be alive
    /// inside the durable cgroup, which is what the stop then acts on.
    Exited,
    /// Some other main process holds this unit now, so the durable identity no
    /// longer describes what is running and nothing may be stopped.
    Foreign,
}

/// Stop authority is the durable unit, cgroup path, device and inode tuple,
/// re-read immediately before each action; the original main process is
/// corroborating evidence, not the authority itself. A forking producer whose
/// main has already exited still leaves descendants inside that exact cgroup,
/// and refusing there would leave them running with nothing else able to reach
/// them. Exactness is unchanged in the direction that matters: a DIFFERENT live
/// main process means a different generation and is refused, and a recycled pid
/// is caught by the start time, so this never widens what may be stopped, it
/// only keeps the already-owned cgroup reachable.
pub fn main_process_authority(
    shown_main_pid: u32,
    shown_main_start_time: Option<u64>,
    durable: &ManagerIdentity,
) -> MainProcessAuthority {
    // The manager reports 0 for a unit with no live main process.
    if shown_main_pid == 0 {
        return MainProcessAuthority::Exited;
    }
    if shown_main_pid != durable.main_pid {
        return MainProcessAuthority::Foreign;
    }
    match shown_main_start_time {
        Some(start) if start == durable.main_start_time => MainProcessAuthority::SameMain,
        // The reported pid is already gone from /proc: it exited between the
        // manager read and the start-time read. That is an exit, never a
        // foreign main, and the durable cgroup remains the authority.
        None => MainProcessAuthority::Exited,
        Some(_) => MainProcessAuthority::Foreign,
    }
}

/// Named outcomes of the owner's periodic reconciliation scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconcileVerdict {
    /// Leave the record exactly as it is.
    LeaveOpen,
    /// A durable stop intent exists whose outcome was never recorded, so the
    /// stop and its signed outcome are driven again.
    ResumeStop,
}

/// Reconciliation RESUMES work that was already authorised and fsynced; it is
/// never itself an authority to stop something. The predicate is therefore the
/// accepted attempt row, which both the daemon failure hook and the shutdown
/// notifier write and fsync before any stop runs, and not the presence of a
/// release. Two consequences, and both are the point: a healthy released agent
/// that nobody asked to stop has no attempt row and survives every scan, and a
/// Prepared-plus-manager record whose notifier died mid-stop has one and is
/// finished even though no release was ever copied to the owner. A record whose
/// outcome is already recorded is closed and is never reopened.
pub fn reconcile_verdict(entry: &GenerationState) -> ReconcileVerdict {
    if entry.is_open() && entry.manager.is_some() && !entry.attempts.is_empty() {
        ReconcileVerdict::ResumeStop
    } else {
        ReconcileVerdict::LeaveOpen
    }
}

/// The exact pair a resumed stop acts on, or `None` when the record is not
/// eligible. Callers use this rather than reading the fields themselves so the
/// verdict and the values acted on cannot drift apart.
pub fn reconcile_target(entry: &GenerationState) -> Option<(Generation, ManagerIdentity)> {
    match reconcile_verdict(entry) {
        ReconcileVerdict::LeaveOpen => None,
        ReconcileVerdict::ResumeStop => Some((entry.prepared.clone()?, entry.manager.clone()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_agent::receipt::{
        self, deterministic_unit_name, Domain, ReceiptBody, SignedReceipt,
    };
    use ed25519_dalek::SigningKey;

    const AGENT_UID: u32 = 1001;

    fn generation() -> Generation {
        let mut g = Generation {
            boot_id: "boot".into(),
            daemon_invocation: "inv".into(),
            fortress_id: "abcdef12".into(),
            manifest_generation: "m".into(),
            ownership_generation: "o".into(),
            reservation_nonce: "a".repeat(64),
            reservation_hash: "b".repeat(64),
            account: "agent".into(),
            uid: AGENT_UID,
            gid: AGENT_UID,
            profile_id: "agent-v1".into(),
            profile_hash: "c".repeat(64),
            executable_sha256: "d".repeat(64),
            unit_name: String::new(),
        };
        g.unit_name = deterministic_unit_name(&g);
        g
    }

    fn manager(g: &Generation) -> ManagerIdentity {
        ManagerIdentity {
            unit_name: g.unit_name.clone(),
            cgroup_path: format!("system.slice/{}", g.unit_name),
            cgroup_dev: 1,
            cgroup_ino: 2,
            main_pid: 10,
            main_start_time: 100,
        }
    }

    fn extinction(g: &Generation, m: &ManagerIdentity) -> SignedReceipt {
        let body = ReceiptBody {
            generation: g.clone(),
            manager: Some(m.clone()),
            hook: None,
            attempt_id: None,
            attempted_scope: None,
            candidate_uids: Vec::new(),
            old_release_hash: None,
            positive_extinction: Some(true),
        };
        receipt::sign(
            Domain::PreparedExtinctionV1,
            body,
            &SigningKey::from_bytes(&[5; 32]),
        )
        .expect("a scoped extinction body signs")
    }

    #[test]
    fn a_stop_signal_is_owed_only_for_a_release_whose_account_the_net_denied() {
        // Nothing was denied: an unresolved release is someone else's business.
        assert_eq!(hook_route(&[], Some(AGENT_UID)), HookRoute::NoSignal);
        // Denied accounts exist, but not this release's account. This is the
        // live-table-only shape, where the kill set carries source (c) work.
        assert_eq!(
            hook_route(&[AGENT_UID + 1, AGENT_UID + 2], Some(AGENT_UID)),
            HookRoute::NoSignal
        );
        // Nothing is wrapped, so there is no release to resolve at all.
        assert_eq!(hook_route(&[AGENT_UID], None), HookRoute::NoSignal);
        // The denied set contains exactly this release's account.
        assert_eq!(
            hook_route(&[AGENT_UID + 1, AGENT_UID], Some(AGENT_UID)),
            HookRoute::Send
        );
    }

    #[test]
    fn descendants_stay_reachable_after_the_original_main_process_exits() {
        let g = generation();
        let m = manager(&g);
        assert_eq!(
            main_process_authority(m.main_pid, Some(m.main_start_time), &m),
            MainProcessAuthority::SameMain
        );
        // A forking producer whose main exited, with descendants still inside
        // the owned cgroup: the durable tuple remains the authority.
        assert_eq!(
            main_process_authority(0, None, &m),
            MainProcessAuthority::Exited
        );
        assert_eq!(
            main_process_authority(m.main_pid, None, &m),
            MainProcessAuthority::Exited
        );
        // A different live main, and a recycled pid with a different start
        // time, both remain refusals.
        assert_eq!(
            main_process_authority(m.main_pid + 1, Some(m.main_start_time), &m),
            MainProcessAuthority::Foreign
        );
        assert_eq!(
            main_process_authority(m.main_pid, Some(m.main_start_time + 1), &m),
            MainProcessAuthority::Foreign
        );
    }

    #[test]
    fn reconciliation_resumes_only_records_that_already_accepted_a_stop_intent() {
        let g = generation();
        let m = manager(&g);
        type Attempts = std::collections::BTreeMap<String, (String, Option<String>)>;
        let none: Attempts = Attempts::new();
        let attempt =
            || -> Attempts { Attempts::from([("attempt".to_owned(), ("f".repeat(64), None))]) };
        let released = |attempts: Attempts| GenerationState {
            prepared: Some(g.clone()),
            manager: Some(m.clone()),
            attempts,
            // A release copy is not needed to decide the verdict; the accepted
            // attempt is the whole predicate.
            release: None,
            outcome: None,
        };
        // A healthy agent whose release was copied to the owner but for which
        // no stop was ever accepted: the scan leaves it running.
        assert_eq!(
            reconcile_verdict(&released(none.clone())),
            ReconcileVerdict::LeaveOpen
        );
        assert_eq!(reconcile_target(&released(none)), None);
        // The same record once a stop intent has been fsynced.
        assert_eq!(
            reconcile_verdict(&released(attempt())),
            ReconcileVerdict::ResumeStop
        );
        assert_eq!(
            reconcile_target(&released(attempt())),
            Some((g.clone(), m.clone()))
        );
        // A Prepared-plus-manager record with no manager identity cannot name a
        // cgroup, so there is nothing to resume.
        assert_eq!(
            reconcile_verdict(&GenerationState {
                prepared: Some(g.clone()),
                manager: None,
                attempts: attempt(),
                ..GenerationState::default()
            }),
            ReconcileVerdict::LeaveOpen
        );
        // A closed record is never reopened by a scan.
        assert_eq!(
            reconcile_verdict(&GenerationState {
                prepared: Some(g.clone()),
                manager: Some(m.clone()),
                attempts: attempt(),
                release: None,
                outcome: Some(extinction(&g, &m)),
            }),
            ReconcileVerdict::LeaveOpen
        );
    }
}
