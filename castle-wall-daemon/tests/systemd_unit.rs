//! Structural checks on the SHIPPED systemd unit. (blocker 6)
//!
//! These do not require systemd or Linux — they parse the unit file that ships
//! in the repo and assert the properties the runtime depends on, so a drift in
//! the unit (a dropped `RuntimeDirectory`, a lost `Type=notify`, a missing
//! reboot-persistence target) fails CI on every platform rather than only
//! surfacing on a real host at boot.
//!
//! The load-bearing contracts:
//! * `Type=notify` — the daemon fires `READY=1` only once the kernel runtime is
//!   live (see `systemd_notify`); the unit must be the notify type or that
//!   signal is meaningless and the unit would hang activating.
//! * `RuntimeDirectory=sanctuary` — provisions the ephemeral IPC socket parent.
//! * `StateDirectory=sanctuary` — provisions the durable ownership journal/key
//!   and the persistent host-lock rendezvous inode used by daemon and recovery.
//! * `TimeoutStartSec` — process-level bound for the SYNCHRONOUS kernel/watcher
//!   binds (there is no in-process bind timeout anymore).
//! * `TimeoutStopSec` + `KillMode=control-group` — bound shutdown and reap an
//!   isolated nft health child if its fork/netlink transaction wedged.
//! * `Restart=on-failure` — fail-before and post-ready health loss exit nonzero;
//!   systemd must restart so the preserved kernel object is re-adopted.
//! * `WantedBy=multi-user.target` — the reboot-survival / persistence path.

use castle_wall_daemon::ownership_journal::DEFAULT_OWNERSHIP_JOURNAL_PATH;
use castle_wall_daemon::runtime_lock::DEFAULT_HOST_LOCK_PATH;

fn unit_text() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("systemd")
        .join("sanctuary-castle-wall.service");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("shipped unit must be readable at {path:?}: {e}"))
}

/// Collect the values of a directive key across the whole unit (a directive may
/// legitimately appear more than once, e.g. ReadWritePaths).
fn directive_values<'a>(unit: &'a str, key: &str) -> Vec<&'a str> {
    unit.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix(key))
        .filter_map(|rest| rest.strip_prefix('='))
        .map(str::trim)
        .collect()
}

#[test]
fn unit_is_type_notify() {
    assert_eq!(
        directive_values(&unit_text(), "Type"),
        vec!["notify"],
        "the daemon fires sd_notify READY=1; the unit must be Type=notify"
    );
}

#[test]
fn unit_restarts_after_fail_before_or_runtime_loss() {
    assert_eq!(
        directive_values(&unit_text(), "Restart"),
        vec!["on-failure"],
        "fail-before and runtime-loss exits rely on systemd restart adoption"
    );
}

#[test]
fn unit_requires_explicit_trusted_service_uid_configuration() {
    let unit = unit_text();
    assert!(unit.contains("EnvironmentFile=/etc/sanctuary/castle-wall.env"));
    assert!(unit.contains("--trusted-service-uid ${SANCTUARY_TRUSTED_SERVICE_UID}"));
    assert!(!unit.contains("pinned.key --trusted-service-uid"));
}

#[test]
fn unit_provisions_the_runtime_directory_for_the_ipc_socket() {
    let unit = unit_text();
    let values = directive_values(&unit, "RuntimeDirectory");
    assert_eq!(
        values,
        vec!["sanctuary"],
        "RuntimeDirectory=sanctuary must provision /run/sanctuary (blocker 6)"
    );
    assert_eq!(
        directive_values(&unit, "ExecStartPre"),
        vec!["/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/${SANCTUARY_FORTRESS_ID}"],
        "the fortress-specific socket parent must be recreated after every /run tmpfs reboot"
    );
}

#[test]
fn unit_provisions_the_durable_state_directory_for_the_ownership_journal() {
    // blocker 3: the ownership journal must live on a DURABLE, root-owned path
    // that survives a service restart (and reboot), so a crash between
    // atomic-create and finalize is reclaimed rather than wedged. StateDirectory
    // (unlike RuntimeDirectory) is not deleted on stop.
    let unit = unit_text();
    let values = directive_values(&unit, "StateDirectory");
    assert_eq!(
        values,
        vec!["sanctuary"],
        "StateDirectory=sanctuary must provision the durable /var/lib/sanctuary"
    );
    let provisioned = format!("/var/lib/{}", values[0]);
    assert!(
        DEFAULT_OWNERSHIP_JOURNAL_PATH.starts_with(&format!("{provisioned}/")),
        "the ownership journal {DEFAULT_OWNERSHIP_JOURNAL_PATH} must live under the \
         provisioned StateDirectory {provisioned}"
    );
    assert!(
        DEFAULT_HOST_LOCK_PATH.starts_with(&format!("{provisioned}/")),
        "the host lock {DEFAULT_HOST_LOCK_PATH} must live under the persistent \
         StateDirectory {provisioned}, not stop-time-removed /run"
    );
    // Locked down: the journal is an ownership proof, so its dir is 0700.
    assert_eq!(directive_values(&unit, "StateDirectoryMode"), vec!["0700"]);
}

#[test]
fn systemd_stop_is_not_disarm() {
    // blocker 1: ordinary stop must PRESERVE the owned table + its ownership
    // journal; deletion is the separate explicit `--disarm` action. So the unit
    // must NOT wire an ExecStop that disarms (or any ExecStop that runs the
    // binary), or a `systemctl stop` would tear down the enforcement object the
    // fail-closed design preserves. The daemon handles SIGTERM itself (releasing
    // only process-local resources), so no ExecStop is needed at all.
    let unit = unit_text();
    let exec_stops = directive_values(&unit, "ExecStop");
    assert!(
        exec_stops.is_empty(),
        "the unit must have NO ExecStop (stop != disarm); found {exec_stops:?}"
    );
    // Belt-and-suspenders: even if some ExecStop were added later, it must never
    // invoke --disarm. Scan only executable DIRECTIVE lines, not comments: the
    // unit's own documentation legitimately names `--disarm` to explain WHY no
    // ExecStop wires it (the explicit-disarm-only invariant), so a raw whole-file
    // grep would false-positive on that intentional comment rather than on a real
    // directive.
    let disarm_in_directive = unit
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .any(|l| l.to_lowercase().contains("--disarm"));
    assert!(
        !disarm_in_directive,
        "no unit directive may invoke --disarm on stop; disarm is an explicit \
         operator recovery action, not a shutdown side effect"
    );
}

#[test]
fn unit_bounds_startup_at_the_process_level() {
    // The synchronous kernel/watcher binds rely on systemd's startup timeout for
    // process-level bounding (blocker 8), so the unit must set it explicitly.
    // Bind the unit text to a local first: directive_values borrows from it, so
    // reading from a temporary would drop the String while the returned slice
    // references are still in use (E0716).
    let unit = unit_text();
    let values = directive_values(&unit, "TimeoutStartSec");
    assert_eq!(values.len(), 1, "exactly one TimeoutStartSec must be set");
    assert!(
        values[0].chars().next().is_some_and(|c| c.is_ascii_digit()),
        "TimeoutStartSec must be a concrete duration, got {:?}",
        values[0]
    );
}

#[test]
fn unit_bounds_shutdown_and_kills_wedged_health_children() {
    let unit = unit_text();
    let timeout = directive_values(&unit, "TimeoutStopSec");
    assert_eq!(timeout.len(), 1, "exactly one TimeoutStopSec must be set");
    assert!(
        timeout[0]
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit()),
        "TimeoutStopSec must be a concrete duration, got {:?}",
        timeout[0]
    );
    assert_eq!(
        directive_values(&unit, "KillMode"),
        vec!["control-group"],
        "a wedged nft health child must be killed with the service"
    );
}

#[test]
fn manual_recovery_holds_the_persistent_runtime_lock_for_the_full_transaction() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("server/docs/castle-wall-linux-deploy.md");
    let doc = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("deployment runbook must be readable at {path:?}: {e}"));
    assert!(doc.contains(DEFAULT_HOST_LOCK_PATH));
    assert!(!doc.contains("/run/sanctuary/castle-wall.nft.lock"));
    let open = doc.find("exec 9<>").expect("open persistent lock fd");
    let flock = doc
        .find("flock --exclusive --nonblock 9")
        .expect("lock the held fd");
    let delete = doc
        .find("nft delete table inet sanctuary-castle")
        .expect("explicit table deletion");
    let verify = doc
        .find("nft-tables-after.json")
        .expect("post-delete absence evidence");
    let retire = doc
        .find("nft-ownership.retired.json")
        .expect("proof retirement");
    let close = doc.find("exec 9>&-").expect("explicit lock release");
    assert!(
        open < flock && flock < delete && delete < verify && verify < retire && retire < close,
        "recovery must hold one fd across evidence, delete, absence verification, and retirement"
    );
}

#[test]
fn unit_has_a_reboot_persistence_target_and_safe_mode() {
    let unit = unit_text();
    // Reboot path: enabling the unit under multi-user.target is what makes it
    // start on every boot.
    assert_eq!(
        directive_values(&unit, "WantedBy"),
        vec!["multi-user.target"],
        "the unit must be wanted by multi-user.target for reboot survival"
    );
    // Safe mode consistent with a root daemon: read-only system with an explicit
    // writable durable-state target.
    assert_eq!(directive_values(&unit, "ProtectSystem"), vec!["strict"]);
    let rw = directive_values(&unit, "ReadWritePaths");
    assert!(
        rw.iter().any(|v| v.contains("/var/lib/sanctuary")),
        "durable state dir must be an explicit writable target, got {rw:?}"
    );
    // CAP_NET_ADMIN is the one capability nftables/NFQUEUE need; NoNewPrivileges
    // must be on.
    assert!(directive_values(&unit, "AmbientCapabilities")
        .iter()
        .any(|v| v.contains("CAP_NET_ADMIN")));
    assert_eq!(directive_values(&unit, "NoNewPrivileges"), vec!["true"]);
}
