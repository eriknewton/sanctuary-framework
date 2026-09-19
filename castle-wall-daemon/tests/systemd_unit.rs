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
    // Total over the whole ExecStartPre list, and ORDER MATTERS: systemd runs
    // them in file order, so this pins the sequence, not just the membership.
    // The second entry is the Node custody-lock root; it is asserted here rather
    // than ignored so that DELETING either provisioning step is a visible diff.
    // Failure mode if this were a `contains` check instead: a dropped step reads
    // as green and only shows up as a socket or lock the deployment cannot open.
    assert_eq!(
        directive_values(&unit, "ExecStartPre"),
        vec![
            "/usr/bin/install -d -m 0750 -o root -g sanctuary /run/sanctuary/${SANCTUARY_FORTRESS_ID}",
            "+/usr/bin/install -d -o root -g sanctuary -m 0700 /run/sanctuary/locks",
        ],
        "the fortress-specific socket parent and the custody lock root must both be \
         recreated after every /run tmpfs reboot"
    );
}

/// Reads the stop-owner unit that ships in the crate as a source artifact.
/// Nothing installs, enables, or starts it in this slice; see the header of
/// `systemd/sanctuary-stop-owner.service`, which states the same bound.
fn stop_owner_unit_text() -> String {
    std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("systemd/sanctuary-stop-owner.service"),
    )
    .expect("the stop-owner unit ships beside the daemon unit in this crate")
}

#[test]
fn the_shipped_daemon_unit_starts_independently_of_the_stop_owner_artifact() {
    // The stop owner refuses READY until launch artifacts that no package
    // delivers today are installed, so the filter daemon's start must not
    // depend on it in any direction. Failure mode if this pin is dropped: the
    // package installs cleanly and Castle Wall simply never reaches active on
    // a host that has the package and nothing else.
    let daemon = unit_text();
    assert!(
        !daemon.contains("sanctuary-stop-owner"),
        "the shipped daemon unit must not name the stop-owner unit, its socket, \
         or its private state while that owner is an uninstalled artifact"
    );
    assert!(
        directive_values(&daemon, "BindsTo").is_empty(),
        "no BindsTo edge may tie filter enforcement to a unit that is not installed"
    );
    assert!(
        directive_values(&daemon, "ExecStopPost").is_empty(),
        "shutdown must not call a stop notifier that the package does not install"
    );
}

#[test]
fn the_stop_owner_unit_grants_no_cgroup_write_path_and_keeps_its_socket_parent_volatile() {
    let owner = stop_owner_unit_text();
    assert_eq!(directive_values(&owner, "User"), vec!["root"]);
    assert_eq!(directive_values(&owner, "Group"), vec!["root"]);
    assert_eq!(
        directive_values(&owner, "StateDirectory"),
        vec!["sanctuary-stop-owner"]
    );
    assert_eq!(directive_values(&owner, "StateDirectoryMode"), vec!["0700"]);
    assert_eq!(
        directive_values(&owner, "RuntimeDirectoryMode"),
        vec!["0700"]
    );
    assert_eq!(
        directive_values(&owner, "InaccessiblePaths"),
        vec!["/var/lib/sanctuary"]
    );
    assert!(directive_values(&owner, "BindsTo").is_empty());
    assert_eq!(
        directive_values(&owner, "ReadWritePaths"),
        vec!["/var/lib/sanctuary-stop-owner /run/sanctuary-stop-owner"]
    );
    // `ProtectSystem=strict` leaves `/sys` writable on its own, so the cgroup
    // hierarchy is read-only for this unit ONLY while ProtectControlGroups is
    // true. Failure mode if this flips: nothing visibly breaks, because the
    // unit GAINS write access to every cgroup on the host rather than losing
    // access to one, so the loss of the bound is silent on a running system and
    // this assertion is the only place it shows.
    assert_eq!(
        directive_values(&owner, "ProtectSystem"),
        vec!["strict"],
        "the owner's filesystem must stay read-only except its two declared paths"
    );
    assert_eq!(
        directive_values(&owner, "ProtectControlGroups"),
        vec!["true"],
        "a release-disabled owner is granted no writable cgroup path anywhere"
    );
    assert!(
        !owner.contains("/sys/fs/cgroup"),
        "no explicit cgroup path may be added to the owner's writable set"
    );
    // MUST MATCH the restart-custody invariant at the socket-bind refusal in
    // `src/protected_agent/owner.rs` (`serve_production`): the owner refuses to
    // start when its socket path already exists, which is safe to do only
    // because systemd removes RuntimeDirectory= on every stop. Declaring
    // RuntimeDirectoryPreserve here would keep a crashed run's socket inode
    // and turn each crash into a permanent refusal to start.
    assert_eq!(
        directive_values(&owner, "RuntimeDirectory"),
        vec!["sanctuary-stop-owner"],
        "the socket parent must be systemd-owned so it is recreated empty per start"
    );
    assert!(
        directive_values(&owner, "RuntimeDirectoryPreserve").is_empty(),
        "preserving the runtime directory would carry a stale socket across a restart"
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
    // PINNED BY VALUE, not merely "a duration": the start-limit interval below is
    // DERIVED from this number, so a change here without a matching change there
    // silently makes the limit untrippable. Must match TimeoutStartSec and the
    // derivation comment in systemd/sanctuary-castle-wall.service.
    assert_eq!(
        values[0], TIMEOUT_START_SEC,
        "TimeoutStartSec is pinned; the start-limit interval is derived from it"
    );
}

/// The unit's startup timeout, in seconds. Raised with the safety net because a
/// startup ownership loss now installs the net inside the start window.
/// Must match `TimeoutStartSec` in systemd/sanctuary-castle-wall.service.
const TIMEOUT_START_SEC: &str = "60";

/// The unit's restart delay, in seconds.
/// Must match `RestartSec` in systemd/sanctuary-castle-wall.service.
const RESTART_SEC: &str = "2";

/// The unit's start burst.
/// Must match `StartLimitBurst` in systemd/sanctuary-castle-wall.service.
const START_LIMIT_BURST: &str = "5";

/// The unit's start-limit window, in seconds.
/// Must match `StartLimitIntervalSec` in systemd/sanctuary-castle-wall.service.
const START_LIMIT_INTERVAL_SEC: &str = "600";

/// The INI section a directive appears in, or None when it is absent.
///
/// systemd reads a directive only in its own section and ignores it elsewhere, so a
/// test that asserts a value without asserting the section cannot tell a live
/// directive from a decorative one.
fn section_of(unit: &str, directive: &str) -> Option<String> {
    let mut current: Option<String> = None;
    for line in unit.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
            current = Some(name.to_string());
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some((key, _)) = trimmed.split_once('=') {
            if key.trim() == directive {
                return current.clone();
            }
        }
    }
    None
}

#[test]
fn unit_ships_a_finite_start_limit_whose_window_outlasts_five_worst_case_activations() {
    let unit = unit_text();
    // SECTION MATTERS: `StartLimitBurst` and `StartLimitIntervalSec` are `[Unit]`
    // directives. systemd silently IGNORES them under `[Service]`, so a unit that
    // carries them in the wrong section has no start limit at all while reading as
    // though it does. Assert the section, not just the value.
    assert_eq!(
        section_of(&unit, "StartLimitBurst").as_deref(),
        Some("Unit"),
        "StartLimitBurst must sit in [Unit]; systemd ignores it under [Service]"
    );
    assert_eq!(
        section_of(&unit, "StartLimitIntervalSec").as_deref(),
        Some("Unit"),
        "StartLimitIntervalSec must sit in [Unit]; systemd ignores it under [Service]"
    );
    // And the directives that ARE per-service stay where they belong, so this test
    // cannot pass by moving everything into one section.
    assert_eq!(
        section_of(&unit, "TimeoutStartSec").as_deref(),
        Some("Service")
    );
    assert_eq!(section_of(&unit, "RestartSec").as_deref(), Some("Service"));

    let burst = directive_values(&unit, "StartLimitBurst");
    let interval = directive_values(&unit, "StartLimitIntervalSec");
    assert_eq!(burst.len(), 1, "exactly one StartLimitBurst must be set");
    assert_eq!(
        interval.len(),
        1,
        "exactly one StartLimitIntervalSec must be set"
    );
    assert_eq!(burst[0], START_LIMIT_BURST);
    assert_eq!(interval[0], START_LIMIT_INTERVAL_SEC);

    // INVARIANT, and the reason both values are pinned: systemd refuses a start
    // only when MORE than `burst` starts fall inside one window, so all `burst`
    // worst-case activations must FIT in the window. A worst case is an activation
    // killed at TimeoutStartSec plus RestartSec. If this arithmetic ever fails, the
    // unit restarts forever while network.target waits on the ordering edge, which
    // is the boot lockout moved from nftables into systemd.
    let burst_n: u64 = burst[0].parse().expect("burst is a count");
    let interval_n: u64 = interval[0].parse().expect("interval is seconds");
    let start_timeout: u64 = TIMEOUT_START_SEC.parse().expect("timeout is seconds");
    let restart_delay: u64 = RESTART_SEC.parse().expect("restart delay is seconds");
    let worst_case_span = burst_n * (start_timeout + restart_delay);
    assert!(
        interval_n > worst_case_span,
        "StartLimitIntervalSec {interval_n} must exceed {burst_n} x ({start_timeout} + \
         {restart_delay}) = {worst_case_span} seconds, or the limit never trips"
    );

    // And the unlimited form is never shipped here: it is what would move the boot
    // lockout into systemd.
    assert!(
        !interval.contains(&"0"),
        "StartLimitIntervalSec=0 (unlimited restarts) must never ship on a unit \
         ordered Before=network.target"
    );

    // RestartSec is pinned too, because the derivation above reads it.
    let restart = directive_values(&unit, "RestartSec");
    assert_eq!(restart.len(), 1, "exactly one RestartSec must be set");
    assert_eq!(restart[0], RESTART_SEC);

    // The recovery an operator needs is named in the unit itself, because a plain
    // `systemctl start` after the limit trips reports only "start request repeated
    // too quickly" and reads as a broken unit file.
    assert!(
        unit.contains("reset-failed"),
        "the unit must name `systemctl reset-failed` as the recovery"
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

// ---------------------------------------------------------------------------
// The finite start limit, exercised against a real systemd rather than parsed.
//
// The structural tests above prove the unit CARRIES the four values in the right
// sections and that the window outlasts five worst-case activations. They cannot prove
// what the values DO: that a service which keeps failing reaches a terminal failed state
// instead of restarting forever, and that a unit ordered behind it is released. This leg
// builds a transient service from those exact shipped values, drives it to the limit, and
// reads the outcome back from systemd.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod start_limit_against_real_systemd {
    use std::process::Command;
    use std::time::{Duration, Instant};

    /// Seconds subtracted from `TimeoutStartSec` for the one slow activation. It must be
    /// strictly less than the start timeout so the activation FAILS on its own rather
    /// than being killed by the timeout: both count toward the limit, and the first is
    /// the one a test can drive deterministically.
    const SLOW_ACTIVATION_HEADROOM_SECS: u64 = 5;

    /// Extra seconds added to the derived wait before the terminal state is expected.
    /// Absorbs scheduling and bus latency only; it is not a retry budget.
    const TERMINAL_STATE_SLACK_SECS: u64 = 20;

    /// How often the unit's state is re-read while waiting.
    const POLL_SPACING: Duration = Duration::from_millis(500);

    /// One directive value, parsed from the SHIPPED unit rather than restated here, so
    /// this leg exercises what the unit actually carries.
    /// Must match the directive of the same name in
    /// systemd/sanctuary-castle-wall.service.
    fn shipped(directive: &str) -> String {
        let unit = super::unit_text();
        let values = super::directive_values(&unit, directive);
        assert_eq!(
            values.len(),
            1,
            "the shipped unit must set exactly one {directive}"
        );
        values[0].to_string()
    }

    /// One unit property as systemd reports it, or an empty string when the read failed.
    /// An empty value never satisfies an assertion below, so a failed read cannot pass.
    fn systemctl_property(unit: &str, property: &str) -> String {
        Command::new("systemctl")
            .args(["show", "--value", "-p", property, unit])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    }

    /// The fixture-owned counter is the portable proof of actual activations. Some systemd
    /// releases retain `Result=exit-code` after the manager refuses a rate-limited restart,
    /// so that manager diagnostic cannot be the pass condition here.
    fn activation_count(counter: &std::path::Path) -> Option<u64> {
        std::fs::read_to_string(counter).ok()?.trim().parse().ok()
    }

    /// Transient units this leg created, torn down on EVERY exit path.
    ///
    /// A `Drop` guard rather than teardown at the end of the test body: a panicking
    /// assertion would otherwise leave a failed transient unit and its start-limit state
    /// on the host for the whole window, and the next run of this leg would inherit it.
    struct TransientUnits {
        names: Vec<String>,
    }

    impl Drop for TransientUnits {
        fn drop(&mut self) {
            for name in &self.names {
                let _ = Command::new("systemctl").args(["stop", name]).output();
                // `reset-failed` is required as well as `stop`: a unit that hit the start
                // limit stays in the failed state with its counter armed until it is
                // reset, which is the same recovery the shipped unit's comment names for
                // an operator.
                let _ = Command::new("systemctl")
                    .args(["reset-failed", name])
                    .output();
            }
        }
    }

    /// True when a transient unit can be created at all. Reports the reason it cannot, so
    /// a skip is never silent.
    fn systemd_run_available() -> bool {
        match Command::new("systemd-run").arg("--version").output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                eprintln!(
                    "SKIP (systemd-run unusable): exit {:?}: {}",
                    out.status.code(),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                return false;
            }
            Err(err) => {
                eprintln!("SKIP (systemd-run not present): {err}");
                return false;
            }
        }
        // A system bus is the second requirement: without it (a container with no
        // systemd, or an unprivileged caller with no polkit agent) a transient unit
        // cannot be created and the leg has nothing to drive.
        match Command::new("systemctl")
            .args(["show", "--value", "-p", "Version"])
            .output()
        {
            Ok(out) if out.status.success() => true,
            Ok(out) => {
                eprintln!(
                    "SKIP (no usable system bus): {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
                false
            }
            Err(err) => {
                eprintln!("SKIP (systemctl not present): {err}");
                false
            }
        }
    }

    #[test]
    fn repeated_failures_reach_a_terminal_failed_state_and_release_the_ordered_dependent() {
        if !systemd_run_available() {
            return;
        }
        let burst: u64 = shipped("StartLimitBurst")
            .parse()
            .expect("burst is a count");
        let interval = shipped("StartLimitIntervalSec");
        let restart_secs: u64 = shipped("RestartSec")
            .parse()
            .expect("restart delay is seconds");
        let start_timeout: u64 = shipped("TimeoutStartSec")
            .parse()
            .expect("start timeout is seconds");
        assert!(
            start_timeout > SLOW_ACTIVATION_HEADROOM_SECS,
            "the slow activation must fit inside the shipped start timeout"
        );
        let slow_activation_secs = start_timeout - SLOW_ACTIVATION_HEADROOM_SECS;

        let work = tempfile::tempdir().expect("a work directory for the transient unit");
        let counter = work.path().join("starts");
        let script = work.path().join("failing-activation.sh");
        // The activation: count this start, sleep only on the FIRST one, then fail
        // without ever notifying readiness. That is the shape the unit's own worst case
        // has, a Type=notify activation that never reaches READY=1, and the reason the
        // first start is the slow one is that the ordered dependent below must be shown
        // waiting behind a slow activation rather than behind an instant failure.
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\n\
                 n=$(cat \"{counter}\" 2>/dev/null || echo 0)\n\
                 n=$((n+1))\n\
                 printf '%s' \"$n\" > \"{counter}\"\n\
                 if [ \"$n\" = \"1\" ]; then sleep {slow_activation_secs}; fi\n\
                 exit 1\n",
                counter = counter.display(),
                slow_activation_secs = slow_activation_secs,
            ),
        )
        .expect("write the activation script");
        let mut perms = std::fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o700);
        }
        std::fs::set_permissions(&script, perms).expect("make the activation executable");

        // Unique per process AND per run: a name reused while its predecessor is still in
        // the failed state would inherit that unit's armed start counter.
        let tag = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_nanos())
                .unwrap_or_default()
        );
        let service = format!("sanctuary-start-limit-{tag}.service");
        let dependent = format!("sanctuary-start-limit-dependent-{tag}.service");
        let _cleanup = TransientUnits {
            names: vec![dependent.clone(), service.clone()],
        };

        let started = Command::new("systemd-run")
            .args([
                format!("--unit={service}"),
                "--property=Type=notify".to_string(),
                "--property=Restart=on-failure".to_string(),
                format!("--property=RestartSec={restart_secs}"),
                format!("--property=TimeoutStartSec={start_timeout}"),
                format!("--property=StartLimitBurst={burst}"),
                format!("--property=StartLimitIntervalSec={interval}"),
                "--no-block".to_string(),
                "/bin/sh".to_string(),
                script.display().to_string(),
            ])
            .output()
            .expect("run systemd-run");
        if !started.status.success() {
            eprintln!(
                "SKIP (the transient service could not be created): {}",
                String::from_utf8_lossy(&started.stderr).trim()
            );
            return;
        }

        // The ordered dependent, which stands in for the shipped unit's
        // `Before=network.target` edge: a WEAK requirement plus an ordering edge, so the
        // failing unit delays it and a failure does not fail it. If the failing unit
        // never reached a terminal state, this would never become active, which is the
        // boot lockout the finite limit exists to prevent.
        let dep = Command::new("systemd-run")
            .args([
                format!("--unit={dependent}"),
                "--property=Type=oneshot".to_string(),
                "--property=RemainAfterExit=yes".to_string(),
                format!("--property=After={service}"),
                format!("--property=Wants={service}"),
                "--no-block".to_string(),
                "/bin/true".to_string(),
            ])
            .output()
            .expect("run systemd-run for the dependent unit");
        if !dep.status.success() {
            eprintln!(
                "SKIP (the ordered dependent could not be created): {}",
                String::from_utf8_lossy(&dep.stderr).trim()
            );
            return;
        }

        // DERIVED, not chosen: one slow activation, then the remaining starts of the
        // burst each separated by the shipped restart delay, plus scheduling slack.
        let deadline = Duration::from_secs(
            slow_activation_secs + burst * (restart_secs + 1) + TERMINAL_STATE_SLACK_SECS,
        );
        let waited_from = Instant::now();
        let mut active_state = String::new();
        let mut result = String::new();
        let mut sub_state = String::new();
        let mut n_restarts = String::new();
        let mut starts = None;
        while waited_from.elapsed() < deadline {
            active_state = systemctl_property(&service, "ActiveState");
            result = systemctl_property(&service, "Result");
            sub_state = systemctl_property(&service, "SubState");
            n_restarts = systemctl_property(&service, "NRestarts");
            starts = activation_count(&counter);
            if starts.is_some_and(|count| count > burst) {
                panic!(
                    "systemd ran more than the shipped burst of {burst} activations: \
                     starts={starts:?}, ActiveState={active_state}, SubState={sub_state}, \
                     Result={result}, NRestarts={n_restarts}"
                );
            }
            // The fixture counter, rather than Result, proves the service reached the exact
            // allowed burst. `Result` is retained below as a diagnostic because some managers
            // leave it at `exit-code` after a rate-limited restart is refused.
            if active_state == "failed" && starts == Some(burst) {
                break;
            }
            std::thread::sleep(POLL_SPACING);
        }
        let diagnostic = format!(
            "starts={starts:?}, ActiveState={active_state}, SubState={sub_state}, \
             Result={result}, NRestarts={n_restarts}"
        );
        assert_eq!(
            active_state, "failed",
            "a unit whose activation keeps failing must reach a TERMINAL failed state \
             within {deadline:?}; {diagnostic}"
        );
        assert_eq!(
            starts,
            Some(burst),
            "the fixture must run exactly the shipped start burst before a retry is refused; \
             {diagnostic}"
        );

        // The next automatic retry is the one systemd must refuse. Keep observing for that
        // full retry period plus the existing scheduler slack: a sixth activation fails
        // immediately above, while a stable counter proves the restart loop is bounded.
        let stability_deadline = Instant::now();
        let stability_window = Duration::from_secs(restart_secs + TERMINAL_STATE_SLACK_SECS);
        while stability_deadline.elapsed() < stability_window {
            active_state = systemctl_property(&service, "ActiveState");
            result = systemctl_property(&service, "Result");
            sub_state = systemctl_property(&service, "SubState");
            n_restarts = systemctl_property(&service, "NRestarts");
            starts = activation_count(&counter);
            if starts.is_some_and(|count| count > burst) {
                panic!(
                    "the retry after the shipped burst started a sixth activation: \
                     starts={starts:?}, ActiveState={active_state}, SubState={sub_state}, \
                     Result={result}, NRestarts={n_restarts}"
                );
            }
            std::thread::sleep(POLL_SPACING);
        }
        let diagnostic = format!(
            "starts={starts:?}, ActiveState={active_state}, SubState={sub_state}, \
             Result={result}, NRestarts={n_restarts}"
        );
        assert_eq!(
            active_state, "failed",
            "the service must remain terminally failed after its refused retry; {diagnostic}"
        );
        assert_eq!(
            starts,
            Some(burst),
            "the activation counter must remain at the shipped burst after the refused retry; \
             {diagnostic}"
        );

        // And the ordered dependent is released by that terminal state.
        let mut dependent_state = String::new();
        let dependent_deadline = Instant::now();
        while dependent_deadline.elapsed() < Duration::from_secs(TERMINAL_STATE_SLACK_SECS) {
            dependent_state = systemctl_property(&dependent, "ActiveState");
            if dependent_state == "active" {
                break;
            }
            std::thread::sleep(POLL_SPACING);
        }
        assert_eq!(
            dependent_state, "active",
            "the unit ordered behind the failing service must become active once that \
             service reaches its terminal state"
        );
    }
}
