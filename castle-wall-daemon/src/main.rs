//! Castle Wall daemon entry point.
//!
//! Boots the daemon: parses argv, loads the pinned fortress public key,
//! binds the IPC UDS, installs SIGTERM/SIGINT handlers, and waits for a
//! shutdown signal. Real Castle Layer 1 enforcement (nftables ruleset
//! install, NFQUEUE bind, manifest watcher) lights up as PR 2b's later
//! checkpoints land. On non-Linux dev hosts, the binary still boots so
//! `cargo check` and `cargo test` work; the kernel-touching paths
//! refuse-to-start with operator-friendly errors at runtime.

use std::process::ExitCode;
use std::time::Duration;

use castle_wall_daemon::config::{ConfigError, DaemonConfig};
use castle_wall_daemon::daemon;

fn print_help() {
    // SAFETY: stdout is the CLI --help contract here, not a log channel. CLI
    // convention requires help text on stdout; the contiguous println! block
    // below is structural operator output and is the channel itself.
    println!("castle-wall-daemon (Sanctuary Castle Wall filter daemon)");
    println!();
    println!("USAGE:");
    println!("    castle-wall-daemon --fortress-id <hex> [options]");
    println!();
    println!("OPTIONS:");
    println!("    --fortress-id <hex>           Fortress identifier (required)");
    println!("    --trusted-service-uid <uid>   Dedicated Sanctuary broker UID (required)");
    println!("    --socket-path <path>          Override default UDS path");
    println!("    --policy-dir <path>           Override default policy directory");
    println!("    --wal-path <path>             Override default WAL path");
    println!("    --pinned-public-key <path>    Override default pinned key path");
    println!("    --boot-and-exit               Boot, run for one tick, then exit (CI smoke)");
    println!("    -h, --help                    Print help");
    println!();
    println!("RECOVERY:");
    // SAFETY: stdout is the CLI --help contract, same as the block above.
    // One call rather than five: rustfmt wraps a long single-argument `println!`
    // onto its own lines, and the closing `);` of a wrapped call breaks the
    // stdout-discipline gate's walk-back to the SAFETY note at the top of this
    // function, so each wrapped call would need its own duplicate annotation.
    // A single literal keeps the help text one block with one channel contract.
    println!(
        "    --preflight-manifest          Answer whether THIS host will admit the installed\n\
         \x20                                 manifest, WITHOUT taking the host lock and without\n\
         \x20                                 touching kernel state, so it is safe to run while\n\
         \x20                                 the daemon is up. Run it with the NEW binary BEFORE\n\
         \x20                                 replacing the old one: exits non-zero and names the\n\
         \x20                                 remediation when the manifest would not be admitted."
    );
    // SAFETY: stdout is the CLI --help contract, same as the blocks above.
    println!(
        "    --disarm                      DELETE the owned nftables table and clear its\n\
         \x20                                 ownership journal, under the host lock. This is the\n\
         \x20                                 ONLY action that removes enforcement state; ordinary\n\
         \x20                                 shutdown / SIGTERM / systemd stop NEVER does. Refuses\n\
         \x20                                 if the daemon is running or the table is foreign."
    );
}

fn has_structural_flag(args: &[String], wanted: &str) -> bool {
    #[allow(unused_mut)]
    let mut value_options: Vec<&str> = vec![
        "--fortress-id",
        "--socket-path",
        "--policy-dir",
        "--wal-path",
        "--pinned-public-key",
        "--producer-key",
        "--producer-pub-key",
        "--trusted-service-uid",
        "--isolated-runtime-root",
        "--isolated-castle-table-tag",
    ];
    // F5 (LINUX-STOP-LOSS-RACE-01, Claude F5, gate I5): the two W1a/W1b
    // value-taking test-isolation seams are listed here ONLY under
    // `test-isolation`, so this scan correctly skips their value while
    // looking for `--disarm` / `--preflight-manifest` in a test-isolation
    // build. A release build never carries these two entries, so its argv
    // scan is byte-identical to base: `--test-health-interval-ms` /
    // `--test-shutdown-at` are unrecognized structural flags there and their
    // value is scanned as an ordinary positional argument, exactly as before
    // this seam existed. The flags themselves are parsed and stripped only
    // under `#[cfg(feature = "test-isolation")]` in `main`, and the real
    // behavior they arm never compiles into a release build either way.
    #[cfg(feature = "test-isolation")]
    {
        value_options.push("--test-health-interval-ms");
        value_options.push("--test-shutdown-at");
    }
    // Invariant: `args` is already `std::env::args().skip(1)` (the program name
    // is stripped by the caller), so scanning MUST start at index 0. Starting at
    // 1 silently skips a structural flag that is the FIRST argument, which is
    // exactly how `--disarm` (the operator recovery verb) and the test-isolation
    // fail-stop trigger are invoked; missing them there sends the flag on to the
    // config parser, which rejects it as unknown and exits 2 instead of acting.
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == wanted {
            return true;
        }
        index += if value_options.contains(&args[index].as_str()) {
            2
        } else {
            1
        };
    }
    false
}

/// Run the explicit `--disarm` recovery action and map its outcome to a process
/// exit code. Success (a deleted table, a cleared stale record, or nothing to do)
/// exits 0; a refusal/ambiguity exits nonzero so an operator or script sees the
/// failure. This is the ONLY action that removes enforcement state.
fn run_disarm(args: &[String]) -> ExitCode {
    // Production always disarms the production paths. In a test-isolation build a
    // spawned `--disarm` can be aimed at the same temporary root the daemon under
    // test used, so the suite proves the real recovery verb without deleting the
    // operator's ownership journal.
    let paths = resolve_disarm_paths(args);
    match daemon::disarm_with(&paths) {
        Ok(outcome) => {
            // SAFETY: stdout is the CLI disarm-result contract here, not a log
            // channel; an operator/script scrapes this line.
            println!("castle-wall-daemon: disarm complete — {outcome}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            // SAFETY: stderr is the CLI disarm-failure contract here. Disarm fails
            // closed (journal retained) on any ambiguity, so a nonzero exit is the
            // operator-visible "did NOT disarm" signal.
            eprintln!("castle-wall-daemon: {err}");
            ExitCode::from(75)
        }
    }
}

// Supervision cadence lives in the library so the nft health-probe budget can be
// DERIVED from it (a real ownership proof must complete inside one tick) and a
// unit test can pin that relationship. Aliased here to keep `main` readable.
/// Run the `--preflight-manifest` check and map its outcome to a process exit code.
///
/// INVARIANT: this function reaches NO lock and NO kernel path. It resolves two file
/// paths, calls the pure check, prints one line and exits. `--disarm`'s
/// `resolve_disarm_paths` is deliberately not reused here, because those are the
/// host lock and journal paths and this verb must not open them.
fn run_preflight_manifest(args: &[String]) -> ExitCode {
    // The installed manifest lives under the fortress's own state directory, so the
    // verb needs either the fortress id (to derive the canonical layout) or both
    // paths explicitly. Naming the missing input beats defaulting to a directory the
    // operator did not mean.
    let explicit_policy_dir = flag_value(args, "--policy-dir").map(std::path::PathBuf::from);
    let explicit_pinned = flag_value(args, "--pinned-public-key").map(std::path::PathBuf::from);
    let derived = flag_value(args, "--fortress-id")
        .map(castle_wall_daemon::config::DaemonConfig::defaults_for_fortress);
    let (policy_dir, pinned_key) = match (explicit_policy_dir, explicit_pinned, derived) {
        (Some(dir), Some(key), _) => (dir, key),
        (dir, key, Some(defaults)) => (
            dir.unwrap_or(defaults.policy_dir),
            key.unwrap_or(defaults.pinned_public_key_path),
        ),
        _ => {
            // SAFETY: stderr is the CLI preflight-failure contract, as below.
            eprintln!(
                "castle-wall-daemon: preflight-manifest FAILED — pass --fortress-id, or both \
                 --policy-dir and --pinned-public-key, so the check reads the manifest you mean"
            );
            return ExitCode::from(1);
        }
    };
    let outcome = castle_wall_daemon::policy::preflight_manifest(&policy_dir, &pinned_key);
    if outcome.is_ok() {
        // SAFETY: stdout is the CLI preflight-result contract here, not a log channel.
        // An operator and an upgrade script both read this exact line.
        println!(
            "castle-wall-daemon: preflight-manifest — {}",
            outcome.message()
        );
        ExitCode::SUCCESS
    } else {
        // SAFETY: stderr is the CLI preflight-failure contract. The nonzero exit beside
        // this line is what aborts an upgrade before the binary is replaced.
        eprintln!(
            "castle-wall-daemon: preflight-manifest FAILED — {}",
            outcome.message()
        );
        ExitCode::from(1)
    }
}

/// The value following `flag` in `args`, when present.
fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Which host-global paths `--disarm` operates on. Always production unless a
/// test-isolation build was given `--isolated-runtime-root`.
fn resolve_disarm_paths(args: &[String]) -> castle_wall_daemon::config::LinuxRuntimePaths {
    #[cfg(feature = "test-isolation")]
    {
        if let Some(index) = args.iter().position(|a| a == "--isolated-runtime-root") {
            if let Some(root) = args.get(index + 1) {
                return castle_wall_daemon::config::LinuxRuntimePaths::isolated_under(
                    std::path::Path::new(root),
                );
            }
        }
    }
    let _ = args;
    castle_wall_daemon::config::LinuxRuntimePaths::production()
}

const SHUTDOWN_TICK: Duration = daemon::SUPERVISOR_SHUTDOWN_TICK;
const HEALTH_INTERVAL: Duration = daemon::SUPERVISOR_HEALTH_INTERVAL;

/// TEST-ISOLATION ONLY. Compiled out of the shipped binary.
///
/// The privileged Linux suite spawns this binary as a subprocess, so the
/// subprocess needs its own way to land on an isolated nftables table; without
/// it a spawned daemon would create and delete the operator's real
/// `sanctuary-castle` table. Consumes `--isolated-castle-table-tag <tag>` before
/// any other work, since the table name must be resolved before the first nft
/// call. A release build has no such flag and rejects it as unknown.
#[cfg(feature = "test-isolation")]
fn install_isolated_castle_table(args: &[String]) -> Result<(), String> {
    let Some(index) = args.iter().position(|a| a == "--isolated-castle-table-tag") else {
        return Ok(());
    };
    let tag = args
        .get(index + 1)
        .ok_or_else(|| "missing value for --isolated-castle-table-tag".to_string())?;
    castle_wall_daemon::nftables::use_isolated_castle_table(&format!(
        "{}{tag}",
        castle_wall_daemon::nftables::ISOLATED_TABLE_PREFIX
    ))
    .map(|_| ())
}

fn main() -> ExitCode {
    // `mut` is used only by the feature-gated isolation-flag strip below; the
    // allow keeps a production build warning-clean without a second code path.
    #[cfg_attr(not(feature = "test-isolation"), allow(unused_mut))]
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // W1a/W1b (LINUX-STOP-LOSS-RACE-01): the two wired-consumer test seams.
    // Declared outside the block below so their parsed values survive it; both
    // stay `None` and unread on every non-test-isolation build.
    #[cfg(feature = "test-isolation")]
    let mut test_health_interval_ms: Option<u64> = None;
    #[cfg(feature = "test-isolation")]
    let mut test_shutdown_at: Option<String> = None;

    #[cfg(feature = "test-isolation")]
    {
        if has_structural_flag(&args, "--test-trigger-nfqueue-deadline-fail-stop") {
            castle_wall_daemon::nfqueue::trigger_verdict_deadline_fail_stop_for_test();
        }
        if let Err(err) = install_isolated_castle_table(&args) {
            // SAFETY: stderr is the CLI parse-error contract here; this branch
            // exists only in a test-isolation build.
            eprintln!("castle-wall-daemon: {err}");
            return ExitCode::from(2);
        }
        if let Some(index) = args.iter().position(|a| a == "--isolated-castle-table-tag") {
            args.drain(index..=(index + 1).min(args.len() - 1));
        }
        // W1a: drained (name + value) before the run-config parser sees it, or
        // that parser rejects it as unknown. Space-separated, matching every
        // other value-taking flag in this file (e.g. `--isolated-runtime-root
        // <path>`), not the `--flag=value` form the design memo uses as prose.
        if let Some(index) = args.iter().position(|a| a == "--test-health-interval-ms") {
            let value = args.get(index + 1).cloned();
            args.drain(index..=(index + 1).min(args.len() - 1));
            match value.and_then(|v| v.parse::<u64>().ok()) {
                Some(ms) => test_health_interval_ms = Some(ms),
                None => {
                    // SAFETY: stderr is the CLI parse-error contract, as above.
                    eprintln!(
                        "castle-wall-daemon: --test-health-interval-ms requires a numeric \
                         millisecond value"
                    );
                    return ExitCode::from(2);
                }
            }
        }
        // W1b: same drain-before-parse requirement. `pre-recovery` must match
        // `DaemonHandle::arm_test_shutdown_at_pre_recovery`'s doc comment in
        // `daemon.rs`. `boot-acquire` is the boot-phase counterpart (A162,
        // LINUX-BOOT-STOP-HOSTWIDE-NET-01): applied to `config` below, BEFORE
        // `daemon::boot` is called, rather than armed on the handle afterward,
        // because the sites it exercises run inside `boot()`'s acquisition,
        // before any `DaemonHandle` exists.
        if let Some(index) = args.iter().position(|a| a == "--test-shutdown-at") {
            let value = args.get(index + 1).cloned();
            args.drain(index..=(index + 1).min(args.len() - 1));
            match value.as_deref() {
                Some("pre-recovery") | Some("boot-acquire") => test_shutdown_at = value,
                _ => {
                    // SAFETY: stderr is the CLI parse-error contract, as above.
                    eprintln!(
                        "castle-wall-daemon: --test-shutdown-at accepts only 'pre-recovery' or \
                         'boot-acquire'"
                    );
                    return ExitCode::from(2);
                }
            }
        }
    }

    // Recovery action: `--disarm` is the ONE explicit, unmistakable path that
    // deletes the owned nftables table and clears its ownership journal. It is
    // deliberately handled BEFORE the run-config parser and is NOT a mode of the
    // normal daemon lifecycle: ordinary shutdown / SIGTERM / systemd stop never
    // disarm. It needs no fortress config (it operates on the host-global lock,
    // journal, and table).
    // Pre-replacement check. Handled BEFORE `--disarm` and before the run-config
    // parser, and deliberately NOT a mode of the daemon lifecycle: it takes no lock,
    // touches no kernel state, and so is the one verb that is safe to run while the
    // daemon is up. Must match `crate::policy::preflight_manifest`, which enforces
    // that by construction.
    if has_structural_flag(&args, "--preflight-manifest") {
        return run_preflight_manifest(&args);
    }

    if has_structural_flag(&args, "--disarm") {
        return run_disarm(&args);
    }

    let boot_and_exit = args.iter().any(|a| a == "--boot-and-exit");
    #[cfg(feature = "test-isolation")]
    let trigger_fatal_control_path = args
        .iter()
        .any(|a| a == "--test-trigger-fatal-control-path");
    let parser_args: Vec<String> = args
        .into_iter()
        .filter(|a| {
            a != "--boot-and-exit" && {
                #[cfg(feature = "test-isolation")]
                {
                    a != "--test-trigger-fatal-control-path"
                }
                #[cfg(not(feature = "test-isolation"))]
                {
                    true
                }
            }
        })
        .collect();

    #[cfg_attr(not(feature = "test-isolation"), allow(unused_mut))]
    let mut config = match DaemonConfig::from_argv(parser_args.iter().map(|s| s.as_str())) {
        Ok(c) => c,
        Err(ConfigError::HelpRequested) => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            // SAFETY: stderr is the CLI parse-error contract here, not a log
            // channel. argv parsing happens before any logging facility could
            // be initialized; CLI convention requires error text on stderr.
            eprintln!("castle-wall-daemon: {}", err);
            print_help();
            return ExitCode::from(2);
        }
    };
    // A162: applied to `config` BEFORE `daemon::boot` runs, unlike
    // `test_health_interval_ms` and `arm_test_shutdown_at_pre_recovery` (both
    // applied after boot returns a handle) -- this seam's sites run INSIDE
    // `boot()`'s acquisition, before any handle exists.
    #[cfg(feature = "test-isolation")]
    if test_shutdown_at.as_deref() == Some("boot-acquire") {
        config.test_boot_time_shutdown_requested = true;
    }

    // SAFETY: stdout is the CLI startup-banner contract here, not a log
    // channel. The banner is emitted before daemon::boot installs the audit
    // channel; this line is the operator-visible "starting" signal.
    println!(
        "castle-wall-daemon: starting for fortress {} (socket {}, policy {}, wal {})",
        config.fortress_id,
        config.socket_path.display(),
        config.policy_dir.display(),
        config.wal_path.display()
    );

    let handle = match daemon::boot(config) {
        Ok(h) => h,
        Err(err) => {
            let mode = daemon::mode_for_error(&err);
            let disposition = castle_wall_daemon::failure::default_disposition(mode);
            // SAFETY: stderr is the CLI refuse-to-start contract here, not a
            // log channel. The message body is operator-formatted upstream by
            // failure::default_disposition; this site is the visible surface.
            eprintln!(
                "{}",
                daemon::refuse_to_start_message(&disposition, &err.to_string())
            );
            return ExitCode::from(75);
        }
    };

    #[cfg(feature = "test-isolation")]
    if trigger_fatal_control_path {
        handle.request_fatal_control_path_for_test();
    }
    // W1b: armed only after a successful boot, so the seam cannot fire before a
    // handle exists to flip. `boot-acquire` is applied to `config` earlier
    // instead (its sites run before a handle exists), so it is excluded here.
    #[cfg(feature = "test-isolation")]
    if test_shutdown_at.as_deref() == Some("pre-recovery") {
        handle.arm_test_shutdown_at_pre_recovery();
    }

    if boot_and_exit {
        // SAFETY: stdout is the CLI boot-and-exit lifecycle contract here,
        // not a log channel. CI smoke harnesses scrape this exact line.
        println!("castle-wall-daemon: --boot-and-exit set; tearing down after one tick");
        std::thread::sleep(SHUTDOWN_TICK);
        let smoke_failure = if handle.is_fatal_control_path_requested() {
            Some("fatal control-path latch was set".to_string())
        } else {
            match handle.kernel_runtime_health() {
                castle_wall_daemon::runtime_health::RuntimeHealthState::Lost(reason) => {
                    Some(format!("kernel runtime was lost: {reason:?}"))
                }
                castle_wall_daemon::runtime_health::RuntimeHealthState::ProbeUnavailable => {
                    Some("kernel runtime health was unprovable".to_string())
                }
                castle_wall_daemon::runtime_health::RuntimeHealthState::Indeterminate => {
                    Some("kernel runtime health remained indeterminate".to_string())
                }
                // A proven loss with a safety-net attempt still outstanding. Reported
                // as a smoke failure (it is not readiness) and NEVER treated as ready,
                // but it is named distinctly from a plain loss so the harness output
                // says the net was going in rather than implying nothing happened.
                // Must match `RuntimeHealthState::Recovering`.
                castle_wall_daemon::runtime_health::RuntimeHealthState::Recovering(reason) => {
                    Some(format!(
                        "kernel runtime was lost and the safety net is being installed \
                         for it: {reason:?}"
                    ))
                }
                castle_wall_daemon::runtime_health::RuntimeHealthState::Ready
                | castle_wall_daemon::runtime_health::RuntimeHealthState::NoRuntime => None,
            }
        };
        let report = match handle.stop() {
            Ok(r) => r,
            Err(err) => {
                // SAFETY: stderr is the CLI shutdown-error contract here, not
                // a log channel. Emitted after the audit channel has been
                // drained; this is the operator-visible failure signal.
                eprintln!("castle-wall-daemon: shutdown error: {}", err);
                return ExitCode::from(75);
            }
        };
        if let Some(reason) = smoke_failure {
            // SAFETY: stderr is the CLI smoke-failure contract, not a log channel. The
            // boot-and-exit CI harness scrapes this line and the nonzero exit beside it.
            eprintln!("castle-wall-daemon: boot-and-exit smoke failed: {reason}");
            return ExitCode::from(75);
        }
        // SAFETY: stdout is the CLI clean-exit contract here, not a log
        // channel. The boot-and-exit smoke harness asserts on this line.
        println!(
            "castle-wall-daemon: clean exit (uptime {:?}, audit overflow {}, audit remaining {})",
            report.uptime, report.audit_overflow_count, report.audit_remaining
        );
        return ExitCode::SUCCESS;
    }

    // Supervise: run until a shutdown signal OR a post-ready kernel-runtime
    // loss. A control-plane-only boot (no kernel runtime) never reports a loss,
    // so this behaves like wait_for_shutdown there; a boot that came up ready
    // and then lost the verdict thread / table / watcher returns
    // KernelRuntimeLost, which we turn into an ordered teardown and a NONZERO
    // exit so systemd (Restart=on-failure) restarts the daemon instead of
    // leaving a live-but-not-enforcing service reporting itself active.
    // W1a: a large `--test-health-interval-ms` keeps the periodic health tick
    // from firing again inside the harness's SIGTERM window, so the daemon's
    // OWN shutdown-time final health pass (S_STOP_FINAL_HEALTH) is what proves
    // the loss, not a race against the normal interval. Every non-test build
    // (and a test build that omits the flag) keeps the production constant.
    #[cfg(feature = "test-isolation")]
    let health_interval = test_health_interval_ms
        .map(Duration::from_millis)
        .unwrap_or(HEALTH_INTERVAL);
    #[cfg(not(feature = "test-isolation"))]
    let health_interval = HEALTH_INTERVAL;
    let outcome = handle.supervise_until_shutdown(SHUTDOWN_TICK, health_interval);
    match &outcome {
        // SAFETY: stderr is the operator-visible supervision-outcome contract. These
        // two arms explain a NONZERO exit that systemd is about to restart; the
        // durable audit for the loss is written by the supervision loop itself.
        daemon::SupervisionOutcome::KernelRuntimeLost(reason) => eprintln!(
            "castle-wall-daemon: kernel runtime lost after ready ({:?}); tearing down and \
             exiting nonzero so systemd restarts enforcement",
            reason
        ),
        // SAFETY: stderr is the operator-visible supervision-outcome contract; same
        // channel and reason as the KernelRuntimeLost arm above.
        daemon::SupervisionOutcome::FatalControlPath => eprintln!(
            "castle-wall-daemon: fatal control-path durability failure after commit; \
             tearing down and exiting nonzero so systemd restarts enforcement"
        ),
        daemon::SupervisionOutcome::RepairRequired {
            reason,
            install_result,
        } => {
            let detail = match install_result {
                castle_wall_daemon::enforcement::PostReadyRecoveryResult::InstallSucceeded => {
                    "the net install returned success, but journal persistence may have failed"
                }
                castle_wall_daemon::enforcement::PostReadyRecoveryResult::InstallFailed => {
                    "protection could not be proved"
                }
                _ => "unexpected recovery result",
            };
            // SAFETY: stderr is the operator-visible repair-required exit contract;
            // it names this returned recovery result before teardown.
            eprintln!("castle-wall-daemon: repair required after runtime loss ({reason:?}): {detail}; repair the host, then run `systemctl reset-failed sanctuary-castle-wall.service` and explicitly start the service; starting before repair may exit 78 again");
        }
        daemon::SupervisionOutcome::ShutdownRequested => {}
    }
    let stop_result = handle.stop();
    let report = match stop_result {
        Ok(r) => Some(r),
        Err(err) => {
            // SAFETY: stderr is the shutdown-error contract after teardown;
            // the operator needs this signal even when no report is available.
            eprintln!("castle-wall-daemon: shutdown error: {}", err);
            None
        }
    };
    let exit_status = supervision_exit_status(&outcome, report.is_some());
    if exit_status != 0 {
        return ExitCode::from(exit_status);
    }
    // Safety: status zero is possible only after a successful shutdown stop,
    // so the report is present on this branch.
    let report = report.expect("clean shutdown has a report");
    // SAFETY: stdout is the CLI clean-exit contract here, not a log channel.
    // Operators rely on this line to confirm the daemon stopped cleanly.
    println!(
        "castle-wall-daemon: clean exit (uptime {:?}, audit overflow {}, audit remaining {})",
        report.uptime, report.audit_overflow_count, report.audit_remaining
    );
    ExitCode::SUCCESS
}

fn supervision_exit_status(outcome: &daemon::SupervisionOutcome, stop_succeeded: bool) -> u8 {
    match outcome {
        daemon::SupervisionOutcome::RepairRequired { .. } => 78,
        daemon::SupervisionOutcome::ShutdownRequested if stop_succeeded => 0,
        daemon::SupervisionOutcome::ShutdownRequested
        | daemon::SupervisionOutcome::KernelRuntimeLost(_)
        | daemon::SupervisionOutcome::FatalControlPath => 75,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use castle_wall_daemon::enforcement::{ComponentKind, NotReadyReason, PostReadyRecoveryResult};

    #[test]
    fn supervision_exit_status_preserves_repair_and_shutdown_matrix() {
        let reason = NotReadyReason::SafetyNetRecovering(ComponentKind::NftablesTable);
        let repair = daemon::SupervisionOutcome::RepairRequired {
            reason,
            install_result: PostReadyRecoveryResult::InstallSucceeded,
        };
        assert_eq!(supervision_exit_status(&repair, true), 78);
        assert_eq!(supervision_exit_status(&repair, false), 78);
        assert_eq!(
            supervision_exit_status(&daemon::SupervisionOutcome::ShutdownRequested, true),
            0
        );
        assert_eq!(
            supervision_exit_status(&daemon::SupervisionOutcome::ShutdownRequested, false),
            75
        );
        assert_eq!(
            supervision_exit_status(&daemon::SupervisionOutcome::FatalControlPath, true),
            75
        );
        assert_eq!(
            supervision_exit_status(&daemon::SupervisionOutcome::FatalControlPath, false),
            75
        );
        let lost = daemon::SupervisionOutcome::KernelRuntimeLost(reason);
        assert_eq!(supervision_exit_status(&lost, true), 75);
        assert_eq!(supervision_exit_status(&lost, false), 75);
    }

    /// F5 (LINUX-STOP-LOSS-RACE-01, Claude F5, gate I5): in a build with the
    /// `test-isolation` feature OFF (this test file's own default build,
    /// unless `cargo test --features test-isolation` is explicitly requested),
    /// the two W1a/W1b seam names must be absent from `value_options`, so a
    /// trailing unrecognized flag never gets treated as a value-taking one and
    /// swallows the token after it. Before the F5 fix this args slice found no
    /// `--disarm` (the seam name unconditionally consumed `--disarm` as its own
    /// value); after the fix the scan is byte-identical to base and finds it.
    /// Lane note: CI runs every `cargo test` with `--features test-isolation`,
    /// so this witness runs only in a default-feature `cargo test` on a
    /// developer host; the structural guarantee is the `#[cfg]` on the two
    /// `value_options` entries.
    #[test]
    #[cfg(not(feature = "test-isolation"))]
    fn default_build_disarm_detection_unchanged_by_a_trailing_unknown_flag() {
        let args = vec!["--test-shutdown-at".to_string(), "--disarm".to_string()];
        assert!(
            has_structural_flag(&args, "--disarm"),
            "a default (non-test-isolation) build must not treat the test-only seam name \
             as a value-taking flag; the argv scan here must match base exactly"
        );
    }
}
