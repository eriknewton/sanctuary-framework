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
    println!("    --disarm                      DELETE the owned nftables table and clear its");
    println!(
        "                                  ownership journal, under the host lock. This is the"
    );
    println!(
        "                                  ONLY action that removes enforcement state; ordinary"
    );
    println!(
        "                                  shutdown / SIGTERM / systemd stop NEVER does. Refuses"
    );
    println!("                                  if the daemon is running or the table is foreign.");
}

fn has_structural_flag(args: &[String], wanted: &str) -> bool {
    let value_options = [
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
    }

    // Recovery action: `--disarm` is the ONE explicit, unmistakable path that
    // deletes the owned nftables table and clears its ownership journal. It is
    // deliberately handled BEFORE the run-config parser and is NOT a mode of the
    // normal daemon lifecycle: ordinary shutdown / SIGTERM / systemd stop never
    // disarm. It needs no fortress config (it operates on the host-global lock,
    // journal, and table).
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

    let config = match DaemonConfig::from_argv(parser_args.iter().map(|s| s.as_str())) {
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
    let outcome = handle.supervise_until_shutdown(SHUTDOWN_TICK, HEALTH_INTERVAL);
    match &outcome {
        daemon::SupervisionOutcome::KernelRuntimeLost(reason) => eprintln!(
            "castle-wall-daemon: kernel runtime lost after ready ({:?}); tearing down and \
             exiting nonzero so systemd restarts enforcement",
            reason
        ),
        daemon::SupervisionOutcome::FatalControlPath => eprintln!(
            "castle-wall-daemon: fatal control-path durability failure after commit; \
             tearing down and exiting nonzero so systemd restarts enforcement"
        ),
        daemon::SupervisionOutcome::ShutdownRequested => {}
    }
    let report = match handle.stop() {
        Ok(r) => r,
        Err(err) => {
            // SAFETY: stderr is the CLI shutdown-error contract here, not a
            // log channel. Emitted after the audit channel has been drained;
            // this is the operator-visible failure signal on the normal
            // shutdown path.
            eprintln!("castle-wall-daemon: shutdown error: {}", err);
            return ExitCode::from(75);
        }
    };
    // A post-ready runtime loss is a failure exit even though teardown was
    // clean: systemd must see nonzero to apply Restart=on-failure.
    if !matches!(outcome, daemon::SupervisionOutcome::ShutdownRequested) {
        return ExitCode::from(75);
    }
    // SAFETY: stdout is the CLI clean-exit contract here, not a log channel.
    // Operators rely on this line to confirm the daemon stopped cleanly.
    println!(
        "castle-wall-daemon: clean exit (uptime {:?}, audit overflow {}, audit remaining {})",
        report.uptime, report.audit_overflow_count, report.audit_remaining
    );
    ExitCode::SUCCESS
}
