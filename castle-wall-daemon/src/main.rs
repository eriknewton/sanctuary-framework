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
    println!("castle-wall-daemon (Sanctuary Castle Wall filter daemon)");
    println!();
    println!("USAGE:");
    println!("    castle-wall-daemon --fortress-id <hex> [options]");
    println!();
    println!("OPTIONS:");
    println!("    --fortress-id <hex>           Fortress identifier (required)");
    println!("    --socket-path <path>          Override default UDS path");
    println!("    --policy-dir <path>           Override default policy directory");
    println!("    --wal-path <path>             Override default WAL path");
    println!("    --pinned-public-key <path>    Override default pinned key path");
    println!("    --boot-and-exit               Boot, run for one tick, then exit (CI smoke)");
    println!("    -h, --help                    Print help");
}

const SHUTDOWN_TICK: Duration = Duration::from_millis(200);

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let boot_and_exit = args.iter().any(|a| a == "--boot-and-exit");
    let parser_args: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--boot-and-exit")
        .collect();

    let config = match DaemonConfig::from_argv(parser_args.iter().map(|s| s.as_str())) {
        Ok(c) => c,
        Err(ConfigError::HelpRequested) => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Err(err) => {
            eprintln!("castle-wall-daemon: {}", err);
            print_help();
            return ExitCode::from(2);
        }
    };

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
            eprintln!(
                "{}",
                daemon::refuse_to_start_message(&disposition, &err.to_string())
            );
            return ExitCode::from(75);
        }
    };

    if boot_and_exit {
        println!("castle-wall-daemon: --boot-and-exit set; tearing down after one tick");
        std::thread::sleep(SHUTDOWN_TICK);
        let report = match handle.stop() {
            Ok(r) => r,
            Err(err) => {
                eprintln!("castle-wall-daemon: shutdown error: {}", err);
                return ExitCode::from(75);
            }
        };
        println!(
            "castle-wall-daemon: clean exit (uptime {:?}, audit overflow {}, audit remaining {})",
            report.uptime, report.audit_overflow_count, report.audit_remaining
        );
        return ExitCode::SUCCESS;
    }

    handle.wait_for_shutdown(SHUTDOWN_TICK);
    let report = match handle.stop() {
        Ok(r) => r,
        Err(err) => {
            eprintln!("castle-wall-daemon: shutdown error: {}", err);
            return ExitCode::from(75);
        }
    };
    println!(
        "castle-wall-daemon: clean exit (uptime {:?}, audit overflow {}, audit remaining {})",
        report.uptime, report.audit_overflow_count, report.audit_remaining
    );
    ExitCode::SUCCESS
}
