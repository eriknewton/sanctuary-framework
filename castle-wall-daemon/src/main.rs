//! Castle Wall daemon entry point.
//!
//! PR 2a behavior: parse argv, print a startup banner, exit 0 if `--help`,
//! exit 0 after one tick if `--phase2a-stub` is passed (used by integration
//! tests). The full lifecycle (UDS bind, accept loop, NFQUEUE bind, manifest
//! watcher, journal listener, audit drain) lands in PR 2b.

use std::process::ExitCode;

use castle_wall_daemon::config::{ConfigError, DaemonConfig};

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
    println!("    --phase2a-stub                Print boot summary and exit (PR 2a only)");
    println!("    -h, --help                    Print help");
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let phase2a_stub = args.iter().any(|a| a == "--phase2a-stub");
    let parser_args: Vec<String> = args
        .into_iter()
        .filter(|a| a != "--phase2a-stub")
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
        "castle-wall-daemon: PR 2a stub for fortress {} (socket {}, policy {}, wal {})",
        config.fortress_id,
        config.socket_path.display(),
        config.policy_dir.display(),
        config.wal_path.display()
    );

    if phase2a_stub {
        println!("castle-wall-daemon: --phase2a-stub set; exiting cleanly without binding kernel surfaces");
        return ExitCode::SUCCESS;
    }

    eprintln!(
        "castle-wall-daemon: kernel-enforcement modules ship in PR 2b. \
         Re-run with --phase2a-stub to verify the binary path.\n\
         See castle-wall-daemon/README.md for the PR 2a / PR 2b split."
    );
    ExitCode::from(75)
}
