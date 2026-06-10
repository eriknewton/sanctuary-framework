use std::os::unix::process::CommandExt;
use std::process::{self, Command};

use castle_wall_daemon::jail;

fn main() {
    if let Err(err) = run() {
        // SAFETY: sanctuary-jail is a CLI preamble; stderr is the operator
        // contract for usage, confinement, and exec failures.
        eprintln!("sanctuary-jail: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let split = argv
        .iter()
        .position(|arg| arg == "--")
        .ok_or_else(usage_error)?;
    let command_argv = &argv[(split + 1)..];
    let program = command_argv.first().ok_or_else(usage_error)?;

    jail::confine_current_process().map_err(|err| err.to_string())?;

    // SAFETY: the "[JAIL]" stderr marker is the drill/operator evidence
    // contract: run-launcher-integration-drill.sh greps for the substring
    // "launcher-applied seccomp-deny-AF_VSOCK installed" (parity with the
    // macOS launcher's python preamble marker). The wrapped program's stdio
    // is otherwise untouched.
    eprintln!(
        "[JAIL] launcher-applied seccomp-deny-AF_VSOCK installed before plugin exec (sanctuary-jail)"
    );

    let mut command = Command::new(program);
    command.args(&command_argv[1..]);
    let err = command.exec();
    Err(format!("exec failed for {program}: {err}"))
}

fn usage_error() -> String {
    "usage: sanctuary-jail -- <program> [args...]".to_string()
}
