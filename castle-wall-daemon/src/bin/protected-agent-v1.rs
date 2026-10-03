//! Fixed install-profile trampoline; successful launch replaces this process.

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    if let Err(error) = castle_wall_daemon::agent_launch::launch() {
        // SAFETY: launch refusals use this process's stderr as the operator diagnostic channel.
        eprintln!("protected-agent-v1: refused: {error}");
    }
    std::process::ExitCode::FAILURE
}
