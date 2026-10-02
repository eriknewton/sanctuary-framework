//! Fixed install-profile trampoline; successful launch replaces this process.

fn main() -> std::process::ExitCode {
    #[cfg(target_os = "linux")]
    if let Err(error) = castle_wall_daemon::agent_launch::launch() {
        eprintln!("protected-agent-v1: refused: {error}");
    }
    std::process::ExitCode::FAILURE
}
