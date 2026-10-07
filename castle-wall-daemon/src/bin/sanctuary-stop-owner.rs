#[cfg(target_os = "linux")]
fn main() {
    if let Err(e) = castle_wall_daemon::protected_agent::owner::serve_production() {
        // SAFETY: stderr is the operator channel for a startup refusal. The
        // owner has no ready logging path before it binds, and systemd's
        // journal is where an operator reads why the unit failed to start.
        eprintln!("sanctuary-stop-owner: refused: {e}");
        std::process::exit(1)
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(1)
}
