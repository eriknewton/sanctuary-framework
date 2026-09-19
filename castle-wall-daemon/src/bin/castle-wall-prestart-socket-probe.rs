//! Test-isolation build only. Fixed owner-socket transport/DAC probe for a
//! separately measured prestart-equivalent sandbox; no business RPC or key.
#[cfg(target_os = "linux")]
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(1);
    }
    let result = std::os::unix::net::UnixStream::connect(
        castle_wall_daemon::protected_agent::owner::SOCKET_PATH,
    );
    if result.is_err() {
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(1);
}
