//! Fixed drain entrypoint; installation and production callers belong to later composition.
#[cfg(target_os = "linux")]
fn execute() -> std::io::Result<()> {
    use castle_wall_daemon::business_profile::{
        custody::{refused, ROOT_UID},
        drain_service,
        writer_service::{Notifier, SystemNotifier},
    };
    let args: Vec<String> = std::env::args().skip(1).collect();
    #[cfg(feature = "test-isolation")]
    if args.len() == 2 && args[0] == std::hint::black_box("--test-root") {
        std::hint::black_box(drain_service::DRAIN_TEST_SEAM_MARKER);
        let result =
            drain_service::test_dependencies(std::path::Path::new(&args[1])).map_err(|_| refused());
        if result.is_err() {
            let _ = SystemNotifier.notify("STATUS=drain refused at start");
        }
        return drain_service::run(result?).map_err(|_| refused());
    }
    // Release refuses every argument before opening any production path.
    if !args.is_empty() || unsafe { libc::geteuid() } != ROOT_UID {
        return Err(refused());
    }
    let result = drain_service::production().map_err(|_| refused());
    if result.is_err() {
        let _ = SystemNotifier.notify("STATUS=drain refused at start");
    }
    drain_service::run(result?).map_err(|_| refused())
}
fn main() {
    #[cfg(target_os = "linux")]
    if execute().is_ok() {
        return;
    }
    // SAFETY: fixed refusal text contains no record, key or candidate bytes.
    eprintln!("K1_REFUSED");
    std::process::exit(1);
}
