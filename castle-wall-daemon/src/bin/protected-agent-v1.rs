//! Phase 0 scaffold; no installation or workload launch is performed.

use castle_wall_daemon::linux_install::{NOT_BUILT_EXIT_CODE, NOT_BUILT_MESSAGE};

fn main() -> std::process::ExitCode {
    // Must match the fixed stub contract in src/linux_install/mod.rs.
    eprintln!("{NOT_BUILT_MESSAGE}");
    std::process::ExitCode::from(NOT_BUILT_EXIT_CODE)
}
