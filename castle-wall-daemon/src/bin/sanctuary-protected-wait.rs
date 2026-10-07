// Release-disabled production wrapper. Even a valid signed release cannot
// reach an exec arm in this binary: there is no exec arm, and no admission,
// CREATE or release engine exists anywhere in this slice for one to consume.
// It refuses in every build, and the refusal is the behaviour, not a fallback
// from a backend that failed.
fn main() {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            std::process::exit(1);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if status.lines().find_map(|l| l.strip_prefix("TracerPid:\t")) != Some("0") {
            std::process::exit(1);
        }
    }
    // SAFETY: stderr states the refusal that IS this binary's whole behaviour,
    // so that a caller which somehow reaches it sees why it exited non-zero
    // rather than an unexplained failure.
    eprintln!("sanctuary-protected-wait: release is disabled");
    std::process::exit(1)
}
