//! `sanctuary-plugin-launcher` CLI front-end.
//!
//! Thin privileged preamble that parses a launch spec from argv + inherited
//! fds and hands off to `castle_wall_daemon::launcher::construct_confinement`,
//! which builds the full plugin sandbox (namespaces, rootfs pivot, cgroup,
//! rlimits, fd/env scrub, seccomp + capability drop), writes the
//! realized-confinement report to the host, and execs the bundle entry.
//!
//! Fail-closed contract: this process either execs the confined plugin (and
//! never returns) or exits non-zero having executed NO plugin code. There is
//! no path in which a partially built sandbox runs the entry. The seccomp
//! filter is installed (step 6) before exec (step 7), so even an exec failure
//! cannot fall through to running an unconfined program.
//!
//! Usage:
//!   sanctuary-plugin-launcher \
//!     --plugin-id <id> --instance-id <id> --mode <rootless|privileged> \
//!     --bundle-dir <abs> --scratch-dir <abs> --cgroup-path <abs> \
//!     --rootfs-hash <hex> --control-pipe-fd <n> --broker-fd <n> \
//!     --entry <relpath> [--rlimit-cpu <s>] [--rlimit-as <bytes>] \
//!     [--rlimit-nofile <n>] -- <entry args...>

use std::process;

use castle_wall_daemon::launcher::{construct_confinement, LaunchSpec, PrivilegeMode};

fn main() {
    if let Err(err) = run() {
        // SAFETY: sanctuary-plugin-launcher is a privileged CLI preamble;
        // stderr is the operator/supervisor contract for usage and abort
        // reasons. Any error here means NO plugin was exec'd; exit 1 fails
        // closed so the supervisor treats the launch as failed and never
        // services an instance whose sandbox was not fully built.
        eprintln!("sanctuary-plugin-launcher: {err}");
        process::exit(1);
    }
    // `construct_confinement` returns `Infallible` on success (it execs and
    // never returns), so reaching here at all is a logic error: fail closed.
    // SAFETY: unreachable on success because a successful launch ends in
    // execve; arriving here means the orchestrator returned Ok without
    // exec'ing, which must not run an unconfined plugin -- exit 1.
    eprintln!("sanctuary-plugin-launcher: orchestrator returned without exec; failing closed");
    process::exit(1);
}

fn run() -> Result<(), String> {
    let spec = parse_spec(std::env::args().skip(1).collect())?;
    // On success this never returns (it execs). On failure it returns an error
    // that we surface to stderr and turn into a non-zero exit.
    match construct_confinement(&spec) {
        Ok(_never) => Ok(()),
        Err(err) => Err(err.to_string()),
    }
}

struct RawSpec {
    plugin_id: Option<String>,
    instance_id: Option<String>,
    mode: Option<String>,
    bundle_dir: Option<String>,
    scratch_dir: Option<String>,
    cgroup_path: Option<String>,
    rootfs_hash: Option<String>,
    control_pipe_fd: Option<String>,
    broker_fd: Option<String>,
    entry: Option<String>,
    rlimit_cpu: u64,
    rlimit_as: u64,
    rlimit_nofile: u64,
    entry_args: Vec<String>,
}

impl Default for RawSpec {
    fn default() -> Self {
        RawSpec {
            plugin_id: None,
            instance_id: None,
            mode: None,
            bundle_dir: None,
            scratch_dir: None,
            cgroup_path: None,
            rootfs_hash: None,
            control_pipe_fd: None,
            broker_fd: None,
            entry: None,
            // Conservative defaults; the supervisor normally sets these.
            rlimit_cpu: 60,
            rlimit_as: 512 * 1024 * 1024,
            rlimit_nofile: 256,
            entry_args: Vec::new(),
        }
    }
}

fn parse_spec(argv: Vec<String>) -> Result<LaunchSpec, String> {
    let mut raw = RawSpec::default();
    let mut iter = argv.into_iter();
    while let Some(flag) = iter.next() {
        if flag == "--" {
            raw.entry_args = iter.collect();
            break;
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("flag {flag} expects a value"))?;
        match flag.as_str() {
            "--plugin-id" => raw.plugin_id = Some(value),
            "--instance-id" => raw.instance_id = Some(value),
            "--mode" => raw.mode = Some(value),
            "--bundle-dir" => raw.bundle_dir = Some(value),
            "--scratch-dir" => raw.scratch_dir = Some(value),
            "--cgroup-path" => raw.cgroup_path = Some(value),
            "--rootfs-hash" => raw.rootfs_hash = Some(value),
            "--control-pipe-fd" => raw.control_pipe_fd = Some(value),
            "--broker-fd" => raw.broker_fd = Some(value),
            "--entry" => raw.entry = Some(value),
            "--rlimit-cpu" => raw.rlimit_cpu = parse_u64("--rlimit-cpu", &value)?,
            "--rlimit-as" => raw.rlimit_as = parse_u64("--rlimit-as", &value)?,
            "--rlimit-nofile" => raw.rlimit_nofile = parse_u64("--rlimit-nofile", &value)?,
            other => return Err(format!("unknown flag {other}")),
        }
    }

    let mode = match raw.mode.as_deref() {
        Some("rootless") | Some("rootless_userns") => PrivilegeMode::RootlessUserns,
        Some("privileged") => PrivilegeMode::Privileged,
        Some(other) => return Err(format!("invalid --mode {other} (rootless|privileged)")),
        None => return Err("missing --mode".to_string()),
    };

    let control_pipe_fd = parse_i32(
        "--control-pipe-fd",
        &require(raw.control_pipe_fd, "--control-pipe-fd")?,
    )?;
    let broker_fd = parse_i32("--broker-fd", &require(raw.broker_fd, "--broker-fd")?)?;

    Ok(LaunchSpec {
        plugin_id: require(raw.plugin_id, "--plugin-id")?,
        instance_id: require(raw.instance_id, "--instance-id")?,
        privilege_mode: mode,
        bundle_dir: require(raw.bundle_dir, "--bundle-dir")?,
        scratch_dir: require(raw.scratch_dir, "--scratch-dir")?,
        entry_relpath: require(raw.entry, "--entry")?,
        entry_args: raw.entry_args,
        cgroup_path: require(raw.cgroup_path, "--cgroup-path")?,
        rootfs_hash: require(raw.rootfs_hash, "--rootfs-hash")?,
        control_pipe_fd,
        broker_fd,
        rlimit_cpu_seconds: raw.rlimit_cpu,
        rlimit_as_bytes: raw.rlimit_as,
        rlimit_nofile: raw.rlimit_nofile,
    })
}

fn require(value: Option<String>, flag: &str) -> Result<String, String> {
    value.ok_or_else(|| format!("missing {flag}"))
}

fn parse_i32(flag: &str, value: &str) -> Result<i32, String> {
    value
        .parse::<i32>()
        .map_err(|e| format!("{flag} must be an integer: {e}"))
}

fn parse_u64(flag: &str, value: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .map_err(|e| format!("{flag} must be a non-negative integer: {e}"))
}
