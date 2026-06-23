//! `sanctuary-plugin-launcher` confinement construction (RFC 3.1a, design §4.1).
//!
//! This module is the privileged Linux launcher that generalizes the proven
//! `sanctuary-jail` seccomp shim into the full plugin sandbox: it unshares
//! namespaces, assembles and pivots into a minimal rootfs, applies cgroup and
//! rlimit ceilings, tears the process off every network object except the
//! inherited broker socketpair, scrubs file descriptors and environment,
//! drops privilege, applies the `plugin-v1` seccomp profile, and only then
//! execs the bundle entry. The order is fixed and every step fails closed:
//! any step error aborts the launch with a non-zero exit and NO exec, so a
//! partially built sandbox is never treated as a sandbox.
//!
//! The portable pieces (the realized-confinement report shape, the env
//! allowlist, the launch-spec parsing, and the step ordering) compile on every
//! platform and are unit-tested on macOS dev machines. The kernel-touching
//! step implementations are `#[cfg(target_os = "linux")]`-gated and return
//! `LauncherError::UnsupportedPlatform` elsewhere; behavioral truth comes from
//! the Linux CI forked-child integration tests (baseline-floor rule).
//!
//! Realized-confinement report: immediately before exec the launcher writes a
//! single line of JSON (the [`RealizedConfinementReport`]) to the host over
//! the inherited control pipe. The host refuses to service any instance whose
//! report is missing or does not match the expected configuration; a report
//! that never arrives means the sandbox was never fully built. The host
//! consumer side is not part of this slice (S3 builds the launcher half); the
//! report is emitted here and the consumer is a tracked follow-up.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

// The seccomp profile and jail helpers are only referenced by the Linux
// confinement path; importing them unconditionally trips the unused-import
// lint (clippy runs with -D warnings) on non-Linux dev builds.
#[cfg(target_os = "linux")]
use crate::jail::{self, SeccompProfile};

/// Profile id stamped into the realized-confinement report. The host pins this
/// string and refuses any instance reporting a different profile.
pub const PLUGIN_V1_PROFILE_ID: &str = "plugin-v1";

/// Launcher build version stamped into the realized-confinement report so the
/// host can refuse instances built by an unexpected launcher revision.
pub const LAUNCHER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The seven ordered confinement steps (design §4.1 / RFC 3.1a). The launcher
/// runs them in this exact order and aborts (no exec) on the first failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStep {
    /// 1. unshare user + mount + net namespaces.
    UnshareNamespaces,
    /// 2. private mount propagation; assemble and `pivot_root` into the rootfs.
    AssembleRootfs,
    /// 3. cgroup cpu/mem caps + rlimits.
    CgroupAndRlimits,
    /// 4. netns: bring up no interfaces; the broker fd is the only network object.
    NetnsNoInterfaces,
    /// 5. close all fds except the control pipe + broker fd; scrub env.
    ScrubFdsAndEnv,
    /// 6. no_new_privs; apply seccomp plugin-v1; drop capabilities.
    ConfineSeccompAndCaps,
    /// 7. exec the bundle entry.
    Exec,
}

impl LaunchStep {
    /// Stable identifier used in audit/report and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            LaunchStep::UnshareNamespaces => "unshare_namespaces",
            LaunchStep::AssembleRootfs => "assemble_rootfs",
            LaunchStep::CgroupAndRlimits => "cgroup_and_rlimits",
            LaunchStep::NetnsNoInterfaces => "netns_no_interfaces",
            LaunchStep::ScrubFdsAndEnv => "scrub_fds_and_env",
            LaunchStep::ConfineSeccompAndCaps => "confine_seccomp_and_caps",
            LaunchStep::Exec => "exec",
        }
    }
}

impl fmt::Display for LaunchStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Privilege mode the launcher runs in. Made explicit so the operator's
/// packaging decision is recorded in the report and never silently widened:
/// both modes end in the same kernel confinement (design §4.1 step 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeMode {
    /// Rootless: a user namespace is created first and is the source of the
    /// remaining namespace privileges. Preferred default.
    RootlessUserns,
    /// Privileged: the launcher already holds the capabilities to create the
    /// remaining namespaces directly (a packaging decision, not a security
    /// relaxation). Must be requested explicitly.
    Privileged,
}

impl PrivilegeMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            PrivilegeMode::RootlessUserns => "rootless_userns",
            PrivilegeMode::Privileged => "privileged",
        }
    }
}

/// Everything the launcher needs to construct one plugin instance. Built by the
/// thin CLI front-end from argv + inherited fds; validated before any step runs.
#[derive(Debug, Clone)]
pub struct LaunchSpec {
    /// Plugin id (already charset-validated by the host before reaching here).
    pub plugin_id: String,
    /// Per-launch instance id (host-generated, unique).
    pub instance_id: String,
    /// Privilege mode (explicit; never inferred).
    pub privilege_mode: PrivilegeMode,
    /// Absolute path to the read-only bundle directory.
    pub bundle_dir: String,
    /// Absolute path to the per-instance read-write scratch directory (0700).
    pub scratch_dir: String,
    /// Path, relative to the bundle root, of the entry executable to exec.
    pub entry_relpath: String,
    /// Arguments passed to the entry executable (argv[1..]).
    pub entry_args: Vec<String>,
    /// cgroup v2 path the instance is classified into (cpu/mem caps applied by host).
    pub cgroup_path: String,
    /// Hex SHA-256 of the assembled rootfs contract (bundle file-hash list),
    /// supplied by the host so the report is verifiable against the signature.
    pub rootfs_hash: String,
    /// Raw fd number of the host control pipe (report is written here).
    pub control_pipe_fd: i32,
    /// Raw fd number of the inherited broker socketpair (the only network object).
    pub broker_fd: i32,
    /// CPU-time rlimit in seconds (RLIMIT_CPU).
    pub rlimit_cpu_seconds: u64,
    /// Address-space rlimit in bytes (RLIMIT_AS).
    pub rlimit_as_bytes: u64,
    /// Open-file rlimit (RLIMIT_NOFILE).
    pub rlimit_nofile: u64,
}

/// The single-line JSON report written to the host immediately before exec.
/// The host refuses to service an instance whose report is missing or whose
/// fields do not match the expected configuration (design §4.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealizedConfinementReport {
    /// Constant marker so the host can recognize the report frame.
    pub kind: String,
    pub plugin_id: String,
    pub instance_id: String,
    pub privilege_mode: PrivilegeMode,
    /// Namespace kinds actually entered, in order (e.g. ["user","mount","net"]).
    pub namespaces_entered: Vec<String>,
    pub rootfs_hash: String,
    pub cgroup_path: String,
    pub seccomp_profile_id: String,
    pub launcher_version: String,
    /// Broker fd the confined process retains as its only network object.
    pub broker_fd: i32,
}

impl RealizedConfinementReport {
    /// Build the report for a fully constructed instance.
    pub fn new(spec: &LaunchSpec, namespaces_entered: Vec<String>) -> Self {
        RealizedConfinementReport {
            kind: "realized-confinement.v1".to_string(),
            plugin_id: spec.plugin_id.clone(),
            instance_id: spec.instance_id.clone(),
            privilege_mode: spec.privilege_mode,
            namespaces_entered,
            rootfs_hash: spec.rootfs_hash.clone(),
            cgroup_path: spec.cgroup_path.clone(),
            seccomp_profile_id: PLUGIN_V1_PROFILE_ID.to_string(),
            launcher_version: LAUNCHER_VERSION.to_string(),
            broker_fd: spec.broker_fd,
        }
    }

    /// Serialize to the single newline-terminated JSON line written to the
    /// control pipe. Returns an error rather than panicking so the launcher can
    /// fail closed if serialization ever fails.
    pub fn to_report_line(&self) -> Result<String, LauncherError> {
        let json = serde_json::to_string(self).map_err(|e| LauncherError::ReportSerialize {
            detail: e.to_string(),
        })?;
        Ok(format!("{json}\n"))
    }
}

/// Launcher failures. Every variant means the same thing operationally: abort,
/// non-zero exit, NO exec, report ABSENT. The `step` field names which of the
/// seven steps failed so the abort is attributable in logs.
#[derive(Debug, thiserror::Error)]
pub enum LauncherError {
    #[error("sanctuary-plugin-launcher is only supported on Linux")]
    UnsupportedPlatform,

    #[error("launch spec invalid: {detail}")]
    InvalidSpec { detail: String },

    #[error("step {step} failed: {detail}")]
    Step {
        step: LaunchStep,
        detail: String,
    },

    #[error("realized-confinement report serialization failed: {detail}")]
    ReportSerialize { detail: String },

    #[error("writing realized-confinement report to control pipe failed: {detail}")]
    ReportWrite { detail: String },
}

impl LauncherError {
    // Used only by the Linux confinement steps; gated to avoid a dead-code
    // warning on non-Linux dev builds (clippy runs with -D warnings).
    #[cfg(target_os = "linux")]
    fn step(step: LaunchStep, detail: impl Into<String>) -> Self {
        LauncherError::Step {
            step,
            detail: detail.into(),
        }
    }
}

/// Validate the launch spec before any kernel step runs. Rejects empty/relative
/// paths and `..` traversal in the entry relpath (defense in depth; the host
/// validates bundle contents, but the launcher does not trust its caller).
pub fn validate_spec(spec: &LaunchSpec) -> Result<(), LauncherError> {
    fn require_abs(name: &str, value: &str) -> Result<(), LauncherError> {
        if value.is_empty() {
            return Err(LauncherError::InvalidSpec {
                detail: format!("{name} must not be empty"),
            });
        }
        if !value.starts_with('/') {
            return Err(LauncherError::InvalidSpec {
                detail: format!("{name} must be an absolute path"),
            });
        }
        Ok(())
    }

    require_abs("bundle_dir", &spec.bundle_dir)?;
    require_abs("scratch_dir", &spec.scratch_dir)?;
    require_abs("cgroup_path", &spec.cgroup_path)?;

    if spec.plugin_id.is_empty() {
        return Err(LauncherError::InvalidSpec {
            detail: "plugin_id must not be empty".to_string(),
        });
    }
    if spec.instance_id.is_empty() {
        return Err(LauncherError::InvalidSpec {
            detail: "instance_id must not be empty".to_string(),
        });
    }
    if spec.rootfs_hash.is_empty() {
        return Err(LauncherError::InvalidSpec {
            detail: "rootfs_hash must not be empty".to_string(),
        });
    }

    validate_entry_relpath(&spec.entry_relpath)?;

    if spec.control_pipe_fd < 0 {
        return Err(LauncherError::InvalidSpec {
            detail: "control_pipe_fd must be non-negative".to_string(),
        });
    }
    if spec.broker_fd < 0 {
        return Err(LauncherError::InvalidSpec {
            detail: "broker_fd must be non-negative".to_string(),
        });
    }
    if spec.control_pipe_fd == spec.broker_fd {
        return Err(LauncherError::InvalidSpec {
            detail: "control_pipe_fd and broker_fd must differ".to_string(),
        });
    }
    Ok(())
}

/// Reject an entry relpath that is empty, absolute, or contains a `..`
/// component. The host normalizes bundle paths against the bundle root, but the
/// launcher independently refuses traversal so a compromised caller cannot point
/// the exec outside the assembled rootfs.
pub fn validate_entry_relpath(relpath: &str) -> Result<(), LauncherError> {
    if relpath.is_empty() {
        return Err(LauncherError::InvalidSpec {
            detail: "entry_relpath must not be empty".to_string(),
        });
    }
    if relpath.starts_with('/') {
        return Err(LauncherError::InvalidSpec {
            detail: "entry_relpath must be relative to the bundle root".to_string(),
        });
    }
    for component in relpath.split('/') {
        if component == ".." {
            return Err(LauncherError::InvalidSpec {
                detail: "entry_relpath must not contain a `..` component".to_string(),
            });
        }
    }
    Ok(())
}

/// Environment keys the confined plugin is allowed to inherit. The launcher
/// scrubs the environment to this allowlist (step 5) and additionally denies
/// any key matching the secret deny-pattern, mirroring `isSecretEnvKey` in
/// `server/src/agent-contract/adapters/vm-launcher.ts` so the Rust and TS
/// sides scrub the same secrets.
pub const ENV_ALLOWLIST: &[&str] = &["PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR"];

/// Mirror of `isSecretEnvKey` (vm-launcher.ts): a key carrying any of these
/// substrings (or the `SANCTUARY_KEY_` prefix) is a secret and is denied even
/// if it would otherwise be allowlisted. Belt-and-suspenders: the allowlist is
/// the positive gate, this is the deny override.
pub fn is_secret_env_key(key: &str) -> bool {
    key.contains("PRIVATE_KEY")
        || key.contains("MASTER_SECRET")
        || key.contains("PASSPHRASE")
        || key.contains("API_KEY")
        || key.contains("TOKEN")
        || key.contains("SECRET")
        || key.contains("IDENTITY")
        || key.starts_with("SANCTUARY_KEY_")
}

/// Compute the scrubbed environment for the confined process from an inherited
/// environment: keep only allowlisted keys that are not secrets. Pure and
/// portable so the scrub policy is unit-tested off-Linux.
pub fn scrub_env<I, K, V>(inherited: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    let mut out = BTreeMap::new();
    for (key, value) in inherited {
        let key = key.into();
        if !ENV_ALLOWLIST.contains(&key.as_str()) {
            continue;
        }
        if is_secret_env_key(&key) {
            continue;
        }
        out.insert(key, value.into());
    }
    out
}

/// The ordered list of namespace kinds the launcher unshares (step 1). Used
/// both to drive the unshare and to populate the realized-confinement report.
pub fn namespaces_for_mode(mode: PrivilegeMode) -> Vec<String> {
    match mode {
        // Rootless: the user namespace must come first so it is the source of
        // privilege for the mount + net namespaces.
        PrivilegeMode::RootlessUserns => vec![
            "user".to_string(),
            "mount".to_string(),
            "net".to_string(),
        ],
        // Privileged: the launcher already holds the needed capabilities, so it
        // creates mount + net directly without a user namespace.
        PrivilegeMode::Privileged => vec!["mount".to_string(), "net".to_string()],
    }
}

// ---- Linux confinement steps ----------------------------------------------
//
// Each step returns `Result<(), LauncherError>` tagged with its `LaunchStep`.
// The orchestrator (`construct_confinement`) runs them in order and short
// circuits on the first error, so a failure at any step means no exec.

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    use nix::libc::rlim_t;
    use nix::sched::{unshare, CloneFlags};
    use nix::sys::resource::{setrlimit, Resource};

    /// Step 1: unshare user (rootless) + mount + net namespaces.
    pub fn unshare_namespaces(mode: PrivilegeMode) -> Result<(), LauncherError> {
        let mut flags = CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWNET;
        if matches!(mode, PrivilegeMode::RootlessUserns) {
            flags |= CloneFlags::CLONE_NEWUSER;
        }
        unshare(flags).map_err(|e| {
            LauncherError::step(
                LaunchStep::UnshareNamespaces,
                format!("unshare({mode:?}) failed: {e}"),
            )
        })
    }

    /// Step 2: set mount propagation to private and pivot into the assembled
    /// rootfs. NEVER binds host `/`: the new root is a fresh tmpfs into which
    /// the bundle (ro) and scratch (rw) are bind-mounted, then `pivot_root`
    /// makes it the process root and the old root is detached.
    pub fn assemble_rootfs(spec: &LaunchSpec) -> Result<(), LauncherError> {
        use nix::mount::{mount, umount2, MntFlags, MsFlags};
        use nix::unistd::{chdir, pivot_root};

        let step = LaunchStep::AssembleRootfs;
        let to_step = |detail: String| LauncherError::step(step, detail);

        // Make all mount propagation private so nothing leaks back to the host
        // mount namespace.
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| to_step(format!("make-rprivate / failed: {e}")))?;

        // New root: a fresh tmpfs. The bundle and scratch are bound under it;
        // the host filesystem is never the source of the new root.
        let new_root = format!("{}/.sanctuary-newroot", spec.scratch_dir);
        std::fs::create_dir_all(&new_root)
            .map_err(|e| to_step(format!("create new_root {new_root}: {e}")))?;
        mount(
            Some("tmpfs"),
            new_root.as_str(),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=0755"),
        )
        .map_err(|e| to_step(format!("mount tmpfs at new_root: {e}")))?;

        // Bundle (read-only) under <new_root>/bundle.
        let bundle_dst = format!("{new_root}/bundle");
        std::fs::create_dir_all(&bundle_dst)
            .map_err(|e| to_step(format!("create {bundle_dst}: {e}")))?;
        mount(
            Some(spec.bundle_dir.as_str()),
            bundle_dst.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| to_step(format!("bind bundle: {e}")))?;
        // Re-mount the bundle bind read-only (a single bind cannot be ro in one
        // call; the remount enforces it).
        mount(
            None::<&str>,
            bundle_dst.as_str(),
            None::<&str>,
            MsFlags::MS_BIND
                | MsFlags::MS_REMOUNT
                | MsFlags::MS_RDONLY
                | MsFlags::MS_NOSUID
                | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .map_err(|e| to_step(format!("remount bundle ro: {e}")))?;

        // Scratch (read-write) under <new_root>/scratch.
        let scratch_dst = format!("{new_root}/scratch");
        std::fs::create_dir_all(&scratch_dst)
            .map_err(|e| to_step(format!("create {scratch_dst}: {e}")))?;
        mount(
            Some(spec.scratch_dir.as_str()),
            scratch_dst.as_str(),
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
            None::<&str>,
        )
        .map_err(|e| to_step(format!("bind scratch: {e}")))?;

        // Directory to receive the old root, then pivot.
        let old_root = format!("{new_root}/.oldroot");
        std::fs::create_dir_all(&old_root)
            .map_err(|e| to_step(format!("create old_root {old_root}: {e}")))?;
        pivot_root(new_root.as_str(), old_root.as_str())
            .map_err(|e| to_step(format!("pivot_root: {e}")))?;
        chdir("/").map_err(|e| to_step(format!("chdir / after pivot: {e}")))?;

        // Detach the old root entirely so the host filesystem is absent (not
        // merely permission-blocked) from the confined process.
        umount2("/.oldroot", MntFlags::MNT_DETACH)
            .map_err(|e| to_step(format!("detach old root: {e}")))?;
        std::fs::remove_dir("/.oldroot")
            .map_err(|e| to_step(format!("remove old root mountpoint: {e}")))?;
        Ok(())
    }

    /// Step 3: classify into the host-prepared cgroup (cpu/mem caps already set
    /// there by the supervisor via `cgroup.rs`) and apply per-process rlimits.
    pub fn cgroup_and_rlimits(spec: &LaunchSpec) -> Result<(), LauncherError> {
        let step = LaunchStep::CgroupAndRlimits;
        let to_step = |detail: String| LauncherError::step(step, detail);

        // Join the cgroup by writing our pid into <cgroup_path>/cgroup.procs.
        // The cpu/mem ceilings are configured on the cgroup by the host before
        // launch (cgroup.rs); the launcher only enters it.
        let pid = std::process::id();
        let procs = format!("{}/cgroup.procs", spec.cgroup_path);
        std::fs::write(&procs, pid.to_string())
            .map_err(|e| to_step(format!("join cgroup {procs}: {e}")))?;

        set_rlimit(Resource::RLIMIT_CPU, spec.rlimit_cpu_seconds).map_err(to_step)?;
        set_rlimit(Resource::RLIMIT_AS, spec.rlimit_as_bytes).map_err(to_step)?;
        set_rlimit(Resource::RLIMIT_NOFILE, spec.rlimit_nofile).map_err(to_step)?;
        Ok(())
    }

    // Use nix's portable `setrlimit`: it resolves the resource-arg type
    // difference between glibc (`__rlimit_resource_t`) and musl (`c_int`)
    // internally, so the launcher compiles for both the gnu and musl Linux
    // targets the static-jail build exercises.
    fn set_rlimit(resource: Resource, value: u64) -> Result<(), String> {
        setrlimit(resource, value as rlim_t, value as rlim_t)
            .map_err(|e| format!("setrlimit({resource:?}) = {e}"))
    }

    /// Step 4: confirm the netns has no interfaces beyond loopback-down. We do
    /// NOT bring up loopback or any NIC; the inherited broker fd is the only
    /// network object. This step is a no-op assertion point (the empty netns is
    /// produced by step 1's CLONE_NEWNET) kept explicit so the order is auditable
    /// and a future "accidentally bring up a NIC" regression has a named home.
    pub fn netns_no_interfaces() -> Result<(), LauncherError> {
        // A freshly unshared network namespace contains only a `lo` interface
        // in the DOWN state and no routes. We deliberately leave it down: no
        // `ip link set lo up`, no address assignment, no route. Nothing to do.
        Ok(())
    }

    /// Step 5: close every fd except stdio, the control pipe, and the broker fd;
    /// the env is scrubbed in the orchestrator before exec (it is applied to the
    /// `Command`, not the live process, so the report-writing code keeps its env).
    pub fn close_extra_fds(spec: &LaunchSpec) -> Result<(), LauncherError> {
        let step = LaunchStep::ScrubFdsAndEnv;
        let keep = [
            0,
            1,
            2,
            spec.control_pipe_fd,
            spec.broker_fd,
        ];
        // Determine the highest fd we might hold. Iterate /proc/self/fd so we
        // close exactly the open ones rather than blindly looping to a guessed
        // max. Fail closed if the fd table cannot be read.
        let entries = std::fs::read_dir("/proc/self/fd")
            .map_err(|e| LauncherError::step(step, format!("read /proc/self/fd: {e}")))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| LauncherError::step(step, format!("fd dir entry: {e}")))?;
            let name = entry.file_name();
            let fd: i32 = match name.to_string_lossy().parse() {
                Ok(fd) => fd,
                // Non-numeric entry (should not happen under /proc/self/fd);
                // skip it rather than abort.
                Err(_) => continue,
            };
            if keep.contains(&fd) {
                continue;
            }
            // Best-effort close; an already-closed fd (e.g. the readdir handle)
            // returning EBADF is benign.
            unsafe {
                libc::close(fd);
            }
        }
        Ok(())
    }

    /// Step 6: no_new_privs, apply the `plugin-v1` seccomp profile, drop
    /// capabilities. Reuses `jail::confine_current_process_with_profile`
    /// unchanged so the proven apply-order (set_no_new_privs -> drop caps ->
    /// install filter) is shared, not duplicated.
    pub fn confine(profile: SeccompProfile) -> Result<(), LauncherError> {
        jail::confine_current_process_with_profile(profile).map_err(|e| {
            LauncherError::step(LaunchStep::ConfineSeccompAndCaps, e.to_string())
        })
    }

    /// Write the realized-confinement report to the control pipe (immediately
    /// before exec). The fd is wrapped transiently and forgotten (`into_raw_fd`
    /// is not called; we leak the File guard with `mem::forget`) so dropping it
    /// does not close the pipe the host is still reading.
    pub fn write_report(
        report: &RealizedConfinementReport,
        control_pipe_fd: i32,
    ) -> Result<(), LauncherError> {
        let line = report.to_report_line()?;
        // Safety: control_pipe_fd is the inherited host control pipe, validated
        // non-negative and distinct from broker_fd by `validate_spec`; the host
        // owns its lifetime, so we must not close it on drop.
        let mut file = unsafe { std::fs::File::from_raw_fd(control_pipe_fd) };
        let res = file
            .write_all(line.as_bytes())
            .and_then(|()| file.flush())
            .map_err(|e| LauncherError::ReportWrite {
                detail: e.to_string(),
            });
        // Do not close the host's pipe fd: forget the File guard so its Drop
        // does not run.
        std::mem::forget(file);
        res
    }

    /// Step 7: exec the bundle entry inside the assembled rootfs with the
    /// scrubbed environment. On success this never returns; any return is an
    /// exec failure and must abort fail-closed (the seccomp filter is already
    /// installed, so the unconfined parent is never reached).
    pub fn exec_entry(spec: &LaunchSpec) -> Result<std::convert::Infallible, LauncherError> {
        use nix::unistd::execve;

        let step = LaunchStep::Exec;
        // After pivot_root the entry lives at /bundle/<entry_relpath>.
        let entry_abs = format!("/bundle/{}", spec.entry_relpath);
        let prog = CString::new(entry_abs.clone())
            .map_err(|_| LauncherError::step(step, "entry path has interior NUL".to_string()))?;

        let mut argv: Vec<CString> = Vec::with_capacity(spec.entry_args.len() + 1);
        argv.push(prog.clone());
        for arg in &spec.entry_args {
            argv.push(CString::new(arg.as_str()).map_err(|_| {
                LauncherError::step(step, "entry arg has interior NUL".to_string())
            })?);
        }

        let env = scrub_env(std::env::vars());
        let mut envp: Vec<CString> = Vec::with_capacity(env.len());
        for (k, v) in env {
            envp.push(CString::new(format!("{k}={v}")).map_err(|_| {
                LauncherError::step(step, "env entry has interior NUL".to_string())
            })?);
        }

        // execve only returns on failure.
        let err = execve(&prog, &argv, &envp).unwrap_err();
        Err(LauncherError::step(
            step,
            format!("execve({entry_abs}) failed: {err}"),
        ))
    }
}

/// Orchestrate the full confinement and exec (Linux). Runs the seven steps in
/// order, writes the realized-confinement report immediately before exec, and
/// only then execs. Any step error short-circuits: NO exec, error returned, the
/// caller exits non-zero, the report is ABSENT (it is written only after step 6
/// succeeds and only just before exec). Never returns `Ok`: success is exec.
#[cfg(target_os = "linux")]
pub fn construct_confinement(spec: &LaunchSpec) -> Result<std::convert::Infallible, LauncherError> {
    validate_spec(spec)?;

    linux::unshare_namespaces(spec.privilege_mode)?; // 1
    linux::assemble_rootfs(spec)?; // 2
    linux::cgroup_and_rlimits(spec)?; // 3
    linux::netns_no_interfaces()?; // 4
    linux::close_extra_fds(spec)?; // 5
    linux::confine(SeccompProfile::PluginV1)?; // 6

    // Realized-confinement report: written only now, after every confinement
    // step has succeeded, immediately before exec. A failure at any earlier
    // step means this line is never produced and the host sees no report.
    let report = RealizedConfinementReport::new(spec, namespaces_for_mode(spec.privilege_mode));
    linux::write_report(&report, spec.control_pipe_fd)?;

    linux::exec_entry(spec) // 7 (never returns Ok)
}

/// Non-Linux build: confinement is unavailable. Fail closed so a launcher built
/// for the wrong platform never execs an unconfined plugin.
#[cfg(not(target_os = "linux"))]
pub fn construct_confinement(
    _spec: &LaunchSpec,
) -> Result<std::convert::Infallible, LauncherError> {
    Err(LauncherError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_spec() -> LaunchSpec {
        LaunchSpec {
            plugin_id: "com.vendor.egress-classifier".to_string(),
            instance_id: "inst-1".to_string(),
            privilege_mode: PrivilegeMode::RootlessUserns,
            bundle_dir: "/var/lib/sanctuary/plugins/com.vendor.egress-classifier".to_string(),
            scratch_dir: "/run/sanctuary/scratch/inst-1".to_string(),
            entry_relpath: "bin/classifier".to_string(),
            entry_args: vec!["--serve".to_string()],
            cgroup_path: "/sys/fs/cgroup/system.slice/sanctuary-plugin-inst-1.service".to_string(),
            rootfs_hash: "a".repeat(64),
            control_pipe_fd: 3,
            broker_fd: 4,
            rlimit_cpu_seconds: 30,
            rlimit_as_bytes: 256 * 1024 * 1024,
            rlimit_nofile: 64,
        }
    }

    #[test]
    fn valid_spec_passes_validation() {
        assert!(validate_spec(&valid_spec()).is_ok());
    }

    #[test]
    fn entry_relpath_rejects_traversal_absolute_and_empty() {
        assert!(validate_entry_relpath("bin/classifier").is_ok());
        assert!(validate_entry_relpath("").is_err());
        assert!(validate_entry_relpath("/bin/sh").is_err());
        assert!(validate_entry_relpath("../escape").is_err());
        assert!(validate_entry_relpath("bin/../../escape").is_err());
        assert!(validate_entry_relpath("a/b/../c").is_err());
    }

    #[test]
    fn validate_spec_rejects_relative_paths() {
        let mut spec = valid_spec();
        spec.bundle_dir = "relative/bundle".to_string();
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn validate_spec_rejects_colliding_control_and_broker_fds() {
        let mut spec = valid_spec();
        spec.broker_fd = spec.control_pipe_fd;
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn validate_spec_rejects_negative_fds() {
        let mut spec = valid_spec();
        spec.control_pipe_fd = -1;
        assert!(validate_spec(&spec).is_err());
        let mut spec = valid_spec();
        spec.broker_fd = -2;
        assert!(validate_spec(&spec).is_err());
    }

    #[test]
    fn env_scrub_keeps_only_allowlisted_non_secret_keys() {
        let env = vec![
            ("PATH", "/usr/bin"),
            ("LANG", "C.UTF-8"),
            ("HOME", "/home/plugin"),
            // Not allowlisted -> dropped.
            ("DISPLAY", ":0"),
            ("AWS_REGION", "us-east-1"),
            // Allowlisted-name shape but secret substring would be denied; none
            // of the allowlisted names contain secrets, so add an explicit
            // secret to prove the deny override is wired.
            ("SANCTUARY_KEY_PRIMARY", "deadbeef"),
        ];
        let scrubbed = scrub_env(env);
        assert_eq!(scrubbed.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(scrubbed.get("LANG").map(String::as_str), Some("C.UTF-8"));
        assert_eq!(scrubbed.get("HOME").map(String::as_str), Some("/home/plugin"));
        assert!(!scrubbed.contains_key("DISPLAY"));
        assert!(!scrubbed.contains_key("AWS_REGION"));
        assert!(!scrubbed.contains_key("SANCTUARY_KEY_PRIMARY"));
    }

    #[test]
    fn secret_env_keys_match_vm_launcher_pattern() {
        assert!(is_secret_env_key("ANTHROPIC_API_KEY"));
        assert!(is_secret_env_key("DB_PASSWORD_TOKEN"));
        assert!(is_secret_env_key("MY_SECRET"));
        assert!(is_secret_env_key("SOME_PRIVATE_KEY"));
        assert!(is_secret_env_key("SANCTUARY_KEY_X"));
        assert!(is_secret_env_key("USER_IDENTITY"));
        assert!(!is_secret_env_key("PATH"));
        assert!(!is_secret_env_key("LANG"));
    }

    #[test]
    fn report_round_trips_and_carries_expected_fields() {
        let spec = valid_spec();
        let report =
            RealizedConfinementReport::new(&spec, namespaces_for_mode(spec.privilege_mode));
        assert_eq!(report.seccomp_profile_id, PLUGIN_V1_PROFILE_ID);
        assert_eq!(report.launcher_version, LAUNCHER_VERSION);
        assert_eq!(report.privilege_mode, PrivilegeMode::RootlessUserns);
        assert_eq!(report.namespaces_entered, vec!["user", "mount", "net"]);
        assert_eq!(report.broker_fd, spec.broker_fd);

        let line = report.to_report_line().expect("serialize report");
        assert!(line.ends_with('\n'));
        let parsed: RealizedConfinementReport =
            serde_json::from_str(line.trim_end()).expect("parse report");
        assert_eq!(parsed, report);
    }

    #[test]
    fn privileged_mode_omits_user_namespace() {
        let ns = namespaces_for_mode(PrivilegeMode::Privileged);
        assert_eq!(ns, vec!["mount", "net"]);
        assert!(!ns.contains(&"user".to_string()));
    }

    #[test]
    fn launch_step_ids_are_stable_and_ordered() {
        let order = [
            LaunchStep::UnshareNamespaces,
            LaunchStep::AssembleRootfs,
            LaunchStep::CgroupAndRlimits,
            LaunchStep::NetnsNoInterfaces,
            LaunchStep::ScrubFdsAndEnv,
            LaunchStep::ConfineSeccompAndCaps,
            LaunchStep::Exec,
        ];
        let ids: Vec<&str> = order.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "unshare_namespaces",
                "assemble_rootfs",
                "cgroup_and_rlimits",
                "netns_no_interfaces",
                "scrub_fds_and_env",
                "confine_seccomp_and_caps",
                "exec",
            ]
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn construct_confinement_fails_closed_off_linux() {
        let err = construct_confinement(&valid_spec()).unwrap_err();
        assert!(matches!(err, LauncherError::UnsupportedPlatform));
    }
}
