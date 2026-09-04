//! Daemon configuration sourced from CLI arguments and environment variables.
//!
//! PR 2a fixes the contract: every value the daemon needs at boot is captured
//! here, parseable from argv with a tiny hand-rolled parser (no clap dep yet
//! to keep the binary small). PR 2b adds the real subcommands beyond `run`.

use std::path::PathBuf;
use std::time::Duration;

use crate::constants::{
    DEFAULT_NO_WALL_DURATION_SECONDS, DEFAULT_PROMPT_TIMEOUT_SECONDS, DEFAULT_WAL_SIZE_CAP_BYTES,
    DEFAULT_WAL_TTL_SECONDS,
};

/// The HOST-GLOBAL Linux enforcement paths a boot will take ownership of.
///
/// These are `/var/lib/sanctuary`-rooted, root-owned, and shared by every
/// fortress on the machine, which is exactly why they are a config FIELD rather
/// than a hardcoded constant read inside `boot()`. Without an override the test
/// suite had no way to avoid the real host lock, the real ownership journal, and
/// the real root-owned journal MAC key: driving `daemon::boot` on any Linux
/// machine mutated the operator's live enforcement state. AGENTS.md,
/// "the operator's machine is not a fixture", makes that a defect, and a
/// convention alone could not fix it because there was no seam to aim elsewhere.
///
/// Production always uses [`LinuxRuntimePaths::production`]; every other value
/// comes from a test that pointed the daemon at a temporary root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxRuntimePaths {
    /// Host-global nftables ownership lock (NOT per-fortress): a second daemon
    /// with a different fortress id contends here and refuses before touching
    /// nftables. See [`crate::runtime_lock`].
    pub host_lock_path: PathBuf,
    /// Durable, authenticated ownership journal. See [`crate::ownership_journal`].
    pub ownership_journal_path: PathBuf,
    /// Root-owned 0600 MAC key that authenticates the journal.
    pub journal_auth_key_path: PathBuf,
}

impl LinuxRuntimePaths {
    /// The shipped layout under the systemd `StateDirectory`. This is the ONLY
    /// value the production boot path and `--disarm` ever use; the constants it
    /// reads are also what `tests/systemd_unit.rs` pins the unit file against.
    pub fn production() -> Self {
        Self {
            host_lock_path: PathBuf::from(crate::runtime_lock::DEFAULT_HOST_LOCK_PATH),
            ownership_journal_path: PathBuf::from(
                crate::ownership_journal::DEFAULT_OWNERSHIP_JOURNAL_PATH,
            ),
            journal_auth_key_path: PathBuf::from(
                crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH,
            ),
        }
    }

    /// An isolated layout rooted at `root` (a per-test temporary directory).
    ///
    /// Unconditional because it grants nothing the public fields do not already
    /// grant; the STRUCTURAL guarantee is elsewhere: `DaemonConfig::from_argv`
    /// offers no way to set these paths in a production build, so the shipped
    /// daemon can only ever boot on [`LinuxRuntimePaths::production`].
    pub fn isolated_under(root: &std::path::Path) -> Self {
        Self {
            host_lock_path: root.join("castle-wall.nft.lock"),
            ownership_journal_path: root.join("nft-ownership.json"),
            journal_auth_key_path: root.join("nft-journal-auth.key"),
        }
    }

    /// True when NONE of these paths is a production default. The test suite
    /// asserts this before it boots anything, so "the tests never touch host
    /// state" is checked rather than assumed.
    pub fn is_isolated_from_production(&self) -> bool {
        // Every path is checked individually, not just the struct as a whole: a
        // partially-isolated set (two temp paths and one production path) is the
        // shape that would still mutate operator state, and a `!=` on the whole
        // struct would happily pass it.
        self.host_lock_path.as_path()
            != std::path::Path::new(crate::runtime_lock::DEFAULT_HOST_LOCK_PATH)
            && self.ownership_journal_path.as_path()
                != std::path::Path::new(crate::ownership_journal::DEFAULT_OWNERSHIP_JOURNAL_PATH)
            && self.journal_auth_key_path.as_path()
                != std::path::Path::new(crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH)
    }
}

/// Static configuration loaded once at daemon startup.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Hex-encoded fortress identifier; used in socket and WAL paths.
    pub fortress_id: String,
    /// Path the daemon will bind its UDS at on Linux.
    pub socket_path: PathBuf,
    /// Directory the daemon scans for the signed allowlist manifest.
    pub policy_dir: PathBuf,
    /// Path the daemon writes its on-disk WAL to.
    pub wal_path: PathBuf,
    /// Path containing the TOFU-pinned fortress public key (raw 32 bytes).
    pub pinned_public_key_path: PathBuf,
    /// Path to the daemon-held audit-producer private key (raw 32-byte
    /// Ed25519 seed, `0600`). Generated on first boot if absent. NEVER
    /// transmitted over IPC and never written where the in-process TS server
    /// reads — this separation is what makes the per-event producer signature
    /// unforgeable by an in-process module (Slice L1).
    pub producer_key_path: PathBuf,
    /// Path to the published audit-producer public key (raw 32 bytes,
    /// world-readable) the consumer TOFU-pins to verify producer signatures.
    /// The server profile places this public half in the broker-traversable
    /// fortress runtime directory; the private seed remains in root-only state.
    pub producer_pub_key_path: PathBuf,
    /// Operator-decision timeout for an open prompt.
    pub prompt_timeout: Duration,
    /// Bounded duration for the emergency `--no-wall` recovery mode.
    pub no_wall_max_duration: Duration,
    /// In-memory audit-ring retention TTL. Durable WAL evidence is retained
    /// until authenticated ACK; it is bounded by `wal_size_cap_bytes` and
    /// never silently expired.
    pub wal_ttl: Duration,
    /// WAL size cap in bytes. One eighth (up to 64 KiB) is reserved for
    /// lifecycle/control recovery evidence so an event flood cannot prevent an
    /// authenticated drain-only restart from reaching its control surface.
    pub wal_size_cap_bytes: u64,
    /// Kernel peer UID of the authenticated Sanctuary service principal.
    /// This is an operator-provisioned identity, never inferred from key-file
    /// ownership (the pinned public key is commonly root-owned).
    pub trusted_service_uid: Option<u32>,
    /// Host-global Linux enforcement paths this boot will take ownership of.
    /// Defaults to [`LinuxRuntimePaths::production`]; only a test ever overrides
    /// it, and doing so is what keeps the suite off the operator's live lock,
    /// journal, and journal MAC key.
    pub linux_runtime_paths: LinuxRuntimePaths,
}

impl DaemonConfig {
    /// Defaults targeted at the canonical Linux layout. Tests construct via
    /// the public fields directly; production loads through `from_argv`.
    pub fn defaults_for_fortress(fortress_id: impl Into<String>) -> Self {
        let fortress_id = fortress_id.into();
        let runtime_dir = PathBuf::from(format!("/run/sanctuary/{}", fortress_id));
        let state_dir = PathBuf::from(format!("/var/lib/sanctuary/{}", fortress_id));
        Self {
            fortress_id,
            socket_path: runtime_dir.join("filter.sock"),
            policy_dir: state_dir.join("policy/egress"),
            wal_path: state_dir.join("filter-events.wal"),
            pinned_public_key_path: state_dir.join("policy/egress/pinned.key"),
            producer_key_path: state_dir.join("policy/egress/audit-producer.key"),
            producer_pub_key_path: runtime_dir.join("audit-producer.pub"),
            prompt_timeout: Duration::from_secs(DEFAULT_PROMPT_TIMEOUT_SECONDS as u64),
            no_wall_max_duration: Duration::from_secs(DEFAULT_NO_WALL_DURATION_SECONDS as u64),
            wal_ttl: Duration::from_secs(DEFAULT_WAL_TTL_SECONDS as u64),
            wal_size_cap_bytes: DEFAULT_WAL_SIZE_CAP_BYTES,
            trusted_service_uid: None,
            linux_runtime_paths: LinuxRuntimePaths::production(),
        }
    }

    /// Validate the strong servers-first deployment profile. The release
    /// daemon is root-owned and accepts IPC only from a distinct, explicitly
    /// provisioned Sanctuary broker UID; policy, keys and WAL remain under the
    /// systemd-owned `/var/lib` root. Test-isolated configurations deliberately
    /// use different host-global paths and are checked by their harness.
    #[cfg(target_os = "linux")]
    pub fn validate_server_profile(&self) -> Result<(), String> {
        if self.linux_runtime_paths != LinuxRuntimePaths::production() {
            return Ok(());
        }
        if self.fortress_id.len() < 8
            || self.fortress_id.len() > 64
            || !self
                .fortress_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(
                "server fortress id must be 8..64 lowercase hexadecimal characters".to_string(),
            );
        }
        if unsafe { libc::geteuid() } != 0 {
            return Err(
                "server enforcement daemon must run as root under the provisioned systemd unit"
                    .to_string(),
            );
        }
        let broker_uid = self
            .trusted_service_uid
            .ok_or_else(|| "dedicated Sanctuary broker UID is required".to_string())?;
        if broker_uid == 0 {
            return Err(
                "trusted service UID must be a dedicated non-root broker principal".to_string(),
            );
        }
        let expected = Self::defaults_for_fortress(&self.fortress_id);
        for (label, got, want) in [
            ("socket", &self.socket_path, &expected.socket_path),
            ("policy", &self.policy_dir, &expected.policy_dir),
            ("WAL", &self.wal_path, &expected.wal_path),
            (
                "pinned key",
                &self.pinned_public_key_path,
                &expected.pinned_public_key_path,
            ),
            (
                "producer key",
                &self.producer_key_path,
                &expected.producer_key_path,
            ),
            (
                "producer public key",
                &self.producer_pub_key_path,
                &expected.producer_pub_key_path,
            ),
        ] {
            if got != want {
                return Err(format!(
                    "server profile forbids overriding the root-owned {label} path: got {}, expected {}",
                    got.display(), want.display()
                ));
            }
        }
        let socket_parent = self
            .socket_path
            .parent()
            .ok_or_else(|| format!("{} has no parent", self.socket_path.display()))?;
        let wal_parent = self
            .wal_path
            .parent()
            .ok_or_else(|| format!("{} has no parent", self.wal_path.display()))?;
        let rules_dir = self.policy_dir.join("rules");
        for parent in [
            socket_parent,
            self.policy_dir.as_path(),
            rules_dir.as_path(),
            wal_parent,
        ] {
            let canonical = std::fs::canonicalize(parent).map_err(|err| {
                format!(
                    "deployment directory {} cannot be canonicalized: {err}",
                    parent.display()
                )
            })?;
            if canonical != parent {
                return Err(format!(
                    "deployment directory {} traverses a symlink (canonical {})",
                    parent.display(),
                    canonical.display()
                ));
            }
            let metadata = std::fs::symlink_metadata(parent).map_err(|err| {
                format!(
                    "root-owned deployment directory {} is unavailable: {err}",
                    parent.display()
                )
            })?;
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let mode = metadata.permissions().mode() & 0o777;
            if !metadata.file_type().is_dir() || metadata.uid() != 0 || mode & 0o022 != 0 {
                return Err(format!(
                    "deployment directory {} must be a real root-owned directory without group/world write (uid={}, mode={mode:o})",
                    parent.display(), metadata.uid()
                ));
            }
        }
        Ok(())
    }

    /// Hand-rolled argv parser. Recognized flags:
    ///   --fortress-id <hex>
    ///   --socket-path <path>
    ///   --policy-dir <path>
    ///   --wal-path <path>
    ///   --pinned-public-key <path>
    ///   --producer-key <path>
    ///   --producer-pub-key <path>
    ///
    /// Unrecognized flags return an error; callers print usage and exit 2.
    pub fn from_argv<I, S>(args: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut iter = args.into_iter();
        let mut fortress_id: Option<String> = None;
        let mut socket_path: Option<PathBuf> = None;
        let mut policy_dir: Option<PathBuf> = None;
        let mut wal_path: Option<PathBuf> = None;
        let mut pinned_public_key_path: Option<PathBuf> = None;
        let mut producer_key_path: Option<PathBuf> = None;
        let mut producer_pub_key_path: Option<PathBuf> = None;
        let mut trusted_service_uid: Option<u32> = None;
        // TEST-ISOLATION ONLY. Compiled out of the shipped binary, so a
        // production daemon has no argv path to any host-global enforcement path
        // other than `LinuxRuntimePaths::production()`.
        #[cfg(feature = "test-isolation")]
        let mut isolated_runtime_paths: Option<LinuxRuntimePaths> = None;

        while let Some(arg) = iter.next() {
            match arg.as_ref() {
                "--fortress-id" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--fortress-id"))?;
                    fortress_id = Some(v.as_ref().to_string());
                }
                "--socket-path" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--socket-path"))?;
                    socket_path = Some(PathBuf::from(v.as_ref()));
                }
                "--policy-dir" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--policy-dir"))?;
                    policy_dir = Some(PathBuf::from(v.as_ref()));
                }
                "--wal-path" => {
                    let v = iter.next().ok_or(ConfigError::MissingValue("--wal-path"))?;
                    wal_path = Some(PathBuf::from(v.as_ref()));
                }
                "--pinned-public-key" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--pinned-public-key"))?;
                    pinned_public_key_path = Some(PathBuf::from(v.as_ref()));
                }
                "--producer-key" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--producer-key"))?;
                    producer_key_path = Some(PathBuf::from(v.as_ref()));
                }
                "--producer-pub-key" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--producer-pub-key"))?;
                    producer_pub_key_path = Some(PathBuf::from(v.as_ref()));
                }
                "--trusted-service-uid" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--trusted-service-uid"))?;
                    trusted_service_uid = Some(v.as_ref().parse().map_err(|_| {
                        ConfigError::InvalidTrustedServiceUid(v.as_ref().to_string())
                    })?);
                }
                // TEST-ISOLATION ONLY: point the host-global lock, ownership
                // journal, and journal MAC key at a temporary root so a spawned
                // daemon in the privileged suite cannot touch operator state.
                // Absent from a release build; the shipped binary rejects it as
                // an unknown flag.
                #[cfg(feature = "test-isolation")]
                "--isolated-runtime-root" => {
                    let v = iter
                        .next()
                        .ok_or(ConfigError::MissingValue("--isolated-runtime-root"))?;
                    let root = PathBuf::from(v.as_ref());
                    isolated_runtime_paths = Some(LinuxRuntimePaths::isolated_under(&root));
                }
                "--help" | "-h" => return Err(ConfigError::HelpRequested),
                other => return Err(ConfigError::Unknown(other.to_string())),
            }
        }

        let fortress_id = fortress_id.ok_or(ConfigError::MissingValue("--fortress-id"))?;
        let mut config = Self::defaults_for_fortress(&fortress_id);
        if let Some(p) = socket_path {
            config.socket_path = p;
        }
        if let Some(p) = policy_dir {
            config.policy_dir = p;
        }
        if let Some(p) = wal_path {
            config.wal_path = p;
        }
        if let Some(p) = pinned_public_key_path {
            config.pinned_public_key_path = p;
        }
        if let Some(p) = producer_key_path {
            config.producer_key_path = p;
        }
        if let Some(p) = producer_pub_key_path {
            config.producer_pub_key_path = p;
        }
        config.trusted_service_uid = trusted_service_uid;
        #[cfg(feature = "test-isolation")]
        if let Some(paths) = isolated_runtime_paths {
            config.linux_runtime_paths = paths;
        }
        Ok(config)
    }
}

/// Errors emitted by the argv parser.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing value for {0}")]
    MissingValue(&'static str),
    #[error("unknown argument: {0}")]
    Unknown(String),
    #[error("--help requested")]
    HelpRequested,
    #[error("invalid --trusted-service-uid: {0}")]
    InvalidTrustedServiceUid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_canonical_layout() {
        let cfg = DaemonConfig::defaults_for_fortress("abc123");
        assert_eq!(cfg.fortress_id, "abc123");
        assert_eq!(
            cfg.socket_path,
            PathBuf::from("/run/sanctuary/abc123/filter.sock")
        );
        assert_eq!(
            cfg.wal_path,
            PathBuf::from("/var/lib/sanctuary/abc123/filter-events.wal")
        );
        assert_eq!(
            cfg.producer_key_path,
            PathBuf::from("/var/lib/sanctuary/abc123/policy/egress/audit-producer.key")
        );
        assert_eq!(
            cfg.producer_pub_key_path,
            PathBuf::from("/run/sanctuary/abc123/audit-producer.pub")
        );
    }

    #[test]
    fn argv_round_trips_required_fields() {
        let cfg =
            DaemonConfig::from_argv(["--fortress-id", "deadbeef", "--trusted-service-uid", "501"])
                .expect("parse");
        assert_eq!(cfg.fortress_id, "deadbeef");
        assert_eq!(cfg.trusted_service_uid, Some(501));
    }

    #[test]
    fn argv_rejects_non_numeric_trusted_service_uid() {
        let err =
            DaemonConfig::from_argv(["--fortress-id", "deadbeef", "--trusted-service-uid", "root"])
                .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidTrustedServiceUid(_)));
    }

    #[test]
    fn argv_rejects_unknown_flag() {
        let err = DaemonConfig::from_argv(["--fortress-id", "x", "--rogue", "y"]).unwrap_err();
        assert!(matches!(err, ConfigError::Unknown(s) if s == "--rogue"));
    }
}
