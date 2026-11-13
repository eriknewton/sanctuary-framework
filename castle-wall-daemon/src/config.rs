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
    #[cfg(any(test, feature = "test-isolation"))]
    pub test_selector_roots: Option<SelectorRoots>,
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
    /// TEST-ISOLATION ONLY (LINUX-BOOT-STOP-HOSTWIDE-NET-01): when set,
    /// `boot()` pre-sets the daemon's shutdown-request flag before kernel
    /// activation runs, simulating a stop already requested during the boot
    /// phase (signal handlers installed, kernel activation not yet reached) --
    /// the boot-phase counterpart of `--test-shutdown-at pre-recovery`. Set via
    /// `--test-shutdown-at boot-acquire` in `main.rs`, applied to `config`
    /// AFTER `from_argv` returns but BEFORE `daemon::boot` runs, never parsed
    /// by `from_argv` itself. This is UNLIKE `test_health_interval_ms`, which
    /// stays a `main` local applied to `supervise_until_shutdown` only AFTER a
    /// successful boot returns a handle: `boot-acquire`'s sites run INSIDE
    /// `boot()`'s acquisition, before any handle exists, so it has to land on
    /// `DaemonConfig` itself rather than being threaded in after the fact.
    /// Compiled out of the shipped binary, so a production boot has no argv
    /// path that can pre-arm this.
    #[cfg(feature = "test-isolation")]
    pub test_boot_time_shutdown_requested: bool,
    /// TEST-ISOLATION ONLY (LINUX-SUPERVISOR-WEDGE-R1-01, harness leg HW3): when
    /// set, `boot()` sleeps this many milliseconds immediately before sending
    /// `READY=1`, to show systemd's watchdog is inactive while the unit is still
    /// activating. Routed exactly like `test_boot_time_shutdown_requested`: set
    /// via `--test-delay-before-ready-ms` in `main.rs` after `from_argv` and
    /// before `daemon::boot`, because the sleep must run inside `boot()`, before
    /// any handle exists. Compiled out of the shipped binary.
    #[cfg(feature = "test-isolation")]
    pub test_delay_before_ready_ms: Option<u64>,
}

/// Shortest fortress id the server profile accepts.
#[cfg(any(target_os = "linux", test))]
const FORTRESS_ID_MIN_LEN: usize = 8;
/// Longest fortress id the server profile accepts: 64 = the hex length of a
/// 32-byte identifier.
#[cfg(any(target_os = "linux", test))]
const FORTRESS_ID_MAX_LEN: usize = 64;

/// THE fortress-id grammar, the one implementation: 8 to 64 lowercase
/// hexadecimal characters. Called by [`DaemonConfig::validate_server_profile`]
/// and by the agent start gate (`src/agent_start.rs`), so the wall and the gate
/// can never disagree on which ids are well formed (TB7s pins the single
/// grammar). Linux-or-test only, like both callers: a macOS release build has
/// no caller and carries no dead code.
#[cfg(any(target_os = "linux", test))]
pub fn validate_fortress_id(fortress_id: &str) -> Result<(), String> {
    if fortress_id.len() < FORTRESS_ID_MIN_LEN
        || fortress_id.len() > FORTRESS_ID_MAX_LEN
        || !fortress_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(
            "server fortress id must be 8..64 lowercase hexadecimal characters".to_string(),
        );
    }
    Ok(())
}

impl DaemonConfig {
    pub fn selector_roots(&self) -> SelectorRoots {
        #[cfg(any(test, feature = "test-isolation"))]
        if let Some(roots) = &self.test_selector_roots {
            return roots.clone();
        }
        SelectorRoots::production()
    }

    /// Defaults targeted at the canonical Linux layout. Tests construct via
    /// the public fields directly; production loads through `from_argv`.
    pub fn defaults_for_fortress(fortress_id: impl Into<String>) -> Self {
        let fortress_id = fortress_id.into();
        let runtime_dir = PathBuf::from(RAW_RUNTIME_ROOT).join(&fortress_id);
        let state_dir = PathBuf::from(RAW_STATE_ROOT).join(&fortress_id);
        Self {
            #[cfg(any(test, feature = "test-isolation"))]
            test_selector_roots: None,
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
            #[cfg(feature = "test-isolation")]
            test_boot_time_shutdown_requested: false,
            #[cfg(feature = "test-isolation")]
            test_delay_before_ready_ms: None,
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
        validate_fortress_id(&self.fortress_id)?;
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

    // A partially-isolated path set is the shape that still reads or mutates
    // operator state, so the predicate has to fail on EACH path individually.
    #[test]
    fn a_production_journal_beside_isolated_paths_is_not_isolated() {
        let root = std::path::Path::new("/tmp/castle-wall-isolation-fixture");
        let isolated = LinuxRuntimePaths::isolated_under(root);
        assert!(isolated.is_isolated_from_production());
        let mut leaky = isolated.clone();
        leaky.journal_auth_key_path =
            PathBuf::from(crate::ownership_journal::DEFAULT_JOURNAL_AUTH_KEY_PATH);
        assert!(
            !leaky.is_isolated_from_production(),
            "a boot with two temporary paths and the operator's own journal key would \
             authenticate against operator state"
        );
        assert!(!LinuxRuntimePaths::production().is_isolated_from_production());
    }
}

// DRAIN_INVENTORY_BEGIN
// must match `drain_schema.json` via `scripts/generate-drain-contract.mjs`
#[rustfmt::skip]
pub const BUSINESS_PROFILE_SELECTOR: &str = "/etc/sanctuary/business-profile.json";
#[cfg(target_os = "linux")]
#[rustfmt::skip]
pub const BUSINESS_SIGNER_CONFIG: &str = crate::business_profile::custody::CONFIG_PATH;
#[rustfmt::skip]
pub const BUSINESS_SIGNER_PEER_POLICY: &str = "/etc/sanctuary/business-signer-peer.json";
#[rustfmt::skip]
pub const BUSINESS_SIGNER_CONTROLLER_POLICY: &str = "/etc/sanctuary/business-signer-controller.json";
#[rustfmt::skip]
pub const BUSINESS_WRITER_CONFIG: &str = "/etc/sanctuary/business-writer.json";
#[rustfmt::skip]
pub const BUSINESS_DRAIN_CONFIG: &str = "/etc/sanctuary/business-drain.json";
#[cfg(target_os = "linux")]
#[rustfmt::skip]
pub const BUSINESS_CUSTODY_ROOT: &str = crate::business_profile::custody::CUSTODY_ROOT;
#[rustfmt::skip]
pub const BUSINESS_DRAIN_ROOT: &str = "/var/lib/sanctuary-business-drain";
#[cfg(target_os = "linux")]
pub const BUSINESS_EVIDENCE: &[&str] = &[
    BUSINESS_PROFILE_SELECTOR,
    BUSINESS_SIGNER_CONFIG,
    BUSINESS_SIGNER_PEER_POLICY,
    BUSINESS_SIGNER_CONTROLLER_POLICY,
    BUSINESS_WRITER_CONFIG,
    BUSINESS_DRAIN_CONFIG,
    BUSINESS_CUSTODY_ROOT,
    BUSINESS_DRAIN_ROOT,
];
#[cfg(all(test, target_os = "linux"))]
#[test]
#[rustfmt::skip]
fn drain_inventory_aliases_match_schema() {
    assert_eq!(BUSINESS_SIGNER_CONFIG, "/etc/sanctuary/business-signer.json");
    assert_eq!(BUSINESS_CUSTODY_ROOT, "/var/lib/sanctuary-business-signer");
}
// DRAIN_INVENTORY_END
pub const RAW_STATE_ROOT: &str = "/var/lib/sanctuary";
pub const RAW_RUNTIME_ROOT: &str = "/run/sanctuary";
pub const RAW_STATE_RELATIVE: &str = "policy/egress/audit-producer.key";
pub const RAW_RUNTIME_RELATIVE: &str = "audit-producer.pub";
pub const RAW_INVENTORY_MAX_ENTRIES: usize = 64; // Policy bound: unexplained legacy fortress accumulation refuses migration.
pub const ID_BYTES: usize = 16; // The enrollment format uses sixteen-byte identifiers.
pub const SELECTOR_ID_HEX_LENGTH: usize = ID_BYTES * 2;
pub const SAFE_INTEGER_MAX: u64 = (1 << 53) - 1; // Largest exact integer shared by JSON runtimes.
pub const SELECTOR_MAX_BYTES: usize = 512; // Next power of two above the maximal canonical selector's 463 bytes.
pub const SELECTOR_MODE: u32 = 0o600; // Enrollment selection is owner-readable and owner-writable only.
pub const CANDIDATE_MAX_BYTES: usize = 4096 - 1; // Linux PATH_MAX includes the terminating NUL.
pub const CANDIDATE_MAX_COMPONENTS: usize = CANDIDATE_MAX_BYTES.div_ceil(2); // One-byte names separated by slashes.

// Work ceiling: 22 fixed directory opens: one root, six /etc/sanctuary
// walks of two parents, two /var/lib walks of two parents, and raw roots
// of three and two parents; plus 64 * (6 + 3) raw parent opens,
// and at most 2 * 2048 candidate parent opens. Each has one fstat; each
// leaf has one no-follow probe. At most two extra descriptors hold the
// selector and enumeration stream. All held descriptors close on return.
// readdir observes at most 65 non-dot names per root, never a full listing;
// the selector reads at most 513 bytes. Resource exhaustion refuses closed.
pub const MAX_RAW_CANDIDATES: usize = 2; // The private and public producer paths are the only caller candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyReason {
    Explicit,
    NoBusinessEvidence,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileRefusal {
    SelectorInvalid,
    InventoryAmbiguous,
    LegacyWithEnrollment,
    RawInventoryPresent,
}
impl std::fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
#[derive(Debug)]
struct Sealed;
#[derive(Debug)]
pub struct LegacyV1Selection {
    _sealed: Sealed,
    reason: LegacyReason,
}
impl LegacyV1Selection {
    pub fn reason(&self) -> LegacyReason {
        self.reason
    }
}
#[derive(Debug)]
pub struct BusinessSelection {
    _sealed: Sealed,
}
#[derive(Debug)]
pub enum ProfileSelection {
    LegacyV1(LegacyV1Selection),
    Business(BusinessSelection),
    Refused(ProfileRefusal),
}

#[derive(Debug, Clone)]
pub struct SelectorRoots {
    anchor: PathBuf,
    expected_owner: u32,
    #[cfg(any(test, feature = "test-isolation"))]
    owners: std::collections::BTreeMap<PathBuf, u32>,
    #[cfg(any(test, feature = "test-isolation"))]
    denied_lookup: std::collections::BTreeSet<PathBuf>,
    #[cfg(any(test, feature = "test-isolation"))]
    denied_open: std::collections::BTreeSet<PathBuf>,
}
impl SelectorRoots {
    // The shipped selector trusts only uid 0 under the real root; isolated roots, owner overrides and deny seams exist only in test builds.
    pub fn production() -> Self {
        Self {
            anchor: PathBuf::from("/"),
            expected_owner: 0,
            #[cfg(any(test, feature = "test-isolation"))]
            owners: Default::default(),
            #[cfg(any(test, feature = "test-isolation"))]
            denied_lookup: Default::default(),
            #[cfg(any(test, feature = "test-isolation"))]
            denied_open: Default::default(),
        }
    }
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn isolated_under(root: &std::path::Path) -> Self {
        Self {
            anchor: root.to_path_buf(),
            expected_owner: nix::unistd::geteuid().as_raw(),
            ..Self::production()
        }
    }
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn expect_owner_at(mut self, path: &std::path::Path, uid: u32) -> Self {
        self.owners.insert(path.to_path_buf(), uid);
        self
    }
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn deny_lookup(mut self, path: &std::path::Path) -> Self {
        self.denied_lookup.insert(path.to_path_buf());
        self
    }
    #[cfg(any(test, feature = "test-isolation"))]
    pub fn deny_open(mut self, path: &std::path::Path) -> Self {
        self.denied_open.insert(path.to_path_buf());
        self
    }
}

// Profile selection reads only root-owned on-disk evidence; an absent or false environment opt-in never selects legacy on a host with business evidence, and a caller-supplied path can only add refusal.
pub fn select_profile(roots: &SelectorRoots, candidates: &[&std::path::Path]) -> ProfileSelection {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (roots, candidates);
        ProfileSelection::LegacyV1(LegacyV1Selection {
            _sealed: Sealed,
            reason: LegacyReason::NoBusinessEvidence,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let result = selection_walk::evaluate(roots, candidates);
        match result {
            // Continuing paths: only complete absent enrollment permits explicit or implicit legacy, including hosts with raw keys.
            Ok(Some(reason)) => ProfileSelection::LegacyV1(LegacyV1Selection {
                _sealed: Sealed,
                reason,
            }),
            // Continuing path: a business token exists only after the business arm proves raw inventory absent.
            Ok(None) => ProfileSelection::Business(BusinessSelection { _sealed: Sealed }),
            Err(reason) => ProfileSelection::Refused(reason),
        }
    }
}

#[cfg(target_os = "linux")]
mod selection_walk {
    use super::*;
    use nix::{
        errno::Errno,
        fcntl::{openat, AtFlags, OFlag},
        sys::stat::{fstatat, Mode},
    };
    use std::{
        fs::File,
        io::Read,
        os::{
            fd::{AsRawFd, FromRawFd, RawFd},
            unix::fs::{MetadataExt, OpenOptionsExt},
        },
        path::{Path, PathBuf},
    };
    use ProfileRefusal::{InventoryAmbiguous, RawInventoryPresent, SelectorInvalid};
    const DIRECTORY_FLAGS: OFlag =
        OFlag::from_bits_truncate(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    const UNTRUSTED_WRITE_BITS: u32 = 0o022; // Group or other write permits another principal to hide enrollment.
    struct Directory(*mut libc::DIR);
    impl Drop for Directory {
        fn drop(&mut self) {
            // SAFETY: this owner closes the successful fdopendir stream exactly once.
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    struct Walk<'a> {
        roots: &'a SelectorRoots,
        held: Vec<File>,
    }
    impl<'a> Walk<'a> {
        fn new(roots: &'a SelectorRoots) -> Result<Self, ProfileRefusal> {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(DIRECTORY_FLAGS.bits())
                .open(&roots.anchor)
                .map_err(|_| InventoryAmbiguous)?;
            let mut walk = Self {
                roots,
                held: vec![file],
            };
            walk.trust(0, Path::new(""))
                .map_err(|_| InventoryAmbiguous)?;
            Ok(walk)
        }
        fn seam(&self, path: &Path, opening: bool) -> Result<(), Errno> {
            #[cfg(any(test, feature = "test-isolation"))]
            if self.roots.denied_lookup.contains(path)
                || (opening && self.roots.denied_open.contains(path))
            {
                return Err(Errno::EACCES);
            }
            let _ = (path, opening);
            Ok(())
        }
        fn owner(&self, path: &Path) -> u32 {
            #[cfg(any(test, feature = "test-isolation"))]
            if let Some(owner) = self.roots.owners.get(path) {
                return *owner;
            }
            let _ = path;
            self.roots.expected_owner
        }
        fn trust(&mut self, index: usize, path: &Path) -> Result<(), Errno> {
            self.seam(path, true)?;
            let stat = self.held[index].metadata().map_err(|_| Errno::EIO)?;
            // Every held parent must retain exclusive ownership of its names, or absence is not evidence.
            if !stat.is_dir()
                || stat.uid() != self.owner(path)
                || stat.mode() & UNTRUSTED_WRITE_BITS != 0
            {
                return Err(Errno::EACCES);
            }
            Ok(())
        }
        fn directory(&mut self, relative: &Path) -> Result<RawFd, Errno> {
            let mut parent = self.held[0].as_raw_fd();
            let mut path = PathBuf::new();
            for component in relative.iter() {
                path.push(component);
                self.seam(&path, true)?;
                // A held no-follow parent prevents a renamed or linked ancestor from redirecting later probes.
                let fd = openat(parent, Path::new(component), DIRECTORY_FLAGS, Mode::empty())?;
                // SAFETY: openat returned a new owned fd, and File closes it on every exit.
                self.held.push(unsafe { File::from_raw_fd(fd) });
                self.trust(self.held.len() - 1, &path)?;
                parent = fd;
            }
            Ok(parent)
        }
        fn present(&mut self, relative: &Path) -> Result<bool, Errno> {
            self.seam(relative, false)?;
            let parent = self.directory(relative.parent().ok_or(Errno::EINVAL)?)?;
            // Entry type never erases enrollment; symlinks are evidence and are never followed.
            fstatat(
                parent,
                Path::new(relative.file_name().ok_or(Errno::EINVAL)?),
                AtFlags::AT_SYMLINK_NOFOLLOW,
            )
            .map(|_| true)
        }
        fn selector(&mut self) -> Result<Option<bool>, ProfileRefusal> {
            let path = Path::new(&BUSINESS_PROFILE_SELECTOR[1..]);
            self.seam(path, true).map_err(|_| InventoryAmbiguous)?;
            let parent = match self.directory(path.parent().ok_or(InventoryAmbiguous)?) {
                Ok(fd) => fd,
                Err(Errno::ENOENT) => return Ok(None),
                Err(_) => return Err(InventoryAmbiguous),
            };
            // The opened object is checked directly; a final symlink must fail before any target can be read.
            let fd = match openat(
                parent,
                Path::new(path.file_name().ok_or(InventoryAmbiguous)?),
                OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
                Mode::empty(),
            ) {
                Ok(fd) => fd,
                Err(Errno::ENOENT) => return Ok(None),
                Err(Errno::ELOOP) => return Err(SelectorInvalid),
                Err(_) => return Err(InventoryAmbiguous),
            };
            // SAFETY: openat returned a new owned fd, and File closes it on every exit.
            let file = unsafe { File::from_raw_fd(fd) };
            let stat = file.metadata().map_err(|_| InventoryAmbiguous)?;
            // A unique owner-only regular inode prevents aliasing and bounds all parsing work.
            if !stat.is_file()
                || stat.nlink() != 1
                || stat.uid() != self.owner(path)
                || stat.mode() & 0o7777 != SELECTOR_MODE
                || stat.len() > SELECTOR_MAX_BYTES as u64
            {
                return Err(SelectorInvalid);
            }
            let mut bytes = Vec::new();
            file.take((SELECTOR_MAX_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .map_err(|_| InventoryAmbiguous)?;
            if bytes.len() > SELECTOR_MAX_BYTES {
                return Err(SelectorInvalid);
            }
            // The selector names the profile and enrollment; only shape and canonical bytes are checked here, not digest agreement with custody or the drain. It grants nothing.
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| SelectorInvalid)?;
            if crate::smb::jcs::encode(&value)
                .map_err(|_| SelectorInvalid)?
                .as_bytes()
                != bytes
                || !valid_selector(&value)
            {
                return Err(SelectorInvalid);
            }
            Ok(Some(value["profile"] == "legacy-v1"))
        }
        fn raw(&mut self, candidates: &[&Path]) -> Result<bool, ProfileRefusal> {
            for (root, suffix) in [
                (RAW_STATE_ROOT, RAW_STATE_RELATIVE),
                (RAW_RUNTIME_ROOT, RAW_RUNTIME_RELATIVE),
            ] {
                let relative = Path::new(&root[1..]);
                let fd = match self.directory(relative) {
                    Ok(fd) => fd,
                    Err(Errno::ENOENT) => continue,
                    Err(_) => return Err(InventoryAmbiguous),
                };
                let read_fd = match openat(fd, ".", DIRECTORY_FLAGS, Mode::empty()) {
                    Ok(fd) => fd,
                    Err(_) => return Ok(true),
                };
                // SAFETY: fdopendir takes ownership on success; the failed conversion is closed below.
                let pointer = unsafe { libc::fdopendir(read_fd) };
                if pointer.is_null() {
                    // SAFETY: the failed fdopendir left read_fd owned by this function.
                    unsafe {
                        libc::close(read_fd);
                    }
                    return Ok(true);
                }
                let dir = Directory(pointer);
                let mut count = 0;
                // Each root admits 64 names and one candidate walk per name; the next name refuses without collecting the directory.
                loop {
                    Errno::clear();
                    // SAFETY: Directory owns a live DIR stream until this loop returns.
                    let entry = unsafe { libc::readdir(dir.0) };
                    if entry.is_null() {
                        if Errno::last() != Errno::UnknownErrno {
                            return Ok(true);
                        }
                        break;
                    }
                    // SAFETY: readdir supplies a NUL-terminated name valid until its next call.
                    let name =
                        unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                    if name == b"." || name == b".." {
                        continue;
                    }
                    count += 1;
                    if count > RAW_INVENTORY_MAX_ENTRIES {
                        return Ok(true);
                    }
                    use std::os::unix::ffi::OsStrExt;
                    let path = relative
                        .join(std::ffi::OsStr::from_bytes(name))
                        .join(suffix);
                    // The fortress name itself is not a key hit; only the no-follow key walk can establish absence.
                    if !matches!(self.present(&path), Err(Errno::ENOENT)) {
                        return Ok(true);
                    }
                }
            }
            // Concrete candidates may only add refusal; they cannot escape an isolated anchor or create an unbounded walk.
            if candidates.len() > MAX_RAW_CANDIDATES {
                return Ok(true);
            }
            for candidate in candidates {
                let raw = candidate.as_os_str().as_encoded_bytes();
                if raw.len() > CANDIDATE_MAX_BYTES || raw.contains(&0) || !candidate.is_absolute() {
                    return Ok(true);
                }
                if raw
                    .split(|b| *b == b'/')
                    .any(|part| part == b"." || part == b"..")
                {
                    return Ok(true);
                }
                let relative = match candidate.strip_prefix(&self.roots.anchor) {
                    Ok(path) => path,
                    Err(_) => return Ok(true),
                };
                if relative.as_os_str().is_empty()
                    || relative.components().count() > CANDIDATE_MAX_COMPONENTS
                {
                    return Ok(true);
                }
                if !matches!(self.present(relative), Err(Errno::ENOENT)) {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
    fn exact(value: &serde_json::Value, names: &[&str]) -> bool {
        value.as_object().is_some_and(|map| {
            map.len() == names.len() && names.iter().all(|name| map.contains_key(*name))
        })
    }
    fn lower_hex(value: &serde_json::Value, length: usize, prefix: &str) -> bool {
        value
            .as_str()
            .and_then(|s| s.strip_prefix(prefix))
            .is_some_and(|s| {
                s.len() == length
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
    fn valid_selector(value: &serde_json::Value) -> bool {
        const DIGEST_HEX_LENGTH: usize = 32 * 2; // SHA-256 bytes encoded as hex pairs.
        const DIGESTS: &[&str] = &["custody_envelope_digest", "roster_digest", "anchor_digest"];
        exact(value, &["version", "profile", "fortress_id", "machine_id", "enrollment_revision", "digests"])
            && value["version"].as_u64() == Some(1) // The initial selector format version.
            && matches!(value["profile"].as_str(), Some("business" | "legacy-v1"))
            && lower_hex(&value["fortress_id"], SELECTOR_ID_HEX_LENGTH, "")
            && lower_hex(&value["machine_id"], SELECTOR_ID_HEX_LENGTH, "")
            && value["enrollment_revision"].as_u64().is_some_and(|n| (1..=SAFE_INTEGER_MAX).contains(&n))
            && exact(&value["digests"], DIGESTS)
            && DIGESTS.iter().all(|name| lower_hex(&value["digests"][name], DIGEST_HEX_LENGTH, "sha256:"))
    }
    pub(super) fn evaluate(
        roots: &SelectorRoots,
        candidates: &[&Path],
    ) -> Result<Option<LegacyReason>, ProfileRefusal> {
        let mut walk = Walk::new(roots)?;
        let selector = walk.selector()?;
        let mut evidence = false;
        // All seven entries must be unambiguous before either profile can continue.
        for path in &BUSINESS_EVIDENCE[1..] {
            match walk.present(Path::new(&path[1..])) {
                Ok(_) => evidence = true,
                Err(Errno::ENOENT) => (),
                Err(_) => return Err(InventoryAmbiguous),
            }
        }
        match (selector, evidence) {
            (Some(true), true) => Err(ProfileRefusal::LegacyWithEnrollment),
            (Some(true), false) => Ok(Some(LegacyReason::Explicit)),
            (None, false) => Ok(Some(LegacyReason::NoBusinessEvidence)),
            _ => {
                if walk.raw(candidates)? {
                    Err(RawInventoryPresent)
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod selector_tests {
    use super::*;
    #[test]
    fn production_roots_trust_only_root_without_seams() {
        let roots = SelectorRoots::production();
        assert_eq!(roots.anchor, PathBuf::from("/"));
        assert_eq!(roots.expected_owner, 0);
        assert!(
            roots.owners.is_empty()
                && roots.denied_lookup.is_empty()
                && roots.denied_open.is_empty()
        );
    }
    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_returns_implicit_legacy_without_lookups() {
        let roots =
            SelectorRoots::isolated_under(std::path::Path::new("/missing-selection-anchor"));
        match select_profile(&roots, &[]) {
            ProfileSelection::LegacyV1(token) => {
                assert_eq!(token.reason(), LegacyReason::NoBusinessEvidence)
            }
            other => panic!("non-Linux must keep legacy without IO: {other:?}"),
        }
    }
}
