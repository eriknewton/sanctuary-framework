//! Daemon configuration sourced from CLI arguments and environment variables.
//!
//! PR 2a fixes the contract: every value the daemon needs at boot is captured
//! here, parseable from argv with a tiny hand-rolled parser (no clap dep yet
//! to keep the binary small). PR 2b adds the real subcommands beyond `run`.

use std::path::PathBuf;
use std::time::Duration;

use crate::constants::{
    DEFAULT_NO_WALL_DURATION_SECONDS, DEFAULT_PROMPT_TIMEOUT_SECONDS,
    DEFAULT_WAL_SIZE_CAP_BYTES, DEFAULT_WAL_TTL_SECONDS,
};

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
    /// Operator-decision timeout for an open prompt.
    pub prompt_timeout: Duration,
    /// Bounded duration for the emergency `--no-wall` recovery mode.
    pub no_wall_max_duration: Duration,
    /// WAL retention TTL.
    pub wal_ttl: Duration,
    /// WAL size cap in bytes.
    pub wal_size_cap_bytes: u64,
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
            prompt_timeout: Duration::from_secs(DEFAULT_PROMPT_TIMEOUT_SECONDS as u64),
            no_wall_max_duration: Duration::from_secs(DEFAULT_NO_WALL_DURATION_SECONDS as u64),
            wal_ttl: Duration::from_secs(DEFAULT_WAL_TTL_SECONDS as u64),
            wal_size_cap_bytes: DEFAULT_WAL_SIZE_CAP_BYTES,
        }
    }

    /// Hand-rolled argv parser. Recognized flags:
    ///   --fortress-id <hex>
    ///   --socket-path <path>
    ///   --policy-dir <path>
    ///   --wal-path <path>
    ///   --pinned-public-key <path>
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_canonical_layout() {
        let cfg = DaemonConfig::defaults_for_fortress("abc123");
        assert_eq!(cfg.fortress_id, "abc123");
        assert_eq!(cfg.socket_path, PathBuf::from("/run/sanctuary/abc123/filter.sock"));
        assert_eq!(cfg.wal_path, PathBuf::from("/var/lib/sanctuary/abc123/filter-events.wal"));
    }

    #[test]
    fn argv_round_trips_required_fields() {
        let cfg = DaemonConfig::from_argv(["--fortress-id", "deadbeef"]).expect("parse");
        assert_eq!(cfg.fortress_id, "deadbeef");
    }

    #[test]
    fn argv_rejects_unknown_flag() {
        let err = DaemonConfig::from_argv(["--fortress-id", "x", "--rogue", "y"]).unwrap_err();
        assert!(matches!(err, ConfigError::Unknown(s) if s == "--rogue"));
    }
}
