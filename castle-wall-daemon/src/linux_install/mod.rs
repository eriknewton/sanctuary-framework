//! Linux installation, signed-policy admission, and bounded operator evidence.

// The fortress grammar is Linux-or-test in config.rs; keep one implementation.
#[cfg(any(target_os = "linux", test))]
pub mod contract;

/// EX_UNAVAILABLE for the phase-0 launch scaffolds until P3 is integrated.
pub const NOT_BUILT_EXIT_CODE: u8 = 69;
/// Must match the stub mains in src/bin/{protected-agent-v1,network-agent-standin}.rs.
pub const NOT_BUILT_MESSAGE: &str = "not built in this commit";

#[cfg(target_os = "linux")]
pub mod transaction;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[cfg(target_os = "linux")]
pub mod account;

#[cfg(target_os = "linux")]
pub mod command;
#[cfg(target_os = "linux")]
pub mod policy;

#[cfg(target_os = "linux")]
pub mod evidence;
