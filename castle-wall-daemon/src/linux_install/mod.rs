//! Shared Linux install contracts. Provisioning and launch are not implemented here.

// The fortress grammar is Linux-or-test in config.rs; keep one implementation.
#[cfg(any(target_os = "linux", test))]
pub mod contract;

/// EX_UNAVAILABLE (sysexits): these binaries have no implementation in phase 0.
pub const NOT_BUILT_EXIT_CODE: u8 = 69;
/// Must match the stub mains in src/bin/{sanctuary-linux,protected-agent-v1,network-agent-standin}.rs.
pub const NOT_BUILT_MESSAGE: &str = "not built in this commit";
