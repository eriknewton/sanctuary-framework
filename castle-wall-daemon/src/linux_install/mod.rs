//! Linux installation, signed-policy admission, and bounded operator evidence.

// The fortress grammar is Linux-or-test in config.rs; keep one implementation.
#[cfg(any(target_os = "linux", test))]
pub mod contract;

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
