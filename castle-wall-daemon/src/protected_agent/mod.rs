//! Release-disabled protected-agent stop authority. No production prepare,
//! CREATE, release publication, or wrapper exec entry point exists in this crate.
pub mod daemon_log;
pub mod ledger;
#[cfg(target_os = "linux")]
pub mod owner;
pub mod profile;
pub mod receipt;
pub mod stop_policy;
#[cfg(target_os = "linux")]
pub use owner::OwnerOutcome as StopClass;

#[cfg(not(target_os = "linux"))]
pub enum StopClass {
    IntentAccepted,
    NoOwnedRelease,
    OwnerUnavailable,
    Inhibit,
}
#[cfg(not(target_os = "linux"))]
pub fn owner_outcome_unavailable() -> StopClass {
    StopClass::OwnerUnavailable
}
