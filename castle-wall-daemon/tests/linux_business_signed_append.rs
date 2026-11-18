// fail-before-exempt: native actor and settlement call-site fixtures read shared protocol and storage contracts.
// W-APPEND
// W-COMPOSE-ENTRY
#![cfg(target_os = "linux")]
#[path = "support/drain_run.rs"]
mod drain_run;
mod isolation;
#[path = "support/signed_append.rs"]
mod signed_append;
#[path = "support/writer_bus.rs"]
mod writer_bus;

#[path = "support/settlement_call_sites.rs"]
mod settlement_call_sites;
