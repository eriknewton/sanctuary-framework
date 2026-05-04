//! Manifest watcher and verifier.
//!
//! PR 2a ships the verifier (Ed25519 signature check + per-rule SHA-256
//! check + canonical-JSON serialization). The inotify watcher and the TOFU
//! pinning lifecycle ship in PR 2b alongside the kernel-touching modules.

pub mod canonical_json;
pub mod verify;
