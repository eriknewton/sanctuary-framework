//! Manifest watcher and verifier.
//!
//! PR 2a ships the verifier (Ed25519 signature check + per-rule SHA-256
//! check + canonical-JSON serialization). The inotify watcher and the TOFU
//! pinning lifecycle ship in PR 2b alongside the kernel-touching modules.

pub mod canonical_json;
pub mod store;
pub mod verify;
pub mod watcher;

pub use store::{
    load_signed_manifest_from_disk, LoadedManifest, ManifestStore, ManifestStoreError,
    MANIFEST_FILENAME, RULES_SUBDIR,
};
pub use watcher::{ManifestWatcher, WatcherError, WatcherEvent, WatcherImpl};
