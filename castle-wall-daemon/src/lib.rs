//! Castle Wall daemon library surface.
//!
//! PR 2b ships the daemon lifecycle and the kernel-enforcement modules
//! behind the IPC contract that PR 2a established. The crate has two modes:
//!
//! 1. Library: pure Rust types and helpers used by both the binary and the
//!    integration tests in `tests/`. The IPC framing parser, the LSP-style
//!    encoder, the message envelope types, and the manifest verifier all
//!    live here; they have no kernel dependencies and compile cleanly on
//!    macOS, Linux, and Windows.
//!
//! 2. Binary: `src/main.rs` wires the daemon lifecycle (argv parsing,
//!    listen-on-socket, accept-and-handshake, JSON-RPC dispatch). On
//!    non-Linux targets the binary still compiles but the kernel-touching
//!    modules return structured "not implemented on this platform" errors.
//!
//! Source: Castle_Wall_Phase1_Scope_Lock_2026-05-03.md (sections 1, 4, 5,
//! 6, 7, 8). Parent ADR: Castle_Architecture_ADR_2026-04-30.md.

pub mod approval;
pub mod audit;
pub mod cgroup;
pub mod config;
pub mod daemon;
pub mod failure;
pub mod habeas;
pub(crate) mod identity;
pub mod ipc;
pub mod jail;
pub mod manifest;
pub mod nfqueue;
pub mod nftables;
pub mod policy;

pub use config::DaemonConfig;
pub use daemon::{
    boot, AttemptError, DaemonError, DaemonExitReport, DaemonHandle, EvaluationOutcome,
};
pub use ipc::framing::{frame, parse_frame, ParseStep};
pub use ipc::messages::{IpcMessage, MessageEnvelope};
pub use manifest::verify::verify_manifest_signature;
pub use policy::{
    build_audit_event_canonical_json, DeniedReason, EvaluationRequest, PolicySnapshot,
    PolicySnapshotError, Verdict,
};

/// Wire constants synchronized with `server/src/castle-wall/constants.ts`.
pub mod constants {
    /// Schema version for v1 allowlist rules, manifest, and signed envelopes.
    pub const SCHEMA_VERSION_V1: u32 = 1;

    /// Audit-log layer for every Castle Wall event.
    pub const AUDIT_LAYER: &str = "l1";

    /// Ed25519 signature scheme tag used in manifest envelopes.
    pub const SIGNATURE_SCHEME_V1: &str = "ed25519-v1";

    /// IPC framing header per scope-lock section 5.
    pub const IPC_CONTENT_LENGTH_HEADER: &str = "Content-Length";

    /// Default operator-decision timeout for an open prompt, in seconds.
    pub const DEFAULT_PROMPT_TIMEOUT_SECONDS: u32 = 30;

    /// Default duration for the emergency `--no-wall` recovery mode (1 hour).
    pub const DEFAULT_NO_WALL_DURATION_SECONDS: u32 = 3600;

    /// Default WAL retention TTL on the filter-daemon side, in seconds.
    pub const DEFAULT_WAL_TTL_SECONDS: u32 = 86_400;

    /// Default WAL size cap on the filter-daemon side, in bytes (100 MB).
    pub const DEFAULT_WAL_SIZE_CAP_BYTES: u64 = 104_857_600;

    /// Fixed length of an IPC request_id nonce in bytes.
    pub const REQUEST_ID_NONCE_BYTES: usize = 16;

    /// JSON-RPC method namespace for IPC messages.
    pub const IPC_NAMESPACE: &str = "castle-wall";
}
