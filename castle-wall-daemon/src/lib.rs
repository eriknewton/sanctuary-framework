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
pub mod crypto;
pub mod daemon;
pub mod decision;
pub mod enforcement;
pub mod failure;
pub mod habeas;
pub mod health_probe;
pub(crate) mod identity;
pub mod ipc;
pub mod jail;
pub mod launcher;
pub mod live_status;
pub mod manifest;
pub mod nfqueue;
pub mod nftables;
pub mod ownership_journal;
pub mod policy;
pub mod runtime_health;
pub mod runtime_lock;
pub mod runtime_providers;
pub mod systemd_notify;
pub mod thread_component;

pub use config::DaemonConfig;
pub use daemon::{
    boot, DaemonError, DaemonExitReport, DaemonHandle, DaemonRuntimeState, SupervisionOutcome,
};
pub use decision::{AttemptError, DecisionEngine, EvaluationOutcome};
pub use enforcement::{
    derive_daemon_state, enforcement_status, AcquiredComponent, ComponentKind, ComponentProvider,
    EnforcementError, EnforcementRuntime, EnforcementStartError, EnforcementStatus, NotReadyReason,
};
pub use ipc::framing::{frame, parse_frame, ParseStep};
pub use ipc::messages::{IpcMessage, MessageEnvelope};
pub use manifest::verify::verify_manifest_signature;
pub use policy::{
    build_audit_event_canonical_json, DeniedReason, EvaluationRequest, PolicySnapshot,
    PolicySnapshotError, Verdict,
};
pub use runtime_providers::{
    disarm_castle_runtime, linux_production_plan, DisarmOutcome, LinuxRuntimeConfig,
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

    /// Domain-separation prefix for the per-event producer signature
    /// (Slice L1). Mirrors `CASTLE_WALL_PRODUCER_SIG_DOMAIN_PREFIX` in
    /// `server/src/castle-wall/constants.ts`. Binding the signature to a
    /// distinct domain prevents a signature minted for any other purpose
    /// (handshake nonce, manifest, transparency checkpoint) from ever
    /// validating as an enforcement-event producer signature.
    pub const PRODUCER_SIG_DOMAIN_PREFIX: &str = "sanctuary.castle-wall.audit-producer.v1\n";

    /// Key id stamped on producer signatures so the reader can select the
    /// right pinned producer public key. Mirrors the TS constant.
    pub const PRODUCER_SIG_KEY_ID_V1: &str = "cw-audit-producer-v1";
}
