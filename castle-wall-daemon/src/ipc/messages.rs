//! IPC message envelopes shared between Sanctuary main and the filter daemon.
//!
//! These types mirror `server/src/castle-wall/ipc/messages.ts`. The
//! serde-derived JSON shape is the wire shape.

use serde::{Deserialize, Serialize};

/// Wire protocol version this daemon speaks. Bumped only when the SHAPE of an
/// existing message changes in a way a peer must know about; purely additive
/// optional fields do not bump it (they are discovered through [`CAPABILITIES`]).
///
/// Must match `CASTLE_WALL_IPC_PROTOCOL_VERSION` in
/// `server/src/castle-wall/ipc/messages.ts`.
pub const IPC_PROTOCOL_VERSION: u32 = 2;

/// Capability token: the daemon REPLIES to `audit_drain_ack` with an
/// `audit_drain_ack_response`. A peer that does not advertise this token in its
/// handshake response gets the pre-v2 one-way behavior (no reply), because an
/// unexpected response frame on a client that never registered a pending request
/// is at best ignored and at worst a protocol fault.
///
/// Must match `CAP_AUDIT_DRAIN_ACK_RESPONSE` in
/// `server/src/castle-wall/ipc/messages.ts`.
pub const CAP_AUDIT_DRAIN_ACK_RESPONSE: &str = "audit_drain_ack_response";

/// Capability token: `status_response` carries the lifecycle/runtime assertion
/// fields (`manifest_state`, `lifecycle_state`, `runtime_state`,
/// `kernel_runtime_ready`, `enforcing`). A consumer that does not see this token
/// advertised must treat those fields as UNAVAILABLE — not as `false` — because
/// a pre-v2 daemon simply does not report them, and absence is not a failure.
///
/// Must match `CAP_STATUS_RUNTIME_FIELDS` in
/// `server/src/castle-wall/ipc/messages.ts`.
pub const CAP_STATUS_RUNTIME_FIELDS: &str = "status_runtime_fields";

/// Capability token: `audit_drain_response` and `audit_drain_ack_response` carry
/// `error_class`, which separates a RETRYABLE condition (the daemon was busy or
/// is stopping; nothing is broken and nothing was lost) from a TERMINAL one (a
/// poisoned lock, a WAL read/truncate failure, an unwired WAL).
///
/// This exists because the consumer previously had only a free-text `error` and
/// converted every one of them into a permanent not-armed wall with a durable
/// `castle_wall_drain_failed` record. A `systemctl stop` with an ACK in flight,
/// or a 2-second control-lock timeout under load, therefore manufactured
/// evidence of a transport/persistence fault for a link that was fine. The class
/// is produced by the ONE mapping in [`DrainErrorClass::of`] rather than by a
/// consumer-side table of daemon error strings, which is the hand-mirrored shape
/// that drifts the moment a message is reworded (AGENTS rule 11).
///
/// Must match `CAP_DRAIN_ERROR_CLASS` in
/// `server/src/castle-wall/ipc/messages.ts`.
pub const CAP_DRAIN_ERROR_CLASS: &str = "drain_error_class";

/// Capability token: `status_response` carries `runtime_health` and
/// `runtime_health_age_ms`, distinguishing a proven loss from an indeterminate
/// probe.
///
/// Must match `CAP_STATUS_RUNTIME_HEALTH` in
/// `server/src/castle-wall/ipc/messages.ts`.
pub const CAP_STATUS_RUNTIME_HEALTH: &str = "status_runtime_health";
/// Authenticated broker may publish one complete signed policy bundle without
/// supplying any daemon filesystem path.
pub const CAP_POLICY_BUNDLE_PUBLISH: &str = "policy_bundle_publish_v1";

/// Every capability this daemon offers, advertised in the handshake challenge.
///
/// This is the ONE list; the handshake, the ack dispatch, and the parity test all
/// read it, so a capability cannot be advertised without being implemented or
/// implemented without being advertised (AGENTS rule 5: one source, full-set
/// parity, not a hand-mirrored table).
pub const CAPABILITIES: &[&str] = &[
    CAP_AUDIT_DRAIN_ACK_RESPONSE,
    CAP_STATUS_RUNTIME_FIELDS,
    CAP_STATUS_RUNTIME_HEALTH,
    CAP_DRAIN_ERROR_CLASS,
    CAP_POLICY_BUNDLE_PUBLISH,
];

/// How a consumer must treat a drain / drain-ack failure.
///
/// Three-valued in effect, because ABSENT (a pre-v2 daemon that sends no class)
/// is a third state the consumer handles separately: it is not `Retryable` and
/// not `Terminal`, it is "this daemon does not say", and the consumer applies its
/// own bounded retry budget instead of inventing either answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrainErrorClass {
    /// A transient condition. The consumer's data is unaffected: on the drain
    /// path nothing was delivered, and on the ACK path the events are ALREADY
    /// durable consumer-side (the consumer advances its own chain state before
    /// acking), so a refused truncation costs daemon WAL space and nothing else.
    /// Retry with backoff; do NOT record a durable fault and do NOT tear the
    /// wall down.
    Retryable,
    /// A condition that will not clear by retrying: a poisoned lock (a holder
    /// panicked), a WAL read/truncate failure (storage or integrity), or a WAL
    /// that is not wired at all. The wall's evidence channel is genuinely broken
    /// and must fail closed.
    Terminal,
}

impl DrainErrorClass {
    /// Stable wire token. Kept beside the enum so the daemon and
    /// `server/src/castle-wall/ipc/messages.ts` cannot drift; must match
    /// `DrainErrorClass` in that file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Retryable => "retryable",
            Self::Terminal => "terminal",
        }
    }
}

/// The three-valued state of the daemon's manifest store as a status reader can
/// observe it.
///
/// A boolean `manifest_state_available` used to fold three different things into
/// `false`: a CONTENDED store lock, a POISONED one, and a store that is not
/// wired at all. The consumer read `!== true` as a proven-degraded runtime and
/// tore down a healthy wall, and the same status also reported
/// `loaded_rule_count: 0` with a null signature, which reads as "the daemon has
/// no rules" — a fabricated fact about a store it could not open. The store lock
/// is genuinely contended in normal operation: verdict evaluation takes it per
/// packet and a manifest reload holds it across verify + WAL fsync, which is
/// exactly what a policy write before arming triggers.
///
/// So: `Ready` and `Empty` are PROVEN observations and their companion count and
/// signature fields are authoritative; `Unavailable` is INDETERMINATE and those
/// fields carry no information; `Degraded` is a PROVEN failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestState {
    /// The store was read and a verified manifest is live. `loaded_rule_count`
    /// and `loaded_manifest_signature_b64url` describe it.
    Ready,
    /// The store was read and holds NO manifest (deny-by-default boot before the
    /// first successful reload). A proven absence: `loaded_rule_count: 0` is the
    /// truth here, not a fabrication.
    Empty,
    /// The store lock was held by another operation right now. Indeterminate:
    /// NOT a loss, NOT readiness, and the count/signature on the same status
    /// frame must be ignored rather than read as zero/null.
    Unavailable,
    /// The store lock is poisoned — a holder panicked mid-mutation. A proven
    /// failure of policy state, which fails closed.
    Degraded,
    /// This daemon has no manifest store wired (not a production shape).
    /// Structural, proven, and distinct from "could not read it".
    Unwired,
}

impl ManifestState {
    /// Stable wire token; must match `CastleWallManifestState` in
    /// `server/src/castle-wall/ipc/messages.ts`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Empty => "empty",
            Self::Unavailable => "unavailable",
            Self::Degraded => "degraded",
            Self::Unwired => "unwired",
        }
    }

    /// True only where the companion `loaded_rule_count` /
    /// `loaded_manifest_signature_b64url` fields on the same frame describe
    /// reality. The one place this question is answered, so a reader cannot
    /// re-derive it slightly differently.
    pub fn companion_fields_are_authoritative(self) -> bool {
        matches!(self, Self::Ready | Self::Empty)
    }
}

/// Tagged union of every Castle Wall IPC message body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
// The negotiated envelope is additively forward-tolerant: optional fields from
// a newer peer are ignored. Nested signed/security-bearing shapes below remain
// deny_unknown_fields so tolerance cannot change authorization semantics.
#[serde(tag = "type")]
pub enum IpcMessage {
    #[serde(rename = "status_request")]
    StatusRequest { request_id: String },
    #[serde(rename = "status_response")]
    StatusResponse {
        request_id: String,
        uptime_seconds: u64,
        /// Authoritative ONLY when `manifest_state` is `"ready"` or `"empty"`.
        /// Both fields are pre-v2 wire surface and cannot become optional, so an
        /// indeterminate store still serializes `null` / `0` here; that is why
        /// `manifest_state` exists and why a consumer must consult it first.
        /// Must match the same rule in
        /// `server/src/castle-wall/ipc/messages.ts`.
        loaded_manifest_signature_b64url: Option<String>,
        loaded_rule_count: u32,
        /// Three-valued manifest-store observation. See
        /// [`ManifestState`]. Optional on the wire so a pre-v2 peer
        /// deserializes; a v2 daemon always sends it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        manifest_state: Option<String>,
        lifecycle_state: String,
        runtime_state: String,
        kernel_runtime_ready: bool,
        enforcing: bool,
        no_wall_engaged: bool,
        /// Probe outcome behind `kernel_runtime_ready`: `"ready"`, `"lost"`,
        /// `"probe_unavailable"`, or `"no_runtime"` (see
        /// [`crate::runtime_health::RuntimeHealthState::as_str`], which is the
        /// only producer of these tokens). Optional on the wire so a pre-v2 peer
        /// deserializes; a v2 daemon always sends it. ABSENT means "this daemon
        /// does not report probe outcomes", which is not the same as
        /// `"probe_unavailable"` and must never be read as `"lost"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_health: Option<String>,
        /// Age of the observation behind `runtime_health`, in milliseconds.
        /// `None` when nothing has been observed yet.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        runtime_health_age_ms: Option<u64>,
    },
    #[serde(rename = "policy_reload_request")]
    PolicyReloadRequest {
        request_id: String,
        manifest_path: String,
    },
    #[serde(rename = "policy_reload_response")]
    PolicyReloadResponse {
        request_id: String,
        ok: bool,
        loaded_manifest_signature_b64url: Option<String>,
        loaded_rule_count: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "policy_bundle_publish_request")]
    PolicyBundlePublishRequest {
        request_id: String,
        manifest_b64url: String,
        rules: Vec<PolicyBundleRule>,
    },
    #[serde(rename = "policy_bundle_publish_response")]
    PolicyBundlePublishResponse {
        request_id: String,
        ok: bool,
        loaded_manifest_signature_b64url: Option<String>,
        loaded_rule_count: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    #[serde(rename = "decision_request")]
    DecisionRequest {
        request_id: String,
        surface: String,
        destination: IpcDestination,
        agent: IpcAgentAttribution,
        timeout_seconds: u32,
    },
    #[serde(rename = "decision_response")]
    DecisionResponse {
        request_id: String,
        decision: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        learn: Option<LearnedDecisionEnvelope>,
    },
    #[serde(rename = "audit_emit")]
    AuditEmit { event: serde_json::Value },
    #[serde(rename = "audit_emit_metric_batch")]
    AuditEmitMetricBatch {
        window_start: String,
        window_end: String,
        by_destination: Vec<MetricBatchEntry>,
    },
    /// Sanctuary main asks the daemon to drain WAL entries strictly above
    /// `after_seq`. Capped at `max_events`. Per scope-lock §8 hybrid pull
    /// model: main drives the pace; daemon never pushes audits unsolicited
    /// once the IPC link is healthy.
    #[serde(rename = "audit_drain_request")]
    AuditDrainRequest {
        request_id: String,
        after_seq: Option<u64>,
        max_events: u32,
    },
    /// Daemon's response carrying a batch of WAL entries (canonical-JSON of
    /// the AuditEntry plus chain metadata). `more_pending` signals that the
    /// daemon hit the `max_events` cap and additional entries remain to be
    /// drained on a subsequent request.
    #[serde(rename = "audit_drain_response")]
    AuditDrainResponse {
        request_id: String,
        events: Vec<AuditDrainEvent>,
        next_after_seq: Option<u64>,
        more_pending: bool,
        /// Absent when the overflow counter cannot be read without blocking.
        /// `None` is intentionally distinct from a measured zero.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        wal_overflow_count: Option<u64>,
        /// A drain transport/storage failure. An empty successful batch MUST
        /// never be used to encode lock contention, poisoning, cancellation,
        /// or a WAL read failure because Sanctuary main treats success as proof
        /// that the evidence channel is live.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// How the consumer must treat `error`. Present whenever `error` is,
        /// on a daemon advertising [`CAP_DRAIN_ERROR_CLASS`]. Absent means the
        /// daemon does not classify, which is neither retryable nor terminal —
        /// see [`DrainErrorClass`].
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_class: Option<String>,
    },
    /// Sanctuary main acknowledges that it has durably committed events up
    /// through `last_acked_seq`. Daemon truncates the WAL through that seq.
    #[serde(rename = "audit_drain_ack")]
    AuditDrainAck {
        request_id: String,
        last_acked_seq: u64,
    },
    /// Explicit daemon confirmation that the durable ACK was applied. The
    /// consumer advances its drain cursor only after `ok=true`; failures remain
    /// retryable and can never be silently converted into reclaimed evidence.
    #[serde(rename = "audit_drain_ack_response")]
    AuditDrainAckResponse {
        request_id: String,
        ok: bool,
        /// ALWAYS echoes the `last_acked_seq` of the request being answered.
        /// The consumer REQUIRES equality before treating the truncation as
        /// confirmed: a reply whose seq differs answers a different question,
        /// and accepting it would let a wrong-sequence confirmation advance the
        /// consumer's reclamation claim (AGENTS rule 7 — a field must mean what
        /// its consumer treats it as meaning). Must match the equality check in
        /// `IpcClient.sendDrainAck` in
        /// `server/src/castle-wall/runtime/ipc-client.ts`.
        last_acked_seq: u64,
        truncated_entries: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
        /// How the consumer must treat `error`. See [`DrainErrorClass`]. A
        /// Busy/stopping refusal is RETRYABLE: the events are already durable
        /// consumer-side, so it costs daemon WAL space, not evidence. A WAL
        /// failure or an ACK for a sequence not served on this connection is a
        /// terminal integrity/protocol failure.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error_class: Option<String>,
    },
    #[serde(rename = "unlock_notification")]
    UnlockNotification {
        fortress_id: String,
        unlocked_at: String,
    },
    #[serde(rename = "lock_notification")]
    LockNotification {
        fortress_id: String,
        locked_at: String,
    },
    #[serde(rename = "handshake_challenge")]
    HandshakeChallenge {
        nonce_b64url: String,
        /// Protocol version this daemon speaks. Optional on the wire: a pre-v2
        /// daemon omits it, and a peer that sees no version must assume v1 and
        /// the EMPTY capability set. Never assume a capability from silence.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol_version: Option<u32>,
        /// Capabilities this daemon offers ([`CAPABILITIES`]). A capability that
        /// is not listed is not available, whatever the peer's own version is.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },
    #[serde(rename = "handshake_response")]
    HandshakeResponse {
        fortress_id: String,
        signing_key_id: String,
        nonce_signature_b64url: String,
        /// Protocol version the CONSUMER speaks. Absent means pre-v2.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol_version: Option<u32>,
        /// Capabilities the consumer accepts. The daemon activates a
        /// consumer-visible behavior change (today: replying to
        /// `audit_drain_ack`) ONLY for a peer that listed the matching token, so
        /// a pre-v2 consumer keeps the exact wire behavior it was built against.
        ///
        /// These fields carry no trust weight: the handshake SIGNATURE proves the
        /// peer's identity over the nonce, and nothing more. A capability list is
        /// a statement about what the peer can PARSE, never about what it is
        /// permitted to do — every authorization decision stays on the kernel
        /// peer UID check (AGENTS rule 7).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        capabilities: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyBundleRule {
    pub file: String,
    pub body_b64url: String,
}

/// JSON-RPC-style outer envelope when bodies need a request/notification tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub jsonrpc: String,
    pub method: String,
    pub params: IpcMessage,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IpcDestination {
    pub host: Option<String>,
    pub ip: String,
    pub port: u16,
    pub protocol: String,
    pub hostname_source: Option<String>,
    pub opaque: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IpcAgentAttribution {
    pub id: String,
    pub template: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LearnedDecisionEnvelope {
    pub granularity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MetricBatchEntry {
    pub host: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub agent_id: String,
    pub allowed_count: u64,
    pub blocked_count: u64,
}

/// One drained WAL entry on the wire. Mirrors `audit::WalEntry` but kept
/// distinct so the IPC schema can evolve independently of on-disk format.
/// `captured_at_unix_ms` is u64 (not u128) so the wire shape round-trips
/// cleanly through serde_json.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditDrainEvent {
    pub seq: u64,
    pub captured_at_unix_ms: u64,
    pub prior_sha256_hex: Option<String>,
    pub event_canonical_json: String,
    pub critical: bool,
    /// Producer signature over `producer_signing_bytes(canonical, ts, seq)`
    /// (Slice L1, see `ipc::producer_sig`). base64url-no-pad of the 64-byte
    /// Ed25519 signature. `None` only when the daemon has no producer key
    /// wired (legacy/test boot); a wired daemon always signs. The consumer
    /// treats a missing signature as non-enforcement-evidence when it has a
    /// pinned producer key (fail closed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_signature_b64url: Option<String>,
    /// Key id identifying which pinned producer public key verifies the
    /// signature. Mirrors `PRODUCER_SIG_KEY_ID_V1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_key_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_challenge_round_trip() {
        let msg = IpcMessage::HandshakeChallenge {
            nonce_b64url: "AAAA".to_string(),
            protocol_version: Some(IPC_PROTOCOL_VERSION),
            capabilities: CAPABILITIES.iter().map(|c| (*c).to_string()).collect(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
        assert!(json.contains("\"type\":\"handshake_challenge\""));
    }

    #[test]
    fn decision_response_with_learn_round_trip() {
        let msg = IpcMessage::DecisionResponse {
            request_id: "req".to_string(),
            decision: "allow_always".to_string(),
            learn: Some(LearnedDecisionEnvelope {
                granularity: "per_template_etld1".to_string(),
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: IpcMessage = serde_json::from_str(&json).unwrap();
        assert_eq!(msg, parsed);
    }

    #[test]
    fn decision_response_without_learn_omits_field() {
        let msg = IpcMessage::DecisionResponse {
            request_id: "req".to_string(),
            decision: "deny_once".to_string(),
            learn: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("learn"));
    }

    #[test]
    fn unknown_type_fails_to_deserialize() {
        let raw = "{\"type\":\"bogus\",\"x\":1}";
        let result: Result<IpcMessage, _> = serde_json::from_str(raw);
        assert!(result.is_err());
    }

    #[test]
    fn additive_envelope_fields_are_tolerated_but_security_shapes_remain_strict() {
        for raw in [
            r#"{"jsonrpc":"2.0","method":"sanctuary.castle_wall.status_request","params":{"type":"status_request","request_id":"r"},"extra":true}"#,
            r#"{"jsonrpc":"2.0","method":"sanctuary.castle_wall.status_request","params":{"type":"status_request","request_id":"r","extra":true}}"#,
        ] {
            assert!(
                serde_json::from_str::<MessageEnvelope>(raw).is_ok(),
                "{raw}"
            );
        }
        let cases = [
            r#"{"jsonrpc":"2.0","method":"sanctuary.castle_wall.decision_request","params":{"type":"decision_request","request_id":"r","surface":"network","destination":{"host":null,"ip":"127.0.0.1","port":443,"protocol":"tcp","hostname_source":null,"opaque":false,"extra":true},"agent":{"id":"a","template":"t"},"timeout_seconds":1}}"#,
            r#"{"jsonrpc":"2.0","method":"sanctuary.castle_wall.decision_request","params":{"type":"decision_request","request_id":"r","surface":"network","destination":{"host":null,"ip":"127.0.0.1","port":443,"protocol":"tcp","hostname_source":null,"opaque":false},"agent":{"id":"a","template":"t","extra":true},"timeout_seconds":1}}"#,
            r#"{"jsonrpc":"2.0","method":"sanctuary.castle_wall.policy_bundle_publish_request","params":{"type":"policy_bundle_publish_request","request_id":"r","manifest_b64url":"AA","rules":[{"file":"r.json","body_b64url":"AA","extra":true}]}}"#,
        ];
        for raw in cases {
            assert!(
                serde_json::from_str::<MessageEnvelope>(raw).is_err(),
                "unknown field was accepted: {raw}"
            );
        }
    }
}
