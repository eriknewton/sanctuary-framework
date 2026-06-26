/**
 * Castle Wall IPC message shapes.
 *
 * Wire shape: JSON-RPC 2.0 over LSP-style framing on Linux (Unix domain socket
 * at `/run/sanctuary/<fortress-id>/filter.sock`); NSXPCConnection on macOS to
 * Mach service `org.sanctuary-framework.castle-wall.xpc`. Both transports carry
 * the same JSON message bodies; only the framing and authentication differ.
 *
 * Source: Castle Wall Phase 1 Scope Lock 2026-05-03 section 5 Option A
 * recommendation, including the post-Codex amendments (locked-state semantics,
 * prompt coalescing, replay protection).
 *
 * Subsequent PRs:
 * - PR 2 implements the Linux daemon side and the SO_PEERCRED + Ed25519
 *   challenge-response handshake.
 * - PR 3 implements the macOS XPC adapter against the same message shapes.
 * - PR 4 wires the `prompt_request` and `prompt_response` flow into the
 *   Sanctuary main dashboard surface.
 */

import type { CastleWallAuditEvent } from "../audit/events.js";
import type { AllowlistManifest, ManifestSignature } from "../allowlist/manifest.js";
import type { AllowlistRule } from "../allowlist/schema.js";

/** JSON-RPC 2.0 request id. The daemon and main both generate these as 16-byte hex. */
export type IpcRequestId = string;

/** Tagged union of every Castle Wall IPC message body. */
export type CastleWallMessage =
  | StatusRequest
  | StatusResponse
  | PolicyReloadRequest
  | PolicyReloadResponse
  | DecisionRequest
  | DecisionResponse
  | DecisionResponseAck
  | AuditEmitNotification
  | AuditEmitMetricBatchNotification
  | AuditDrainRequest
  | AuditDrainResponse
  | AuditDrainAck
  | UnlockNotification
  | LockNotification
  | HandshakeChallenge
  | HandshakeResponse
  | ArmLeaseNotification
  | ManifestSubscribeRequest
  | ManifestUpdatedNotification
  | FlowDecisionRecordedNotification
  | FlowPendingApprovalNotification;

/** Request from main to daemon: "are you alive?" */
export interface StatusRequest {
  type: "status_request";
  request_id: IpcRequestId;
}

/** Response from daemon to main carrying liveness + last loaded manifest fingerprint. */
export interface StatusResponse {
  type: "status_response";
  request_id: IpcRequestId;
  uptime_seconds: number;
  loaded_manifest_signature_b64url: string | null;
  loaded_rule_count: number;
  no_wall_engaged: boolean;
}

/** Request from main to daemon: "manifest changed; re-read." */
export interface PolicyReloadRequest {
  type: "policy_reload_request";
  request_id: IpcRequestId;
  manifest_path: string;
}

/** Response from daemon to main confirming reload outcome. */
export interface PolicyReloadResponse {
  type: "policy_reload_response";
  request_id: IpcRequestId;
  ok: boolean;
  loaded_manifest_signature_b64url: string | null;
  loaded_rule_count: number;
  error?: string;
}

/**
 * Destination details captured by the filter daemon at flow inception.
 * The `hostname_source` label tells main how confidently the host string
 * was derived; opaque flows surface a confidence-warning UI per scope-lock
 * E6.3.
 */
export interface IpcDestination {
  host: string | null;
  ip: string;
  port: number;
  protocol: "tcp" | "udp";
  hostname_source: "dns" | "sni" | "url" | "socket" | null;
  opaque: boolean;
}

/** Agent attribution sent with every novel-destination prompt request. */
export interface IpcAgentAttribution {
  id: string;
  template: string;
}

/** Request from daemon to main: "novel destination; need operator decision." */
export interface DecisionRequest {
  type: "decision_request";
  request_id: IpcRequestId;
  surface: "egress";
  destination: IpcDestination;
  agent: IpcAgentAttribution;
  timeout_seconds: number;
}

/** Granularity at which the operator's "always" choice is persisted. */
export type LearnedGranularity =
  | "per_template_domain"
  | "per_template_etld1"
  | "per_instance_domain";

/** The four decision values the operator can pick on a novel-destination prompt, plus the timeout-default. */
export type DecisionValue =
  | "allow_once"
  | "allow_always"
  | "deny_once"
  | "deny_always"
  | "timeout_default_deny";

/** Response from main to daemon carrying the operator's decision. */
export interface DecisionResponse {
  type: "decision_response";
  request_id: IpcRequestId;
  decision: DecisionValue;
  learn?: {
    granularity: LearnedGranularity;
  };
}

/** Response from main/listener to CLI confirming operator decision delivery. */
export interface DecisionResponseAck {
  type: "decision_response_ack";
  request_id: IpcRequestId;
  ok: boolean;
  error?: string;
}

/** One-way notification from daemon to main: "block / allow / decision happened; log it." */
export interface AuditEmitNotification {
  type: "audit_emit";
  event: CastleWallAuditEvent;
}

/** Per-event producer signature carried by a macOS extension verdict. */
export interface AuditProducerSignatureNotification {
  /** Exact canonical JSON body the extension signed. */
  event_canonical_json: string;
  /** Capture timestamp bound into the signature. */
  captured_at_unix_ms: number;
  /** Monotonic extension-side sequence bound into the signature. */
  seq: number;
  /** Prior CastleWallAuditEvent canonical hash, or null for genesis. */
  prior_sha256_hex: string | null;
  /** base64url-no-pad of the 64-byte Ed25519 producer signature. */
  signature_b64url: string;
  /** Key id selecting the pinned producer public key. */
  key_id: string;
}

/** Aggregate metric batch (per scope-lock section 8 Option D metric path). */
export interface AuditEmitMetricBatchNotification {
  type: "audit_emit_metric_batch";
  window_start: string;
  window_end: string;
  by_destination: Array<{
    host: string | null;
    port: number;
    protocol: "tcp" | "udp";
    agent_id: string;
    allowed_count: number;
    blocked_count: number;
  }>;
}

/**
 * Request from main to daemon: drain WAL entries strictly above `after_seq`,
 * capped at `max_events`. Per scope-lock §8 hybrid PULL model: main drives the
 * pace; the daemon never pushes audits unsolicited once the IPC link is healthy.
 * Mirrors the daemon's `IpcMessage::AuditDrainRequest`
 * (`castle-wall-daemon/src/ipc/messages.rs`).
 */
export interface AuditDrainRequest {
  type: "audit_drain_request";
  request_id: IpcRequestId;
  /** Drain entries with seq strictly greater than this. Omit/null for "from start". */
  after_seq?: number | null;
  /** Hard cap on the batch size; the daemon sets `more_pending` when it hits this. */
  max_events: number;
}

/**
 * One drained WAL entry on the wire. Mirrors the daemon's `AuditDrainEvent`
 * struct EXACTLY (`castle-wall-daemon/src/ipc/messages.rs`): the producer
 * signature fields are what carry the Slice L1 per-event authenticity material
 * from the enforcing daemon into the consumer's re-verification gate. The
 * drain loop populates `CriticalEventEnvelope.producer` from these fields so
 * the audit consumer can prove the event came from the daemon (not an
 * in-process forger). `producer_signature_b64url`/`producer_key_id` are absent
 * only when the daemon has no producer key wired (legacy/test boot); a wired
 * daemon always signs, and a pinned-key consumer fails closed on a missing
 * signature.
 */
export interface AuditDrainEvent {
  seq: number;
  captured_at_unix_ms: number;
  prior_sha256_hex: string | null;
  /** The exact canonical-JSON string the daemon committed to its WAL and signed. */
  event_canonical_json: string;
  critical: boolean;
  /** base64url-no-pad of the 64-byte Ed25519 producer signature, or absent. */
  producer_signature_b64url?: string | null;
  /** Key id selecting the pinned producer public key (mirrors `PRODUCER_SIG_KEY_ID_V1`). */
  producer_key_id?: string | null;
}

/**
 * Daemon's response to a drain request: a batch of WAL entries plus chain
 * metadata. `more_pending` signals the daemon hit the `max_events` cap and more
 * entries remain. Mirrors `IpcMessage::AuditDrainResponse`.
 */
export interface AuditDrainResponse {
  type: "audit_drain_response";
  request_id: IpcRequestId;
  events: AuditDrainEvent[];
  next_after_seq?: number | null;
  more_pending: boolean;
  wal_overflow_count: number;
}

/**
 * Main acknowledges that it has durably committed events through
 * `last_acked_seq`; the daemon truncates its WAL through that seq. One-way (no
 * response). Mirrors `IpcMessage::AuditDrainAck`.
 */
export interface AuditDrainAck {
  type: "audit_drain_ack";
  request_id: IpcRequestId;
  last_acked_seq: number;
}

/** Notification from main to daemon: "fortress unlocked; accept policy mutations." */
export interface UnlockNotification {
  type: "unlock_notification";
  fortress_id: string;
  unlocked_at: string;
}

/** Notification from main to daemon: "fortress locked; serve last validated snapshot." */
export interface LockNotification {
  type: "lock_notification";
  fortress_id: string;
  locked_at: string;
}

/** Daemon-to-main challenge issued on connect (Linux UDS handshake). */
export interface HandshakeChallenge {
  type: "handshake_challenge";
  nonce_b64url: string;
}

/** Main-to-daemon handshake response signed by the fortress identity key. */
export interface HandshakeResponse {
  type: "handshake_response";
  fortress_id: string;
  signing_key_id: string;
  nonce_signature_b64url: string;
}

/** Authenticated daemon-to-extension lease heartbeat for the armed wall. */
export interface ArmLeaseNotification {
  type: "arm_lease";
  armed: boolean;
  revoked?: boolean;
  ttl_seconds?: number | null;
  heartbeat_interval_seconds: number;
  updated_at: string;
}

/**
 * Castle Wall macOS Phase 1 (Alpha-2) message types: manifest sync + flow
 * decision telemetry.
 *
 * Source: Castle Wall macOS Phase 1 packet filter + manifest sync spawn
 * prompt (2026-05-11), section "Server-side IPC additions". Reserved as a
 * dedicated message-class block per Federation Protocol v0.1 section 10.3.
 */

/**
 * Subscribe request from the macOS system extension. The runtime registers
 * the connection as a manifest-change subscriber; subscription is cleared
 * when the IPC connection closes. The runtime emits an immediate
 * `manifest_updated` notification carrying the current snapshot so the
 * extension boots with an authoritative ruleset.
 */
export interface ManifestSubscribeRequest {
  type: "manifest_subscribe";
  request_id: IpcRequestId;
}

/**
 * Notification from runtime to subscribers. Phase 1 ships a full snapshot;
 * future surfaces may add a delta variant under a different `type`.
 */
export interface ManifestUpdatedNotification {
  type: "manifest_updated";
  manifest: AllowlistManifest;
  signature: ManifestSignature;
  rules: AllowlistRule[];
}

/**
 * The verdict the macOS extension recorded on a flow. Phase 1 verdicts are
 * binary: `allow` (a manifest rule matched as `allow`) or `drop` (manifest
 * rule matched as `deny`, OR default-deny because no rule matched after the
 * uncertain branch resolved to drop). The `matched_rule_id` is the
 * authoritative provenance link for the audit log; `null` indicates the
 * default-deny branch with no matching rule.
 */
export interface FlowDecisionRecordedNotification {
  type: "flow_decision_recorded";
  decision: "allow" | "drop";
  destination: IpcDestination;
  agent: IpcAgentAttribution;
  matched_rule_id?: string | null;
  recorded_at: string;
  producer?: AuditProducerSignatureNotification | null;
}

/**
 * Surface from the macOS extension when a flow's evaluation outcome is
 * Uncertain (no allow rule, no deny rule, default-deny pending operator
 * decision). The runtime queues the request into the existing approval
 * pipeline; the eventual operator decision lands back on the extension via
 * a separate `decision_response` envelope keyed by `request_id`.
 */
export interface FlowPendingApprovalNotification {
  type: "flow_pending_approval";
  request_id: IpcRequestId;
  destination: IpcDestination;
  agent: IpcAgentAttribution;
  surface: "egress";
  expires_in_seconds: number;
}
