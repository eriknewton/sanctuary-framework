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

/**
 * Wire protocol version this build of Sanctuary main speaks.
 *
 * Must match `IPC_PROTOCOL_VERSION` in
 * `castle-wall-daemon/src/ipc/messages.rs`.
 *
 * The daemon ships as a separately installed binary while this consumer ships
 * via npm, so SKEW IN EITHER DIRECTION is a real deployment state, not a
 * theoretical one. Neither side may assume the other's version: the daemon
 * advertises what it can do in the handshake challenge, the consumer declares
 * what it can parse in the handshake response, and each activates a newer shape
 * only for a peer that named it. A missing version means pre-v2 and the EMPTY
 * capability set; silence is never read as support.
 */
export const CASTLE_WALL_IPC_PROTOCOL_VERSION = 2;

/**
 * The daemon replies to `audit_drain_ack` with an `audit_drain_ack_response`.
 *
 * Pre-v2 the ACK was one-way. A new consumer that awaited a reply from a pre-v2
 * daemon would time out on every ACK, never advance its drain cursor, and the
 * daemon's WAL would grow to its cap and fail closed, denying all wrapped-agent
 * egress: a full outage from a partial upgrade. So the consumer awaits the reply
 * ONLY when the daemon advertised this token, and otherwise falls back to the
 * one-way behavior it was built against.
 *
 * Must match `CAP_AUDIT_DRAIN_ACK_RESPONSE` in
 * `castle-wall-daemon/src/ipc/messages.rs`.
 */
export const CAP_AUDIT_DRAIN_ACK_RESPONSE = "audit_drain_ack_response";

/**
 * `status_response` carries the lifecycle/runtime assertion fields
 * (`manifest_state`, `lifecycle_state`, `runtime_state`,
 * `kernel_runtime_ready`, `enforcing`).
 *
 * When this is NOT advertised, those fields are ABSENT rather than false, and a
 * consumer must report the runtime as unavailable/unknown. Reading absence as
 * `false` would manufacture a "degraded" verdict about a daemon that simply does
 * not report the field (AGENTS: absent, indeterminate and unproven all read as
 * not-proven; none of them reads as passing, and none of them is evidence of
 * failure either).
 *
 * Must match `CAP_STATUS_RUNTIME_FIELDS` in
 * `castle-wall-daemon/src/ipc/messages.rs`.
 */
export const CAP_STATUS_RUNTIME_FIELDS = "status_runtime_fields";

/**
 * `status_response` carries `runtime_health` and `runtime_health_age_ms`, which
 * separate a PROVEN runtime loss from an indeterminate health probe.
 *
 * Must match `CAP_STATUS_RUNTIME_HEALTH` in
 * `castle-wall-daemon/src/ipc/messages.rs`.
 */
export const CAP_STATUS_RUNTIME_HEALTH = "status_runtime_health";

/**
 * Every capability THIS consumer can parse, declared in the handshake response.
 * One list, read by the handshake and by the parity test, so the declaration and
 * the implementation cannot drift (AGENTS rule 5).
 *
 * Must equal `CAPABILITIES` in `castle-wall-daemon/src/ipc/messages.rs`.
 */
export const CAP_DRAIN_ERROR_CLASS = "drain_error_class";
export const CAP_POLICY_BUNDLE_PUBLISH = "policy_bundle_publish_v1";

export const CASTLE_WALL_IPC_CAPABILITIES = [
  CAP_AUDIT_DRAIN_ACK_RESPONSE,
  CAP_STATUS_RUNTIME_FIELDS,
  CAP_STATUS_RUNTIME_HEALTH,
  CAP_DRAIN_ERROR_CLASS,
  CAP_POLICY_BUNDLE_PUBLISH,
] as const;

/**
 * How a drain / drain-ack failure must be treated.
 *
 * Produced only by `DrainErrorClass::as_str` in
 * `castle-wall-daemon/src/ipc/messages.rs`; must match that function's tokens.
 *
 * - `retryable` a transient condition (control-lock contention inside the
 *   daemon's 2s budget, or a daemon that is stopping). Nothing is broken and
 *   nothing was lost: on the drain path no events were delivered, and on the ACK
 *   path the events are ALREADY durable consumer-side because the consumer
 *   advances its own chain state before acking. Retry with bounded backoff.
 * - `terminal` a poisoned lock, a WAL read/truncate failure, or an unwired WAL.
 *   The evidence channel is genuinely broken and must fail closed.
 *
 * ABSENT is a third state and is handled separately by the consumer (see
 * `classifyDrainFailure`): a pre-v2 daemon does not classify, so the consumer
 * applies its own bounded retry budget rather than inventing either answer.
 * Reading absence as `terminal` is the defect this replaces — it converted every
 * `systemctl stop` and every busy 2-second window into a permanently not-armed
 * wall with a durable `castle_wall_drain_failed` record.
 */
export type DrainErrorClass = "retryable" | "terminal";

/**
 * The three-valued (five-token) state of the daemon's manifest store.
 *
 * Produced only by `ManifestState::as_str` in
 * `castle-wall-daemon/src/ipc/messages.rs`; must match that function's tokens.
 *
 * - `ready`       a verified manifest is live. `loaded_rule_count` and
 *                 `loaded_manifest_signature_b64url` describe it.
 * - `empty`       the store was read and holds no manifest (deny-by-default boot
 *                 before the first reload). PROVEN absence: `loaded_rule_count:
 *                 0` is true here.
 * - `unavailable` the store lock was busy. INDETERMINATE: not a loss, not
 *                 readiness, and the companion fields on the same frame carry no
 *                 information.
 * - `degraded`    the store lock is poisoned (a holder panicked mid-mutation).
 *                 A PROVEN failure.
 * - `unwired`     this daemon has no manifest store (not a production shape).
 */
export type CastleWallManifestState =
  | "ready"
  | "empty"
  | "unavailable"
  | "degraded"
  | "unwired";

/**
 * True only where `loaded_rule_count` / `loaded_manifest_signature_b64url` on
 * the same status frame describe reality.
 *
 * The one place this question is answered. Both fields are pre-v2 wire surface
 * and cannot become optional, so an indeterminate store still serializes `0` and
 * `null`; reading those without consulting the state is how "the daemon could
 * not open its store" became "the daemon has no rules". Must match
 * `ManifestState::companion_fields_are_authoritative` in
 * `castle-wall-daemon/src/ipc/messages.rs`.
 */
export function manifestFieldsAreAuthoritative(
  state: CastleWallManifestState | undefined
): boolean {
  return state === "ready" || state === "empty";
}

/**
 * Probe outcome behind `kernel_runtime_ready`. Produced only by
 * `RuntimeHealthState::as_str` in `castle-wall-daemon/src/runtime_health.rs`;
 * must match that function's tokens.
 *
 * - `ready`             a fresh positive proof
 * - `lost`              a PROVEN loss of a required component
 * - `probe_unavailable` INDETERMINATE (contention, deadline, stale observation)
 * - `no_runtime`        this daemon holds no kernel runtime at all
 */
export type RuntimeHealthToken =
  | "ready"
  | "lost"
  | "probe_unavailable"
  | "no_runtime";

/** Tagged union of every Castle Wall IPC message body. */
export type CastleWallMessage =
  | StatusRequest
  | StatusResponse
  | PolicyReloadRequest
  | PolicyReloadResponse
  | PolicyBundlePublishRequest
  | PolicyBundlePublishResponse
  | DecisionRequest
  | DecisionResponse
  | DecisionResponseAck
  | AuditEmitNotification
  | AuditEmitMetricBatchNotification
  | AuditDrainRequest
  | AuditDrainResponse
  | AuditDrainAck
  | AuditDrainAckResponse
  | UnlockNotification
  | LockNotification
  | HandshakeChallenge
  | HandshakeResponse
  | ArmLeaseNotification
  | ManifestSubscribeRequest
  | ManifestUpdatedNotification
  | FlowDecisionRecordedNotification
  | FlowPendingApprovalNotification
  | EnforcementAvailabilityReportNotification
  | EnforcementAvailabilityRequest
  | EnforcementAvailabilityResponse;

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
  /**
   * Authoritative ONLY when `manifest_state` is `ready` or `empty`. Read them
   * through {@link manifestFieldsAreAuthoritative}, never directly: a daemon
   * whose store lock was busy still serializes `null` / `0` here, because both
   * fields are pre-v2 surface that cannot become optional.
   */
  loaded_manifest_signature_b64url: string | null;
  loaded_rule_count: number;
  /**
   * The operator's explicit no-wall emergency bypass. Populated for real by the
   * macOS provider; the Linux daemon has no no-wall transition and reports a
   * structural `false` (see `LINUX_DAEMON_ENGAGES_NO_WALL` in
   * `castle-wall-daemon/src/live_status.rs`), so a `true` here always came from
   * a producer that can actually engage it.
   */
  no_wall_engaged: boolean;
  /**
   * The lifecycle/runtime assertion block, gated by
   * {@link CAP_STATUS_RUNTIME_FIELDS}.
   *
   * OPTIONAL on purpose: a pre-v2 daemon does not send these, and an installed
   * daemon can be older than the npm consumer. Absence means "this daemon does
   * not report it", which is NOT the same as `false`. Read absence through
   * `castleWallRuntimeReadiness()` (which returns `unavailable`) rather than
   * comparing the fields directly, or a legacy daemon reads as degraded.
   */
  manifest_state?: CastleWallManifestState;
  lifecycle_state?: "activating" | "running" | "degraded" | "stopping";
  runtime_state?:
    | "control_plane_only"
    | "kernel_runtime_ready"
    | "enforcing"
    | "degraded"
    | "stopping";
  kernel_runtime_ready?: boolean;
  enforcing?: boolean;
  /** Gated by {@link CAP_STATUS_RUNTIME_HEALTH}. */
  runtime_health?: RuntimeHealthToken;
  /** Age of the observation behind `runtime_health`, in milliseconds. */
  runtime_health_age_ms?: number;
}

/**
 * The TRUTHFUL, reachable states of the Linux kernel runtime as a consumer can
 * observe them. Four distinct things that a boolean pair cannot express:
 *
 * - `enforcing`             a wrapped agent's egress is actually being gated.
 *                           NOT produced by the current daemon slice; the
 *                           per-agent cgroup jump rule that would flip it is not
 *                           installed, so a gate that REQUIRES this is
 *                           unsatisfiable by construction and would report every
 *                           healthy host as degraded forever.
 * - `kernel_runtime_ready`  the kernel runtime is live (owned table + bound
 *                           NFQUEUE + watcher) with no agent wrapped behind it.
 *                           This is the current slice's ceiling and the honest
 *                           top of the reachable model.
 * - `control_plane_only`    the daemon serves authenticated IPC but holds no
 *                           kernel runtime (macOS, unprivileged host).
 * - `degraded`              a component that came up ready was PROVEN lost.
 * - `unavailable`           indeterminate: the daemon does not report these
 *                           fields (pre-v2), or its health probe returned no
 *                           answer. Not health, and not failure.
 */
export type CastleWallRuntimeReadiness =
  | "enforcing"
  | "kernel_runtime_ready"
  | "control_plane_only"
  | "degraded"
  | "unavailable";

/**
 * Map a `status_response` onto the truthful readiness model above.
 *
 * The ordering is the honesty contract, and each branch exists because the
 * alternative was a false claim:
 *
 * 1. `no_wall_engaged` -> `degraded`. The operator's explicit emergency bypass
 *    dominates EVERY other reading, including an indeterminate one. It is
 *    checked first because it is the only branch that is a decision rather than
 *    an observation: a bypassed wall plus a momentarily-unavailable probe is
 *    still a bypassed wall, and returning `unavailable` for it would let it pass
 *    the caller's fail-closed branch. The comment used to claim this precedence
 *    while the code checked `probe_unavailable` first.
 * 2. Fields absent  -> `unavailable`. A pre-v2 daemon does not report them;
 *    reading `undefined !== "running"` as "degraded" invents a failure.
 * 3. `runtime_health` says `probe_unavailable` (or a stale/absent observation)
 *    -> `unavailable`. Contention is not loss.
 * 4. A proven-lost/non-running lifecycle, or a PROVEN-bad manifest store ->
 *    `degraded`.
 * 5. A merely INDETERMINATE manifest store -> `unavailable`. The store lock is
 *    contended in normal operation (per-verdict reads, and a reload that holds
 *    it across verify + WAL fsync, which is what the policy write before arming
 *    triggers). Reading that as `degraded` tore down healthy walls.
 * 6. `enforcing` -> `enforcing`; kernel-ready -> `kernel_runtime_ready`.
 *
 * Never returns `enforcing` from a merely-ready runtime: agent wrapping is a
 * strictly stronger claim and this slice does not make it.
 */
export function castleWallRuntimeReadiness(
  status: Pick<
    StatusResponse,
    | "lifecycle_state"
    | "manifest_state"
    | "runtime_state"
    | "kernel_runtime_ready"
    | "enforcing"
    | "no_wall_engaged"
    | "runtime_health"
  >
): CastleWallRuntimeReadiness {
  // 1. The operator's explicit bypass outranks everything, proven or not.
  if (status.no_wall_engaged === true) return "degraded";
  // 2. The daemon does not report the runtime block at all.
  if (status.runtime_state === undefined || status.lifecycle_state === undefined) {
    return "unavailable";
  }
  // 3. The daemon reports it but has no current proof behind it.
  if (status.runtime_health === "probe_unavailable") {
    return "unavailable";
  }
  // 4. Proven-bad states.
  if (status.runtime_health === "lost") return "degraded";
  if (status.runtime_state === "degraded" || status.runtime_state === "stopping") {
    return "degraded";
  }
  if (status.lifecycle_state !== "running") return "degraded";
  // A poisoned store is a proven policy failure; an unwired one is a proven
  // structural gap. Both are real degradations of the wall.
  if (status.manifest_state === "degraded" || status.manifest_state === "unwired") {
    return "degraded";
  }
  // 5. INDETERMINATE store: withhold the readiness claim without asserting a
  //    failure. Absence of the field entirely (pre-v2 daemon) lands here too.
  if (status.manifest_state === undefined || status.manifest_state === "unavailable") {
    return "unavailable";
  }
  // 6. Positive claims, weakest-sufficient first.
  if (status.runtime_state === "enforcing" && status.enforcing === true) {
    return "enforcing";
  }
  if (status.runtime_state === "kernel_runtime_ready" && status.kernel_runtime_ready === true) {
    return "kernel_runtime_ready";
  }
  if (status.runtime_state === "control_plane_only") return "control_plane_only";
  // A shape the model does not recognize is not-proven, never passing.
  return "unavailable";
}

/**
 * Request from main to daemon: "manifest changed; re-read."
 *
 * The daemon RECOMPOSES the manifest from the persisted rule files under
 * `<fortress>/policy/egress/rules/` (multiple provenance-tagged files, not a
 * single manifest document) and RE-SIGNS it through the pinned signer, so there
 * is no single "manifest path" to hand it. `manifest_path` is therefore OPTIONAL
 * and advisory only: no daemon reads it (it was a fabricated, non-existent path
 * on the macOS reload path). Kept optional for wire compatibility; new callers
 * should omit it.
 */
export interface PolicyReloadRequest {
  type: "policy_reload_request";
  request_id: IpcRequestId;
  manifest_path?: string;
}

/** Closed, non-sensitive phase labels for bounded reload failure diagnostics. */
export const POLICY_RELOAD_STAGES = [
  "publication_queue",
  "resolver_read",
  "composition_start",
  "composition_inputs",
  "pin_check",
  "rule_enumeration",
  "rule_read",
  "distress_read",
  "resolver_snapshot",
  "routing_marker_read",
  "rule_composition",
  "manifest_sign",
  "manifest_verify",
  "broadcast",
] as const;

export type PolicyReloadStage = (typeof POLICY_RELOAD_STAGES)[number];

/** Response from daemon to main confirming reload outcome. */
export interface PolicyReloadResponse {
  type: "policy_reload_response";
  request_id: IpcRequestId;
  ok: boolean;
  loaded_manifest_signature_b64url: string | null;
  loaded_rule_count: number;
  error?: string;
  /** Last bounded phase entered before a failed reload; never contains a path or rule id. */
  failure_stage?: PolicyReloadStage;
  /** Milliseconds spent in `failure_stage` when the failure response was formed. */
  failure_stage_elapsed_ms?: number;
  /** Total reload milliseconds when the failure response was formed. */
  reload_elapsed_ms?: number;
}

export interface PolicyBundleRule {
  file: string;
  body_b64url: string;
}

/** Complete signed policy bytes sent over the authenticated broker session. */
export interface PolicyBundlePublishRequest {
  type: "policy_bundle_publish_request";
  request_id: IpcRequestId;
  manifest_b64url: string;
  rules: PolicyBundleRule[];
}

export interface PolicyBundlePublishResponse {
  type: "policy_bundle_publish_response";
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
  /** Prior producer signed-body chain hash, or null for genesis. */
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
  /** Absent when the daemon could not read the counter without blocking. */
  wal_overflow_count?: number;
  /** Present when the daemon could not prove a real WAL snapshot. */
  error?: string;
  /**
   * How `error` must be treated. Present whenever `error` is, on a daemon
   * advertising {@link CAP_DRAIN_ERROR_CLASS}. Route it through
   * {@link classifyDrainFailure} rather than comparing it here, so the
   * absent-class fallback lives in one place.
   */
  error_class?: DrainErrorClass;
}

/**
 * Main acknowledges that it has durably committed events through
 * `last_acked_seq`; the daemon truncates its WAL through that seq and replies
 * explicitly. Mirrors `IpcMessage::AuditDrainAck`.
 */
export interface AuditDrainAck {
  type: "audit_drain_ack";
  request_id: IpcRequestId;
  last_acked_seq: number;
}

/** Daemon confirmation that an ACK was durably applied, or a retryable error. */
export interface AuditDrainAckResponse {
  type: "audit_drain_ack_response";
  request_id: IpcRequestId;
  ok: boolean;
  /**
   * ALWAYS the `last_acked_seq` of the request being answered. The consumer
   * REQUIRES equality before treating the truncation as confirmed: a reply
   * carrying a different seq answers a different question, and accepting it
   * would advance a reclamation claim the daemon never made (AGENTS rule 7 - a
   * field must mean what its consumer treats it as meaning). Enforced in
   * `IpcClient.sendDrainAck`; the daemon side echoes it on every arm (see
   * `handle_audit_drain_ack` in `castle-wall-daemon/src/ipc/server.rs`).
   */
  last_acked_seq: number;
  truncated_entries: number;
  error?: string;
  /**
   * How `error` must be treated. On this path a refusal is RETRYABLE by
   * default: the events are already durable consumer-side, so a refused
   * truncation costs daemon WAL space, not evidence.
   */
  error_class?: DrainErrorClass;
}

/**
 * Decide how a drain / drain-ack failure must be handled, from the daemon's
 * class plus what the consumer knows about the path it came from.
 *
 * ONE function, because the absent-class case is the whole reason a naive
 * `error_class === "terminal"` check would be wrong. Three inputs, three
 * outcomes:
 *
 * - The daemon classified it -> honor that. It is the only party that knows
 *   whether its lock timed out or was poisoned.
 * - No class, and the consumer's data for this path is ALREADY DURABLE (the ACK
 *   path) -> `retryable`. Nothing is at risk; the cost of a wrong guess is
 *   daemon WAL space, and the cost of guessing `terminal` is a false not-armed
 *   wall on every legacy daemon restart.
 * - No class, and the path DELIVERS evidence (the drain path) -> `unclassified`.
 *   Neither answer is known, so the caller applies its own bounded retry budget
 *   and fails closed only when that budget is exhausted. Inventing `terminal`
 *   here is the defect being removed; inventing `retryable` would let a genuinely
 *   broken legacy daemon retry forever while the wall claimed health.
 */
export function classifyDrainFailure(input: {
  errorClass: DrainErrorClass | undefined;
  /**
   * True when the events this failure concerns are already durably held by the
   * consumer, so nothing can be lost by retrying (the ACK path).
   */
  consumerDataAlreadyDurable: boolean;
}): DrainErrorClass | "unclassified" {
  if (input.errorClass === "retryable" || input.errorClass === "terminal") {
    return input.errorClass;
  }
  return input.consumerDataAlreadyDurable ? "retryable" : "unclassified";
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
  /** Daemon protocol version. Absent means pre-v2. */
  protocol_version?: number;
  /** Capabilities the daemon offers. Absent or empty means none. */
  capabilities?: string[];
}

/** Main-to-daemon handshake response signed by the fortress identity key. */
export interface HandshakeResponse {
  type: "handshake_response";
  fortress_id: string;
  signing_key_id: string;
  nonce_signature_b64url: string;
  /** Consumer protocol version. A pre-v2 daemon ignores it. */
  protocol_version?: number;
  /**
   * Capabilities this consumer can parse. Carries NO authority: the signature
   * proves who signed the nonce and nothing else, and the daemon's authorization
   * decision stays on the kernel peer UID. Its only effect is to let the daemon
   * withhold a newer response shape from a consumer that would not understand it.
   */
  capabilities?: string[];
}

/**
 * Authenticated daemon-to-extension lease heartbeat for the armed wall.
 *
 * O-02: the lease can flip the extension into `fail_open_deadman`, so an
 * emitted frame carries a fortress-key Ed25519 signature over the canonical
 * signed body (see `armLeaseSignedBody` in
 * `server/src/castle-wall/runtime/macos-ipc-listener.ts`). The signature
 * fields are wire-ADDITIVE: an older extension ignores them; a current
 * extension REJECTS a frame without a valid signature and a monotonically
 * fresh `updated_at` (verification lives in
 * `castle-wall-macos/Sources/CastleWallFilter/SignedArmLeaseVerification.swift`).
 * Field names must match `ArmLeaseBody` CodingKeys in
 * `castle-wall-macos/Sources/CastleWallIPC/Messages.swift`.
 */
export interface ArmLeaseNotification {
  type: "arm_lease";
  armed: boolean;
  revoked?: boolean;
  ttl_seconds?: number | null;
  heartbeat_interval_seconds: number;
  /**
   * Signer-side freshness stamp; the extension consumes it (monotonic +
   * bounded-age), so a replayed stale frame cannot re-anchor the dead-man
   * deadline to the receiver's clock.
   */
  updated_at: string;
  /** Key id of the fortress signing key that produced `lease_signature_b64url`. */
  signing_key_id?: string;
  /**
   * base64url (no padding) Ed25519 signature over the canonical signed body
   * (`armLeaseSignedBody`), verified by the extension against the pinned
   * fortress public key.
   */
  lease_signature_b64url?: string;
}

/**
 * Extension-originated enforcement-availability assertion.
 *
 * Green surfaces must be derived from this block only after the daemon verifies
 * the attached audit-producer signature. The producer timestamp is diagnostic;
 * freshness is stamped by the receiving consumer as `observed_at`.
 */
export interface EnforcementAvailabilitySnapshot {
  protocol_version: 1;
  source: "macos_extension";
  lease_state: "live" | "missing" | "unarmed" | "failed_open";
  lease_reason:
    | "ok"
    | "arm_lease_missing"
    | "not_armed"
    | "lease_revoked"
    | "ttl_expired"
    | "heartbeat_stopped";
  manifest_state: "applied" | "absent";
  manifest_signature_b64url: string | null;
  provider_bound: boolean;
  producer_claimed_at?: string;
}

/**
 * One-way notification from the macOS extension to the daemon reporting the
 * extension's current enforcement availability level. It is accepted as a
 * surface signal only when the `producer` tuple verifies against the pinned
 * audit-producer key and the signed canonical body binds to the visible
 * `enforcement` block. Unsigned or malformed reports are non-green.
 */
export interface EnforcementAvailabilityReportNotification {
  type: "enforcement_availability_report";
  enforcement: EnforcementAvailabilitySnapshot;
  producer?: AuditProducerSignatureNotification | null;
}

/**
 * Local query over `castle.sock` asking the daemon for the least-green fresh
 * enforcement-availability level across live extension connections. This is a
 * read-only status request: the daemon must answer from already-received
 * extension reports and must not mint a green result from daemon intent.
 */
export interface EnforcementAvailabilityRequest {
  type: "enforcement_availability_request";
  request_id: IpcRequestId;
}

/**
 * Daemon response to `enforcement_availability_request`. `availability.status`
 * is the only color authority for macOS Castle Wall green surfaces; `observed_at`
 * is the daemon receive time for the report that determined the verdict.
 */
export interface EnforcementAvailabilityResponse {
  type: "enforcement_availability_response";
  request_id: IpcRequestId;
  availability: {
    status: "live" | "non_green" | "undetermined";
    reason: string;
    observed_at: string | null;
    freshness_window_ms: number;
    active_connection_count: number;
  };
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
  /**
   * Optional v3 per-decision carriage of the same extension-originated
   * availability block reported by `enforcement_availability_report`. Consumers
   * may use it only when the producer signature verifies and the signed flow
   * canonical body contains this exact block.
   */
  enforcement?: EnforcementAvailabilitySnapshot | null;
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
