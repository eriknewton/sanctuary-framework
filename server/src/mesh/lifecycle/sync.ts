/**
 * Sync protocol (§3.2 + §3.5 delta) and Q6 agent-state-transfer.
 *
 * Sync rides the v0.1 `sync_request` / `sync_response` event types over
 * unicast direct streams. v0.1 ships a basic synchronous request/response -
 * the libp2p adapter (Follow-up #2) wires the actual transport; here we
 * provide the per-side handlers and a contract that the orchestrator wires
 * into its router.
 *
 * Q6 agent-state-transfer reuses the same request/response pair with
 * `kind: "agent_state_transfer"`. The snapshot is opaque fortress-store-format bytes,
 * encrypted under an HKDF-derived key (same chain shape as the per-node
 * transport key, distinct info string). This composes with the existing
 * snapshot format without schema change because the snapshot stays opaque
 * to federation.
 */

import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { stringToBytes } from "../../core/encoding.js";
import { decrypt, encrypt } from "../../core/encryption.js";
import { canonicalizeToBytes } from "../canonical-json.js";
import { HKDF_AGENT_STATE_TRANSFER_INFO_PREFIX } from "./constants.js";
import type { CanonicalAuditLog } from "./canonical-audit.js";
import type {
  LocatorTableStore,
  NodeLifecycleEventLog,
  PolicyBundleStore,
  PolicyBundleUpsertResult,
} from "./local-state.js";
import type { PolicyUpdatePayload, SignedEvent } from "../types.js";
import type {
  SyncRequestPayload,
  SyncResponsePayload,
} from "./types.js";

// ═══════════════════════════════════════════════════════════════════════
// Server-side: build a sync response
// ═══════════════════════════════════════════════════════════════════════

export interface SyncResponderState {
  policy_bundle: PolicyBundleStore;
  locator_table: LocatorTableStore;
  lifecycle_log: NodeLifecycleEventLog;
  /** Canonical audit log - present only on the canonical-audit node. */
  audit_log?: CanonicalAuditLog;
  on_policy_update?: (
    evt: SignedEvent<PolicyUpdatePayload>,
    result: PolicyBundleUpsertResult
  ) => void;
}

export function buildSyncResponse(
  request: SyncRequestPayload,
  state: SyncResponderState
): SyncResponsePayload {
  if (request.kind === "agent_state_transfer") {
    // The agent-state-transfer payload itself is added by a higher-level
    // call site (which holds the snapshot bytes + the wrapping key). The
    // base sync response for this kind is structurally empty - the snapshot
    // attaches as `agent_state_wrapped` via a separate code path so this
    // pure function stays free of crypto state.
    // Echo request_id must match SyncRequestPayload.request_id in ./types.ts —
    // the initiator correlates the response to its outstanding request (C12-REPLAY).
    return { kind: "agent_state_transfer", request_id: request.request_id };
  }

  const policy_updates = state.policy_bundle.delta(
    request.since_policy_versions ?? {}
  );

  const locator_updates = state.locator_table.delta(
    request.since_locator_version ?? 0
  );

  // Initial-sync requests: ship the entire lifecycle log.
  // Delta-sync requests: ship the post-known-event tail (caller passes
  // `since_event_id` via a future API; v0.1 ships entire log on initial,
  // empty on delta-without-pointer because the rejoining node's last
  // received event id is held client-side and the libp2p adapter
  // (Follow-up #2) wires it through).
  const node_lifecycle_events =
    request.kind === "initial_sync" ? state.lifecycle_log.snapshot() : [];

  const audit_batches: SyncResponsePayload["audit_batches"] = [];
  if (state.audit_log && request.since_audit_seqs) {
    for (const [emitterId, sinceSeq] of Object.entries(
      request.since_audit_seqs
    )) {
      const range = state.audit_log.rangeFor(emitterId, sinceSeq);
      audit_batches.push(...range);
    }
  }

  return {
    kind: request.kind,
    // Echo request_id — must match SyncRequestPayload.request_id in ./types.ts.
    request_id: request.request_id,
    policy_updates,
    locator_updates,
    node_lifecycle_events,
    audit_batches,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Q6 - agent-state-transfer wrapping
// ═══════════════════════════════════════════════════════════════════════

/**
 * Derive the symmetric key under which an agent snapshot is wrapped during
 * migration (Q6). Both the source node (which encrypts) and the destination
 * node (which decrypts) derive this same key from the fortress-master secret
 * + the migration tuple - no transport-layer key exchange, no round-trip.
 */
export function deriveAgentStateTransferKey(params: {
  fortress_master_secret: Uint8Array;
  source_node_id: string;
  destination_node_id: string;
  agent_id: string;
  authorizing_locator_version: number;
}): Uint8Array {
  const salt = stringToBytes(
    params.source_node_id + ":" + params.destination_node_id
  );
  const info = stringToBytes(
    HKDF_AGENT_STATE_TRANSFER_INFO_PREFIX +
      params.agent_id +
      ":" +
      params.authorizing_locator_version
  );
  return hkdf(sha256, params.fortress_master_secret, salt, info, 32);
}

/**
 * Wrap a fortress-store snapshot for migration. The snapshot bytes are opaque to
 * federation - produced by the store's existing snapshot format (no schema
 * change required for Q6).
 */
export function wrapAgentSnapshot(params: {
  snapshot_bytes: Uint8Array;
  fortress_master_secret: Uint8Array;
  source_node_id: string;
  destination_node_id: string;
  agent_id: string;
  authorizing_locator_version: number;
}) {
  const key = deriveAgentStateTransferKey(params);
  const aad = canonicalizeToBytes({
    src: params.source_node_id,
    dst: params.destination_node_id,
    agent: params.agent_id,
    locator_version: params.authorizing_locator_version,
  });
  return encrypt(params.snapshot_bytes, key, aad);
}

/** Unwrap on the destination side. AAD prevents target-substitution. */
export function unwrapAgentSnapshot(params: {
  wrapped: ReturnType<typeof wrapAgentSnapshot>;
  fortress_master_secret: Uint8Array;
  source_node_id: string;
  destination_node_id: string;
  agent_id: string;
  authorizing_locator_version: number;
}): Uint8Array {
  const key = deriveAgentStateTransferKey(params);
  const aad = canonicalizeToBytes({
    src: params.source_node_id,
    dst: params.destination_node_id,
    agent: params.agent_id,
    locator_version: params.authorizing_locator_version,
  });
  return decrypt(params.wrapped, key, aad);
}

// ═══════════════════════════════════════════════════════════════════════
// Client-side: apply a sync response
// ═══════════════════════════════════════════════════════════════════════

export interface ApplySyncResult {
  policy_applied: number;
  policy_older: number;
  policy_rejected: number;
  locator_applied: number;
  locator_older: number;
  locator_conflicts: number;
  lifecycle_events_received: number;
  audit_batches_received: number;
}

/**
 * Apply a verified sync response on the requesting node. Caller MUST have
 * verified every signed event in the response via verifySignedEvent first;
 * this function is plain table updates, not a trust boundary.
 */
export function applySyncResponse(
  response: SyncResponsePayload,
  state: SyncResponderState
): ApplySyncResult {
  const result: ApplySyncResult = {
    policy_applied: 0,
    policy_older: 0,
    policy_rejected: 0,
    locator_applied: 0,
    locator_older: 0,
    locator_conflicts: 0,
    lifecycle_events_received: 0,
    audit_batches_received: 0,
  };

  for (const evt of response.policy_updates ?? []) {
    const r = state.policy_bundle.upsert(evt);
    state.on_policy_update?.(evt, r);
    if (r === "applied") result.policy_applied++;
    else if (r === "policy_version_replay") result.policy_older++;
    else result.policy_rejected++;
  }
  for (const evt of response.locator_updates ?? []) {
    const r = state.locator_table.upsert(evt);
    if (r === "applied") result.locator_applied++;
    else if (r === "conflict") result.locator_conflicts++;
    else result.locator_older++;
  }
  // C12-REPLAY / SYNC-APPEND-01: lifecycle events are NO LONGER appended here.
  // `MeshNode.applySync` is the SINGLE append site — it verifies, freshness-
  // checks, and authorization-dedupes each event BEFORE appending, then passes
  // an EMPTY lifecycle list to this function. Appending here as well was the
  // double-append defect (design §3.3 point 3). We still count what arrived.
  result.lifecycle_events_received = (
    response.node_lifecycle_events ?? []
  ).length;
  result.audit_batches_received = (response.audit_batches ?? []).length;

  return result;
}
