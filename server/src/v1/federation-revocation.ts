/**
 * /v1 federation node revocation + node-certificate auto-renewal core.
 *
 * Revocation source of truth: an operator-authority `node_eviction` event in
 * the existing hash-chained federation log. The event is only honored when the
 * operator principal signature verifies through the pinned fortress master and
 * its monotonic eviction serial advances the local projection. The projection
 * is grow-only: there is no un-eviction path for a node id.
 *
 * Renewal source of truth: a local automatic renewal tick re-issues this
 * daemon's node certificate before the expiry backstop can lock out a live,
 * non-revoked node. The timer is injectable/testable; the real cross-machine
 * sleep/wake scheduler drill remains outside this core module.
 *
 * Wire compatibility note: operator-authority `node_eviction` events are
 * explicit v1 wire shapes. There is no backward-compatibility window for event
 * ingest: federating peers must run lockstep versions for sync and eviction;
 * older or newer peers fail closed rather than receiving a downgrade
 * translation. Legacy non-expiring node certificates still verify and federate;
 * certificate-expiry lockstep is not claimed here.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  cryptoSuiteRegistry,
  createHybridSuitePublicKeys,
  ED25519_PUBLIC_KEY_BYTES,
  HYBRID_SIGNATURE_SUITE_ID,
  ML_DSA_65_PUBLIC_KEY_BYTES,
  ML_DSA_65_SECRET_KEY_BYTES,
  type SignatureBundle,
  type SuiteSigner,
} from "../core/crypto-suite-registry.js";
import type { HybridPrivateKeyMaterial } from "../mesh/trust-root-hybrid.js";
import type { HybridCertificatePublicKeys } from "../mesh/types.js";
import {
  issueNodeIdentityCertificate,
  verifyPrincipalCertificate,
} from "../mesh/trust-root.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../mesh/types.js";
import { canonicalJson } from "./operator-signed.js";
import {
  FEDERATION_POLICY_BUNDLE_EVENT_KIND,
  FEDERATION_POLICY_BUNDLE_EVENT_VERSION,
  parseFederationPolicyBundlePayload,
} from "./federation-policy-bundle.js";

export const FEDERATION_NODE_EVICTION_EVENT_KIND = "node_eviction" as const;
export const FEDERATION_NODE_EVICTION_EVENT_VERSION =
  "sanctuary.v1.node-eviction" as const;
export const FEDERATION_SYNC_WIRE_VERSION =
  "sanctuary.v1.federation-sync-envelope" as const;
export const V1_FEDERATION_NODE_EVICTION_DOMAIN =
  "sanctuary.v1.federation-node-eviction";

/**
 * Operator-authority ROOT-REVOCATION event (rotate-root --compromised, Slice
 * 3c-1). Distinct from `node_eviction`: a `node_eviction` revokes ONE node's
 * cert; a `federation_root_revocation` revokes the WHOLE old fortress-master
 * (root) K1 after a compromise rotate to K2. It is the durable, replay-proofed
 * record that the old root must never again be trusted as a chain anchor.
 *
 * DOWNGRADE-RESISTANCE INVARIANT: this event is signed by the NEW principal
 * under K2 (the post-rotation root), NEVER by K1. An attacker who stole K1
 * cannot forge a revocation that the fortress would fold (the verify step pins
 * the CURRENT principal/K2). And there is no old-(K1)-signed adoption artifact
 * anywhere in the compromise flow: re-pin is out of band (Slice 3c-2).
 */
export const FEDERATION_ROOT_REVOCATION_EVENT_KIND =
  "federation_root_revocation" as const;
export const FEDERATION_ROOT_REVOCATION_EVENT_VERSION =
  "sanctuary.v1.federation-root-revocation" as const;
export const V1_FEDERATION_ROOT_REVOCATION_DOMAIN =
  "sanctuary.v1.federation-root-revocation";

const DAY_MS = 24 * 60 * 60 * 1000;

export const DEFAULT_FEDERATION_NODE_CERT_LIFETIME_MS = 365 * DAY_MS;
export const DEFAULT_FEDERATION_NODE_CERT_RENEWAL_LEAD_MS = 30 * DAY_MS;
export const DEFAULT_FEDERATION_NODE_CERT_RENEWAL_GRACE_MS = 7 * DAY_MS;
export const DEFAULT_FEDERATION_NODE_CERT_RENEWAL_CHECK_INTERVAL_MS = DAY_MS;

export interface FederationNodeEvictionPayload {
  event_version: typeof FEDERATION_NODE_EVICTION_EVENT_VERSION;
  fortress_id: string;
  node_id: string;
  reason: string;
  effective_at: string;
  eviction_serial: number;
  operator_principal_id: string;
  operator_signature: string;
}

export interface FederationRevocationLogEvent {
  event_id: string;
  origin_node_id: string;
  sequence: number;
  occurred_at: string;
  kind: string;
  payload: Record<string, unknown>;
  previous_hash: string | null;
  event_hash: string;
}

export interface FederationNodeRevocationProjection {
  revokedNodeIds: Set<string>;
  highestEvictionSerial: number;
}

/**
 * The signed body of a root-revocation event. Mirrors the node-eviction payload
 * shape: an operator-authority record carrying the revoked material + a strictly
 * monotonic serial, signed by the operator principal. The signed master here is
 * the OLD (now-revoked) root K1; the SIGNATURE is by the NEW principal under K2.
 */
export interface FederationRootRevocationPayload {
  event_version: typeof FEDERATION_ROOT_REVOCATION_EVENT_VERSION;
  fortress_id: string;
  /** Base64url Ed25519 public key of the REVOKED old fortress-master (K1). */
  revoked_master_pubkey: string;
  effective_at: string;
  /** Strictly-monotonic per-fortress revocation serial (replay/rollback proof). */
  revocation_serial: number;
  operator_principal_id: string;
  operator_signature: string;
  /**
   * PQC Slice 3 (hybrid rotate-root --compromised): a HYBRID signature bundle
   * (Ed25519 + ML-DSA-65, both-must-pass) over the same signed body, produced by
   * the NEW K2 hybrid PRINCIPAL's two private keys. Present ONLY on a hybrid
   * compromise revocation. This makes the revocation's authenticity itself
   * post-quantum protected: a future quantum adversary cannot forge the
   * revocation by breaking only the Ed25519 `operator_signature`. Absent on a
   * classical revocation (byte-compatible).
   */
  operator_signature_bundle?: SignatureBundle;
  /**
   * PQC Slice 3 (hybrid rotate-root --compromised): the BOTH old hybrid master
   * component public keys (Ed25519 + ML-DSA-65) being revoked. Present ONLY when
   * the compromised fortress was hybrid; absent (undefined) on a classical
   * revocation so a classical payload stays byte-for-byte unchanged. Binding both
   * old components means any chain pinning EITHER the old Ed25519 OR the old
   * ML-DSA component is rejectable from a single revocation event. This field is
   * part of the signed body (the operator signature covers it), so it cannot be
   * stripped without breaking the signature.
   */
  revoked_hybrid?: FederationRootRevocationHybridBinding;
}

/**
 * The both-components binding of the revoked old HYBRID master (rotate-root
 * --compromised on a hybrid fortress). Both base64url public keys + their key
 * refs are recorded so the revoked-set enforcement can reject a chain pinning
 * EITHER old component. PUBLIC.
 */
export interface FederationRootRevocationHybridBinding {
  ed25519: { key_ref: string; public_key: string };
  ml_dsa_65: { key_ref: string; public_key: string };
}

/**
 * The folded root-revocation projection: a grow-only set of revoked root
 * (fortress-master) pubkeys + the highest accepted revocation serial. Parallel
 * to {@link FederationNodeRevocationProjection} for nodes.
 */
export interface FederationRootRevocationProjection {
  revokedRootPubkeys: Set<string>;
  highestRevocationSerial: number;
}

export interface FederationAcceptanceEvent {
  event_id: string;
  origin_node_id: string;
  sequence: number;
  occurred_at: string;
  kind: string;
  payload: Record<string, unknown>;
  previous_hash: string | null;
  event_hash: string;
}

export interface FederationAcceptanceAppendResult {
  accepted: FederationAcceptanceEvent[];
  rejected: Array<{ event_id: string; reason: string }>;
}

export interface FederationEventAcceptanceResult
  extends FederationAcceptanceAppendResult {
  senderRevoked: boolean;
  revocationStateAvailable: boolean;
  batchRejected: boolean;
}

export interface AcceptFederationEventsFailClosedParams {
  events: FederationAcceptanceEvent[];
  fortressId: string;
  wireVersion?: unknown;
  senderNodeId?: string;
  isNodeRevoked?: (nodeId: string) => boolean;
  /**
   * Validate append eligibility without mutating durable federation state.
   * Used to project same-batch eviction effects before the single commit.
   */
  validateEvents?(events: FederationAcceptanceEvent[]): FederationAcceptanceAppendResult;
  appendEvents(events: FederationAcceptanceEvent[]): FederationAcceptanceAppendResult;
}

export type FederationEvictionVerification =
  | {
      ok: true;
      nodeId: string;
      evictionSerial: number;
      payload: FederationNodeEvictionPayload;
    }
  | { ok: false; reason: FederationEvictionRejectionReason };

export type FederationEvictionRejectionReason =
  | "wrong_event_kind"
  | "wrong_authority_origin"
  | "malformed_payload"
  | "fortress_mismatch"
  | "principal_mismatch"
  | "principal_chain_invalid"
  | "operator_signature_invalid"
  | "eviction_serial_replay"
  | "unsupported_event_version";

export interface FederationNodeCertificateRenewalConfig {
  certLifetimeMs?: number;
  renewalLeadMs?: number;
  renewalGraceMs?: number;
  /**
   * Must be <= renewalLeadMs. A longer ticker interval can skip the only
   * pre-expiry renewal window and let the local live certificate lapse.
   */
  renewalCheckIntervalMs?: number;
  now?: () => number;
}

export interface NormalizedFederationNodeCertificateRenewalConfig {
  certLifetimeMs: number;
  renewalLeadMs: number;
  renewalGraceMs: number;
  renewalCheckIntervalMs: number;
  now: () => number;
}

export type FederationNodeCertificateRenewalResult =
  | {
      renewed: true;
      certificate: NodeIdentityCertificate;
      previousExpiresAt: string | undefined;
      nextExpiresAt: string;
    }
  | {
      renewed: false;
      certificate: NodeIdentityCertificate | null;
      reason:
        | "missing_local_cert"
        | "legacy_non_expiring"
        | "not_local_node"
        | "not_due"
        | "revoked";
    };

export interface FederationNodeCertificateAutoRenewalHandle {
  tick(): Promise<void>;
  stop(): void;
}

export function federationOperatorAuthorityOrigin(fortressId: string): string {
  return `operator:${fortressId}`;
}

export function isFederationOperatorAuthorityEvent(
  event: FederationRevocationLogEvent,
  fortressId: string,
): boolean {
  return (
    event.origin_node_id === federationOperatorAuthorityOrigin(fortressId) &&
    (event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND ||
      event.kind === FEDERATION_POLICY_BUNDLE_EVENT_KIND)
  );
}

function lengthPrefixed(field: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + field.length);
  new DataView(out.buffer).setUint32(0, field.length, false);
  out.set(field, 4);
  return out;
}

export function buildFederationNodeEvictionMessage(
  payload: Omit<FederationNodeEvictionPayload, "operator_signature">,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_FEDERATION_NODE_EVICTION_DOMAIN),
    lengthPrefixed(encoder.encode(canonicalJson(payload))),
  ];
  const total = parts.reduce((n, part) => n + part.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

export function signFederationNodeEvictionPayload(params: {
  fortressId: string;
  nodeId: string;
  reason: string;
  effectiveAt: string;
  evictionSerial: number;
  operatorPrincipalId: string;
  operatorPrincipalPrivateKey: Uint8Array;
}): FederationNodeEvictionPayload {
  const body = {
    event_version: FEDERATION_NODE_EVICTION_EVENT_VERSION,
    fortress_id: params.fortressId,
    node_id: params.nodeId,
    reason: params.reason,
    effective_at: params.effectiveAt,
    eviction_serial: params.evictionSerial,
    operator_principal_id: params.operatorPrincipalId,
  };
  const signature = ed25519.sign(
    buildFederationNodeEvictionMessage(body),
    params.operatorPrincipalPrivateKey,
  );
  return {
    ...body,
    operator_signature: toBase64url(signature),
  };
}

export function verifyFederationNodeEvictionEvent(input: {
  event: FederationRevocationLogEvent;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  highestEvictionSerial: number;
}): FederationEvictionVerification {
  const { event } = input;
  if (event.kind !== FEDERATION_NODE_EVICTION_EVENT_KIND) {
    return { ok: false, reason: "wrong_event_kind" };
  }
  if (
    event.origin_node_id !==
    federationOperatorAuthorityOrigin(input.fortressId)
  ) {
    return { ok: false, reason: "wrong_authority_origin" };
  }

  if (event.payload.event_version !== FEDERATION_NODE_EVICTION_EVENT_VERSION) {
    return { ok: false, reason: "unsupported_event_version" };
  }
  const payload = parseNodeEvictionPayload(event.payload);
  if (payload === null) return { ok: false, reason: "malformed_payload" };
  if (payload.fortress_id !== input.fortressId) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (
    payload.operator_principal_id !==
    input.operatorPrincipalCert.principal_id
  ) {
    return { ok: false, reason: "principal_mismatch" };
  }
  if (payload.eviction_serial <= input.highestEvictionSerial) {
    return { ok: false, reason: "eviction_serial_replay" };
  }

  try {
    verifyPrincipalCertificate(input.operatorPrincipalCert, input.pinnedMaster);
  } catch {
    return { ok: false, reason: "principal_chain_invalid" };
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64url(payload.operator_signature);
  } catch {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  if (signature.length !== 64) {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  const signedBody = {
    event_version: payload.event_version,
    fortress_id: payload.fortress_id,
    node_id: payload.node_id,
    reason: payload.reason,
    effective_at: payload.effective_at,
    eviction_serial: payload.eviction_serial,
    operator_principal_id: payload.operator_principal_id,
  };
  const ok = verify(
    buildFederationNodeEvictionMessage(signedBody),
    signature,
    fromBase64url(input.operatorPrincipalCert.principal_pubkey),
  );
  if (!ok) return { ok: false, reason: "operator_signature_invalid" };

  return {
    ok: true,
    nodeId: payload.node_id,
    evictionSerial: payload.eviction_serial,
    payload,
  };
}

export function foldFederationNodeEvictionEvent(input: {
  event: FederationRevocationLogEvent;
  projection: FederationNodeRevocationProjection;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
}): FederationEvictionVerification {
  const verification = verifyFederationNodeEvictionEvent({
    event: input.event,
    fortressId: input.fortressId,
    pinnedMaster: input.pinnedMaster,
    operatorPrincipalCert: input.operatorPrincipalCert,
    highestEvictionSerial: input.projection.highestEvictionSerial,
  });
  if (!verification.ok) return verification;
  input.projection.revokedNodeIds.add(verification.nodeId);
  input.projection.highestEvictionSerial = verification.evictionSerial;
  return verification;
}

/**
 * Single fail-closed acceptance gate for federation event batches.
 *
 * The batch wire version and every reserved eviction event are preflighted
 * before any append. A lockstep/authority failure rejects the whole batch so a
 * mixed batch cannot smuggle ordinary events alongside an unsupported or
 * unauthorized reserved event.
 *
 * Operator-authority evictions are projected in memory so the post-batch
 * revoked set is visible before any ordinary event is accepted. The durable
 * append is called once with the whole accepted set so a mid-batch persistence
 * failure cannot leave evictions and ordinary events split across commits.
 */
export function acceptFederationEventsFailClosed(
  params: AcceptFederationEventsFailClosedParams,
): FederationEventAcceptanceResult {
  const { events, isNodeRevoked } = params;
  if (events.length === 0) {
    return {
      accepted: [],
      rejected: [],
      senderRevoked: false,
      revocationStateAvailable: true,
      batchRejected: false,
    };
  }

  if (params.wireVersion !== FEDERATION_SYNC_WIRE_VERSION) {
    return rejectAllForBatchReason(events, "unsupported_wire_version");
  }

  const reservedEventRejection = reservedEventBatchRejection(
    events,
    params.fortressId,
  );
  if (reservedEventRejection !== null) {
    return rejectAllForBatchReason(events, reservedEventRejection);
  }

  if (typeof isNodeRevoked !== "function") {
    return rejectAllForUnavailableRevocation(events);
  }

  const evaluatorReady = evaluateRevocationState(
    idsToEvaluate(events, params.senderNodeId),
    isNodeRevoked,
  );
  if (!evaluatorReady.ok) {
    return rejectAllForUnavailableRevocation(events);
  }

  const evictionEvents: FederationAcceptanceEvent[] = [];
  const ordinaryEvents: FederationAcceptanceEvent[] = [];
  for (const event of events) {
    if (isFederationOperatorAuthorityEvent(event, params.fortressId)) {
      evictionEvents.push(event);
    } else {
      ordinaryEvents.push(event);
    }
  }

  let appendEvictions: FederationAcceptanceAppendResult;
  try {
    appendEvictions =
      evictionEvents.length > 0
        ? validateEventsForProjection(params, evictionEvents)
        : { accepted: [], rejected: [] };
  } catch {
    return rejectAllForBatchReason(events, "append_failed");
  }

  const pendingEvictedNodeIds = pendingEvictionNodeIds(appendEvictions.accepted);
  const projectedRevoked = (nodeId: string): boolean =>
    evaluatorReady.revoked.get(nodeId) === true ||
    pendingEvictedNodeIds.has(nodeId);
  const senderRevoked =
    params.senderNodeId === undefined
      ? false
      : projectedRevoked(params.senderNodeId);
  const ordinaryCandidates: FederationAcceptanceEvent[] = [];
  const revokedRejections: FederationAcceptanceAppendResult["rejected"] = [];
  for (const event of ordinaryEvents) {
    if (senderRevoked || projectedRevoked(event.origin_node_id)) {
      revokedRejections.push({
        event_id: event.event_id,
        reason: "node_revoked",
      });
      continue;
    }
    ordinaryCandidates.push(event);
  }

  const acceptedCandidates = [...appendEvictions.accepted, ...ordinaryCandidates];
  let appendAccepted: FederationAcceptanceAppendResult;
  try {
    appendAccepted =
      acceptedCandidates.length > 0
        ? params.appendEvents(acceptedCandidates)
        : { accepted: [], rejected: [] };
  } catch {
    return rejectAllForBatchReason(events, "append_failed");
  }

  return {
    accepted: appendAccepted.accepted,
    rejected: [
      ...appendEvictions.rejected,
      ...revokedRejections,
      ...appendAccepted.rejected,
    ],
    senderRevoked,
    revocationStateAvailable: true,
    batchRejected: false,
  };
}

function validateEventsForProjection(
  params: AcceptFederationEventsFailClosedParams,
  events: FederationAcceptanceEvent[],
): FederationAcceptanceAppendResult {
  if (typeof params.validateEvents === "function") {
    return params.validateEvents(events);
  }
  return {
    accepted: [],
    rejected: events.map((event) => ({
      event_id: event.event_id,
      reason: "revocation_validation_unavailable",
    })),
  };
}

function pendingEvictionNodeIds(events: FederationAcceptanceEvent[]): Set<string> {
  const nodeIds = new Set<string>();
  for (const event of events) {
    const payload = parseNodeEvictionPayload(event.payload);
    if (payload !== null) nodeIds.add(payload.node_id);
  }
  return nodeIds;
}

function reservedEventBatchRejection(
  events: FederationAcceptanceEvent[],
  fortressId: string,
): string | null {
  const authorityOrigin = federationOperatorAuthorityOrigin(fortressId);
  for (const event of events) {
    const isEvictionKind = event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND;
    const isPolicyBundleKind =
      event.kind === FEDERATION_POLICY_BUNDLE_EVENT_KIND;
    const isReservedKind = isEvictionKind || isPolicyBundleKind;
    const isAuthorityOrigin = event.origin_node_id === authorityOrigin;
    if (!isReservedKind && !isAuthorityOrigin) continue;
    if (!isReservedKind || !isAuthorityOrigin) {
      return "operator_authority_invalid";
    }
    if (isEvictionKind) {
      if (event.payload.event_version !== FEDERATION_NODE_EVICTION_EVENT_VERSION) {
        return "unsupported_event_version";
      }
      if (parseNodeEvictionPayload(event.payload) === null) {
        return "malformed_payload";
      }
    } else {
      if (event.payload.event_version !== FEDERATION_POLICY_BUNDLE_EVENT_VERSION) {
        return "unsupported_event_version";
      }
      if (parseFederationPolicyBundlePayload(event.payload) === null) {
        return "malformed_payload";
      }
    }
  }
  return null;
}

function rejectAllForBatchReason(
  events: FederationAcceptanceEvent[],
  reason: string,
): FederationEventAcceptanceResult {
  return {
    accepted: [],
    rejected: events.map((event) => ({
      event_id: event.event_id,
      reason,
    })),
    senderRevoked: false,
    revocationStateAvailable: true,
    batchRejected: true,
  };
}

function rejectAllForUnavailableRevocation(
  events: FederationAcceptanceEvent[],
): FederationEventAcceptanceResult {
  return {
    accepted: [],
    rejected: events.map((event) => ({
      event_id: event.event_id,
      reason: "revocation_state_unavailable",
    })),
    senderRevoked: false,
    revocationStateAvailable: false,
    batchRejected: true,
  };
}

function idsToEvaluate(
  events: FederationAcceptanceEvent[],
  senderNodeId: string | undefined,
): Set<string> {
  const ids = new Set<string>();
  if (senderNodeId !== undefined) ids.add(senderNodeId);
  for (const event of events) ids.add(event.origin_node_id);
  return ids;
}

function evaluateRevocationState(
  nodeIds: Set<string>,
  isNodeRevoked: (nodeId: string) => boolean,
): { ok: true; revoked: Map<string, boolean> } | { ok: false } {
  const revoked = new Map<string, boolean>();
  try {
    for (const nodeId of nodeIds) {
      revoked.set(nodeId, isNodeRevoked(nodeId));
    }
  } catch {
    return { ok: false };
  }
  return { ok: true, revoked };
}

/**
 * Replays an already-accepted durable eviction into the in-memory projection.
 *
 * Acceptance-time verification is the security boundary for eviction
 * signatures. Reprojection after a legitimate principal rotation must not
 * re-verify old durable events under the current principal certificate, or a
 * rotation would resurrect nodes evicted under the prior principal. This helper
 * still validates the stable wire shape, fortress binding, authority origin,
 * and serial monotonicity, but deliberately does not re-check the old signature
 * against the current principal.
 */
export function foldAcceptedFederationNodeEvictionEvent(input: {
  event: FederationRevocationLogEvent;
  projection: FederationNodeRevocationProjection;
  fortressId: string;
}): FederationEvictionVerification {
  const { event } = input;
  if (event.kind !== FEDERATION_NODE_EVICTION_EVENT_KIND) {
    return { ok: false, reason: "wrong_event_kind" };
  }
  if (event.origin_node_id !== federationOperatorAuthorityOrigin(input.fortressId)) {
    return { ok: false, reason: "wrong_authority_origin" };
  }
  if (event.payload.event_version !== FEDERATION_NODE_EVICTION_EVENT_VERSION) {
    return { ok: false, reason: "unsupported_event_version" };
  }
  const payload = parseNodeEvictionPayload(event.payload);
  if (payload === null) return { ok: false, reason: "malformed_payload" };
  if (payload.fortress_id !== input.fortressId) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (payload.eviction_serial <= input.projection.highestEvictionSerial) {
    return { ok: false, reason: "eviction_serial_replay" };
  }

  input.projection.revokedNodeIds.add(payload.node_id);
  input.projection.highestEvictionSerial = payload.eviction_serial;
  return {
    ok: true,
    nodeId: payload.node_id,
    evictionSerial: payload.eviction_serial,
    payload,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// Root revocation (rotate-root --compromised, Slice 3c-1)
// ═══════════════════════════════════════════════════════════════════════

export type FederationRootRevocationVerification =
  | {
      ok: true;
      revokedMasterPubkey: string;
      revocationSerial: number;
      payload: FederationRootRevocationPayload;
    }
  | { ok: false; reason: FederationRootRevocationRejectionReason };

export type FederationRootRevocationRejectionReason =
  | "wrong_event_kind"
  | "wrong_authority_origin"
  | "malformed_payload"
  | "fortress_mismatch"
  | "principal_mismatch"
  | "principal_chain_invalid"
  | "operator_signature_invalid"
  | "operator_signature_bundle_invalid"
  | "revocation_serial_replay"
  | "unsupported_event_version";

export function buildFederationRootRevocationMessage(
  payload: Omit<FederationRootRevocationPayload, "operator_signature">,
): Uint8Array {
  const encoder = new TextEncoder();
  const parts = [
    encoder.encode(V1_FEDERATION_ROOT_REVOCATION_DOMAIN),
    lengthPrefixed(encoder.encode(canonicalJson(payload))),
  ];
  const total = parts.reduce((n, part) => n + part.length, 0);
  const message = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  return message;
}

/**
 * Sign a root-revocation payload with the NEW (post-compromise) operator
 * principal private key, the one chaining to K2. The caller MUST zero the
 * private key after return (constraint 6). Signing under K2 (never K1) is the
 * structural downgrade-resistance guarantee: a thief holding K1 cannot forge a
 * revocation the fortress would fold.
 */
export function signFederationRootRevocationPayload(params: {
  fortressId: string;
  revokedMasterPubkey: string;
  effectiveAt: string;
  revocationSerial: number;
  operatorPrincipalId: string;
  operatorPrincipalPrivateKey: Uint8Array;
}): FederationRootRevocationPayload {
  const body = {
    event_version: FEDERATION_ROOT_REVOCATION_EVENT_VERSION,
    fortress_id: params.fortressId,
    revoked_master_pubkey: params.revokedMasterPubkey,
    effective_at: params.effectiveAt,
    revocation_serial: params.revocationSerial,
    operator_principal_id: params.operatorPrincipalId,
  };
  const signature = ed25519.sign(
    buildFederationRootRevocationMessage(body),
    params.operatorPrincipalPrivateKey,
  );
  return {
    ...body,
    operator_signature: toBase64url(signature),
  };
}

/** Surface id for the hybrid root-revocation signature bundle. */
export const ROOT_REVOCATION_HYBRID_SURFACE_ID =
  "sanctuary.v1.federation-root-revocation.hybrid" as const;

/**
 * Sign a HYBRID root-revocation payload (rotate-root --compromised on a hybrid
 * fortress). Produces BOTH:
 *   - the classical `operator_signature` (Ed25519) over the canonical message,
 *     signed by the NEW K2 hybrid principal's Ed25519 private key, so a
 *     classical verifier path stays intact; and
 *   - the `operator_signature_bundle` (Ed25519 + ML-DSA-65, both-must-pass) over
 *     the same body via the new K2 hybrid principal's two private keys, so the
 *     revocation's authenticity is post-quantum protected;
 *   - the `revoked_hybrid` binding identifying BOTH old hybrid master components.
 *
 * Signed under K2 (the post-rotation hybrid principal), NEVER under K1: a thief
 * holding the OLD root cannot forge a revocation the fortress would fold. The
 * caller MUST zero `newHybridPrincipalPrivateKeys` after return (constraint 6).
 */
export async function signFederationRootRevocationPayloadHybrid(params: {
  fortressId: string;
  /** The old CLASSICAL Ed25519 master pubkey (base64url), still recorded. */
  revokedMasterPubkey: string;
  /** Both old HYBRID master component public keys being revoked. */
  revokedHybrid: FederationRootRevocationHybridBinding;
  effectiveAt: string;
  revocationSerial: number;
  operatorPrincipalId: string;
  /**
   * The NEW K2 CLASSICAL principal private key (Ed25519). Signs the classical
   * `operator_signature` field so the existing classical verify path
   * ({@link verifyFederationRootRevocationEvent}) accepts it against the
   * fortress's classical issuing-principal cert. The caller MUST zero this.
   */
  newClassicalPrincipalPrivateKey: Uint8Array;
  /** The NEW K2 hybrid principal's two private keys (Ed25519 + ML-DSA-65). */
  newHybridPrincipalPrivateKeys: HybridPrivateKeyMaterial;
}): Promise<FederationRootRevocationPayload> {
  if (
    params.newHybridPrincipalPrivateKeys.ed25519.private_key.length !==
    ED25519_PUBLIC_KEY_BYTES
  ) {
    throw new Error("hybrid revocation Ed25519 private key must be 32 bytes");
  }
  if (
    params.newHybridPrincipalPrivateKeys.ml_dsa_65.secret_key.length !==
    ML_DSA_65_SECRET_KEY_BYTES
  ) {
    throw new Error("hybrid revocation ML-DSA-65 secret key must be 4032 bytes");
  }
  const body = {
    event_version: FEDERATION_ROOT_REVOCATION_EVENT_VERSION,
    fortress_id: params.fortressId,
    revoked_master_pubkey: params.revokedMasterPubkey,
    effective_at: params.effectiveAt,
    revocation_serial: params.revocationSerial,
    operator_principal_id: params.operatorPrincipalId,
    revoked_hybrid: params.revokedHybrid,
  };
  const message = buildFederationRootRevocationMessage(body);
  // Classical Ed25519 leg: the `operator_signature` field is the Ed25519
  // signature over the canonical revocation MESSAGE (so the existing classical
  // verify path, verifyFederationRootRevocationEvent, accepts it against the
  // fortress's CLASSICAL issuing-principal cert), signed by the NEW K2 classical
  // principal Ed25519 key.
  const edSignature = ed25519.sign(
    message,
    params.newClassicalPrincipalPrivateKey,
  );
  // Hybrid bundle leg (both-must-pass): signs the descriptor-bound preimage the
  // suite constructs (each component signs the bytes the registry hands it).
  const signer: SuiteSigner = {
    ed25519: {
      key_ref: params.newHybridPrincipalPrivateKeys.ed25519.key_ref,
      sign: (bytes) =>
        ed25519.sign(bytes, params.newHybridPrincipalPrivateKeys.ed25519.private_key),
    },
    ml_dsa_65: {
      key_ref: params.newHybridPrincipalPrivateKeys.ml_dsa_65.key_ref,
      sign: (bytes) =>
        ml_dsa65.sign(bytes, params.newHybridPrincipalPrivateKeys.ml_dsa_65.secret_key),
    },
  };
  const bundle = await cryptoSuiteRegistry.signSurface(
    {
      surface_id: ROOT_REVOCATION_HYBRID_SURFACE_ID,
      surface_version: FEDERATION_ROOT_REVOCATION_EVENT_VERSION,
      signature_suite: HYBRID_SIGNATURE_SUITE_ID,
      // The bundle's signed preimage wraps the raw revocation message as an
      // opaque base64url payload; both bundle components cover these exact bytes.
      payload: toBase64url(message),
    },
    signer,
  );
  return {
    ...body,
    operator_signature: toBase64url(edSignature),
    operator_signature_bundle: bundle,
  };
}

/**
 * Verify the HYBRID leg of a hybrid root-revocation payload: BOTH the Ed25519
 * and ML-DSA-65 components of `operator_signature_bundle` must verify under the
 * NEW K2 hybrid principal public keys (both-must-pass). Returns true only when
 * both pass; false on any defect. The classical `operator_signature` Ed25519
 * leg is verified separately by {@link verifyFederationRootRevocationEvent}.
 */
export async function verifyFederationRootRevocationHybridBundle(
  payload: FederationRootRevocationPayload,
  newHybridPrincipalPublicKeys: HybridCertificatePublicKeys,
): Promise<boolean> {
  const bundle = payload.operator_signature_bundle;
  if (!bundle) return false;
  if (!payload.revoked_hybrid) return false;
  const signedBody = {
    event_version: payload.event_version,
    fortress_id: payload.fortress_id,
    revoked_master_pubkey: payload.revoked_master_pubkey,
    effective_at: payload.effective_at,
    revocation_serial: payload.revocation_serial,
    operator_principal_id: payload.operator_principal_id,
    revoked_hybrid: payload.revoked_hybrid,
  };
  const message = buildFederationRootRevocationMessage(signedBody);
  let edPub: Uint8Array;
  let mlPub: Uint8Array;
  try {
    edPub = fromBase64url(newHybridPrincipalPublicKeys.ed25519.public_key);
    mlPub = fromBase64url(newHybridPrincipalPublicKeys.ml_dsa_65.public_key);
  } catch {
    return false;
  }
  if (edPub.length !== ED25519_PUBLIC_KEY_BYTES) return false;
  if (mlPub.length !== ML_DSA_65_PUBLIC_KEY_BYTES) return false;
  return cryptoSuiteRegistry.verifySurface(
    {
      surface_id: ROOT_REVOCATION_HYBRID_SURFACE_ID,
      surface_version: FEDERATION_ROOT_REVOCATION_EVENT_VERSION,
      signature_suite: HYBRID_SIGNATURE_SUITE_ID,
      payload: toBase64url(message),
    },
    bundle,
    createHybridSuitePublicKeys({
      ed25519KeyRef: newHybridPrincipalPublicKeys.ed25519.key_ref,
      ed25519PublicKey: edPub,
      mlDsa65KeyRef: newHybridPrincipalPublicKeys.ml_dsa_65.key_ref,
      mlDsa65PublicKey: mlPub,
    }),
  );
}

// ─────────────────────────────────────────────────────────────────────────
// SCOPE (Slice 3c-1): the verify + fold functions below are the VERIFIER
// SUBSTRATE and the test-proven downgrade-resistance invariants (sign-under-K2 /
// reject-under-K1, serial-monotonicity, principal-chain). They are NOT yet a
// live production enforcement path: in 3c-1 no production code appends, syncs,
// or folds a wire root-revocation event; enforcement runs entirely off the
// durable revoked-root projection set + the `isRootRevoked` hook. The
// wire-acceptance fold path (a peer/joiner adopting a remote root-revocation
// event) is a LATER slice (3c-2 / 3d). Keep these: the downgrade-resistance
// proof requires the sign+verify pair, and they are the design-specified Q6
// substrate the later slice consumes.
// ─────────────────────────────────────────────────────────────────────────

/**
 * Verify a root-revocation event under the CURRENT principal cert (which chains
 * to K2, the post-rotation root). Mirrors {@link
 * verifyFederationNodeEvictionEvent}: kind + authority origin + payload shape +
 * fortress binding + principal binding + serial monotonicity + principal chain
 * + operator signature. A `false`/throw at the call site fails closed.
 */
export async function verifyFederationRootRevocationEvent(input: {
  event: FederationRevocationLogEvent;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  operatorHybridPrincipalPublicKeys?: HybridCertificatePublicKeys;
  highestRevocationSerial: number;
}): Promise<FederationRootRevocationVerification> {
  const { event } = input;
  if (event.kind !== FEDERATION_ROOT_REVOCATION_EVENT_KIND) {
    return { ok: false, reason: "wrong_event_kind" };
  }
  if (
    event.origin_node_id !== federationOperatorAuthorityOrigin(input.fortressId)
  ) {
    return { ok: false, reason: "wrong_authority_origin" };
  }
  if (event.payload.event_version !== FEDERATION_ROOT_REVOCATION_EVENT_VERSION) {
    return { ok: false, reason: "unsupported_event_version" };
  }
  const payload = parseRootRevocationPayload(event.payload);
  if (payload === null) return { ok: false, reason: "malformed_payload" };
  if (payload.fortress_id !== input.fortressId) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (
    payload.operator_principal_id !== input.operatorPrincipalCert.principal_id
  ) {
    return { ok: false, reason: "principal_mismatch" };
  }
  if (payload.revocation_serial <= input.highestRevocationSerial) {
    return { ok: false, reason: "revocation_serial_replay" };
  }

  try {
    verifyPrincipalCertificate(input.operatorPrincipalCert, input.pinnedMaster);
  } catch {
    return { ok: false, reason: "principal_chain_invalid" };
  }

  let signature: Uint8Array;
  try {
    signature = fromBase64url(payload.operator_signature);
  } catch {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  if (signature.length !== 64) {
    return { ok: false, reason: "operator_signature_invalid" };
  }
  const signedBody = {
    event_version: payload.event_version,
    fortress_id: payload.fortress_id,
    revoked_master_pubkey: payload.revoked_master_pubkey,
    effective_at: payload.effective_at,
    revocation_serial: payload.revocation_serial,
    operator_principal_id: payload.operator_principal_id,
    // Hybrid revocations sign over the revoked_hybrid binding too; include it
    // (and only it) when present so the preimage matches what was signed. A
    // classical payload omits it, leaving the body byte-for-byte unchanged.
    ...(payload.revoked_hybrid !== undefined
      ? { revoked_hybrid: payload.revoked_hybrid }
      : {}),
  };
  const ok = verify(
    buildFederationRootRevocationMessage(signedBody),
    signature,
    fromBase64url(input.operatorPrincipalCert.principal_pubkey),
  );
  if (!ok) return { ok: false, reason: "operator_signature_invalid" };
  if (payload.revoked_hybrid !== undefined) {
    if (input.operatorHybridPrincipalPublicKeys === undefined) {
      return { ok: false, reason: "operator_signature_bundle_invalid" };
    }
    const hybridOk = await verifyFederationRootRevocationHybridBundle(
      payload,
      input.operatorHybridPrincipalPublicKeys,
    );
    if (!hybridOk) {
      return { ok: false, reason: "operator_signature_bundle_invalid" };
    }
  }

  return {
    ok: true,
    revokedMasterPubkey: payload.revoked_master_pubkey,
    revocationSerial: payload.revocation_serial,
    payload,
  };
}

/**
 * Verify-then-fold a root-revocation event under the current principal/K2. Used
 * on the ACCEPTANCE path (a NEW event arriving), where the operator signature is
 * the security boundary. Adds the revoked root pubkey to the grow-only set and
 * lifts the serial floor.
 */
export async function foldFederationRootRevocationEvent(input: {
  event: FederationRevocationLogEvent;
  projection: FederationRootRevocationProjection;
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  operatorHybridPrincipalPublicKeys?: HybridCertificatePublicKeys;
}): Promise<FederationRootRevocationVerification> {
  const verification = await verifyFederationRootRevocationEvent({
    event: input.event,
    fortressId: input.fortressId,
    pinnedMaster: input.pinnedMaster,
    operatorPrincipalCert: input.operatorPrincipalCert,
    operatorHybridPrincipalPublicKeys: input.operatorHybridPrincipalPublicKeys,
    highestRevocationSerial: input.projection.highestRevocationSerial,
  });
  if (!verification.ok) return verification;
  input.projection.revokedRootPubkeys.add(verification.revokedMasterPubkey);
  if (verification.payload.revoked_hybrid !== undefined) {
    input.projection.revokedRootPubkeys.add(
      verification.payload.revoked_hybrid.ed25519.public_key,
    );
    input.projection.revokedRootPubkeys.add(
      verification.payload.revoked_hybrid.ml_dsa_65.public_key,
    );
  }
  input.projection.highestRevocationSerial = verification.revocationSerial;
  return verification;
}

/**
 * Replay an already-accepted durable root-revocation into the in-memory
 * projection. As with {@link foldAcceptedFederationNodeEvictionEvent}, the
 * acceptance-time verification was the security boundary; reprojection after a
 * legitimate principal rotation must NOT re-verify the old signature under the
 * current principal (a rotation would otherwise un-revoke). This validates the
 * stable wire shape + fortress binding + authority origin + serial monotonicity,
 * but deliberately does not re-check the signature.
 */
export function foldAcceptedFederationRootRevocationEvent(input: {
  event: FederationRevocationLogEvent;
  projection: FederationRootRevocationProjection;
  fortressId: string;
}): FederationRootRevocationVerification {
  const { event } = input;
  if (event.kind !== FEDERATION_ROOT_REVOCATION_EVENT_KIND) {
    return { ok: false, reason: "wrong_event_kind" };
  }
  if (
    event.origin_node_id !== federationOperatorAuthorityOrigin(input.fortressId)
  ) {
    return { ok: false, reason: "wrong_authority_origin" };
  }
  if (event.payload.event_version !== FEDERATION_ROOT_REVOCATION_EVENT_VERSION) {
    return { ok: false, reason: "unsupported_event_version" };
  }
  const payload = parseRootRevocationPayload(event.payload);
  if (payload === null) return { ok: false, reason: "malformed_payload" };
  if (payload.fortress_id !== input.fortressId) {
    return { ok: false, reason: "fortress_mismatch" };
  }
  if (payload.revocation_serial <= input.projection.highestRevocationSerial) {
    return { ok: false, reason: "revocation_serial_replay" };
  }

  input.projection.revokedRootPubkeys.add(payload.revoked_master_pubkey);
  if (payload.revoked_hybrid !== undefined) {
    input.projection.revokedRootPubkeys.add(payload.revoked_hybrid.ed25519.public_key);
    input.projection.revokedRootPubkeys.add(payload.revoked_hybrid.ml_dsa_65.public_key);
  }
  input.projection.highestRevocationSerial = payload.revocation_serial;
  return {
    ok: true,
    revokedMasterPubkey: payload.revoked_master_pubkey,
    revocationSerial: payload.revocation_serial,
    payload,
  };
}

function parseRootRevocationPayload(
  payload: Record<string, unknown>,
): FederationRootRevocationPayload | null {
  const eventVersion = payload.event_version;
  const fortressId = payload.fortress_id;
  const revokedMasterPubkey = payload.revoked_master_pubkey;
  const effectiveAt = payload.effective_at;
  const revocationSerial = payload.revocation_serial;
  const operatorPrincipalId = payload.operator_principal_id;
  const operatorSignature = payload.operator_signature;
  if (eventVersion !== FEDERATION_ROOT_REVOCATION_EVENT_VERSION) return null;
  if (typeof fortressId !== "string" || fortressId.length === 0) return null;
  if (
    typeof revokedMasterPubkey !== "string" ||
    revokedMasterPubkey.length === 0
  ) {
    return null;
  }
  if (typeof effectiveAt !== "string" || Number.isNaN(Date.parse(effectiveAt))) {
    return null;
  }
  if (
    typeof revocationSerial !== "number" ||
    !Number.isSafeInteger(revocationSerial) ||
    revocationSerial < 1
  ) {
    return null;
  }
  if (
    typeof operatorPrincipalId !== "string" ||
    operatorPrincipalId.length === 0
  ) {
    return null;
  }
  if (typeof operatorSignature !== "string" || operatorSignature.length === 0) {
    return null;
  }
  const revokedHybrid = parseRevokedHybridBinding(payload.revoked_hybrid);
  if (revokedHybrid === "invalid") return null;
  const signatureBundle = parseSignatureBundle(payload.operator_signature_bundle);
  if (signatureBundle === "invalid") return null;
  if (revokedHybrid !== undefined && signatureBundle === undefined) return null;
  if (revokedHybrid === undefined && signatureBundle !== undefined) return null;
  return {
    event_version: eventVersion,
    fortress_id: fortressId,
    revoked_master_pubkey: revokedMasterPubkey,
    effective_at: effectiveAt,
    revocation_serial: revocationSerial,
    operator_principal_id: operatorPrincipalId,
    operator_signature: operatorSignature,
    ...(revokedHybrid !== undefined ? { revoked_hybrid: revokedHybrid } : {}),
    ...(signatureBundle !== undefined ? { operator_signature_bundle: signatureBundle } : {}),
  };
}

/**
 * Parse the optional `revoked_hybrid` binding. Returns undefined when absent,
 * "invalid" when present-but-malformed (so the whole payload is rejected; a
 * tampered hybrid binding must never silently parse as a classical revocation),
 * or the typed binding when well-formed.
 */
function parseRevokedHybridBinding(
  value: unknown,
): FederationRootRevocationHybridBinding | undefined | "invalid" {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) return "invalid";
  const v = value as Record<string, unknown>;
  const ed = v.ed25519;
  const ml = v.ml_dsa_65;
  if (typeof ed !== "object" || ed === null) return "invalid";
  if (typeof ml !== "object" || ml === null) return "invalid";
  const edRec = ed as Record<string, unknown>;
  const mlRec = ml as Record<string, unknown>;
  if (
    typeof edRec.key_ref !== "string" ||
    edRec.key_ref.length === 0 ||
    typeof edRec.public_key !== "string" ||
    edRec.public_key.length === 0 ||
    typeof mlRec.key_ref !== "string" ||
    mlRec.key_ref.length === 0 ||
    typeof mlRec.public_key !== "string" ||
    mlRec.public_key.length === 0
  ) {
    return "invalid";
  }
  return {
    ed25519: { key_ref: edRec.key_ref, public_key: edRec.public_key },
    ml_dsa_65: { key_ref: mlRec.key_ref, public_key: mlRec.public_key },
  };
}

function parseSignatureBundle(
  value: unknown,
): SignatureBundle | undefined | "invalid" {
  if (value === undefined) return undefined;
  if (typeof value !== "object" || value === null) return "invalid";
  const bundle = value as Record<string, unknown>;
  if (
    bundle.bundle_version !== "sanctuary.signature-bundle.v1" ||
    typeof bundle.signature_suite !== "string" ||
    bundle.signature_suite.length === 0 ||
    !Array.isArray(bundle.components)
  ) {
    return "invalid";
  }
  const components = bundle.components.map((component) => {
    if (typeof component !== "object" || component === null) return "invalid";
    const c = component as Record<string, unknown>;
    if (
      typeof c.alg !== "string" ||
      c.alg.length === 0 ||
      typeof c.key_ref !== "string" ||
      c.key_ref.length === 0 ||
      typeof c.sig !== "string" ||
      c.sig.length === 0
    ) {
      return "invalid";
    }
    return { alg: c.alg, key_ref: c.key_ref, sig: c.sig };
  });
  if (components.some((component) => component === "invalid")) return "invalid";
  return {
    bundle_version: "sanctuary.signature-bundle.v1",
    signature_suite: bundle.signature_suite,
    components: components as SignatureBundle["components"],
  };
}

function parseNodeEvictionPayload(
  payload: Record<string, unknown>,
): FederationNodeEvictionPayload | null {
  const fortressId = payload.fortress_id;
  const eventVersion = payload.event_version;
  const nodeId = payload.node_id;
  const reason = payload.reason;
  const effectiveAt = payload.effective_at;
  const evictionSerial = payload.eviction_serial;
  const operatorPrincipalId = payload.operator_principal_id;
  const operatorSignature = payload.operator_signature;
  if (eventVersion !== FEDERATION_NODE_EVICTION_EVENT_VERSION) {
    return null;
  }
  if (typeof fortressId !== "string" || fortressId.length === 0) return null;
  if (typeof nodeId !== "string" || nodeId.length === 0) return null;
  if (typeof reason !== "string" || reason.length === 0) return null;
  if (typeof effectiveAt !== "string" || Number.isNaN(Date.parse(effectiveAt))) {
    return null;
  }
  if (
    typeof evictionSerial !== "number" ||
    !Number.isSafeInteger(evictionSerial) ||
    evictionSerial < 1
  ) {
    return null;
  }
  if (typeof operatorPrincipalId !== "string" || operatorPrincipalId.length === 0) {
    return null;
  }
  if (typeof operatorSignature !== "string" || operatorSignature.length === 0) {
    return null;
  }
  return {
    event_version: eventVersion,
    fortress_id: fortressId,
    node_id: nodeId,
    reason,
    effective_at: effectiveAt,
    eviction_serial: evictionSerial,
    operator_principal_id: operatorPrincipalId,
    operator_signature: operatorSignature,
  };
}

export function normalizeFederationNodeCertificateRenewalConfig(
  config?: FederationNodeCertificateRenewalConfig,
): NormalizedFederationNodeCertificateRenewalConfig {
  const normalized = {
    certLifetimeMs:
      config?.certLifetimeMs ?? DEFAULT_FEDERATION_NODE_CERT_LIFETIME_MS,
    renewalLeadMs:
      config?.renewalLeadMs ?? DEFAULT_FEDERATION_NODE_CERT_RENEWAL_LEAD_MS,
    renewalGraceMs:
      config?.renewalGraceMs ?? DEFAULT_FEDERATION_NODE_CERT_RENEWAL_GRACE_MS,
    renewalCheckIntervalMs:
      config?.renewalCheckIntervalMs ??
      DEFAULT_FEDERATION_NODE_CERT_RENEWAL_CHECK_INTERVAL_MS,
    now: config?.now ?? Date.now,
  };
  for (const [name, value] of Object.entries(normalized)) {
    if (name === "now") continue;
    if (
      typeof value !== "number" ||
      !Number.isFinite(value) ||
      value <= 0
    ) {
      throw new Error(`invalid federation node renewal config: ${name}`);
    }
  }
  if (normalized.renewalLeadMs >= normalized.certLifetimeMs) {
    throw new Error(
      "invalid federation node renewal config: renewalLeadMs must be shorter than certLifetimeMs",
    );
  }
  if (normalized.renewalCheckIntervalMs > normalized.renewalLeadMs) {
    throw new Error(
      "invalid federation node renewal config: renewalCheckIntervalMs must be less than or equal to renewalLeadMs",
    );
  }
  return normalized;
}

export function nodeCertificateExpiresAt(
  config?: FederationNodeCertificateRenewalConfig,
): string {
  const normalized = normalizeFederationNodeCertificateRenewalConfig(config);
  return new Date(normalized.now() + normalized.certLifetimeMs).toISOString();
}

export function shouldRenewNodeCertificate(
  certificate: NodeIdentityCertificate,
  config?: FederationNodeCertificateRenewalConfig,
): boolean {
  if (!certificate.expires_at) return false;
  const normalized = normalizeFederationNodeCertificateRenewalConfig(config);
  const expiresMs = Date.parse(certificate.expires_at);
  if (Number.isNaN(expiresMs)) return false;
  const now = normalized.now();
  return (
    expiresMs - normalized.renewalLeadMs <= now &&
    now <= expiresMs + normalized.renewalGraceMs
  );
}

export function renewNodeIdentityCertificateIfDue(params: {
  certificate: NodeIdentityCertificate | null;
  localNodeId: string;
  pinnedMaster: FortressMasterPublicKey;
  operatorPrincipalCert: PrincipalCertificate;
  operatorPrincipalPrivateKey: Uint8Array;
  masterPrivateKey?: Uint8Array;
  isNodeRevoked(nodeId: string): boolean;
  config?: FederationNodeCertificateRenewalConfig;
}): FederationNodeCertificateRenewalResult {
  const certificate = params.certificate;
  if (certificate === null) {
    return { renewed: false, certificate: null, reason: "missing_local_cert" };
  }
  if (!certificate.expires_at) {
    return {
      renewed: false,
      certificate,
      reason: "legacy_non_expiring",
    };
  }
  if (certificate.node_id !== params.localNodeId) {
    return { renewed: false, certificate, reason: "not_local_node" };
  }
  if (params.isNodeRevoked(certificate.node_id)) {
    return { renewed: false, certificate, reason: "revoked" };
  }
  if (!shouldRenewNodeCertificate(certificate, params.config)) {
    return { renewed: false, certificate, reason: "not_due" };
  }
  const nextExpiresAt = nodeCertificateExpiresAt(params.config);
  const renewed = issueNodeIdentityCertificate({
    node_id: certificate.node_id,
    node_pubkey: fromBase64url(certificate.node_pubkey),
    node_mode: certificate.node_mode,
    fortress_id: certificate.fortress_id,
    capabilities: certificate.capabilities,
    parent_chain: {
      fortress_master_pubkey: params.pinnedMaster.public_key,
      principal_id: params.operatorPrincipalCert.principal_id,
      principal_pubkey: params.operatorPrincipalCert.principal_pubkey,
    },
    principal_private_key: params.operatorPrincipalPrivateKey,
    tee_attestation_hash: certificate.tee_attestation_hash,
    master_private_key: params.masterPrivateKey,
    expires_at: nextExpiresAt,
  });
  return {
    renewed: true,
    certificate: renewed,
    previousExpiresAt: certificate.expires_at,
    nextExpiresAt,
  };
}

export function startFederationNodeCertificateAutoRenewal(opts: {
  renewNow(): void | Promise<void>;
  config?: FederationNodeCertificateRenewalConfig;
  setIntervalFn?: typeof setInterval;
  clearIntervalFn?: typeof clearInterval;
}): FederationNodeCertificateAutoRenewalHandle {
  const config = normalizeFederationNodeCertificateRenewalConfig(opts.config);
  const setIntervalFn = opts.setIntervalFn ?? setInterval;
  const clearIntervalFn = opts.clearIntervalFn ?? clearInterval;
  let stopped = false;

  const tick = async (): Promise<void> => {
    if (stopped) return;
    try {
      await opts.renewNow();
    } catch {
      // Renewal failures must not crash the daemon. If renewal cannot happen,
      // the unchanged certificate will still be denied by the normal expiry
      // backstop once it is genuinely expired.
    }
  };

  void tick();
  const timer = setIntervalFn(() => {
    void tick();
  }, config.renewalCheckIntervalMs);
  timer.unref?.();

  return {
    tick,
    stop() {
      if (stopped) return;
      stopped = true;
      clearIntervalFn(timer);
    },
  };
}
