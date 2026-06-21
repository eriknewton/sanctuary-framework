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
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
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

export const FEDERATION_NODE_EVICTION_EVENT_KIND = "node_eviction" as const;
export const FEDERATION_NODE_EVICTION_EVENT_VERSION =
  "sanctuary.v1.node-eviction" as const;
export const FEDERATION_SYNC_WIRE_VERSION =
  "sanctuary.v1.federation-sync-envelope" as const;
export const V1_FEDERATION_NODE_EVICTION_DOMAIN =
  "sanctuary.v1.federation-node-eviction";

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
    event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND
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
 * Operator-authority evictions are appended first so the post-batch revoked set
 * is visible before any ordinary event is accepted. If revocation state cannot
 * be evaluated, no event in the batch is trusted.
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

  const appendEvictions =
    evictionEvents.length > 0
      ? params.appendEvents(evictionEvents)
      : { accepted: [], rejected: [] };

  const postEvictionEval = evaluateRevocationState(
    idsToEvaluate(ordinaryEvents, params.senderNodeId),
    isNodeRevoked,
  );
  if (!postEvictionEval.ok) {
    return {
      accepted: appendEvictions.accepted,
      rejected: [
        ...appendEvictions.rejected,
        ...ordinaryEvents.map((event) => ({
          event_id: event.event_id,
          reason: "revocation_state_unavailable",
        })),
      ],
      senderRevoked: false,
      revocationStateAvailable: false,
      batchRejected: false,
    };
  }

  const senderRevoked =
    params.senderNodeId === undefined
      ? false
      : postEvictionEval.revoked.get(params.senderNodeId) === true;
  const ordinaryCandidates: FederationAcceptanceEvent[] = [];
  const revokedRejections: FederationAcceptanceAppendResult["rejected"] = [];
  for (const event of ordinaryEvents) {
    if (senderRevoked || postEvictionEval.revoked.get(event.origin_node_id) === true) {
      revokedRejections.push({
        event_id: event.event_id,
        reason: "node_revoked",
      });
      continue;
    }
    ordinaryCandidates.push(event);
  }

  const appendOrdinary =
    ordinaryCandidates.length > 0
      ? params.appendEvents(ordinaryCandidates)
      : { accepted: [], rejected: [] };

  return {
    accepted: [...appendEvictions.accepted, ...appendOrdinary.accepted],
    rejected: [
      ...appendEvictions.rejected,
      ...revokedRejections,
      ...appendOrdinary.rejected,
    ],
    senderRevoked,
    revocationStateAvailable: true,
    batchRejected: false,
  };
}

function reservedEventBatchRejection(
  events: FederationAcceptanceEvent[],
  fortressId: string,
): string | null {
  const authorityOrigin = federationOperatorAuthorityOrigin(fortressId);
  for (const event of events) {
    const isEvictionKind = event.kind === FEDERATION_NODE_EVICTION_EVENT_KIND;
    const isAuthorityOrigin = event.origin_node_id === authorityOrigin;
    if (!isEvictionKind && !isAuthorityOrigin) continue;
    if (!isEvictionKind || !isAuthorityOrigin) {
      return "eviction_authority_invalid";
    }
    if (event.payload.event_version !== FEDERATION_NODE_EVICTION_EVENT_VERSION) {
      return "unsupported_event_version";
    }
    if (parseNodeEvictionPayload(event.payload) === null) {
      return "malformed_payload";
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
