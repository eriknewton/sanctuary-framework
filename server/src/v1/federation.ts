/**
 * /v1 federation endpoints + join-authorization ceremony (PR-A3).
 *
 *   POST /v1/federation/enable             SESSION + OPERATOR_SIGNED, Tier 1
 *   POST /v1/federation/disable            SESSION + OPERATOR_SIGNED, Tier 1
 *   GET  /v1/federation/status             SESSION
 *   POST /v1/federation/authorize/init     SESSION + OPERATOR_SIGNED, Tier 1
 *   POST /v1/federation/authorize/complete BOOTSTRAP_TOKEN (pre-session class)
 *
 * The join ceremony is operator-authorized in two crypto-verified steps and
 * is built by WRAPPING the existing mesh lifecycle primitives — it does not
 * reimplement them:
 *
 *  - `authorize/init` mints a short-lived, operator-principal-signed
 *    bootstrap token (`issueBootstrapToken`). The token alone is not
 *    membership; it is the joining node's right to submit a JoinRequest.
 *  - The joining node assembles a JoinRequest (`sanctuary federation join`)
 *    and submits it to `authorize/complete`, which verifies the bootstrap
 *    token signature (`verifyBootstrapToken`), the node_mode binding, and the
 *    HKDF salt proof (`verifyJoinHkdfSaltProof` — defeats a stolen token held
 *    without the master-derived transport key), then runs the operator
 *    approval gate (`JoinApprover`) and issues a NodeIdentityCertificate
 *    (`issueCertificateForApprovedJoin`). This mirrors
 *    `MeshNode.acceptJoinRequest` field-for-field on the same helpers.
 *
 * Fail closed (CLAUDE.md constraint 4): a JoinRequest that cannot be
 * cryptographically verified is DENIED, never trusted — verification is
 * signature/proof based, never shape based. Every ceremony step writes an
 * audit entry on BOTH success and denial (PR-A1 audit-write-completeness gap,
 * design note 5). The pre-session `authorize/complete` collapses every
 * failure to one uniform 401 so a probing caller learns nothing about whether
 * federation is enabled, whether a node id is known, or which check failed.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash } from "node:crypto";
import { fromBase64url } from "../core/encoding.js";
import {
  issueBootstrapToken,
  verifyBootstrapToken,
  verifyJoinHkdfSaltProof,
} from "../mesh/lifecycle/bootstrap-token.js";
import { issueCertificateForApprovedJoin } from "../mesh/lifecycle/join-approver.js";
import { deriveNodeTransportKey } from "../mesh/trust-root.js";
import type { NodeMode } from "../mesh/constants.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
  NodeIdentityCertificate,
} from "../mesh/types.js";
import type {
  BootstrapToken,
  JoinApprover,
  JoinRequest,
} from "../mesh/lifecycle/types.js";
import type { V1SessionClaims } from "./session-service.js";
import { canonicalJson, verifyOperatorSignature } from "./operator-signed.js";
import { writeJson, readJsonBody, denyUnauthorized, denyForbidden } from "./http.js";
import {
  verifySyncEnvelope,
  signSyncEnvelope,
  type FederationSyncEnvelope,
} from "./federation-sync-envelope.js";

const NODE_MODES: readonly NodeMode[] = [
  "local",
  "operator_cloud",
  "sovereign_tee",
];

/** A path owned by the federation handler (post-session class). */
export function isFederationPath(pathname: string): boolean {
  return (
    pathname === "/v1/federation/enable" ||
    pathname === "/v1/federation/disable" ||
    pathname === "/v1/federation/status" ||
    pathname === "/v1/federation/authorize/init" ||
    pathname === "/v1/federation/sync" ||
    pathname === "/v1/federation/sync/peer" ||
    pathname === "/v1/nodes"
  );
}

/** The pre-session (bootstrap-token-authenticated) join-submission path. */
export function isFederationCeremonyPath(pathname: string): boolean {
  return pathname === "/v1/federation/authorize/complete";
}

// ── Fortress materials + ceremony ─────────────────────────────────────────

/**
 * Fortress materials needed to mint bootstrap tokens and approve joins. Bound
 * into the dashboard out of band (the console/mesh boot path owns supplying
 * these); until bound, federation cannot operate and every authorize path
 * fails closed. Private-key/master-secret accessors return TRANSIENT copies
 * the caller is responsible for; this module never persists or logs them.
 */
export interface FederationContext {
  fortressId: string;
  /** This fortress node's id (echoed into status). */
  nodeId: string;
  pinnedMasterPubkey: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  /** Transient operator principal private key (signs tokens + certs). */
  getIssuingPrincipalPrivateKey(): Uint8Array;
  /** Transient fortress-master secret (derives the transport key for proofs). */
  getFortressMasterSecret(): Uint8Array;
  /** Transient fortress-master private key, when this node holds it (cert master sig). */
  getMasterPrivateKey?(): Uint8Array | undefined;
  /**
   * This daemon's OWN node identity certificate (issued when it joined the
   * fortress), used to wrap the reciprocal outbound slice in a peer-verifiable
   * sync envelope. Optional: when absent, a peer-sync still ACCEPTS inbound
   * (the inbound verification needs only the pinned master), but the response
   * carries bare events the peer cannot cryptographically attribute.
   */
  localNodeCert?: NodeIdentityCertificate;
  /** Transient private key matching `localNodeCert.node_pubkey` (signs the reciprocal envelope). */
  getLocalNodePrivateKey?(): Uint8Array | undefined;
  /**
   * Operator approval gate. Defaults to issuing a certificate for any
   * request that already passed cryptographic verification (the bootstrap
   * token IS the operator's prior authorization). Inject a denying approver
   * to model a policy refusal.
   */
  approver?: JoinApprover;
}

export type AuthorizeCompleteResult =
  | {
      approved: true;
      certificate: NodeIdentityCertificate;
      issuingPrincipalCert: PrincipalCertificate;
      nodeId: string;
    }
  | { approved: false; denialReason: string };

/**
 * The join-authorization ceremony, composed from the mesh lifecycle
 * primitives. Stateless except for the in-memory roster of joined node ids
 * (status only); all trust decisions are crypto-verified per call.
 */
export class JoinCeremony {
  constructor(private readonly ctx: FederationContext) {}

  /** Mint a bootstrap token for a node the operator is authorizing to join. */
  authorizeInit(params: {
    intendedNodeId: string;
    intendedNodeMode: NodeMode;
  }): BootstrapToken {
    return issueBootstrapToken({
      intended_node_id: params.intendedNodeId,
      intended_node_mode: params.intendedNodeMode,
      fortress_id: this.ctx.fortressId,
      issuing_principal: this.ctx.issuingPrincipalCert.principal_id,
      principal_private_key: this.ctx.getIssuingPrincipalPrivateKey(),
    });
  }

  /**
   * Verify a submitted JoinRequest and, on approval, issue its certificate.
   * Mirrors `MeshNode.acceptJoinRequest`: bootstrap-token signature →
   * node_mode binding → HKDF salt proof → operator gate. Any verification
   * failure returns `{ approved: false }` with an operator-facing reason; the
   * HTTP layer collapses every denial to one uniform 401.
   */
  async authorizeComplete(request: JoinRequest): Promise<AuthorizeCompleteResult> {
    // 1. Bootstrap token must verify against the issuing principal cert for
    //    THIS fortress (signature + fortress binding + TTL). Throws on any
    //    failure — caught and mapped to a uniform denial.
    try {
      verifyBootstrapToken({
        token: request.bootstrap_token,
        expected_fortress_id: this.ctx.fortressId,
        issuing_principal_cert: this.ctx.issuingPrincipalCert,
      });
    } catch (err) {
      return { approved: false, denialReason: `bootstrap token rejected: ${reason(err)}` };
    }

    // 2. The declared node_mode must match the mode the token was minted for.
    if (request.node_mode !== request.bootstrap_token.intended_node_mode) {
      return {
        approved: false,
        denialReason: "node_mode does not match bootstrap token",
      };
    }
    if (!NODE_MODES.includes(request.node_mode)) {
      return { approved: false, denialReason: "unknown node_mode" };
    }

    // 3. HKDF salt proof: the requester must hold the master-derived transport
    //    key, not merely a stolen bootstrap token.
    let proofOk: boolean;
    try {
      const transportKey = deriveNodeTransportKey({
        fortress_master_secret: this.ctx.getFortressMasterSecret(),
        node_id: request.bootstrap_token.intended_node_id,
        node_mode: request.node_mode,
      });
      proofOk = verifyJoinHkdfSaltProof({
        intended_node_id: request.bootstrap_token.intended_node_id,
        node_mode: request.node_mode,
        node_transport_key: transportKey,
        proof: request.hkdf_salt_proof,
      });
    } catch (err) {
      return { approved: false, denialReason: `hkdf proof error: ${reason(err)}` };
    }
    if (!proofOk) {
      return {
        approved: false,
        denialReason: "hkdf_salt_proof failed — token holder lacks master-derived transport key",
      };
    }

    // 4. node_pubkey must be a well-formed Ed25519 key.
    try {
      const key = fromBase64url(request.node_pubkey);
      if (key.length !== 32) {
        return { approved: false, denialReason: "node_pubkey is not a 32-byte key" };
      }
    } catch {
      return { approved: false, denialReason: "node_pubkey is malformed" };
    }

    // 5. Operator approval gate. Default approver issues a certificate for the
    //    (now crypto-verified) request; an injected approver may deny.
    const approver = this.ctx.approver ?? this.defaultApprover();
    let result;
    try {
      result = await approver.requestApproval(request);
    } catch (err) {
      return { approved: false, denialReason: `approval gate error: ${reason(err)}` };
    }
    if (!result.approved || !result.certificate) {
      return {
        approved: false,
        denialReason: result.denial_reason ?? "operator denied join",
      };
    }

    return {
      approved: true,
      certificate: result.certificate,
      issuingPrincipalCert: this.ctx.issuingPrincipalCert,
      nodeId: result.certificate.node_id,
    };
  }

  private defaultApprover(): JoinApprover {
    const ctx = this.ctx;
    return {
      async requestApproval(request: JoinRequest) {
        const certificate = issueCertificateForApprovedJoin({
          request,
          pinned_master_pubkey: ctx.pinnedMasterPubkey,
          issuing_principal_cert: ctx.issuingPrincipalCert,
          issuing_principal_private_key: ctx.getIssuingPrincipalPrivateKey(),
          master_private_key: ctx.getMasterPrivateKey?.(),
        });
        return { approved: true, certificate };
      },
    };
  }
}

function reason(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// ── Service state ──────────────────────────────────────────────────────────

/** Audit hook: writes one entry per ceremony step (success AND denial). */
export type FederationAudit = (entry: {
  operation: string;
  result: "success" | "failure";
  identityId: string;
  details: Record<string, unknown>;
}) => Promise<void>;

export interface V1FederationDeps {
  /** Live fortress materials, or null when federation is not provisioned. */
  getContext(): FederationContext | null;
  isEnabled(): boolean;
  setEnabled(enabled: boolean): void;
  /** Operator identity public key for OPERATOR_SIGNED gating (PR-A2 parity). */
  resolveOperatorPublicKey(): Uint8Array | null;
  audit: FederationAudit;
  /** Joined node ids, for the status roster summary. */
  rosterNodeIds(): string[];
  /** Record a newly joined node (status roster). */
  recordJoin(nodeId: string): void;
  /** List federated nodes for GET /v1/nodes. */
  listNodes(): FederationNodeView[];
  /** Local append-only events available for exchange. */
  listFederationEvents(since?: FederationSyncCursor): FederationEvent[];
  /** Validate and append remote sync events. */
  appendFederationEvents(events: FederationEvent[]): FederationAppendResult;
  /**
   * Highest peer-sync high-water already accepted from `senderNodeId`, or null
   * if none. Gates whole-envelope rollback on the cross-node `/sync/peer` path
   * (PR-A5). Per-sender; advances only on a successful accept.
   */
  acceptedHighWaterFor(senderNodeId: string): number | null;
  /** Record a newly-accepted peer-sync high-water for `senderNodeId`. */
  recordAcceptedHighWater(senderNodeId: string, highWater: number): void;
  /** Monotonic outbound high-water this daemon stamps on reciprocal envelopes. */
  nextOutboundHighWater(): number;
}

export interface FederationNodeView {
  node_id: string;
  label: string | null;
  attestation_status: "verified" | "pending" | "failed" | "unknown";
  first_seen: string;
  last_seen: string;
  last_sync: {
    received_at: string | null;
    sent_at: string | null;
    last_sequence: number;
  };
}

export interface FederationEvent {
  event_id: string;
  origin_node_id: string;
  sequence: number;
  occurred_at: string;
  kind: string;
  payload: Record<string, unknown>;
  previous_hash: string | null;
  event_hash: string;
}

export interface FederationSyncCursor {
  node_id?: string;
  after_sequence?: number;
}

export interface FederationAppendResult {
  accepted: FederationEvent[];
  rejected: Array<{ event_id: string; reason: string }>;
}

// ── Handlers ────────────────────────────────────────────────────────────────

/**
 * Post-session federation routes. The router has already validated the
 * SESSION_TOKEN; `claims` is the authenticated client.
 */
export async function handleFederationRequest(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
  claims: V1SessionClaims,
): Promise<boolean> {
  if (method === "GET" && url.pathname === "/v1/nodes") {
    handleNodes(deps, res);
    return true;
  }
  if (method === "GET" && url.pathname === "/v1/federation/status") {
    handleStatus(deps, res);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/enable") {
    await handleEnableDisable(deps, req, res, claims, true);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/disable") {
    await handleEnableDisable(deps, req, res, claims, false);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/authorize/init") {
    await handleAuthorizeInit(deps, req, res, claims);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/sync") {
    await handleSync(deps, req, res, claims);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/sync/peer") {
    await handlePeerSync(deps, req, res, claims);
    return true;
  }
  // Wrong method on an owned path: not found to an authenticated caller.
  writeJson(res, 404, { error: "not found" });
  return true;
}

function handleNodes(deps: V1FederationDeps, res: ServerResponse): void {
  writeJson(res, 200, {
    nodes: deps.listNodes(),
    total: deps.listNodes().length,
  });
}

function handleStatus(deps: V1FederationDeps, res: ServerResponse): void {
  const ctx = deps.getContext();
  const enabled = deps.isEnabled() && ctx !== null;
  // Field discipline: never echo key material; only public identifiers.
  writeJson(res, 200, {
    enabled,
    provisioned: ctx !== null,
    fortress_id: ctx?.fortressId ?? null,
    node_id: ctx?.nodeId ?? null,
    roster: { size: deps.rosterNodeIds().length },
  });
}

/**
 * Verify the inline OPERATOR_SIGNED signature over a federation admin payload.
 * Returns true only when an operator identity is configured AND the signature
 * verifies; otherwise false (the caller maps false to the generic 403, no
 * distinguishable reason — same contract as the agents write path).
 */
function verifyOperator(
  deps: V1FederationDeps,
  action: string,
  payload: Record<string, unknown>,
  signature: unknown,
): boolean {
  if (typeof signature !== "string" || signature.length === 0) return false;
  const operatorPublicKey = deps.resolveOperatorPublicKey();
  if (!operatorPublicKey) return false; // fail closed: no operator identity
  return verifyOperatorSignature({
    action,
    payload,
    signature,
    operatorPublicKey,
  });
}

async function handleEnableDisable(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
  enable: boolean,
): Promise<void> {
  const action = enable ? "/v1/federation/enable" : "/v1/federation/disable";
  const operation = enable ? "v1_federation_enable" : "v1_federation_disable";
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { idempotency_key, operator_signature } = body as {
    idempotency_key?: unknown;
    operator_signature?: unknown;
  };
  const signedPayload: Record<string, unknown> = {};
  if (typeof idempotency_key === "string") signedPayload.idempotency_key = idempotency_key;

  if (!verifyOperator(deps, action, signedPayload, operator_signature)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: "operator",
      details: { reason: "operator_signature_invalid" },
    });
    denyForbidden(res);
    return;
  }

  // Enabling requires provisioned fortress materials; disabling is always
  // honored (idempotent off). Honest authenticated error, not an auth oracle.
  if (enable && deps.getContext() === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: "operator",
      details: { reason: "federation_not_provisioned" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  deps.setEnabled(enable);
  await deps.audit({
    operation,
    result: "success",
    identityId: "operator",
    details: { enabled: enable },
  });
  writeJson(res, 200, { enabled: enable });
}

async function handleAuthorizeInit(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const action = "/v1/federation/authorize/init";
  const operation = "v1_federation_authorize_init";
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { intended_node_id, intended_node_mode, operator_signature } = body as {
    intended_node_id?: unknown;
    intended_node_mode?: unknown;
    operator_signature?: unknown;
  };

  if (typeof intended_node_id !== "string" || intended_node_id.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  if (
    typeof intended_node_mode !== "string" ||
    !NODE_MODES.includes(intended_node_mode as NodeMode)
  ) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }

  const signedPayload: Record<string, unknown> = {
    intended_node_id,
    intended_node_mode,
  };
  if (!verifyOperator(deps, action, signedPayload, operator_signature)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: intended_node_id,
      details: { reason: "operator_signature_invalid" },
    });
    denyForbidden(res);
    return;
  }

  const ctx = deps.getContext();
  if (!deps.isEnabled() || ctx === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: intended_node_id,
      details: { reason: "federation_disabled" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  let token: BootstrapToken;
  try {
    token = new JoinCeremony(ctx).authorizeInit({
      intendedNodeId: intended_node_id,
      intendedNodeMode: intended_node_mode as NodeMode,
    });
  } catch (err) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: intended_node_id,
      details: { reason: reason(err) },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  await deps.audit({
    operation,
    result: "success",
    identityId: intended_node_id,
    details: { intended_node_mode, nonce: token.nonce },
  });
  writeJson(res, 200, { bootstrap_token: token });
}

async function handleSync(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const action = "/v1/federation/sync";
  const operation = "v1_federation_sync";
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { node_id, events, cursor, idempotency_key, operator_signature } = body as {
    node_id?: unknown;
    events?: unknown;
    cursor?: unknown;
    idempotency_key?: unknown;
    operator_signature?: unknown;
  };
  if (typeof node_id !== "string" || node_id.length === 0 || !Array.isArray(events)) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const parsedEvents = parseFederationEvents(events);
  if (parsedEvents === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const parsedCursor = parseSyncCursor(cursor);
  if (cursor !== undefined && parsedCursor === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }

  const signedPayload: Record<string, unknown> = {
    node_id,
    events: parsedEvents,
  };
  if (parsedCursor) signedPayload.cursor = parsedCursor;
  if (typeof idempotency_key === "string") signedPayload.idempotency_key = idempotency_key;

  if (!verifyOperator(deps, action, signedPayload, operator_signature)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "operator_signature_invalid" },
    });
    denyForbidden(res);
    return;
  }

  if (!deps.isEnabled() || deps.getContext() === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "federation_disabled" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  const append = deps.appendFederationEvents(parsedEvents);
  const outbound = deps.listFederationEvents(parsedCursor ?? undefined);
  await deps.audit({
    operation,
    result: append.rejected.length === 0 ? "success" : "failure",
    identityId: node_id,
    details: {
      accepted: append.accepted.length,
      rejected: append.rejected.length,
    },
  });
  writeJson(res, 200, {
    accepted: append.accepted.map((event) => event.event_id),
    rejected: append.rejected,
    events: outbound,
    nodes: deps.listNodes(),
  });
}

/**
 * Cross-MACHINE peer sync (PR-A5 — the federation marquee). Unlike `/sync`,
 * which authorizes the request with THIS fortress's own operator signature
 * (correct only when the caller is the same operator process — the A4
 * "loopback position-only" path), `/sync/peer` accepts a sync from ANOTHER of
 * the operator's machines. The session token still gates network access, but
 * trust in the EVENTS comes from the {@link FederationSyncEnvelope}: the peer
 * presents its node identity certificate, which the recipient verifies chains
 * to its OWN pinned fortress-master (`verifySyncEnvelope` → `verifyCertChain`).
 *
 * This is the "no implicit trust across the boundary" rule (CLAUDE.md
 * constraint 4) realized for the cross-machine case: a node whose certificate
 * does NOT chain to this fortress's master — a different operator — is rejected
 * with the generic 403 even with a valid session. The hash-chained log defeats
 * per-event tampering/replay; the envelope high-water defeats whole-envelope
 * rollback. No private key crosses the wire (constraint 6).
 *
 * On accept, the recipient appends the verified slice, records the new
 * per-sender high-water, and answers with its OWN outbound slice wrapped in a
 * reciprocal peer-verifiable envelope (when this daemon holds its node cert +
 * key), so the exchange is symmetric and the originating node can verify the
 * response the same way.
 */
async function handlePeerSync(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const operation = "v1_federation_sync_peer";
  const ctx = deps.getContext();

  // Federation must be enabled and provisioned (we need the pinned master to
  // verify the peer's chain). Honest authenticated 503 — the session already
  // proved /v1 access, so this is not an auth oracle.
  if (!deps.isEnabled() || ctx === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: "peer",
      details: { reason: "federation_disabled" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }

  // Verify the peer's envelope against THIS fortress's pinned master. Every
  // structural/crypto defect collapses to the generic 403 (no per-reason
  // oracle for a probing peer); the audit entry records the precise reason.
  const verification = verifySyncEnvelope({
    envelope: body,
    pinnedMaster: ctx.pinnedMasterPubkey,
    recipientNodeId: ctx.nodeId,
    acceptedHighWaterFor: (senderNodeId) => deps.acceptedHighWaterFor(senderNodeId),
  });
  if (!verification.ok) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: peerSenderNodeId(body),
      details: { reason: verification.reason },
    });
    denyForbidden(res);
    return;
  }

  // The peer is a verified member of THIS fortress. Append its slice through
  // the same hash-chain validator the self-operator path uses. Advance the
  // per-sender high-water ONLY when the WHOLE slice appended cleanly AND it
  // actually carried new work (>=1 accepted event):
  //   - a partial append (sequence gap / previous_hash mismatch) must NOT burn
  //     the high-water, or a future correct lower-water resend from that sender
  //     would be wrongly rejected as a rollback;
  //   - an EMPTY / no-op envelope must NOT advance the high-water either, or a
  //     verified-but-careless (or hostile) peer could "burn" its own high-water
  //     to a huge value with a content-free envelope and self-DoS every future
  //     legitimate sync (codex PR-A5 r2 MEDIUM). High-water is a property of
  //     committed work, never of an empty signed envelope.
  const append = deps.appendFederationEvents(verification.events);
  if (append.rejected.length === 0 && append.accepted.length > 0) {
    deps.recordAcceptedHighWater(verification.senderNodeId, verification.syncHighWater);
  }

  // The reciprocal envelope is signed by THIS node and therefore may only carry
  // THIS node's OWN events (origin == this node id) — the same origin-binding
  // invariant the inbound path enforces. A node never forwards another node's
  // events inside its own signed envelope; multi-hop propagation happens through
  // pairwise syncs, not delegated forwarding (which would need its own proof).
  // The cursor still scopes which of this node's own events to return.
  const outbound = deps
    .listFederationEvents(verification.cursor ?? undefined)
    .filter((event) => event.origin_node_id === ctx.nodeId);
  const responseEnvelope = buildReciprocalEnvelope(deps, ctx, verification.senderNodeId, outbound);

  await deps.audit({
    operation,
    result: append.rejected.length === 0 ? "success" : "failure",
    identityId: verification.senderNodeId,
    details: {
      accepted: append.accepted.length,
      rejected: append.rejected.length,
      high_water: verification.syncHighWater,
    },
  });

  writeJson(res, 200, {
    accepted: append.accepted.map((event) => event.event_id),
    rejected: append.rejected,
    // The reciprocal slice, peer-verifiable when this daemon holds its node
    // identity; otherwise the bare events (the peer keeps its own log honest
    // via the per-event hash chain it already validates on append).
    ...(responseEnvelope ? { envelope: responseEnvelope } : { events: outbound }),
    nodes: deps.listNodes(),
  });
}

/**
 * Wrap this daemon's outbound slice in a reciprocal {@link FederationSyncEnvelope}
 * the peer can verify the same way the daemon just verified the inbound one.
 * Returns null when this daemon does not hold its own node identity (cert +
 * private key) — in that case the response degrades to bare events rather than
 * forging an attribution. The node private key is transient and never logged.
 */
function buildReciprocalEnvelope(
  deps: V1FederationDeps,
  ctx: FederationContext,
  recipientNodeId: string,
  outbound: FederationEvent[],
): FederationSyncEnvelope | null {
  const nodeCert = ctx.localNodeCert;
  const nodePrivateKey = ctx.getLocalNodePrivateKey?.();
  if (!nodeCert || !nodePrivateKey) return null;
  try {
    return signSyncEnvelope({
      fortressId: ctx.fortressId,
      senderNodeId: ctx.nodeId,
      recipientNodeId,
      syncHighWater: deps.nextOutboundHighWater(),
      events: outbound,
      senderNodeCert: nodeCert,
      issuingPrincipalCert: ctx.issuingPrincipalCert,
      nodePrivateKey,
    });
  } finally {
    nodePrivateKey.fill(0);
  }
}

/** Best-effort sender node id for an audit entry on a rejected peer envelope. */
function peerSenderNodeId(body: unknown): string {
  if (typeof body === "object" && body !== null) {
    const id = (body as Record<string, unknown>).sender_node_id;
    if (typeof id === "string" && id.length > 0) return id;
  }
  return "unknown";
}

/**
 * Pre-session join-submission ceremony (BOOTSTRAP_TOKEN auth class). Reached
 * by the router BEFORE the session gate, like session/init. Every failure —
 * federation off, missing materials, bad body, unverifiable request — returns
 * the SAME uniform 401 so a probing joining node gets no oracle.
 */
export async function handleFederationCeremony(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  if (method !== "POST" || url.pathname !== "/v1/federation/authorize/complete") {
    return false;
  }
  const operation = "v1_federation_authorize_complete";
  const ctx = deps.getContext();
  const body = await readJsonBody(req);
  const request = parseJoinRequest(body);

  // Federation off / unprovisioned / malformed body: uniform 401, no oracle.
  if (!deps.isEnabled() || ctx === null || request === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: joinRequestNodeId(body),
      details: {
        reason: !deps.isEnabled() || ctx === null ? "federation_unavailable" : "malformed_request",
      },
    });
    denyUnauthorized(res);
    return true;
  }

  const outcome = await new JoinCeremony(ctx).authorizeComplete(request);
  if (!outcome.approved) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: request.bootstrap_token.intended_node_id,
      details: { reason: outcome.denialReason },
    });
    // Fail closed: an unverifiable peer is denied with the uniform 401.
    denyUnauthorized(res);
    return true;
  }

  deps.recordJoin(outcome.nodeId);
  await deps.audit({
    operation,
    result: "success",
    identityId: outcome.nodeId,
    details: { node_id: outcome.nodeId },
  });
  writeJson(res, 200, {
    certificate: outcome.certificate,
    issuing_principal_cert: outcome.issuingPrincipalCert,
  });
  return true;
}

/** Structural parse of a JoinRequest body. Returns null on any shape error. */
function parseJoinRequest(body: unknown): JoinRequest | null {
  if (typeof body !== "object" || body === null) return null;
  const { bootstrap_token, node_pubkey, node_mode, attestation, hkdf_salt_proof } =
    body as Record<string, unknown>;
  if (typeof node_pubkey !== "string" || node_pubkey.length === 0) return null;
  if (typeof node_mode !== "string") return null;
  if (typeof hkdf_salt_proof !== "string" || hkdf_salt_proof.length === 0) return null;
  if (typeof bootstrap_token !== "object" || bootstrap_token === null) return null;
  const bt = bootstrap_token as Record<string, unknown>;
  if (typeof bt.intended_node_id !== "string") return null;
  if (typeof bt.issuing_principal !== "string") return null;
  if (typeof bt.signature !== "string") return null;
  return {
    bootstrap_token: bootstrap_token as unknown as BootstrapToken,
    node_pubkey,
    node_mode: node_mode as NodeMode,
    ...(typeof attestation === "string" ? { attestation } : {}),
    hkdf_salt_proof,
  };
}

/** Best-effort node id for an audit entry on a malformed request. */
function joinRequestNodeId(body: unknown): string {
  if (typeof body === "object" && body !== null) {
    const bt = (body as Record<string, unknown>).bootstrap_token;
    if (typeof bt === "object" && bt !== null) {
      const id = (bt as Record<string, unknown>).intended_node_id;
      if (typeof id === "string") return id;
    }
  }
  return "unknown";
}

export function federationEventHash(event: Omit<FederationEvent, "event_hash">): string {
  return createHash("sha256").update(canonicalJson(event)).digest("base64url");
}

export function validateFederationEventHash(event: FederationEvent): boolean {
  const { event_hash, ...withoutHash } = event;
  return federationEventHash(withoutHash) === event_hash;
}

function parseFederationEvents(events: unknown[]): FederationEvent[] | null {
  const out: FederationEvent[] = [];
  for (const event of events) {
    if (typeof event !== "object" || event === null) return null;
    const e = event as Record<string, unknown>;
    if (typeof e.event_id !== "string" || e.event_id.length === 0) return null;
    if (typeof e.origin_node_id !== "string" || e.origin_node_id.length === 0) return null;
    if (typeof e.sequence !== "number" || !Number.isSafeInteger(e.sequence) || e.sequence < 1) {
      return null;
    }
    if (typeof e.occurred_at !== "string" || e.occurred_at.length === 0) return null;
    if (typeof e.kind !== "string" || e.kind.length === 0) return null;
    if (typeof e.payload !== "object" || e.payload === null || Array.isArray(e.payload)) {
      return null;
    }
    if (e.previous_hash !== null && e.previous_hash !== undefined && typeof e.previous_hash !== "string") {
      return null;
    }
    if (typeof e.event_hash !== "string" || e.event_hash.length === 0) return null;
    out.push({
      event_id: e.event_id,
      origin_node_id: e.origin_node_id,
      sequence: e.sequence,
      occurred_at: e.occurred_at,
      kind: e.kind,
      payload: e.payload as Record<string, unknown>,
      previous_hash: e.previous_hash === undefined ? null : e.previous_hash,
      event_hash: e.event_hash,
    });
  }
  return out;
}

function parseSyncCursor(cursor: unknown): FederationSyncCursor | null {
  if (cursor === undefined || cursor === null) return {};
  if (typeof cursor !== "object" || Array.isArray(cursor)) return null;
  const c = cursor as Record<string, unknown>;
  const out: FederationSyncCursor = {};
  if (c.node_id !== undefined) {
    if (typeof c.node_id !== "string" || c.node_id.length === 0) return null;
    out.node_id = c.node_id;
  }
  if (c.after_sequence !== undefined) {
    if (
      typeof c.after_sequence !== "number" ||
      !Number.isSafeInteger(c.after_sequence) ||
      c.after_sequence < 0
    ) {
      return null;
    }
    out.after_sequence = c.after_sequence;
  }
  return out;
}
