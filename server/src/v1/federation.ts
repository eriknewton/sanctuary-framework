/**
 * /v1 federation endpoints + join-authorization ceremony (PR-A3).
 *
 *   POST /v1/federation/enable             SESSION + OPERATOR_SIGNED, Tier 1
 *   POST /v1/federation/disable            SESSION + OPERATOR_SIGNED, Tier 1
 *   GET  /v1/federation/status             SESSION
 *   POST /v1/federation/authorize/init     SESSION + OPERATOR_SIGNED, Tier 1
 *   POST /v1/federation/revoke             SESSION + OPERATOR_SIGNED, Tier 1
 *   POST /v1/federation/authorize/complete BOOTSTRAP_TOKEN (pre-session class)
 *
 * The join ceremony is operator-authorized in two crypto-verified steps and
 * is built by WRAPPING the existing mesh lifecycle primitives - it does not
 * reimplement them:
 *
 *  - `authorize/init` mints a short-lived, operator-principal-signed
 *    bootstrap token (`issueBootstrapToken`). The token alone is not
 *    membership; it is the joining node's right to submit a JoinRequest.
 *  - The joining node assembles a JoinRequest (`sanctuary federation join`)
 *    and submits it to `authorize/complete`, which verifies the bootstrap
 *    token signature (`verifyBootstrapToken`), the node_mode binding, and the
 *    HKDF salt proof (`verifyJoinHkdfSaltProof` - defeats a stolen token held
 *    without the master-derived transport key), then runs the operator
 *    approval gate (`JoinApprover`) and issues a NodeIdentityCertificate
 *    (`issueCertificateForApprovedJoin`). This mirrors
 *    `MeshNode.acceptJoinRequest` field-for-field on the same helpers.
 *
 * Fail closed (CLAUDE.md constraint 4): a JoinRequest that cannot be
 * cryptographically verified is DENIED, never trusted - verification is
 * signature/proof based, never shape based. Every ceremony step writes an
 * audit entry on BOTH success and denial (PR-A1 audit-write-completeness gap,
 * design note 5). The pre-session `authorize/complete` collapses every
 * failure to one uniform 401 so a probing caller learns nothing about whether
 * federation is enabled, whether a node id is known, or which check failed.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { fromBase64url, toBase64url } from "../core/encoding.js";
import { verify } from "../core/identity.js";
import {
  issueBootstrapToken,
  verifyBootstrapToken,
  verifyJoinHkdfSaltProof,
} from "../mesh/lifecycle/bootstrap-token.js";
import {
  deriveNodeTransportKey,
  issueNodeIdentityCertificate,
  verifyCertChain,
  verifyFederationRootRotationCertificate,
} from "../mesh/trust-root.js";
import type { NodeMode } from "../mesh/constants.js";
import {
  NODE_TRUST_BOUNDARY_VERSION,
  type NodeDrillStatus,
  type NodeModeForPosture,
  type NodeTrustBoundary,
} from "../mesh/node-posture.js";
import type {
  FederationRootRotationCertificate,
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
import {
  writeJson,
  readJsonBody,
  denyUnauthorized,
  denyForbidden,
  denyForbiddenWithRequestId,
} from "./http.js";
import {
  verifySyncEnvelope,
  signSyncEnvelope,
  type FederationSyncEnvelope,
} from "./federation-sync-envelope.js";
import {
  FEDERATION_NODE_EVICTION_EVENT_KIND,
  FEDERATION_SYNC_WIRE_VERSION,
  normalizeFederationNodeCertificateRenewalConfig,
  federationOperatorAuthorityOrigin,
  signFederationNodeEvictionPayload,
  type FederationNodeCertificateRenewalConfig,
} from "./federation-revocation.js";
import {
  evaluateGuardianRevocationSignOff,
  type GuardianRevocationRequirement,
} from "./federation-revocation-guardian-gate.js";
import {
  ED25519_PUBLIC_KEY_BYTES,
  ED25519_SIGNATURE_BYTES,
} from "../core/crypto-suite-registry.js";

const NODE_MODES: readonly NodeMode[] = [
  "local",
  "operator_cloud",
  "sovereign_tee",
];

/**
 * Peer sync can carry node+principal certificate chains. Slice 2 hybrid certs
 * are larger than the default 16 KiB v1 write cap, but still bounded before
 * JSON parsing to keep malformed peer traffic cheap to reject.
 */
export const V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES = 96 * 1024;
export const V1_FEDERATION_REISSUE_NODE_CERT_MAX_BODY_BYTES = 96 * 1024;

export const FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION =
  "sanctuary.v1.federation-reissue-node-cert";
export const FEDERATION_REISSUE_NODE_CERT_PROOF_DOMAIN =
  "sanctuary.v1.federation-reissue-node-cert-proof";

/** A path owned by the federation handler (post-session class). */
export function isFederationPath(pathname: string): boolean {
  return (
    pathname === "/v1/federation/enable" ||
    pathname === "/v1/federation/disable" ||
    pathname === "/v1/federation/status" ||
    pathname === "/v1/federation/authorize/init" ||
    pathname === "/v1/federation/revoke" ||
    pathname === "/v1/federation/sync" ||
    pathname === "/v1/nodes"
  );
}

/** The pre-session (bootstrap-token-authenticated) join-submission path. */
export function isFederationCeremonyPath(pathname: string): boolean {
  return pathname === "/v1/federation/authorize/complete";
}

/**
 * Federation P1 pre-session "node-cert-authenticated" auth class. A path in this
 * class is reached BEFORE the /v1 session gate (router.ts dispatch, alongside the
 * BOOTSTRAP_TOKEN ceremony class): the caller carries NO `Authorization` header
 * and NO shared operator login. The ONLY trust decision is the cryptographic
 * sync-envelope verification inside the handler (the node certificate must chain
 * to THIS fortress's pinned master). The pre-session session-token gate that used
 * to front `/sync/peer` only gated NETWORK ACCESS, never data trust, so removing
 * it changes nothing about the trust boundary (CLAUDE.md constraint 4 is still
 * enforced cryptographically); it only lets a remote operator's machine reach
 * the route over a plain network connection without minting a session against a
 * daemon it is not the operator of.
 *
 * This class contains only routes whose handler performs its own cryptographic
 * proof before trusting the caller: peer-sync envelopes and node-cert reissue
 * proof-of-possession challenges.
 */
export function isFederationNodeCertAuthPath(pathname: string): boolean {
  return (
    pathname === "/v1/federation/sync/peer" ||
    pathname === "/v1/federation/rotate/reissue-node-cert"
  );
}

// ── Fortress materials + ceremony ─────────────────────────────────────────

/**
 * Fortress materials needed to mint bootstrap tokens and approve joins. Bound
 * into the dashboard out of band (the console/mesh boot path owns supplying
 * these); until bound, federation cannot operate and every authorize path
 * fails closed. Private-key/master-secret accessors return TRANSIENT copies
 * the caller is responsible for; this module never persists or logs them.
 */
export interface FederationBaseContext {
  fortressId: string;
  /** This fortress node's id (echoed into status). */
  nodeId: string;
  /** Mode of this daemon's own node context. Defaults to local when omitted. */
  nodeMode?: NodeMode;
  pinnedMasterPubkey: FortressMasterPublicKey;
  issuingPrincipalCert: PrincipalCertificate;
  /**
   * This daemon's OWN node identity certificate (issued when it joined the
   * fortress), used to wrap the reciprocal outbound slice in a peer-verifiable
   * sync envelope. Optional: when absent, a peer-sync still ACCEPTS inbound
   * (the inbound verification needs only the pinned master), but the response
   * carries no reciprocal events because bare unattributable events fail closed.
   */
  localNodeCert?: NodeIdentityCertificate;
  /** Transient private key matching `localNodeCert.node_pubkey` (signs the reciprocal envelope). */
  getLocalNodePrivateKey?(): Uint8Array | undefined;
  /**
   * Revocation projection hook. Mandatory: join/sync deny a node id that is
   * already in the grow-only revoked set; if absent or throwing, callers fail
   * closed rather than issuing/accepting a certificate on stale state.
   */
  isNodeRevoked(nodeId: string): boolean;
  /** Operator-tunable renewal policy for new/renewed node certs. */
  nodeCertificateRenewal?: FederationNodeCertificateRenewalConfig;
  /**
   * Additive joiner adoption state (3c-2): roots this node has already accepted
   * as revoked plus the monotonic revocation serial floor. Issuer contexts get
   * the same information from the durable sync-state projection; joiner contexts
   * can carry it from their custody record so boot preserves compromise-adoption
   * state without issuer authority.
   *
   * Where these are READ (M3, re-gate 2026-07-30): not by the route handlers in
   * this file directly - the dashboard's `setFederationContext` folds them into
   * its grow-only revoked-root projection at bind time, and the routes consume
   * that projection through the injected `isRootRevoked` dependency (the
   * sync-envelope `root_revoked` refusals and the reissue endpoint's
   * revoked-root denial). A context that omits them simply contributes nothing
   * to the projection; it never clears previously folded state.
   */
  revokedRootPubkeys?: Set<string>;
  highestRevocationSerial?: number;
}

export interface FederationIssuerContext extends FederationBaseContext {
  nodeMode?: Exclude<NodeMode, "operator_cloud">;
  /** Transient operator principal private key (signs tokens + certs). */
  getIssuingPrincipalPrivateKey(): Uint8Array;
  /** Transient fortress-master secret (derives the transport key for proofs). */
  getFortressMasterSecret(): Uint8Array;
  /** Transient fortress-master private key, when this node holds it (cert master sig). */
  getMasterPrivateKey?(): Uint8Array | undefined;
  /**
   * Operator approval gate. Required for issuance. Tests may inject the
   * test-only auto-approve helper; production must inject a real gate.
   */
  approver: JoinApprover;
  /**
   * The rotation certificate this fortress ITSELF adopted at its last
   * `rotate-root --renew` (sourced from the durable trust-root record, NOT from
   * any request). It attests the predecessor master -> the current pinned master
   * under the stable fortress_id. Absent on a freshly-provisioned root that has
   * never rotated.
   *
   * SECURITY (3c-2 node-cert reissue): the pre-session reissue endpoint pins the
   * predecessor master from THIS field, never from the attacker-controlled
   * request body. A reissue-with-rotation must present a `rotation_cert` that is
   * byte-identical (canonical-JSON equal) to this recorded one, so an attacker
   * cannot substitute a self-minted master as the "old" root and have the server
   * mint a real current-root-chained cert for an arbitrary node. If this field is
   * absent (the fortress never rotated) the reissue-with-rotation path fails
   * closed.
   */
  recordedRotationCert?: FederationRootRotationCertificate;
  /**
   * The rotation serial this fortress has adopted (the serial of
   * {@link recordedRotationCert}), from the durable trust-root record. Used as
   * the `minSerial` floor so even a genuine-lineage rotation cert with a
   * rolled-back / replayed serial is rejected. Absent on a never-rotated root.
   */
  recordedRotationSerial?: number;
  /**
   * True when this fortress was provisioned with the Ed25519+ML-DSA-65 hybrid
   * (PQC) suite. Sourced from the durable trust-root record. The 3c-2 reissue
   * endpoint refuses entirely on a hybrid fortress (hybrid reissue is out of
   * scope for this slice) so a classical-only rotation cert can never silently
   * downgrade the post-quantum root.
   */
  isHybrid?: boolean;
}

/**
 * A NON-ISSUER federation context. Covers a local-mode JOINER (Slice 3a) and an
 * operator_cloud node (OC Slice 2) alike: a node that holds its OWN node
 * identity and can present its cert on `/sync/peer`, but holds NONE of the
 * issuing material and structurally cannot mint bootstrap tokens or issue certs.
 *
 * The `?: never` fields are the structural invariant: a non-issuer context that
 * carries an issuer accessor is a type error, and {@link
 * assertNonIssuerContextHasNoIssuerAuthority} rejects it at runtime for ANY
 * non-issuer node mode.
 *
 * `nodeMode` is the full `NodeMode` set here: a `local` node can be EITHER an
 * issuer or a non-issuer joiner, so the issuer/non-issuer distinction is carried
 * by the presence of the issuer accessors, NOT by the node mode.
 */
export interface FederationNonIssuerContext extends FederationBaseContext {
  nodeMode: NodeMode;
  getIssuingPrincipalPrivateKey?: never;
  getFortressMasterSecret?: never;
  getMasterPrivateKey?: never;
  approver?: never;
}

/**
 * Back-compat alias for OC Slice 2 callers/tests: an operator_cloud node is a
 * non-issuer context pinned to `nodeMode: "operator_cloud"`.
 */
export type FederationNonIssuerOperatorCloudContext =
  FederationNonIssuerContext & { nodeMode: "operator_cloud" };

export type FederationContext =
  | FederationIssuerContext
  | FederationNonIssuerContext;

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
    const issuer = this.issuerContext();
    return issueBootstrapToken({
      intended_node_id: params.intendedNodeId,
      intended_node_mode: params.intendedNodeMode,
      fortress_id: issuer.fortressId,
      issuing_principal: issuer.issuingPrincipalCert.principal_id,
      principal_private_key: issuer.getIssuingPrincipalPrivateKey(),
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
    //    failure - caught and mapped to a uniform denial.
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
    if (request.node_mode !== "sovereign_tee" && request.attestation !== undefined) {
      return {
        approved: false,
        denialReason: "self-reported TEE attestation is not accepted for this node_mode",
      };
    }

    // 3. A revoked node id cannot rejoin through the bootstrap-token path.
    //    Re-admission requires a fresh node identity. If the revocation state
    //    cannot be evaluated, deny rather than issue a cert on stale state.
    try {
      if (typeof this.ctx.isNodeRevoked !== "function") {
        return { approved: false, denialReason: "revocation state unavailable" };
      }
      if (this.ctx.isNodeRevoked(request.bootstrap_token.intended_node_id)) {
        return { approved: false, denialReason: "node revoked" };
      }
    } catch {
      return {
        approved: false,
        denialReason: "revocation state unavailable",
      };
    }

    // 4. HKDF salt proof: the requester must hold the master-derived transport
    //    key, not merely a stolen bootstrap token.
    //
    //    Operator Cloud Slice 2: an `operator_cloud` join uses a DIFFERENT,
    //    substitution-bound proof (`computeOperatorCloudJoinProof`: HMAC over
    //    {nonce, node_pubkey, bundle_digest} under the node-scoped proof key),
    //    which the production operator-cloud approver verifies against the
    //    approved provision claim. The local-mode HKDF salt proof here HMACs
    //    only {node_id, node_mode} and is replayable across keypairs, so it must
    //    NOT be the gate for operator-cloud joins. We defer the operator-cloud
    //    proof to the approver and keep the local-mode proof mandatory for the
    //    local / sovereign_tee modes.
    if (request.node_mode !== "operator_cloud") {
      let proofOk: boolean;
      try {
        const issuer = this.issuerContext();
        const transportKey = deriveNodeTransportKey({
          fortress_master_secret: issuer.getFortressMasterSecret(),
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
          denialReason: "hkdf_salt_proof failed, token holder lacks master-derived transport key",
        };
      }
    }

    // 5. node_pubkey must be a well-formed Ed25519 key.
    try {
      const key = fromBase64url(request.node_pubkey);
      if (key.length !== ED25519_PUBLIC_KEY_BYTES) {
        return { approved: false, denialReason: "node_pubkey is not a 32-byte key" };
      }
    } catch {
      return { approved: false, denialReason: "node_pubkey is malformed" };
    }

    // 6. Operator approval gate. There is no default auto-issuing path here:
    //    production must inject a real gate and tests inject explicit helpers.
    const issuer = this.issuerContextOrNull();
    if (issuer === null || !issuer.approver) {
      return {
        approved: false,
        denialReason: "operator approval gate unavailable",
      };
    }
    const approver = issuer.approver;
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

  private issuerContext(): FederationIssuerContext {
    const issuer = this.issuerContextOrNull();
    if (issuer === null) {
      throw new Error("issuer authority unavailable for this federation context");
    }
    return issuer;
  }

  private issuerContextOrNull(): FederationIssuerContext | null {
    // operator_cloud is structurally a non-issuer: it can never carry issuer
    // authority, so it is short-circuited here regardless of accessor shape.
    if (this.ctx.nodeMode === "operator_cloud") return null;
    // For local / sovereign_tee, issuer authority is carried by the accessors
    // (a local node can be EITHER an issuer or a non-issuer joiner). A context
    // missing either required accessor is a non-issuer (e.g. a local joiner).
    if (
      typeof this.ctx.getIssuingPrincipalPrivateKey !== "function" ||
      typeof this.ctx.getFortressMasterSecret !== "function"
    ) {
      return null;
    }
    return this.ctx as FederationIssuerContext;
  }
}

/** The issuer-authority accessor/approver fields a non-issuer must never carry. */
const ISSUER_AUTHORITY_FIELDS: readonly string[] = [
  "getIssuingPrincipalPrivateKey",
  "getFortressMasterSecret",
  "getMasterPrivateKey",
  "approver",
];

/**
 * Reject any context that should be a NON-ISSUER but carries issuer authority.
 *
 * A context is treated as a non-issuer when it is operator_cloud (structurally
 * never an issuer) OR when it does not present the COMPLETE issuer accessor pair
 * (`getIssuingPrincipalPrivateKey` + `getFortressMasterSecret`), i.e. a local
 * joiner or a partially-populated context. In either case, the presence of ANY
 * issuer-authority field (a function accessor or an approver) is an escalation
 * and throws. A complete, consistent issuer context passes untouched.
 *
 * This generalizes the original operator_cloud-only guard to cover the local
 * joiner introduced in Federation Slice 3a without weakening the OC invariant.
 */
export function assertNonIssuerContextHasNoIssuerAuthority(
  ctx: FederationContext,
): void {
  const candidate = ctx as FederationContext & Record<string, unknown>;
  const hasCompleteIssuerAccessors =
    typeof candidate.getIssuingPrincipalPrivateKey === "function" &&
    typeof candidate.getFortressMasterSecret === "function";
  // A non-operator_cloud context that DOES present the complete issuer accessor
  // pair is a legitimate issuer context; leave it untouched.
  if (ctx.nodeMode !== "operator_cloud" && hasCompleteIssuerAccessors) return;
  // Otherwise it must be a clean non-issuer: no issuer-authority field at all.
  for (const field of ISSUER_AUTHORITY_FIELDS) {
    if (field in candidate && candidate[field] !== undefined) {
      throw new Error(
        ctx.nodeMode === "operator_cloud"
          ? "operator_cloud federation context must not carry issuer authority"
          : "non-issuer federation context must not carry issuer authority",
      );
    }
  }
}

/**
 * Back-compat alias for OC Slice 2 callers/tests. The original name asserted the
 * operator_cloud non-issuer invariant; it now delegates to the generalized
 * guard (which preserves the operator_cloud-specific error message).
 */
export const assertOperatorCloudContextHasNoIssuerAuthority =
  assertNonIssuerContextHasNoIssuerAuthority;

export function federationContextHasIssuerAuthority(
  ctx: FederationContext | null,
): ctx is FederationIssuerContext {
  return (
    ctx !== null &&
    ctx.nodeMode !== "operator_cloud" &&
    typeof ctx.getIssuingPrincipalPrivateKey === "function" &&
    typeof ctx.getFortressMasterSecret === "function" &&
    typeof ctx.approver?.requestApproval === "function"
  );
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
  setEnabled(enabled: boolean): void | Promise<void>;
  /** Operator identity public key for OPERATOR_SIGNED gating (PR-A2 parity). */
  resolveOperatorPublicKey(): Uint8Array | null;
  audit: FederationAudit;
  /** Joined node ids, for the status roster summary. */
  rosterNodeIds(): string[];
  /**
   * Record a newly joined node (status roster + DURABLE fleet membership).
   * ASYNC + fail-closed (PR-A durable membership): the in-memory roster upsert is
   * applied, then the DURABLE sync-state snapshot is persisted so the node
   * survives a reboot and is counted for the paid node-count. THROWS if that
   * persist fails so the caller fails closed (a join that did not durably commit
   * its membership must not be acknowledged as fully joined). The join endpoint
   * does NOT catch this throw: it propagates to the dashboard's top-level handler
   * and surfaces as a generic HTTP 500, NOT a 401; either way no success/cert is
   * returned. On that persist failure the implementation ROLLS BACK its in-memory
   * mutations before re-throwing, so a failed join leaves NO phantom node in the
   * roster / `summary.admitted` (consistent with the never-inflated durable
   * basis). When no durable store is wired (in-memory rigs) the persist is a
   * no-op and cannot throw.
   */
  recordJoin(certificate: NodeIdentityCertificate): Promise<void>;
  /** List federated nodes for GET /v1/nodes. */
  listNodes(): FederationNodeView[];
  /** Local append-only events available for exchange. */
  listFederationEvents(since?: FederationSyncCursor): FederationEvent[];
  /**
   * Validate and append remote sync events. ASYNC because a folded
   * operator-authority `node_eviction` advances the DURABLE revocation
   * projection (Federation 3/3b P0): the append commits the in-memory fold,
   * then persists the security-state snapshot. THROWS if that persist fails so
   * the caller fails closed (a revocation that did not durably commit must not
   * be acknowledged as accepted). When no eviction was folded the persist is a
   * no-op and the call cannot throw on durability grounds.
   */
  appendFederationEvents(
    events: FederationEvent[],
    options?: FederationAppendOptions,
  ): Promise<FederationAppendResult>;
  /**
   * Highest peer-sync high-water already accepted from `senderNodeId`, or null
   * if none. Gates whole-envelope rollback on the cross-node `/sync/peer` path
   * (PR-A5). Per-sender; advances only on a successful accept.
   */
  acceptedHighWaterFor(senderNodeId: string): number | null;
  /**
   * Record a newly-accepted peer-sync high-water for `senderNodeId`. ASYNC +
   * fail-closed (Federation 3/3b P0): the in-memory advance is committed, then
   * the DURABLE sync-state snapshot is persisted. Resolves `true` only when the
   * advance is durably committed; resolves `false` (the in-memory advance rolled
   * back) when the persist failed, so the caller MUST deny rather than
   * acknowledge an accept whose anti-replay high-water did not reach disk.
   */
  recordAcceptedHighWater(
    senderNodeId: string,
    highWater: number,
    certificate?: NodeIdentityCertificate,
  ): Promise<boolean>;
  /**
   * Monotonic outbound high-water this daemon stamps on reciprocal envelopes.
   * ASYNC + fail-closed (Federation 3/3b P0): the advanced counter is persisted
   * before it is handed out so a restart cannot re-emit an already-used outbound
   * high-water. Resolves the new value on success; THROWS if the persist failed
   * so the caller does not sign a reciprocal envelope on an un-committed counter.
   */
  nextOutboundHighWater(): Promise<number>;
  /** Grow-only revocation projection. Throws/false distinction is security-significant. */
  isNodeRevoked(nodeId: string): boolean;
  /**
   * RR-1 pre-wire (Federation 3/3b P0): reject any certificate chaining to a
   * REVOKED fortress-master (root) pubkey. Feature-inert in P0 (the revoked-root
   * set is always empty until rotate-root Slice 3c POPULATES it on compromise
   * recovery) but wired at all three chokepoints now so 3c need only fill the
   * set, never re-thread the call sites. Fail-closed contract identical to {@link
   * isNodeRevoked}: a throw or absence is treated as "cannot evaluate -> deny".
   * `masterPubkeyB64u` is the base64url fortress-master public key the presented
   * chain terminates at.
   */
  isRootRevoked(masterPubkeyB64u: string): boolean;
  /** Best-effort local cert auto-renewal tick before this daemon presents its cert. */
  renewLocalNodeCertificate(): void;
  /** Issue a server challenge for pre-session node-cert reissue POP. */
  issueReissueChallenge(
    params: FederationReissueChallengeParams,
  ): FederationReissueChallenge | Promise<FederationReissueChallenge>;
  /** Consume exactly one reissue challenge before issuance; false is fail-closed. */
  consumeReissueChallenge(
    params: FederationConsumeReissueChallengeParams,
  ): Promise<boolean>;
  /** Structured aggregate disclosure for status surfaces. */
  federationPosture(): FederationPostureSummary;
  /**
   * OPTIONAL, operator-configurable M-of-N guardian sign-off requirement for the
   * revoke/kill path. DEFAULT-OFF: when this dep is absent or returns `null`,
   * the revoke handler runs the legacy single-operator path unchanged (provably
   * a no-op). When it returns a {@link GuardianRevocationRequirement}, the
   * handler requires M-of-N valid guardian signatures BEFORE minting the
   * eviction and FAILS CLOSED (refuses, never executes) on insufficient,
   * invalid, forged, or duplicate guardian approvals. Composes the existing
   * guardian threshold evaluator onto the existing operator-signed revocation
   * primitive; it can only ADD a required precondition, never weaken one.
   *
   * Return contract (fail-closed):
   *   - `null`                          -> no requirement configured; legacy
   *                                        single-operator revoke (byte-for-byte).
   *   - a {@link GuardianRevocationRequirement} -> enforce M-of-N.
   *   - `{ unavailable: true }`         -> a requirement WAS configured but is
   *                                        currently unverifiable (a persisted
   *                                        roster failed to re-verify against the
   *                                        pinned master). The handler MUST REFUSE
   *                                        every revocation, never fall through to
   *                                        single-operator kill.
   */
  requireGuardianRevocationSignOff?(): GuardianRevocationSignOffState;
}

/**
 * State returned by the guardian-revocation sign-off hook. Distinguishes "no
 * requirement" (allowed single-operator path) from "requirement configured but
 * unverifiable" (fail-closed refusal) so a broken/tampered persisted requirement
 * can never silently revert the fleet to single-operator kill.
 */
export type GuardianRevocationSignOffState =
  | GuardianRevocationRequirement
  | { unavailable: true }
  | null;

export interface FederationNodeView {
  node_id: string;
  label: string | null;
  attestation_status: "verified" | "pending" | "failed" | "unknown";
  node_mode: NodeModeForPosture;
  host_provider: string | null;
  trust_boundary: NodeTrustBoundary;
  tee_attested: boolean;
  disclosure_acknowledged_at: string | null;
  drill_status: NodeDrillStatus;
  first_seen: string;
  last_seen: string;
  last_sync: {
    received_at: string | null;
    sent_at: string | null;
    last_sequence: number;
  };
  applied_policy: {
    version: number | null;
    hash: string | null;
    hash_algorithm: string | null;
    applied_at: string | null;
    source_event_id: string | null;
  };
}

export interface FederationPostureSummary {
  version: typeof NODE_TRUST_BOUNDARY_VERSION;
  local_nodes: number;
  operator_cloud_nodes: number;
  sovereign_tee_nodes: number;
  unknown_nodes: number;
  provider_in_trust_boundary: boolean;
  tee_attested: boolean;
  disclosure: string | null;
  /**
   * F1 E1: the guardian-requirement DISABLE-gate's break-glass countdown, when
   * armed. `active: false` when IDLE (no countdown in flight). Additive field
   * so an older reader ignores it. Surfaced so any operator or guardian who
   * opens the dashboard cannot miss an in-flight teardown of the fleet-kill
   * guard (design 6.3).
   */
  guardian_break_glass:
    | {
        active: true;
        intent: "disable" | "lower";
        target_m: number | null;
        initiated_at: string;
        completes_at: string;
        time_remaining_ms: number;
      }
    | { active: false };
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

export interface FederationAppendOptions {
  senderNodeId?: string;
  wireVersion?: unknown;
}

export interface FederationReissueChallenge {
  challenge_id: string;
  challenge: string;
  expires_at: string;
}

export interface FederationReissueChallengeParams {
  fortressId: string;
  nodeId: string;
}

export interface FederationConsumeReissueChallengeParams
  extends FederationReissueChallengeParams {
  challengeId: string;
  challenge: string;
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
  if (method === "POST" && url.pathname === "/v1/federation/revoke") {
    await handleRevoke(deps, req, res, claims);
    return true;
  }
  if (method === "POST" && url.pathname === "/v1/federation/sync") {
    await handleSync(deps, req, res, claims);
    return true;
  }
  // NOTE: /v1/federation/sync/peer is NO LONGER reachable here (Federation P1).
  // It moved to the pre-session node-cert-authenticated class
  // (isFederationNodeCertAuthPath, dispatched in router.ts before the session
  // gate). If an authenticated caller reaches THIS dispatcher with that path, it
  // falls through to the 404 below: the cert-auth dispatch already handled the
  // pre-session case, and a session-bearing caller gets no special treatment.
  // Wrong method on an owned path: not found to an authenticated caller.
  writeJson(res, 404, { error: "not found" });
  return true;
}

/**
 * Federation P1 pre-session node-cert-authenticated entry. Reached by the router
 * BEFORE the /v1 session gate (like the BOOTSTRAP_TOKEN ceremony), so the caller
 * holds NO session token. Only POSTs in this class are handled here; a non-POST
 * or any other path falls through (returns false) so the router routes it to the
 * session gate exactly like a non-POST ceremony request; it must NEVER fall
 * through to legacy `/api` routing, and an unhandled in-class path fails closed
 * at the router (it never reaches a handler that could fall open).
 *
 * The session that previously fronted this route was only a network-access gate;
 * the sole trust decision is `handlePeerSync`'s cryptographic envelope
 * verification, unchanged.
 */
export async function handleFederationNodeCertAuth(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  method: string,
): Promise<boolean> {
  if (method === "POST" && url.pathname === "/v1/federation/sync/peer") {
    await handlePeerSync(deps, req, res);
    return true;
  }
  if (
    method === "POST" &&
    url.pathname === "/v1/federation/rotate/reissue-node-cert"
  ) {
    await handleReissueNodeCert(deps, req, res);
    return true;
  }
  // In-class-but-unhandled route fails closed: a future node-cert-auth path
  // (e.g. rotate/reissue-node-cert in Slice 3b) that is added to the class set
  // but not yet given a branch here must NOT fall open. Return false; the router
  // sends it to the session gate (generic 401 unauth / 404 to an authed caller),
  // never to legacy routing.
  return false;
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
  const posture = deps.federationPosture();
  // Field discipline: never echo key material; only public identifiers.
  writeJson(res, 200, {
    enabled,
    provisioned: ctx !== null,
    fortress_id: ctx?.fortressId ?? null,
    node_id: ctx?.nodeId ?? null,
    roster: { size: deps.rosterNodeIds().length },
    operator_cloud_nodes: posture.operator_cloud_nodes,
    provider_in_trust_boundary: posture.provider_in_trust_boundary,
    tee_attested: posture.tee_attested,
    trust_boundary: posture,
  });
}

/**
 * Verify the inline OPERATOR_SIGNED signature over a federation admin payload.
 * Returns true only when an operator identity is configured AND the signature
 * verifies; otherwise false (the caller maps false to the generic 403, no
 * distinguishable reason - same contract as the agents write path).
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

  try {
    await deps.setEnabled(enable);
  } catch {
    await deps.audit({
      operation,
      result: "failure",
      identityId: "operator",
      details: { reason: "durable_state_persist_failed", enabled: enable },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }
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

async function handleRevoke(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
  _claims: V1SessionClaims,
): Promise<void> {
  const action = "/v1/federation/revoke";
  const operation = "v1_federation_revoke";
  const body = await readJsonBody(req);
  if (typeof body !== "object" || body === null) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const { node_id, reason: rawReason, idempotency_key, operator_signature } = body as {
    node_id?: unknown;
    reason?: unknown;
    idempotency_key?: unknown;
    operator_signature?: unknown;
  };
  if (typeof node_id !== "string" || node_id.length === 0) {
    writeJson(res, 400, { error: "bad request" });
    return;
  }
  const revocationReason =
    typeof rawReason === "string" && rawReason.length > 0
      ? rawReason
      : "operator_revoked";
  const signedPayload: Record<string, unknown> = {
    node_id,
    reason: revocationReason,
  };
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

  const ctx = deps.getContext();
  if (ctx === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "federation_not_provisioned" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }
  if (!federationContextHasIssuerAuthority(ctx)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "issuer_authority_unavailable" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  // OPTIONAL guardian sign-off gate (default-off, fail-closed). When the host
  // has not configured a requirement, `requirement` is null and this block is a
  // no-op: control falls straight through to the legacy single-operator mint
  // below, byte-for-byte unchanged. When a requirement IS configured, an
  // M-of-N guardian quorum bound to THIS (fortress, node) revocation must
  // verify before the eviction is minted; any insufficient/invalid/forged/
  // duplicate approval set REFUSES the revocation (it is never executed).
  const guardianSignOff = deps.requireGuardianRevocationSignOff?.() ?? null;
  if (guardianSignOff !== null) {
    // FAIL-CLOSED: a configured-but-unverifiable requirement (a persisted roster
    // that failed to re-verify against the pinned master) must REFUSE, never fall
    // through to single-operator kill.
    if ("unavailable" in guardianSignOff) {
      await deps.audit({
        operation,
        result: "failure",
        identityId: node_id,
        details: { reason: "guardian_signoff_unavailable" },
      });
      denyForbidden(res);
      return;
    }
    const { guardian_approvals } = body as { guardian_approvals?: unknown };
    const decision = evaluateGuardianRevocationSignOff({
      requirement: guardianSignOff,
      fortressId: ctx.fortressId,
      nodeId: node_id,
      approvals: guardian_approvals,
    });
    // Emit a dedicated audit event on EVERY guardian-gated decision (allowed OR
    // refused), so the durable audit trail records the M-of-N sign-off outcome
    // (who approved a fleet-kill and when) distinctly from the revoke outcome.
    await deps.audit({
      operation: "v1_federation_revoke_guardian_signoff",
      result: decision.allowed ? "success" : "failure",
      identityId: node_id,
      details: decision.allowed
        ? {
            guardian_signoff: "allowed",
            valid_guardian_ids: decision.validGuardianIds,
          }
        : { guardian_signoff: "refused", reason: decision.reason },
    });
    if (!decision.allowed) {
      // Preserve the pre-existing revoke-failure audit event too (the revoke
      // path's own outcome), unchanged in shape.
      await deps.audit({
        operation,
        result: "failure",
        identityId: node_id,
        details: { reason: decision.reason },
      });
      denyForbidden(res);
      return;
    }
  }

  const originNodeId = federationOperatorAuthorityOrigin(ctx.fortressId);
  const prior = deps.listFederationEvents({ node_id: originNodeId });
  const previous = prior.length > 0 ? prior[prior.length - 1] : null;
  const evictionSerial = nextEvictionSerial(prior);
  const effectiveAt = new Date().toISOString();
  const payload = signFederationNodeEvictionPayload({
    fortressId: ctx.fortressId,
    nodeId: node_id,
    reason: revocationReason,
    effectiveAt,
    evictionSerial,
    operatorPrincipalId: ctx.issuingPrincipalCert.principal_id,
    operatorPrincipalPrivateKey: ctx.getIssuingPrincipalPrivateKey(),
  });
  const eventWithoutHash = {
    event_id: `${originNodeId}:${(previous?.sequence ?? 0) + 1}`,
    origin_node_id: originNodeId,
    sequence: (previous?.sequence ?? 0) + 1,
    occurred_at: effectiveAt,
    kind: FEDERATION_NODE_EVICTION_EVENT_KIND,
    payload: payload as unknown as Record<string, unknown>,
    previous_hash: previous?.event_hash ?? null,
  };
  const event: FederationEvent = {
    ...eventWithoutHash,
    event_hash: federationEventHash(eventWithoutHash),
  };

  let append: FederationAppendResult;
  try {
    append = await deps.appendFederationEvents([event], {
      senderNodeId: originNodeId,
      wireVersion: FEDERATION_SYNC_WIRE_VERSION,
    });
  } catch {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "durable_state_persist_failed" },
    });
    denyForbidden(res);
    return;
  }
  if (append.accepted.length !== 1 || append.rejected.length !== 0) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: append.rejected[0]?.reason ?? "append_rejected" },
    });
    writeJson(res, 409, {
      error: "conflict",
      rejected: append.rejected,
    });
    return;
  }

  await deps.audit({
    operation,
    result: "success",
    identityId: node_id,
    details: {
      event_id: event.event_id,
      eviction_serial: evictionSerial,
    },
  });
  writeJson(res, 200, {
    revoked: true,
    node_id,
    event_id: event.event_id,
    eviction_serial: evictionSerial,
  });
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
  const { wire_version, node_id, events, cursor, idempotency_key, operator_signature } = body as {
    wire_version?: unknown;
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
  if (wire_version !== FEDERATION_SYNC_WIRE_VERSION) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "unsupported_wire_version" },
    });
    denyForbidden(res);
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
    wire_version,
    node_id,
    events: parsedEvents,
  };
  if (cursor !== undefined && cursor !== null && parsedCursor) {
    signedPayload.cursor = parsedCursor;
  }
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

  const syncCtx = deps.getContext();
  if (!deps.isEnabled() || syncCtx === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "federation_disabled" },
    });
    writeJson(res, 503, { error: "unavailable" });
    return;
  }

  // RR-1 pre-wire (feature-inert until rotate-root Slice 3c). Reject a sync
  // against a fortress whose own pinned master (root) has been revoked. The set
  // is empty in P0, so this never fires today; wired here so 3c need only fill
  // the set. A throw is treated as unevaluable -> deny.
  if (rootRevokedFailClosed(deps, syncCtx.pinnedMasterPubkey.public_key)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "root_revoked" },
    });
    denyForbidden(res);
    return;
  }

  let append: FederationAppendResult;
  try {
    append = await deps.appendFederationEvents(parsedEvents, {
      senderNodeId: node_id,
      wireVersion: wire_version,
    });
  } catch {
    // A folded revocation could not be durably persisted (Federation 3/3b P0
    // fail-closed): deny rather than acknowledge an accept whose revocation
    // state did not reach disk. The in-memory revocation stays applied
    // (grow-only fail-safe); the peer's retry re-persists the whole snapshot.
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "durable_state_persist_failed" },
    });
    denyForbidden(res);
    return;
  }
  let senderRevoked: boolean;
  try {
    senderRevoked = deps.isNodeRevoked(node_id);
  } catch {
    await deps.audit({
      operation,
      result: "failure",
      identityId: node_id,
      details: { reason: "revocation_state_unavailable" },
    });
    denyForbidden(res);
    return;
  }
  const outbound = senderRevoked
    ? []
    : deps.listFederationEvents(parsedCursor ?? undefined);
  await deps.audit({
    operation,
    result: append.rejected.length === 0 ? "success" : "failure",
    identityId: node_id,
    details: {
      accepted: append.accepted.length,
      rejected: append.rejected.length,
      sender_revoked: senderRevoked,
    },
  });
  writeJson(res, 200, {
    accepted: append.accepted.map((event) => event.event_id),
    rejected: append.rejected,
    ...(senderRevoked ? {} : { events: outbound }),
    nodes: deps.listNodes(),
  });
}

interface ReissueNodeCertCompleteRequest {
  node_id: string;
  challenge_id: string;
  challenge: string;
  current_node_cert: NodeIdentityCertificate;
  current_issuing_principal_cert: PrincipalCertificate;
  rotation_cert: FederationRootRotationCertificate;
  node_signature: string;
}

class ReissueNodeCertFailure extends Error {
  constructor(
    readonly auditReason: string,
    /** Extra NON-SECRET facts for the issuer audit entry only. Never sent on the wire. */
    readonly auditFacts: Record<string, unknown> = {},
  ) {
    super(auditReason);
  }
}

/**
 * Per-denial-reason remediation, written into the ISSUER's audit entry ONLY
 * (never into a response). This is the operator-facing half of the correlation
 * id: `sanctuary audit search --request-id <id>` prints the precise reason AND
 * the exact next step, instead of leaving the operator to infer it.
 *
 * The two lineage reasons carry the restart instruction because a running
 * endpoint does NOT pick up a `rotate-root` performed under it
 * (F-FED-ROTLINEAGE). `federation_disabled` still carries an explicit
 * enable/status instruction because disabled is the only safe server-side
 * response when the operator switch is off or could not be rehydrated.
 */
const REISSUE_DENIAL_OPERATOR_NEXT_STEP: Readonly<Record<string, string>> = {
  malformed_or_oversized_body:
    "the request body was unparseable or over the size cap. Re-run the joiner verb rather than replaying a captured request; if it repeats, the two ends are running incompatible builds.",
  malformed_request:
    "the request did not carry the fields this endpoint requires. Re-run the joiner verb; if it repeats, the two ends are running incompatible builds.",
  revocation_state_unavailable:
    "this fortress could not read its own node-revocation state, so it refused rather than issue on stale state. Check the fortress's storage health and audit integrity, then retry.",
  challenge_store_unavailable:
    "this fortress could not open its single-use challenge store, so it refused rather than skip the proof-of-possession round. Check storage health and retry.",
  old_root_revoked:
    "the PREDECESSOR root in this fortress's own recorded lineage has been revoked, so that lineage can no longer anchor an issuance. The node must re-join against the current root with `sanctuary federation rejoin`, not adopt.",
  rotation_cert_invalid:
    "this fortress's own recorded rotation cert failed verification against its predecessor master (including the anti-rollback serial floor). This is a fortress-side integrity problem, not a joiner problem: inspect the trust-root record before retrying.",
  rotation_cert_not_current_root:
    "this fortress's recorded rotation cert does not attest the root it currently pins, so its lineage is internally inconsistent. Inspect the trust-root record; do not retry the adopt until it is resolved.",
  old_cert_chain_invalid:
    "the node cert chain presented for reissue is not a valid chain for this fortress and this node. Re-join the node with `sanctuary federation rejoin` instead of adopting.",
  proof_invalid:
    "the proof of possession over the server challenge did not verify against the presented node cert. Re-run the adopt so it obtains a fresh challenge; if it repeats, this node's stored private key does not match the cert it presented.",
  certificate_issue_failed:
    "this fortress could not mint the replacement certificate. Check the fortress's issuing material and storage health, then retry.",
  federation_disabled:
    "federation is OFF in the running fortress process. Current builds persist the enabled switch across endpoint restarts; run `sanctuary federation status --fortress-url <url>` on the issuer, then run `sanctuary federation enable --fortress-url <url>` if it is disabled, and retry.",
  no_recorded_rotation_lineage:
    "this fortress PROCESS has no recorded root-rotation lineage. Either the fortress has never run `rotate-root`, or a rotation happened while this endpoint was already running (a running endpoint does NOT pick up a rotate-root). Restart the fortress endpoint, run `sanctuary federation status --fortress-url <url>` and enable only if it reports disabled, then retry the adopt. Compare recorded_rotation_serial below with presented_rotation_serial: a presented serial above the recorded one means this process is behind the on-disk root.",
  rotation_cert_not_recorded_lineage:
    "the presented rotation cert is not the rotation this fortress recorded. Either it is a superseded/orphaned cert (e.g. the losing side of a same-serial fork), or this endpoint has not picked up the newest rotate-root. Redistribute the rotation cert printed by the CURRENT `rotate-root`, restart the fortress endpoint if it was running during the rotation, then retry. Compare recorded_rotation_serial with presented_rotation_serial below.",
  root_revoked:
    "the root this fortress pins is in its revoked set; a revoked root can never anchor an issuance. Complete the compromise re-key and have joiners re-join with `sanctuary federation rejoin` against the new root.",
  node_revoked:
    "this node id is revoked on the issuer. Re-authorize it (`sanctuary federation authorize --node-id <id>`) and have it re-join; a revoked node is never reissued.",
  challenge_invalid:
    "the reissue challenge was missing, expired, already spent, or did not match. Retry the adopt so it obtains a fresh challenge; a challenge is single-use by design.",
  issuer_authority_unavailable:
    "this fortress holds no issuing material (it is a joiner or an operator-cloud node, not the issuer). Run the reissue against the ISSUER's fortress URL.",
  hybrid_reissue_unsupported:
    "this fortress uses the post-quantum hybrid suite, for which node-cert reissue is not implemented; refusing rather than verifying only the classical half. Re-join the node out of band instead of adopting.",
};

async function handleReissueNodeCert(
  deps: V1FederationDeps,
  req: IncomingMessage,
  res: ServerResponse,
): Promise<void> {
  // F-FED-OPAQUEDENY: ONE opaque correlation id per request, minted BEFORE any
  // check runs so it can never encode which check failed, and attached to every
  // response THIS HANDLER emits (real challenge, decoy challenge, success, and
  // every denial) so its presence is not an oracle either. A request rejected in
  // front of the handler (the shared /v1 rate limiter's 429) has no id and needs
  // none. See `denyForbiddenWithRequestId` for the full argument.
  const requestId = randomUUID();
  const body = await readJsonBody(req, V1_FEDERATION_REISSUE_NODE_CERT_MAX_BODY_BYTES);
  if (!isRecord(body)) {
    await auditReissueFailure(
      deps,
      "v1_federation_reissue_node_cert",
      reissueRequestNodeId(body),
      "malformed_or_oversized_body",
      requestId,
    );
    denyForbiddenWithRequestId(res, requestId);
    return;
  }

  if (body.action === "challenge") {
    await handleReissueNodeCertChallenge(deps, body, res, requestId);
    return;
  }
  if (body.action === "complete") {
    await handleReissueNodeCertComplete(deps, body, res, requestId);
    return;
  }

  await auditReissueFailure(
    deps,
    "v1_federation_reissue_node_cert",
    reissueRequestNodeId(body),
    "malformed_request",
    requestId,
  );
  denyForbiddenWithRequestId(res, requestId);
}

async function handleReissueNodeCertChallenge(
  deps: V1FederationDeps,
  body: Record<string, unknown>,
  res: ServerResponse,
  requestId: string,
): Promise<void> {
  const operation = "v1_federation_reissue_node_cert_challenge";
  const nodeId = typeof body.node_id === "string" && body.node_id.length > 0
    ? body.node_id
    : null;
  const ctx = deps.getContext();
  const unavailable = !deps.isEnabled() || ctx === null;
  if (nodeId === null) {
    await auditReissueFailure(deps, operation, "peer", "malformed_request", requestId);
    denyForbiddenWithRequestId(res, requestId);
    return;
  }
  if (unavailable || !federationContextHasIssuerAuthority(ctx)) {
    await auditReissueFailure(
      deps,
      operation,
      nodeId,
      unavailable ? "federation_disabled" : "issuer_authority_unavailable",
      requestId,
    );
    writeReissueChallenge(res, dummyReissueChallenge(), requestId);
    return;
  }

  if (rootRevokedFailClosed(deps, ctx.pinnedMasterPubkey.public_key)) {
    await auditReissueFailure(deps, operation, nodeId, "root_revoked", requestId);
    writeReissueChallenge(res, dummyReissueChallenge(), requestId);
    return;
  }

  let revoked: boolean;
  try {
    revoked = deps.isNodeRevoked(nodeId);
  } catch {
    await auditReissueFailure(
      deps,
      operation,
      nodeId,
      "revocation_state_unavailable",
      requestId,
    );
    writeReissueChallenge(res, dummyReissueChallenge(), requestId);
    return;
  }
  if (revoked) {
    await auditReissueFailure(deps, operation, nodeId, "node_revoked", requestId);
    writeReissueChallenge(res, dummyReissueChallenge(), requestId);
    return;
  }

  let issued: FederationReissueChallenge;
  try {
    issued = await deps.issueReissueChallenge({
      fortressId: ctx.fortressId,
      nodeId,
    });
  } catch {
    await auditReissueFailure(
      deps,
      operation,
      nodeId,
      "challenge_store_unavailable",
      requestId,
    );
    writeReissueChallenge(res, dummyReissueChallenge(), requestId);
    return;
  }

  await deps.audit({
    operation,
    result: "success",
    identityId: nodeId,
    details: {
      request_id: requestId,
      challenge_id: issued.challenge_id,
      expires_at: issued.expires_at,
    },
  });
  writeReissueChallenge(res, issued, requestId);
}

/**
 * The single writer for every challenge-path 200, REAL and DECOY alike, so the
 * two stay byte-shape identical (the decoy is what keeps a probing caller from
 * learning whether federation is on). `request_id` is written here rather than
 * at the call sites for the same reason: one writer cannot drift into emitting
 * it on only one of the two.
 */
function writeReissueChallenge(
  res: ServerResponse,
  challenge: FederationReissueChallenge,
  requestId: string,
): void {
  writeJson(res, 200, {
    request_version: FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION,
    request_id: requestId,
    ...challenge,
  });
}

function dummyReissueChallenge(): FederationReissueChallenge {
  return {
    challenge_id: randomUUID(),
    challenge: toBase64url(randomBytes(32)),
    expires_at: new Date(Date.now() + 60_000).toISOString(),
  };
}

async function handleReissueNodeCertComplete(
  deps: V1FederationDeps,
  body: Record<string, unknown>,
  res: ServerResponse,
  requestId: string,
): Promise<void> {
  const operation = "v1_federation_reissue_node_cert";
  const request = parseReissueNodeCertComplete(body);
  const ctx = deps.getContext();
  const unavailable = !deps.isEnabled() || ctx === null;
  if (request === null || unavailable || !federationContextHasIssuerAuthority(ctx)) {
    await auditReissueFailure(
      deps,
      operation,
      reissueRequestNodeId(body),
      unavailable
        ? "federation_disabled"
        : request === null
          ? "malformed_request"
          : "issuer_authority_unavailable",
      requestId,
    );
    denyForbiddenWithRequestId(res, requestId);
    return;
  }

  if (rootRevokedFailClosed(deps, ctx.pinnedMasterPubkey.public_key)) {
    await auditReissueFailure(deps, operation, request.node_id, "root_revoked", requestId);
    denyForbiddenWithRequestId(res, requestId);
    return;
  }

  let consumed: boolean;
  try {
    consumed = await deps.consumeReissueChallenge({
      fortressId: ctx.fortressId,
      nodeId: request.node_id,
      challengeId: request.challenge_id,
      challenge: request.challenge,
    });
  } catch {
    consumed = false;
  }
  if (!consumed) {
    await auditReissueFailure(
      deps,
      operation,
      request.node_id,
      "challenge_invalid",
      requestId,
    );
    denyForbiddenWithRequestId(res, requestId);
    return;
  }

  let certificate: NodeIdentityCertificate;
  try {
    certificate = reissueNodeCertificate(deps, ctx, request);
  } catch (err) {
    await auditReissueFailure(
      deps,
      operation,
      request.node_id,
      err instanceof ReissueNodeCertFailure
        ? err.auditReason
        : "certificate_issue_failed",
      requestId,
      err instanceof ReissueNodeCertFailure ? err.auditFacts : {},
    );
    denyForbiddenWithRequestId(res, requestId);
    return;
  }

  await deps.audit({
    operation,
    result: "success",
    identityId: request.node_id,
    details: {
      request_id: requestId,
      node_id: request.node_id,
      rotation_serial: request.rotation_cert.rotation_serial,
      expires_at: certificate.expires_at ?? null,
    },
  });
  writeJson(res, 200, {
    reissued: true,
    request_version: FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION,
    request_id: requestId,
    node_id: request.node_id,
    certificate,
    issuing_principal_cert: ctx.issuingPrincipalCert,
    pinned_master: ctx.pinnedMasterPubkey,
  });
}

function reissueNodeCertificate(
  deps: V1FederationDeps,
  ctx: FederationIssuerContext,
  request: ReissueNodeCertCompleteRequest,
): NodeIdentityCertificate {
  const rotationCert = request.rotation_cert;

  // HOLE 2 (PQC downgrade): fail closed on a hybrid fortress. Hybrid reissue is
  // out of scope for Slice 3c-2; accepting a classical-only rotation cert on a
  // hybrid (Ed25519+ML-DSA-65) fortress would silently downgrade the
  // post-quantum root (the classical `samePinnedMaster` compares only the
  // Ed25519 half). Refuse the endpoint entirely rather than verify half the
  // binding. Matches the fail-closed contract on
  // `FederationRootRotationCertificate.hybrid_rotation` (mesh/types.ts).
  if (ctx.isHybrid === true) {
    throw new ReissueNodeCertFailure("hybrid_reissue_unsupported");
  }
  // Defense in depth: a classical issuer must never process a cert that even
  // CARRIES a hybrid binding (it cannot verify the ML-DSA-65 half).
  if (!isRecord(rotationCert) || rotationCert.hybrid_rotation !== undefined) {
    throw new ReissueNodeCertFailure("hybrid_reissue_unsupported");
  }

  // HOLE 1 (forged old master): pin the predecessor master from THIS fortress's
  // OWN durable rotation lineage, NEVER from the request. The endpoint is
  // pre-session / unauthenticated, so the only safe anchor for the "old" master
  // is the rotation cert the fortress itself adopted at its last
  // `rotate-root --renew` (carried in the trust-root record -> ctx). If the
  // fortress never rotated, there is no predecessor to chain an old K1 cert to:
  // the reissue-with-rotation path fails closed.
  const recordedRotationCert = ctx.recordedRotationCert;
  if (
    recordedRotationCert === undefined ||
    ctx.recordedRotationSerial === undefined
  ) {
    throw new ReissueNodeCertFailure(
      "no_recorded_rotation_lineage",
      lineageDiagnosticFacts(ctx, request),
    );
  }
  // The submitted rotation cert must be byte-identical (canonical-JSON equal) to
  // the one the fortress persisted. This is the strongest tie: an attacker
  // cannot swap in a self-minted predecessor master, replay a stale serial, or
  // alter the rotated_at / signature, because anything but the exact recorded
  // cert is rejected here.
  if (canonicalJson(rotationCert) !== canonicalJson(recordedRotationCert)) {
    throw new ReissueNodeCertFailure(
      "rotation_cert_not_recorded_lineage",
      lineageDiagnosticFacts(ctx, request),
    );
  }
  if (recordedRotationCert.fortress_id !== ctx.fortressId) {
    throw new ReissueNodeCertFailure("rotation_cert_invalid");
  }
  // Predecessor master pinned from the RECORDED cert. created_at is not consumed
  // by the verifiers (they key only on public_key + fortress_id); we carry the
  // recorded rotated_at for shape completeness.
  const oldPinnedMaster: FortressMasterPublicKey = {
    public_key: recordedRotationCert.old_master_pubkey,
    fortress_id: recordedRotationCert.fortress_id,
    created_at: recordedRotationCert.rotated_at,
  };

  if (rootRevokedFailClosed(deps, recordedRotationCert.old_master_pubkey)) {
    throw new ReissueNodeCertFailure("old_root_revoked");
  }
  try {
    // minSerial = adopted serial - 1 so the recorded serial itself is accepted
    // while any serial <= the predecessor is rejected (rollback/replay proof,
    // even within genuine lineage).
    verifyFederationRootRotationCertificate(recordedRotationCert, oldPinnedMaster, {
      minSerial: ctx.recordedRotationSerial - 1,
    });
  } catch {
    throw new ReissueNodeCertFailure("rotation_cert_invalid");
  }
  if (!samePinnedMaster(recordedRotationCert.new_master, ctx.pinnedMasterPubkey)) {
    throw new ReissueNodeCertFailure("rotation_cert_not_current_root");
  }

  const nodeCert = request.current_node_cert;
  const principalCert = request.current_issuing_principal_cert;
  if (nodeCert.node_id !== request.node_id || nodeCert.fortress_id !== ctx.fortressId) {
    throw new ReissueNodeCertFailure("old_cert_chain_invalid");
  }
  try {
    verifyCertChain(nodeCert, principalCert, oldPinnedMaster);
  } catch {
    throw new ReissueNodeCertFailure("old_cert_chain_invalid");
  }

  let revoked: boolean;
  try {
    revoked = deps.isNodeRevoked(request.node_id);
  } catch {
    throw new ReissueNodeCertFailure("revocation_state_unavailable");
  }
  if (revoked) throw new ReissueNodeCertFailure("node_revoked");

  let nodePubkey: Uint8Array;
  let signature: Uint8Array;
  try {
    nodePubkey = fromBase64url(nodeCert.node_pubkey);
    signature = fromBase64url(request.node_signature);
  } catch {
    throw new ReissueNodeCertFailure("proof_invalid");
  }
  if (nodePubkey.length !== ED25519_PUBLIC_KEY_BYTES || signature.length !== ED25519_SIGNATURE_BYTES) {
    throw new ReissueNodeCertFailure("proof_invalid");
  }
  const proofMessage = buildFederationReissueNodeCertProofMessage({
    fortressId: ctx.fortressId,
    nodeId: request.node_id,
    challengeId: request.challenge_id,
    challenge: request.challenge,
    currentNodeCert: nodeCert,
    currentIssuingPrincipalCert: principalCert,
    rotationCert,
  });
  if (!verify(proofMessage, signature, nodePubkey)) {
    throw new ReissueNodeCertFailure("proof_invalid");
  }

  const renewal = normalizeFederationNodeCertificateRenewalConfig(
    ctx.nodeCertificateRenewal,
  );
  const expiresAt = new Date(renewal.now() + renewal.certLifetimeMs).toISOString();
  try {
    return issueNodeIdentityCertificate({
      node_id: request.node_id,
      node_pubkey: nodePubkey,
      node_mode: nodeCert.node_mode,
      fortress_id: ctx.fortressId,
      capabilities: nodeCert.capabilities,
      parent_chain: {
        fortress_master_pubkey: ctx.pinnedMasterPubkey.public_key,
        principal_id: ctx.issuingPrincipalCert.principal_id,
        principal_pubkey: ctx.issuingPrincipalCert.principal_pubkey,
      },
      principal_private_key: ctx.getIssuingPrincipalPrivateKey(),
      master_private_key: ctx.getMasterPrivateKey?.(),
      expires_at: expiresAt,
      ...(typeof nodeCert.tee_attestation_hash === "string"
        ? { tee_attestation_hash: nodeCert.tee_attestation_hash }
        : {}),
    });
  } catch {
    throw new ReissueNodeCertFailure("certificate_issue_failed");
  }
}

export function buildFederationReissueNodeCertProofMessage(params: {
  fortressId: string;
  nodeId: string;
  challengeId: string;
  challenge: string;
  currentNodeCert: NodeIdentityCertificate;
  currentIssuingPrincipalCert: PrincipalCertificate;
  rotationCert: FederationRootRotationCertificate;
}): Uint8Array {
  return new TextEncoder().encode(
    canonicalJson({
      domain: FEDERATION_REISSUE_NODE_CERT_PROOF_DOMAIN,
      request_version: FEDERATION_REISSUE_NODE_CERT_REQUEST_VERSION,
      fortress_id: params.fortressId,
      node_id: params.nodeId,
      challenge_id: params.challengeId,
      challenge: params.challenge,
      current_node_cert_sha256: sha256Canonical(params.currentNodeCert),
      current_issuing_principal_cert_sha256: sha256Canonical(
        params.currentIssuingPrincipalCert,
      ),
      rotation_cert_sha256: sha256Canonical(params.rotationCert),
    }),
  );
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("base64url");
}

function parseReissueNodeCertComplete(
  body: Record<string, unknown>,
): ReissueNodeCertCompleteRequest | null {
  if (
    typeof body.node_id !== "string" ||
    body.node_id.length === 0 ||
    typeof body.challenge_id !== "string" ||
    body.challenge_id.length === 0 ||
    typeof body.challenge !== "string" ||
    body.challenge.length === 0 ||
    typeof body.node_signature !== "string" ||
    body.node_signature.length === 0 ||
    !isRecord(body.current_node_cert) ||
    !isRecord(body.current_issuing_principal_cert) ||
    !isRecord(body.rotation_cert)
  ) {
    return null;
  }
  return {
    node_id: body.node_id,
    challenge_id: body.challenge_id,
    challenge: body.challenge,
    current_node_cert: body.current_node_cert as unknown as NodeIdentityCertificate,
    current_issuing_principal_cert:
      body.current_issuing_principal_cert as unknown as PrincipalCertificate,
    rotation_cert: body.rotation_cert as unknown as FederationRootRotationCertificate,
    node_signature: body.node_signature,
  };
}

function samePinnedMaster(
  a: FortressMasterPublicKey,
  b: FortressMasterPublicKey,
): boolean {
  return (
    a.public_key === b.public_key &&
    a.fortress_id === b.fortress_id &&
    a.created_at === b.created_at
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Record a reissue denial in the ISSUER's audit log, with everything the
 * operator needs to act: the precise reason (which the wire response
 * deliberately does not carry), the correlation id printed to the caller, the
 * remediation for that reason, and any non-secret diagnostic facts the failing
 * check gathered. All of this is LOCAL: nothing here is ever written to a
 * response body.
 */
async function auditReissueFailure(
  deps: V1FederationDeps,
  operation: string,
  identityId: string,
  reasonCode: string,
  requestId: string,
  facts: Record<string, unknown> = {},
): Promise<void> {
  const nextStep = REISSUE_DENIAL_OPERATOR_NEXT_STEP[reasonCode];
  await deps.audit({
    operation,
    result: "failure",
    identityId,
    details: {
      reason: reasonCode,
      request_id: requestId,
      ...(nextStep !== undefined ? { operator_next_step: nextStep } : {}),
      ...facts,
    },
  });
}

/**
 * The two numbers that separate the two very different situations behind a
 * lineage refusal, for the ISSUER's audit entry only.
 *
 * `recorded_rotation_serial` is what THIS PROCESS holds (loaded at boot, from
 * the durable trust-root record); `presented_rotation_serial` is what the caller
 * sent. Presented ABOVE recorded means the caller has a newer rotation than this
 * process does, i.e. the endpoint has not picked up a `rotate-root` and needs a
 * restart (F-FED-ROTLINEAGE). Presented AT OR BELOW recorded points at a
 * superseded or orphaned cert instead.
 *
 * NOT A TRUST INPUT. The presented serial is untrusted attacker-controlled data
 * and is used for exactly one thing: printing a number in a local audit entry
 * next to the label `presented_` so an operator can compare them. No branch in
 * the issuance decision reads it, and neither number is ever written to a
 * response.
 */
function lineageDiagnosticFacts(
  ctx: FederationIssuerContext,
  request: ReissueNodeCertCompleteRequest,
): Record<string, unknown> {
  const presented = request.rotation_cert.rotation_serial;
  return {
    recorded_rotation_serial: ctx.recordedRotationSerial ?? null,
    presented_rotation_serial: typeof presented === "number" ? presented : null,
  };
}

function reissueRequestNodeId(body: unknown): string {
  if (isRecord(body) && typeof body.node_id === "string" && body.node_id.length > 0) {
    return body.node_id;
  }
  return "peer";
}

/**
 * Cross-MACHINE peer sync (PR-A5 marquee; relaxed to pre-session in Federation
 * P1). Unlike `/sync`, which authorizes the request with THIS fortress's own
 * operator signature (correct only when the caller is the same operator process,
 * the A4 "loopback position-only" path), `/sync/peer` accepts a sync from
 * ANOTHER of the operator's machines. There is NO session and NO operator login
 * on this route (Federation P1: it moved to the pre-session node-cert-auth
 * class); trust in the EVENTS comes SOLELY from the {@link
 * FederationSyncEnvelope}: the peer presents its node identity certificate, which
 * the recipient verifies chains to its OWN pinned fortress-master
 * (`verifySyncEnvelope` → `verifyCertChain`). That single cryptographic
 * verification is the only trust decision.
 *
 * This is the "no implicit trust across the boundary" rule (CLAUDE.md
 * constraint 4) realized for the cross-machine case: a node whose certificate
 * does NOT chain to this fortress's master (a different operator) is rejected
 * with the generic 403. The hash-chained log defeats per-event tampering/replay;
 * the envelope high-water defeats whole-envelope rollback. No private key crosses
 * the wire (constraint 6).
 *
 * NO MEMBERSHIP ORACLE (Federation P1 §2): a pre-session caller must learn
 * nothing about whether federation is enabled, whether it is provisioned, or
 * WHICH check failed. Every rejection (federation off/unprovisioned, malformed
 * or over-cap body, envelope verification failure) collapses to the SAME generic
 * 403 on the wire. The audit log records the precise reason; the response never
 * does. (Previously this route returned 503 when federation was disabled, which,
 * now that there is no session in front, would have been an enabled-state
 * oracle for an unauthenticated probe.)
 *
 * CONFIDENTIALITY HONESTY (Federation P1 §5, CC-1): the signed envelope provides
 * INTEGRITY + AUTHENTICITY, NOT confidentiality. The default listener is plain
 * HTTP; over it the events and the node roster cross the wire in cleartext. A
 * pre-session `/sync/peer` deployment therefore REQUIRES a confidential composed
 * transport (Tailscale / WireGuard / a TLS-terminating front); the route does
 * NOT terminate TLS itself (out of scope; transport is composed per the 06-24
 * federation decision).
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
): Promise<void> {
  const operation = "v1_federation_sync_peer";
  const ctx = deps.getContext();

  // Federation must be enabled and provisioned (we need the pinned master to
  // verify the peer's chain). NO-ORACLE (P1 §2): there is no session in front of
  // this route now, so a distinguishable 503 would tell an unauthenticated probe
  // that this fortress is NOT a provisioned federation member. Collapse it to the
  // SAME generic 403 every other denial returns; the audit entry keeps the
  // precise reason.
  if (!deps.isEnabled() || ctx === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: "peer",
      details: { reason: "federation_disabled" },
    });
    denyForbidden(res);
    return;
  }

  // NO-ORACLE (P1 §2): a malformed or over-cap body also collapses to the same
  // generic 403. The body cap still rejects oversized peer traffic cheaply (over
  // V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES -> readJsonBody returns undefined
  // before JSON.parse), but the WIRE response is identical to a verify failure so
  // a probe cannot distinguish "too big / not JSON" from "bad envelope".
  const body = await readJsonBody(req, V1_FEDERATION_SYNC_PEER_MAX_BODY_BYTES);
  if (typeof body !== "object" || body === null) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: peerSenderNodeId(body),
      details: { reason: "malformed_or_oversized_body" },
    });
    denyForbidden(res);
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
    isNodeRevoked: (senderNodeId) => deps.isNodeRevoked(senderNodeId),
    // RR-1 pre-wire (feature-inert until rotate-root Slice 3c populates the set).
    isRootRevoked: (masterPubkeyB64u) => deps.isRootRevoked(masterPubkeyB64u),
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
  // the single fail-closed revocation chokepoint. Advance the per-sender
  // high-water ONLY when the WHOLE slice appended cleanly AND it actually
  // carried new work (>=1 accepted event):
  //   - a partial append (sequence gap / previous_hash mismatch) must NOT burn
  //     the high-water, or a future correct lower-water resend from that sender
  //     would be wrongly rejected as a rollback;
  //   - an EMPTY / no-op envelope must NOT advance the high-water either, or a
  //     verified-but-careless (or hostile) peer could "burn" its own high-water
  //     to a huge value with a content-free envelope and self-DoS every future
  //     legitimate sync (codex PR-A5 r2 MEDIUM). High-water is a property of
  //     committed work, never of an empty signed envelope.
  let append: FederationAppendResult;
  try {
    append = await deps.appendFederationEvents(verification.events, {
      senderNodeId: verification.senderNodeId,
      wireVersion: verification.wireVersion,
    });
  } catch {
    // A folded revocation could not be durably persisted (Federation 3/3b P0
    // fail-closed): deny rather than acknowledge an accept whose revocation
    // state did not reach disk. The in-memory revocation stays applied
    // (grow-only fail-safe); the peer's retry re-persists the whole snapshot.
    await deps.audit({
      operation,
      result: "failure",
      identityId: verification.senderNodeId,
      details: { reason: "durable_state_persist_failed" },
    });
    denyForbidden(res);
    return;
  }

  let senderRevokedAfterAcceptance: boolean;
  try {
    senderRevokedAfterAcceptance = deps.isNodeRevoked(verification.senderNodeId);
  } catch {
    await deps.audit({
      operation,
      result: "failure",
      identityId: verification.senderNodeId,
      details: { reason: "revocation_state_unavailable" },
    });
    denyForbidden(res);
    return;
  }

  if (append.rejected.length === 0 && append.accepted.length > 0) {
    const highWaterPersisted = await deps.recordAcceptedHighWater(
      verification.senderNodeId,
      verification.syncHighWater,
      verification.senderNodeCert,
    );
    if (!highWaterPersisted) {
      // The anti-replay high-water advance did not durably commit (Federation
      // 3/3b P0 fail-closed): deny rather than let the peer believe its slice
      // was accepted with a high-water that a restart would forget (which would
      // re-open the very replay window this slice closes). The events appended
      // above are still hash-chained + deduped on the next attempt, so a retry
      // is safe; an un-acknowledged accept is the correct fail-closed posture.
      await deps.audit({
        operation,
        result: "failure",
        identityId: verification.senderNodeId,
        details: { reason: "durable_state_persist_failed" },
      });
      denyForbidden(res);
      return;
    }
  }

  // The reciprocal envelope is signed by THIS node and therefore may only carry
  // THIS node's OWN events (origin == this node id) - the same origin-binding
  // invariant the inbound path enforces. A node never forwards another node's
  // events inside its own signed envelope; multi-hop propagation happens through
  // pairwise syncs, not delegated forwarding (which would need its own proof).
  // The cursor still scopes which of this node's own events to return.
  const outbound = senderRevokedAfterAcceptance
    ? []
    : deps
        .listFederationEvents(verification.cursor ?? undefined)
        .filter((event) => event.origin_node_id === ctx.nodeId);
  let responseEnvelope: FederationSyncEnvelope | null;
  try {
    responseEnvelope = senderRevokedAfterAcceptance
      ? null
      : await buildReciprocalEnvelope(
          deps,
          ctx,
          verification.senderNodeId,
          outbound,
        );
  } catch {
    // The outbound high-water advance could not be durably persisted
    // (Federation 3/3b P0 fail-closed). The inbound slice was already accepted
    // and its high-water persisted above, so do NOT fail the whole exchange:
    // simply omit the reciprocal envelope. The peer re-requests on its next
    // sync; a missing reciprocal slice is a benign degrade, never a replay risk.
    responseEnvelope = null;
  }

  await deps.audit({
    operation,
    result: append.rejected.length === 0 ? "success" : "failure",
    identityId: verification.senderNodeId,
    details: {
      accepted: append.accepted.length,
      rejected: append.rejected.length,
      high_water: verification.syncHighWater,
      sender_revoked: senderRevokedAfterAcceptance,
      reply_suppressed: senderRevokedAfterAcceptance,
    },
  });

  writeJson(res, 200, {
    accepted: append.accepted.map((event) => event.event_id),
    rejected: append.rejected,
    // The reciprocal slice is peer-verifiable only when this daemon holds its
    // node identity. Missing identity returns no bare events: unattributable
    // reciprocal data has no current wire version and fails closed.
    ...(senderRevokedAfterAcceptance
      ? {}
      : responseEnvelope
        ? { envelope: responseEnvelope }
        : {}),
    nodes: deps.listNodes(),
  });
}

/**
 * Wrap this daemon's outbound slice in a reciprocal {@link FederationSyncEnvelope}
 * the peer can verify the same way the daemon just verified the inbound one.
 * Returns null when this daemon does not hold its own node identity (cert +
 * private key) rather than forging an attribution. The caller must not emit
 * bare events as a fallback. The node private key is transient and never logged.
 */
async function buildReciprocalEnvelope(
  deps: V1FederationDeps,
  ctx: FederationContext,
  recipientNodeId: string,
  outbound: FederationEvent[],
): Promise<FederationSyncEnvelope | null> {
  deps.renewLocalNodeCertificate();
  const nodeCert = ctx.localNodeCert;
  const nodePrivateKey = ctx.getLocalNodePrivateKey?.();
  if (!nodeCert || !nodePrivateKey) return null;
  // Reserve + DURABLY persist the next outbound high-water BEFORE signing, so a
  // restart can never re-emit an already-used counter. A persist failure throws
  // out of nextOutboundHighWater; the caller treats that as "no reciprocal
  // slice" (benign degrade), never as a counter it already handed out.
  let syncHighWater: number;
  try {
    syncHighWater = await deps.nextOutboundHighWater();
  } catch (err) {
    nodePrivateKey.fill(0);
    throw err;
  }
  try {
    return signSyncEnvelope({
      fortressId: ctx.fortressId,
      senderNodeId: ctx.nodeId,
      recipientNodeId,
      syncHighWater,
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
 * RR-1 fail-closed evaluation of the revoked-ROOT predicate (Federation 3/3b
 * P0). Returns true (-> the caller denies) when the fortress master is revoked
 * OR when the predicate throws (revocation state unevaluable). Feature-inert in
 * P0 because the revoked-root set is empty until rotate-root Slice 3c populates
 * it; centralizing the throw-is-deny rule here keeps every chokepoint identical.
 */
function rootRevokedFailClosed(
  deps: V1FederationDeps,
  masterPubkeyB64u: string,
): boolean {
  if (typeof deps.isRootRevoked !== "function") return true;
  try {
    return deps.isRootRevoked(masterPubkeyB64u);
  } catch {
    return true;
  }
}

/**
 * Pre-session join-submission ceremony (BOOTSTRAP_TOKEN auth class). Reached
 * by the router BEFORE the session gate, like session/init. Every failure -
 * federation off, missing materials, bad body, unverifiable request - returns
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

  // RR-1 pre-wire (feature-inert until rotate-root Slice 3c). A join against a
  // fortress whose own pinned master (root) has been revoked must fail closed,
  // so a compromised root cannot keep admitting new nodes. Empty set in P0 (this
  // never fires today); wired so 3c only fills the set. Throw -> deny. Collapses
  // to the SAME uniform 401 as every other ceremony denial (no oracle).
  if (rootRevokedFailClosed(deps, ctx.pinnedMasterPubkey.public_key)) {
    await deps.audit({
      operation,
      result: "failure",
      identityId: request.bootstrap_token.intended_node_id,
      details: { reason: "root_revoked" },
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

  // PR-A durable membership: persist the roster before acknowledging the join.
  // A persist failure THROWS here; there is no try/catch around this call, so the
  // throw propagates to the dashboard's top-level request handler and surfaces as
  // a generic HTTP 500 ({"error":"Internal server error"}), NOT a 401. Either way
  // the join is NOT acknowledged (no success response, no certificate returned),
  // which is the fail-closed behavior we want: a join whose membership did not
  // reach disk must not be treated as joined (the node would be silently
  // forgotten on the next reboot and dropped from the paid count).
  await deps.recordJoin(outcome.certificate);
  await deps.audit({
    operation,
    result: "success",
    identityId: outcome.nodeId,
    details: { node_id: outcome.nodeId, node_mode: outcome.certificate.node_mode },
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

function nextEvictionSerial(events: FederationEvent[]): number {
  let max = 0;
  for (const event of events) {
    if (event.kind !== FEDERATION_NODE_EVICTION_EVENT_KIND) continue;
    const serial = event.payload.eviction_serial;
    if (typeof serial === "number" && Number.isSafeInteger(serial) && serial > max) {
      max = serial;
    }
  }
  return max + 1;
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
