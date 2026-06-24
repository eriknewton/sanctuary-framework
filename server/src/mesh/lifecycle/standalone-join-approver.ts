/**
 * Standalone-boot production JoinApprover for LOCAL / sovereign_tee federation
 * joins (the operator's own second machine).
 *
 * Context: the standalone `sanctuary dashboard` boot previously wired a
 * tests-only auto-deny placeholder into the federation issuer context, so a real
 * stock-CLI cross-machine join could never complete even after the operator ran
 * the OPERATOR_SIGNED `federation enable` + `authorize/init`. This is the real
 * gate that replaces it.
 *
 * Model: TOKEN-AS-APPROVAL. The operator's live Tier-1 decision already happened
 * at the OPERATOR_SIGNED `authorize/init` that minted the bootstrap token. By the
 * time this approver runs (step 6 of `JoinCeremony.authorizeComplete`), the
 * ceremony has ALREADY verified, in order:
 *   1. bootstrap-token signature + fortress binding + expiry + issuing principal,
 *   2. node_mode binding to the token,
 *   3. revocation (live `isNodeRevoked` projection; deny-on-throw),
 *   4. the HKDF salt proof (possession of the master-derived transport key),
 *   5. node_pubkey well-formedness.
 * So this approver MUST NOT re-verify token / HKDF / revocation: those are
 * already enforced upstream and re-doing them would duplicate, not strengthen,
 * the gate. Its net-new job is the ONE control the ceremony lacks: single-use
 * (replay) protection. It also denies operator_cloud (those route through the
 * separate operator-cloud approver with its own provision-claim flow) and fails
 * closed on any missing / invalid input.
 *
 * The single-use store mirrors the already-shipped, already-reviewed
 * {@link OperatorCloudProvisionClaimStore} `consume`-style single-use pattern.
 */

import { fromBase64url } from "../../core/encoding.js";
import { issueCertificateForApprovedJoin } from "./join-approver.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../types.js";
import type { JoinApprovalResult, JoinApprover, JoinRequest } from "./types.js";

/**
 * In-memory single-use store for spent bootstrap-token nonces, keyed on
 * (fortress_id, node_id, nonce). `consume` is atomic single-shot: the FIRST call
 * for a (key) records it and returns true; any later call for the same key
 * returns false (the replay is denied). A nonce is only remembered until its
 * expiry, after which it is pruned (the token signature + TTL are already
 * enforced upstream, so the store only needs to remember a nonce for as long as
 * a valid token could still bear it).
 *
 * DURABLE-STORE DEBT (matches the OperatorCloudProvisionClaimStore note):
 * production should wire this to the encrypted state store so single-use survives
 * a daemon restart. In-memory is acceptable for this slice because a restart
 * drops the entire federation context anyway and bootstrap tokens expire in
 * BOOTSTRAP_TOKEN_TTL_MS (15 minutes); a restart mid-TTL would forget one spent
 * nonce and re-allow that single token until it expires. Low blast radius (same
 * node id + pubkey), but a genuine follow-up. See the final report.
 */
export class BootstrapNonceStore {
  private readonly spent = new Map<string, number>();

  private key(fortressId: string, nodeId: string, nonce: string): string {
    return `${fortressId} ${nodeId} ${nonce}`;
  }

  /** Drop entries whose expiry has passed (best-effort sweep on each consume). */
  private prune(nowMs: number): void {
    for (const [key, expiresAtMs] of this.spent) {
      if (expiresAtMs < nowMs) this.spent.delete(key);
    }
  }

  /**
   * Atomically consume the nonce. Returns true if this is the FIRST time the
   * nonce is seen (records it as spent until `expiresAtMs`); returns false if it
   * was already spent (a replay): the caller must DENY on false.
   */
  consume(
    fortressId: string,
    nodeId: string,
    nonce: string,
    expiresAtMs: number,
    nowMs = Date.now(),
  ): boolean {
    this.prune(nowMs);
    const key = this.key(fortressId, nodeId, nonce);
    if (this.spent.has(key)) return false;
    this.spent.set(key, expiresAtMs);
    return true;
  }

  /** Whether a nonce is currently recorded as spent (status / tests). */
  isSpent(
    fortressId: string,
    nodeId: string,
    nonce: string,
    nowMs = Date.now(),
  ): boolean {
    const expiresAtMs = this.spent.get(this.key(fortressId, nodeId, nonce));
    if (expiresAtMs === undefined) return false;
    return expiresAtMs >= nowMs;
  }
}

export interface StandaloneJoinApproverParams {
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  /** Transient accessor for the issuing principal private key (signs the cert). */
  getIssuingPrincipalPrivateKey(): Uint8Array;
  /** Transient accessor for the fortress-master private key, when held (master cert sig). */
  getMasterPrivateKey?(): Uint8Array | undefined;
  /** Single-use nonce store; one instance per dashboard boot (federation-context lifetime). */
  nonceStore: BootstrapNonceStore;
  /** Optional node-cert expiry. */
  expiresAt?: string;
  /** Clock injection for tests. */
  nowMs?: () => number;
}

/**
 * Build the PRODUCTION standalone-boot join approver for local / sovereign_tee
 * nodes. It:
 *   1. DENIES operator_cloud (wrong approver),
 *   2. DENIES a request missing a verified bootstrap-token context (fail closed),
 *   3. CONSUMES the bootstrap nonce single-use (DENIES a replay),
 *   4. issues the node identity certificate via the shared
 *      `issueCertificateForApprovedJoin` using the issuer materials.
 *
 * It deliberately does NOT re-verify token signature, HKDF proof, or revocation:
 * those are enforced by `authorizeComplete` steps 1-5 BEFORE the approver runs.
 * Every denial returns a generic operator-facing reason; the HTTP layer collapses
 * denials to a uniform 401 (no oracle). No private key is persisted or logged.
 */
export function createStandaloneJoinApprover(
  params: StandaloneJoinApproverParams,
): JoinApprover {
  return {
    async requestApproval(request: JoinRequest): Promise<JoinApprovalResult> {
      // 1. operator_cloud is never issuable by the standalone (local) approver.
      if (request.node_mode === "operator_cloud") {
        return {
          approved: false,
          denial_reason: "standalone approver only issues local / sovereign_tee nodes",
        };
      }

      // 2. Fail closed if the verified token context is somehow absent. The
      //    ceremony parses + verifies the token upstream, but this approver must
      //    not assume it: a request with no token, no fortress id, no node id, or
      //    no nonce is denied rather than issued.
      const token = request.bootstrap_token;
      if (
        typeof token !== "object" ||
        token === null ||
        typeof token.fortress_id !== "string" ||
        token.fortress_id.length === 0 ||
        typeof token.intended_node_id !== "string" ||
        token.intended_node_id.length === 0 ||
        typeof token.nonce !== "string" ||
        token.nonce.length === 0 ||
        typeof token.expires_at !== "string" ||
        token.expires_at.length === 0
      ) {
        return { approved: false, denial_reason: "missing or invalid bootstrap token context" };
      }

      // The cert binds to the token's intended node, so issuance must match the
      // ceremony's mode binding. The ceremony already rejected a mode mismatch
      // (step 2), but re-assert defensively rather than issue on a divergent shape.
      if (request.node_mode !== token.intended_node_mode) {
        return { approved: false, denial_reason: "node_mode does not match bootstrap token" };
      }

      // 3. Single-use: consume the nonce atomically. A replay (same nonce) is
      //    denied. This is the net-new control the upstream ceremony lacks.
      const nowMs = params.nowMs?.() ?? Date.now();
      const expiresAtMs = Date.parse(token.expires_at);
      if (!Number.isFinite(expiresAtMs)) {
        return { approved: false, denial_reason: "bootstrap token expiry is invalid" };
      }
      const firstUse = params.nonceStore.consume(
        token.fortress_id,
        token.intended_node_id,
        token.nonce,
        expiresAtMs,
        nowMs,
      );
      if (!firstUse) {
        return { approved: false, denial_reason: "bootstrap token already used" };
      }

      // Defense-in-depth: reject a malformed node pubkey before issuance (the
      // ceremony already checks this at step 5; harmless and cheap to re-check).
      try {
        if (fromBase64url(request.node_pubkey).length !== 32) {
          return { approved: false, denial_reason: "node_pubkey is not a 32-byte key" };
        }
      } catch {
        return { approved: false, denial_reason: "node_pubkey is malformed" };
      }

      // 4. Issue the certificate. The transient master private key (when held) is
      //    pulled, used, and zeroed so no master-key copy outlives issuance.
      const masterPrivateKey = params.getMasterPrivateKey?.();
      try {
        const certificate = issueCertificateForApprovedJoin({
          request,
          pinned_master_pubkey: params.pinned_master_pubkey,
          issuing_principal_cert: params.issuing_principal_cert,
          issuing_principal_private_key: params.getIssuingPrincipalPrivateKey(),
          master_private_key: masterPrivateKey,
          expires_at: params.expiresAt,
        });
        return { approved: true, certificate };
      } finally {
        masterPrivateKey?.fill(0);
      }
    },
  };
}
