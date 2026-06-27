/**
 * Operator Cloud Slice 2, pending-provision-claim store + production JoinApprover.
 *
 * The home/issuer node, after the Tier-1 `operator_cloud_provision` approval
 * returns approve, records a PENDING APPROVED PROVISION CLAIM. The production
 * JoinApprover for an `operator_cloud` join consumes a matching, unexpired,
 * unconsumed claim before issuing the certificate. Absent / expired / mismatched
 * / already-consumed -> denial.
 *
 * This is the structural enforcement behind two BLOCKING criteria:
 *  - HIGH-1 / HIGH-4 anti-substitution: the claim binds node_pubkey_hash,
 *    bootstrap nonce, manifest digest, scoped-secret ciphertext digest, and
 *    decrypt-scope digest. A leaked bundle consumed by a substituted keypair, or
 *    a substituted bundle, fails the digest/pubkey match and is denied.
 *  - The cloud join is NEVER auto-approved: certificate issuance for an
 *    operator-cloud node is impossible without a live Tier-1 decision recorded
 *    as this exact claim. There is no default approver (Slice 1 already denies
 *    when no approver is bound).
 */

import { fromBase64url } from "../../core/encoding.js";
import type { StorageBackend } from "../../storage/interface.js";
import {
  computeNodePubkeyHash,
  verifyOperatorCloudJoinProof,
} from "../operator-cloud-provision.js";
import {
  DurableClaimSetStore,
  type OperatorCloudProvisionClaim,
} from "./durable-claim-set-store.js";
import { issueCertificateForApprovedJoin } from "./join-approver.js";
import type {
  FortressMasterPublicKey,
  PrincipalCertificate,
} from "../types.js";
import type { JoinApprovalResult, JoinApprover, JoinRequest } from "./types.js";

/** At-rest namespace + record key + HKDF label for the durable claim set. */
export const OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE = "_federation";
export const OPERATOR_CLOUD_CLAIM_STORE_KEY = "operator-cloud-provision-claims-v1";
export const OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO =
  "federation-operator-cloud-provision-claim-set";

export type { OperatorCloudProvisionClaim };

export interface RecordProvisionClaimParams {
  fortress_id: string;
  node_id: string;
  node_pubkey_hash: string;
  bootstrap_nonce: string;
  manifest_digest: string;
  scoped_secret_ciphertext_digest: string;
  scope_digest: string;
  bundle_digest: string;
  expires_at: string;
}

/**
 * Single-use pending-claim store. A claim is single-use: `consume` flips
 * `consumed` and never returns it again.
 *
 * DURABILITY: when constructed with a {@link DurableClaimSetStore} backend, the
 * claim set is loaded from the encrypted state store on first use and persisted
 * on every `record` / `consume`, so both an unconsumed claim AND a consumed
 * claim's single-use state survive a daemon restart (a consumed claim stays
 * consumed -> the cloud join is not replayable mid-TTL). The atomic gate is the
 * synchronous in-memory check (single-threaded event loop); the durable write is
 * ordered so a claim is NEVER consumed-as-approved unless its consumed state was
 * durably committed: the in-memory `consumed` flag is set, then persisted, and if
 * the persist FAILS the flag is rolled back and `consume` returns null (deny,
 * allow-without-durable-record is impossible). A corrupt durable record fails the
 * load and every consume DENIES (cannot prove unconsumed), never a silent reset.
 *
 * When constructed WITHOUT a backend (tests / non-persistent callers), it is a
 * pure in-memory store with the same single-use semantics.
 */
export class OperatorCloudProvisionClaimStore {
  private readonly claims = new Map<string, OperatorCloudProvisionClaim>();
  private readonly durable?: DurableClaimSetStore;
  /** Lazy one-time load of the durable set; null until the first record/consume. */
  private loadOnce: Promise<void> | null = null;

  constructor(durable?: DurableClaimSetStore) {
    this.durable = durable;
  }

  /**
   * Build a durable-backed store from the boot context (encrypted state store +
   * custody master). Any production wiring that records / consumes operator-cloud
   * provision claims uses this so single-use survives a restart.
   */
  static durableFromBoot(
    storage: StorageBackend,
    masterKey: Uint8Array,
  ): OperatorCloudProvisionClaimStore {
    return new OperatorCloudProvisionClaimStore(
      new DurableClaimSetStore({
        storage,
        masterKey,
        namespace: OPERATOR_CLOUD_CLAIM_STORE_NAMESPACE,
        recordKey: OPERATOR_CLOUD_CLAIM_STORE_KEY,
        hkdfLabel: OPERATOR_CLOUD_CLAIM_STORE_HKDF_INFO,
      }),
    );
  }

  private key(fortressId: string, nodeId: string, nonce: string): string {
    return `${fortressId} ${nodeId} ${nonce}`;
  }

  /**
   * Load the durable claim set into memory exactly once. THROWS (propagated, so
   * the caller fails closed) on a corrupt record. No-op for an in-memory store.
   */
  async init(nowMs = Date.now()): Promise<void> {
    if (!this.durable) return;
    if (this.loadOnce === null) {
      const durable = this.durable;
      this.loadOnce = durable.load(nowMs).then((loaded) => {
        for (const [key, claim] of loaded) this.claims.set(key, claim);
      });
    }
    await this.loadOnce;
  }

  /**
   * Record a Tier-1-approved claim. When durable, persists the claim set before
   * returning so a restart remembers it. THROWS if the durable persist fails (a
   * claim that was not durably committed must not be silently treated as
   * recorded).
   */
  async record(
    params: RecordProvisionClaimParams,
  ): Promise<OperatorCloudProvisionClaim> {
    await this.init();
    const claim: OperatorCloudProvisionClaim = {
      fortress_id: params.fortress_id,
      node_id: params.node_id,
      node_mode: "operator_cloud",
      node_pubkey_hash: params.node_pubkey_hash,
      bootstrap_nonce: params.bootstrap_nonce,
      manifest_digest: params.manifest_digest,
      scoped_secret_ciphertext_digest: params.scoped_secret_ciphertext_digest,
      scope_digest: params.scope_digest,
      bundle_digest: params.bundle_digest,
      expires_at: params.expires_at,
      consumed: false,
    };
    const key = this.key(params.fortress_id, params.node_id, params.bootstrap_nonce);
    this.claims.set(key, claim);
    if (this.durable) {
      try {
        await this.durable.persist(this.claims);
      } catch (err) {
        // The claim was not durably committed: roll back so we do not act on a
        // recorded-but-not-persisted claim, and surface the failure.
        this.claims.delete(key);
        throw err;
      }
    }
    return claim;
  }

  /** Peek a claim without consuming it (status surfaces). */
  async peek(
    fortressId: string,
    nodeId: string,
    nonce: string,
  ): Promise<OperatorCloudProvisionClaim | null> {
    await this.init();
    return this.claims.get(this.key(fortressId, nodeId, nonce)) ?? null;
  }

  /**
   * Atomically consume the matching claim if it is present, unconsumed, and
   * unexpired. Returns the claim on success; null otherwise (absent / consumed /
   * expired / durable-persist-failed). The caller verifies digest/pubkey bindings
   * BEFORE acting on it; `consume` only enforces single-use + expiry + durable
   * commit. When durable, the consumed flag is persisted before returning the
   * claim; if the persist FAILS the flag is rolled back and consume returns null
   * (fail closed). A corrupt durable record makes the load THROW (propagated so
   * the caller fails closed).
   */
  async consume(
    fortressId: string,
    nodeId: string,
    nonce: string,
    nowMs = Date.now(),
  ): Promise<OperatorCloudProvisionClaim | null> {
    await this.init(nowMs);
    const claim = this.claims.get(this.key(fortressId, nodeId, nonce));
    if (!claim) return null;
    if (claim.consumed) return null;
    if (Date.parse(claim.expires_at) < nowMs) return null;
    // Claim the slot synchronously before the await: a concurrent re-entrant
    // consume for the same claim in the same tick sees consumed === true above.
    claim.consumed = true;
    if (this.durable) {
      try {
        await this.durable.persist(this.claims);
      } catch {
        // The consumed state was NOT durably committed: roll back and DENY.
        claim.consumed = false;
        return null;
      }
    }
    return claim;
  }
}

export interface OperatorCloudJoinApproverParams {
  pinned_master_pubkey: FortressMasterPublicKey;
  issuing_principal_cert: PrincipalCertificate;
  issuing_principal_private_key: Uint8Array;
  master_private_key?: Uint8Array;
  claimStore: OperatorCloudProvisionClaimStore;
  /**
   * The node-scoped proof key for the node being provisioned, supplied by the
   * home node when it recorded the claim (the same derived transport key that
   * rode in the bundle's scoped-secret section). Used to verify the
   * operator-cloud join proof binding.
   */
  nodeJoinProofKey: Uint8Array;
  nowMs?: () => number;
  expiresAt?: string;
}

/**
 * Build the PRODUCTION operator-cloud join approver. It only issues a cert when
 * a Tier-1-approved provision claim matches the request EXACTLY:
 *   - bootstrap nonce + node id + fortress id locate the claim,
 *   - node_pubkey_hash binds the cert to the keypair the operator approved,
 *   - the operator-cloud join proof binds nonce + pubkey + bundle digest under
 *     the node-scoped proof key.
 * Any mismatch denies; the HTTP layer collapses denials to a uniform 401.
 */
export function createOperatorCloudJoinApprover(
  params: OperatorCloudJoinApproverParams,
): JoinApprover {
  return {
    async requestApproval(request: JoinRequest): Promise<JoinApprovalResult> {
      if (request.node_mode !== "operator_cloud") {
        return {
          approved: false,
          denial_reason: "operator-cloud approver only issues operator_cloud nodes",
        };
      }
      const nowMs = params.nowMs?.() ?? Date.now();
      const token = request.bootstrap_token;
      // The claim store may fail the durable load (corrupt record) -> fail
      // closed: a thrown load propagates as a denial, never a silent reset.
      let claim: OperatorCloudProvisionClaim | null;
      try {
        claim = await params.claimStore.consume(
          token.fortress_id,
          token.intended_node_id,
          token.nonce,
          nowMs,
        );
      } catch {
        return {
          approved: false,
          denial_reason: "operator-cloud provision-claim store unavailable",
        };
      }
      if (!claim) {
        return {
          approved: false,
          denial_reason: "no matching unconsumed approved provision claim",
        };
      }
      // Bind the cert to the keypair the operator approved (HIGH-1).
      const nodePubkeyHash = computeNodePubkeyHash(request.node_pubkey);
      if (nodePubkeyHash !== claim.node_pubkey_hash) {
        return {
          approved: false,
          denial_reason: "node_pubkey does not match approved provision claim",
        };
      }
      // Verify the operator-cloud join proof binds nonce + pubkey + bundle.
      const proofOk = verifyOperatorCloudJoinProof({
        nodeJoinProofKey: params.nodeJoinProofKey,
        fortressId: token.fortress_id,
        nodeId: token.intended_node_id,
        bootstrapNonce: token.nonce,
        nodePubkeyB64: request.node_pubkey,
        bundleDigest: claim.bundle_digest,
        proof: request.hkdf_salt_proof,
      });
      if (!proofOk) {
        return {
          approved: false,
          denial_reason: "operator-cloud join proof does not bind the approved bundle",
        };
      }
      // Defense-in-depth: reject a malformed node pubkey before issuance.
      try {
        if (fromBase64url(request.node_pubkey).length !== 32) {
          return { approved: false, denial_reason: "node_pubkey is not a 32-byte key" };
        }
      } catch {
        return { approved: false, denial_reason: "node_pubkey is malformed" };
      }
      const certificate = issueCertificateForApprovedJoin({
        request,
        pinned_master_pubkey: params.pinned_master_pubkey,
        issuing_principal_cert: params.issuing_principal_cert,
        issuing_principal_private_key: params.issuing_principal_private_key,
        master_private_key: params.master_private_key,
        expires_at: params.expiresAt,
      });
      return { approved: true, certificate };
    },
  };
}
