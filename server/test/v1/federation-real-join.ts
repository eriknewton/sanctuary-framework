/**
 * Real-join test helper (Slice 3c support).
 *
 * Drives a REAL join ceremony in-process against a drill-seeded ISSUER fortress
 * and returns exactly what the joiner side legitimately receives: the issued
 * node certificate, the issuing principal cert, the joiner's own node private
 * key, and the bootstrap token. The approval gate is supplied HERE, in the test
 * layer (using the real `issueCertificateForApprovedJoin` primitive), NOT in the
 * drill seed: the seed composes production functions and injects no approver.
 *
 * This is the input a real `federation join --persist` / a joiner seed consumes:
 * a joiner only ever persists what a real join yields, never fabricated issuer
 * material.
 */

import { JoinCeremony, type FederationIssuerContext } from "../../src/v1/federation.js";
import {
  createAutoApproveJoinApprover,
} from "../../src/mesh/lifecycle/join-approver.js";
import { assembleJoinRequest } from "../../src/cli/federation.js";
import { toBase64url, fromBase64url } from "../../src/core/encoding.js";
import type {
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";
import type { BootstrapToken } from "../../src/mesh/lifecycle/types.js";
import type { PeerSyncIdentity } from "../../src/v1/federation-client.js";
import type { SeededIssuerFortress } from "../util/federation-drill-seed.js";
import { makeMultiNodeFortress } from "./fed-materials.js";

export interface JoinerCeremonyResult {
  bootstrapToken: BootstrapToken;
  certificate: NodeIdentityCertificate;
  issuingPrincipalCert: PrincipalCertificate;
  /** The joiner's OWN node private key (transient; caller owns zeroing). */
  localNodePrivateKey: Uint8Array;
  /** base64url fortress master secret (out-of-band channel for the join proof). */
  masterSecretB64: string;
}

/**
 * Build a `FederationIssuerContext` from a seeded issuer fortress, attaching a
 * test-supplied approval gate. The auto-approve approver is the TEST'S choice
 * here (the production gate is wired by the dashboard/console thread); the drill
 * seed does NOT carry it.
 */
export function issuerContextWithApprover(
  issuer: SeededIssuerFortress,
): FederationIssuerContext {
  const base = issuer.trustRoot.context;
  return {
    ...base,
    approver: createAutoApproveJoinApprover({
      pinned_master_pubkey: issuer.pinnedMaster,
      issuing_principal_cert: issuer.issuingPrincipalCert,
      issuing_principal_private_key: base.getIssuingPrincipalPrivateKey(),
      master_private_key: base.getMasterPrivateKey?.(),
    }),
  } as FederationIssuerContext;
}

/**
 * Run a real authorize-init -> assemble -> authorize-complete ceremony for
 * `joinerNodeId` against the seeded issuer, and return the joiner-side result.
 */
export async function buildJoinerCeremonyResult(
  issuer: SeededIssuerFortress,
  joinerNodeId: string,
): Promise<JoinerCeremonyResult> {
  const ctx = issuerContextWithApprover(issuer);
  const ceremony = new JoinCeremony(ctx);
  const bootstrapToken = ceremony.authorizeInit({
    intendedNodeId: joinerNodeId,
    intendedNodeMode: "local",
  });

  const assembled = assembleJoinRequest({
    bootstrapToken,
    fortressMasterSecret: issuer.masterSecret,
  });

  const outcome = await new JoinCeremony(ctx).authorizeComplete(assembled.joinRequest);
  if (!outcome.approved) {
    assembled.nodePrivateKey.fill(0);
    throw new Error(`real join ceremony was denied: ${outcome.denialReason}`);
  }
  // Sanity: the issued cert's pubkey matches the joiner's generated keypair.
  if (
    outcome.certificate.node_pubkey !== toBase64url(assembled.nodePublicKey)
  ) {
    assembled.nodePrivateKey.fill(0);
    throw new Error("issued cert node_pubkey does not match the assembled join keypair");
  }

  return {
    bootstrapToken,
    certificate: outcome.certificate,
    issuingPrincipalCert: outcome.issuingPrincipalCert,
    localNodePrivateKey: assembled.nodePrivateKey,
    masterSecretB64: toBase64url(issuer.masterSecret),
  };
}

/** Decode a node private key copy (helper for callers building a PeerSyncIdentity). */
export function nodePrivateKeyCopy(key: Uint8Array): Uint8Array {
  return Uint8Array.from(key);
}

/**
 * An in-process `authorize/complete` responder bound to the seeded issuer, for
 * injecting as the CLI `request` seam. It runs the REAL `JoinCeremony` against
 * the actual JoinRequest body the verb submits, so the issued cert is bound to
 * the verb's freshly-generated node keypair (the cert pubkey matches the key the
 * verb persists). A non-`authorize/complete` path is rejected so the stub never
 * silently masks an unexpected request.
 */
export function makeIssuerCompleteResponder(
  issuer: SeededIssuerFortress,
): (path: string, init?: { body?: unknown }) => Promise<{
  certificate: NodeIdentityCertificate;
  issuing_principal_cert: PrincipalCertificate;
}> {
  const ctx = issuerContextWithApprover(issuer);
  return async (path, init) => {
    if (path !== "/v1/federation/authorize/complete") {
      throw new Error(`unexpected request path in issuer responder: ${path}`);
    }
    const request = JSON.parse(String(init?.body)) as Parameters<
      JoinCeremony["authorizeComplete"]
    >[0];
    const outcome = await new JoinCeremony(ctx).authorizeComplete(request);
    if (!outcome.approved) {
      const { DashboardRequestError } = await import(
        "../../src/cli/dashboard-request.js"
      );
      throw new DashboardRequestError(outcome.denialReason, "auth", 401);
    }
    return {
      certificate: outcome.certificate,
      issuing_principal_cert: outcome.issuingPrincipalCert,
    };
  };
}

/**
 * Build a whole SEPARATE fortress (different master, different operator) with a
 * single node + a PeerSyncIdentity, for the cross-operator isolation assertion:
 * its cert chains to its OWN master, not the joiner's pinned master, so a peer
 * sync from it is rejected.
 */
export function makeMultiNodeStranger(nodeId: string): { peerIdentity: PeerSyncIdentity } {
  const fortress = makeMultiNodeFortress([nodeId]);
  return { peerIdentity: fortress.nodes[nodeId]!.peerIdentity };
}

/** Re-export for callers that need to round-trip a node pubkey. */
export { fromBase64url };
