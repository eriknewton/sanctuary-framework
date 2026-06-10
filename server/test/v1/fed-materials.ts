/**
 * Shared federation test materials (PR-A3).
 *
 * Builds a self-consistent fortress: an Ed25519 master keypair (trust root),
 * a symmetric fortress-master secret (HKDF source for node transport keys), a
 * Root principal certificate signed by the master, and a {@link
 * FederationContext} the join ceremony consumes. `assembleJoinRequest` (the
 * real CLI path) is used to produce JoinRequests so tests exercise both sides
 * of the ceremony against the SAME primitives.
 */

import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import {
  generateFortressMaster,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import type { FederationContext } from "../../src/v1/federation.js";
import { assembleJoinRequest } from "../../src/cli/federation.js";

export interface FedMaterials {
  context: FederationContext;
  fortressId: string;
  /** 32-byte symmetric fortress-master secret (out-of-band to a joining node). */
  masterSecret: Uint8Array;
}

export function makeFederationMaterials(opts?: {
  approver?: FederationContext["approver"];
}): FedMaterials {
  const master = generateFortressMaster();
  const fortressId = master.public.fortress_id;
  const masterSecret = randomBytes(32);

  const principalPriv = randomBytes(32);
  const principalPub = ed25519.getPublicKey(principalPriv);
  const principalId = "principal-root";
  const principalCert = issuePrincipalCertificate({
    principal_id: principalId,
    principal_pubkey: principalPub,
    role: "Root",
    fortress_id: fortressId,
    master_private_key: master.private_key,
  });

  const context: FederationContext = {
    fortressId,
    nodeId: "fortress-node-1",
    pinnedMasterPubkey: master.public,
    issuingPrincipalCert: principalCert,
    getIssuingPrincipalPrivateKey: () => principalPriv,
    getFortressMasterSecret: () => masterSecret,
    getMasterPrivateKey: () => master.private_key,
    ...(opts?.approver ? { approver: opts.approver } : {}),
  };

  return { context, fortressId, masterSecret };
}

export { assembleJoinRequest };
