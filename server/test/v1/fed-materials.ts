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
  issueNodeIdentityCertificate,
} from "../../src/mesh/trust-root.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import { generateNodeKeypair } from "../../src/mesh/lifecycle/join-approver.js";
import type {
  FortressMasterPublicKey,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";
import type { FederationContext } from "../../src/v1/federation.js";
import type { PeerSyncIdentity } from "../../src/v1/federation-client.js";
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

// ── PR-A5 multi-node fortress (the cross-machine marquee) ──────────────────

/** One operator's machine: a node identity bound into one shared fortress. */
export interface FortressNode {
  nodeId: string;
  nodeCert: NodeIdentityCertificate;
  nodePrivateKey: Uint8Array;
  /** FederationContext for this node's daemon (same pinned master as its peers). */
  context: FederationContext;
  /** PeerSyncIdentity this node uses to drive an outbound peer sync. */
  peerIdentity: PeerSyncIdentity;
}

export interface MultiNodeFortress {
  fortressId: string;
  pinnedMaster: FortressMasterPublicKey;
  principalCert: PrincipalCertificate;
  masterSecret: Uint8Array;
  /** Each named machine's identity, all chaining to the one shared master. */
  nodes: Record<string, FortressNode>;
}

/**
 * Build ONE fortress (one master, one Root principal) with several named node
 * identities — the marquee's "one operator, many machines." Every node's cert
 * chains to the SAME pinned master, so each daemon recognizes the others by
 * cert-chain verification, with no implicit trust. Each node gets a daemon
 * `FederationContext` (carrying its own node cert + key for the reciprocal
 * envelope) and a `PeerSyncIdentity` for driving outbound syncs.
 */
export function makeMultiNodeFortress(nodeIds: string[]): MultiNodeFortress {
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

  const nodes: Record<string, FortressNode> = {};
  for (const nodeId of nodeIds) {
    const { publicKey, privateKey } = generateNodeKeypair();
    const nodeCert = issueNodeIdentityCertificate({
      node_id: nodeId,
      node_pubkey: publicKey,
      node_mode: "local",
      fortress_id: fortressId,
      capabilities: CAP_STANDARD_FORTRESS_NODE,
      parent_chain: {
        fortress_master_pubkey: master.public.public_key,
        principal_id: principalId,
        principal_pubkey: principalCert.principal_pubkey,
      },
      principal_private_key: principalPriv,
      master_private_key: master.private_key,
    });

    const context: FederationContext = {
      fortressId,
      nodeId,
      pinnedMasterPubkey: master.public,
      issuingPrincipalCert: principalCert,
      getIssuingPrincipalPrivateKey: () => principalPriv,
      getFortressMasterSecret: () => masterSecret,
      getMasterPrivateKey: () => master.private_key,
      localNodeCert: nodeCert,
      getLocalNodePrivateKey: () => privateKey,
    };

    const peerIdentity: PeerSyncIdentity = {
      fortressId,
      nodeId,
      nodeCert,
      issuingPrincipalCert: principalCert,
      nodePrivateKey: privateKey,
      pinnedMaster: master.public,
    };

    nodes[nodeId] = { nodeId, nodeCert, nodePrivateKey: privateKey, context, peerIdentity };
  }

  return { fortressId, pinnedMaster: master.public, principalCert, masterSecret, nodes };
}

export { assembleJoinRequest };
