/**
 * Shared test fixture for policy-engine tests. Builds a real fortress with
 * real Ed25519 keys + real principal cert + real node cert via WP-MVP-3's
 * mesh surface. No crypto mocking.
 */

import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../src/mesh/constants.js";
import type { VerifyContext } from "../../src/mesh/envelope.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import type {
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

export interface TestFortress {
  master: ReturnType<typeof generateFortressMaster>;
  principalKeypair: ReturnType<typeof generateKeypair>;
  principalCert: PrincipalCertificate;
  nodeKeypair: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
}

export function buildFortress(principalId = "root"): TestFortress {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: principalId,
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const nodeKeypair = generateKeypair();
  const nodeCert = issueNodeIdentityCertificate({
    node_id: "node-" + toBase64url(randomBytes(4)),
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: principalId,
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
  });
  return { master, principalKeypair, principalCert, nodeKeypair, nodeCert };
}

export function verifyCtxFor(f: TestFortress): VerifyContext {
  return {
    pinnedMasterPubkey: f.master.public,
    lookupNodeCert: (id) => (id === f.nodeCert.node_id ? f.nodeCert : undefined),
    lookupPrincipalCert: (id) =>
      id === f.principalCert.principal_id ? f.principalCert : undefined,
  };
}
