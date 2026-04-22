/**
 * Agent Contract v0.1 — Test Fixture.
 *
 * Builds a real fortress (master + principal + node) and a
 * mesh VerifyContext that points at that fortress, so Agent-Contract tests
 * can exercise issue + verify paths against real crypto. No mocks.
 */

import { generateKeypair } from "../../src/core/identity.js";
import { randomBytes } from "../../src/core/random.js";
import { toBase64url } from "../../src/core/encoding.js";
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

export interface TestFortressContext {
  master: ReturnType<typeof generateFortressMaster>;
  principalKeypair: ReturnType<typeof generateKeypair>;
  principalCert: PrincipalCertificate;
  nodeKeypair: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
  /** Simulated fortress-master secret used for per-agent key derivation. */
  fortressMasterSecret: Uint8Array;
  /** Ready-to-use VerifyContext pinning this fortress. */
  verifyContext: VerifyContext;
}

export function buildTestFortress(
  principalId = "root"
): TestFortressContext {
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

  // Separate 32-byte secret for per-agent HKDF — distinct from the
  // fortress-master signing seed. In production this is the
  // operator-passphrase-derived master secret (Argon2id). For tests any
  // 32 random bytes work.
  const fortressMasterSecret = randomBytes(32);

  const verifyContext: VerifyContext = {
    pinnedMasterPubkey: master.public,
    lookupNodeCert: (id) => (id === nodeCert.node_id ? nodeCert : undefined),
    lookupPrincipalCert: (id) =>
      id === principalCert.principal_id ? principalCert : undefined,
  };

  return {
    master,
    principalKeypair,
    principalCert,
    nodeKeypair,
    nodeCert,
    fortressMasterSecret,
    verifyContext,
  };
}

/**
 * Build a minimal canonical-JSON blob representing a pinned policy. The
 * content of the blob is opaque to the Agent Contract layer — all that
 * matters is that issuance + verification use the same bytes so the hashes
 * agree.
 */
export function buildPolicyBlobBytes(policy_version: number): Uint8Array {
  const json = JSON.stringify({
    fake_policy: true,
    policy_version,
  });
  return new TextEncoder().encode(json);
}
