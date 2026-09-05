import { toBase64url } from "../../../../server/src/core/encoding.js";
import { generateKeypair } from "../../../../server/src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../../../server/src/mesh/constants.js";
import { MeshChainError } from "../../../../server/src/mesh/errors.js";
import { NodeRoster } from "../../../../server/src/mesh/lifecycle/node-roster.js";
import {
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
  verifyCertChain,
} from "../../../../server/src/mesh/trust-root.js";
import type { NodeIdentityCertificate } from "../../../../server/src/mesh/types.js";
import { registerFixture } from "../../registry.js";
import {
  failedSince,
  ROW_DID_KEY,
  ROW_DID_KEY_LABEL,
} from "./helpers.js";

// Entrypoints: mesh/trust-root.verifyCertChain and
// mesh/lifecycle/node-roster.lookupActiveNodeCert. Existing mirror:
// server/test/mesh/trust-root.test.ts.
// ASSURANCE_MATRIX row: 19, did:key encoding. This fixture binds the same
// identity-key material to the node certificate resolution path.

function makeCertRig() {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const nodeKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: "synthetic-root",
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const cert = issueNodeIdentityCertificate({
    node_id: "synthetic-node",
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: principalCert.principal_id,
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
    master_private_key: master.private_key,
  });
  return { master, principalCert, cert, nodePublicKey: toBase64url(nodeKeypair.publicKey) };
}

function malformedCert(cert: NodeIdentityCertificate): NodeIdentityCertificate {
  return {
    ...cert,
    node_pubkey: "not-valid-base64url!",
  };
}

registerFixture(
  ROW_DID_KEY,
  ROW_DID_KEY_LABEL,
  "known node certificate resolves to expected signing key",
  async () => {
    const start = performance.now();
    try {
      const { master, principalCert, cert, nodePublicKey } = makeCertRig();
      verifyCertChain(cert, principalCert, master.public);
      const roster = new NodeRoster();
      roster.add(cert);
      roster.markActive(cert.node_id);
      const resolved = roster.lookupActiveNodeCert(cert.node_id);

      return {
        passed: resolved?.node_pubkey === nodePublicKey,
        message: `resolved=${resolved?.node_id ?? "missing"}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_DID_KEY,
  ROW_DID_KEY_LABEL,
  "unknown certificate lookup has no silent default key",
  async () => {
    const start = performance.now();
    try {
      const { cert } = makeCertRig();
      const roster = new NodeRoster();
      roster.add(cert);
      roster.markActive(cert.node_id);
      const resolved = roster.lookupActiveNodeCert("missing-node");

      return {
        passed: resolved === undefined,
        message: "lookup returned undefined for unknown node",
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_DID_KEY,
  ROW_DID_KEY_LABEL,
  "malformed certificate key field is rejected",
  async () => {
    const start = performance.now();
    try {
      const { master, principalCert, cert } = makeCertRig();
      try {
        verifyCertChain(malformedCert(cert), principalCert, master.public);
      } catch (error) {
        return {
          passed: error instanceof MeshChainError,
          message: error instanceof Error ? error.name : String(error),
          durationMs: performance.now() - start,
        };
      }
      return {
        passed: false,
        message: "malformed certificate unexpectedly verified",
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);
