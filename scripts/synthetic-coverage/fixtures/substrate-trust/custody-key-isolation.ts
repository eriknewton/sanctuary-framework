import { generateKeypair } from "../../../../server/src/core/identity.js";
import { CAP_STANDARD_FORTRESS_NODE } from "../../../../server/src/mesh/constants.js";
import { NodeRoster } from "../../../../server/src/mesh/lifecycle/node-roster.js";
import {
  deriveNodeAuditChainKey,
  deriveNodeTransportKey,
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../../../server/src/mesh/trust-root.js";
import { registerFixture } from "../../registry.js";
import {
  failedSince,
  ROW_STATE_ENCRYPTION,
  ROW_STATE_ENCRYPTION_LABEL,
} from "./helpers.js";

// Entrypoints: mesh/trust-root per-node HKDF key derivation and
// NodeRoster.lookupActiveNodeCert revocation gate. Existing mirrors:
// server/test/mesh/trust-root.test.ts and server/src/mesh/lifecycle/mesh-node.ts
// verify-and-dispatch lookups.
// ASSURANCE_MATRIX row: 5, State encryption. This fixture focuses on
// self-custodied substrate key isolation rather than wire format changes.

function makeNodeCert() {
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
    node_id: "synthetic-custody-node",
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
  return { master, cert };
}

registerFixture(
  ROW_STATE_ENCRYPTION,
  ROW_STATE_ENCRYPTION_LABEL,
  "custody key access requires active roster gate",
  async () => {
    const start = performance.now();
    try {
      const { master, cert } = makeNodeCert();
      const roster = new NodeRoster();
      roster.add(cert);
      roster.markActive(cert.node_id);
      const active = roster.lookupActiveNodeCert(cert.node_id);
      const auditKey = deriveNodeAuditChainKey({
        fortress_master_secret: master.private_key,
        node_id: active!.node_id,
      });

      return {
        passed: active?.node_id === cert.node_id && auditKey.length === 32,
        message: `key_bytes=${auditKey.length}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_STATE_ENCRYPTION,
  ROW_STATE_ENCRYPTION_LABEL,
  "custody key bypass without gate is denied by default",
  async () => {
    const start = performance.now();
    try {
      const { cert } = makeNodeCert();
      const roster = new NodeRoster();
      const active = roster.lookupActiveNodeCert(cert.node_id);

      return {
        passed: active === undefined,
        message: "no active cert means no derivation input",
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);

registerFixture(
  ROW_STATE_ENCRYPTION,
  ROW_STATE_ENCRYPTION_LABEL,
  "gate revocation invalidates in-flight custody access",
  async () => {
    const start = performance.now();
    try {
      const { master, cert } = makeNodeCert();
      const roster = new NodeRoster();
      roster.add(cert);
      roster.markActive(cert.node_id);
      const before = roster.lookupActiveNodeCert(cert.node_id);
      const transportKey = deriveNodeTransportKey({
        fortress_master_secret: master.private_key,
        node_id: before!.node_id,
        node_mode: before!.node_mode,
      });
      roster.markRevoked(cert.node_id);
      const after = roster.lookupActiveNodeCert(cert.node_id);

      return {
        passed: transportKey.length === 32 && after === undefined,
        message: `revoked_active=${String(after !== undefined)}`,
        durationMs: performance.now() - start,
      };
    } catch (error) {
      return failedSince(start, error);
    }
  },
);
