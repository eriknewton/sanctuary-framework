/**
 * Sanctuary Federation Protocol v0.1 — AuditBatch Tests
 *
 * Exercises: batch sealing, per-entry signing, HKDF chain proof, monotonic
 * rollback detection, prev_batch_hash continuity, signature_scheme crypto-agility.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { generateKeypair } from "../../src/core/identity.js";
import { toBase64url } from "../../src/core/encoding.js";
import { randomBytes } from "../../src/core/random.js";
import {
  sealAuditBatch,
  sealAuditEntry,
  verifyAuditBatch,
  type VerifyBatchContext,
} from "../../src/mesh/audit-batch.js";
import {
  CAP_STANDARD_FORTRESS_NODE,
  SIGNATURE_SCHEME_V1,
} from "../../src/mesh/constants.js";
import {
  MeshAuditBatchError,
  MeshChainDiscontinuityError,
  MeshRollbackDetectedError,
  MeshSignatureError,
} from "../../src/mesh/errors.js";
import {
  deriveNodeAuditChainKey,
  generateFortressMaster,
  issueNodeIdentityCertificate,
  issuePrincipalCertificate,
} from "../../src/mesh/trust-root.js";
import type {
  AuditBatch,
  AuditEntry,
  NodeIdentityCertificate,
  PrincipalCertificate,
} from "../../src/mesh/types.js";

interface TestEmitter {
  master: ReturnType<typeof generateFortressMaster>;
  principalKeypair: ReturnType<typeof generateKeypair>;
  principalCert: PrincipalCertificate;
  nodeKeypair: ReturnType<typeof generateKeypair>;
  nodeCert: NodeIdentityCertificate;
  auditChainKey: Uint8Array;
}

function buildEmitter(): TestEmitter {
  const master = generateFortressMaster();
  const principalKeypair = generateKeypair();
  const principalCert = issuePrincipalCertificate({
    principal_id: "root",
    principal_pubkey: principalKeypair.publicKey,
    role: "root",
    fortress_id: master.public.fortress_id,
    master_private_key: master.private_key,
  });
  const nodeKeypair = generateKeypair();
  const nodeId = "node-" + toBase64url(randomBytes(4));
  const nodeCert = issueNodeIdentityCertificate({
    node_id: nodeId,
    node_pubkey: nodeKeypair.publicKey,
    node_mode: "local",
    fortress_id: master.public.fortress_id,
    capabilities: CAP_STANDARD_FORTRESS_NODE,
    parent_chain: {
      fortress_master_pubkey: master.public.public_key,
      principal_id: "root",
      principal_pubkey: principalCert.principal_pubkey,
    },
    principal_private_key: principalKeypair.privateKey,
  });
  const auditChainKey = deriveNodeAuditChainKey({
    fortress_master_secret: master.private_key,
    node_id: nodeId,
  });
  return {
    master,
    principalKeypair,
    principalCert,
    nodeKeypair,
    nodeCert,
    auditChainKey,
  };
}

function contextFor(
  e: TestEmitter,
  previousByNode: Map<string, AuditBatch | null>
): VerifyBatchContext {
  return {
    pinnedMasterPubkey: e.master.public,
    lookupNodeCert: (id) => (id === e.nodeCert.node_id ? e.nodeCert : undefined),
    lookupPrincipalCert: (id) =>
      id === e.principalCert.principal_id ? e.principalCert : undefined,
    lookupAuditChainKey: (id) =>
      id === e.nodeCert.node_id ? e.auditChainKey : undefined,
    lookupPreviousBatch: (id) => previousByNode.get(id) ?? null,
  };
}

function makeEntry(e: TestEmitter, agent: string): AuditEntry {
  return sealAuditEntry({
    emitter_node: e.nodeCert.node_id,
    emitter_agent: agent,
    emitter_principal: "root",
    policy_version: 1,
    attestation_state: "verified",
    payload: { action: "tool_call", tool: "state_read" },
    node_private_key: e.nodeKeypair.privateKey,
  });
}

describe("mesh/audit-batch — seal + verify happy path", () => {
  it("seals and verifies a first batch (batch_seq=0)", () => {
    const e = buildEmitter();
    const entries = [makeEntry(e, "agent-a"), makeEntry(e, "agent-b")];
    const batch = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries,
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    expect(batch.batch_seq).toBe(0);
    expect(batch.prev_batch_hash).toBe("");
    expect(batch.hkdf_chain_proof).toBeTruthy();
    expect(batch.entries).toHaveLength(2);

    const prev = new Map<string, AuditBatch | null>();
    expect(() => verifyAuditBatch(batch, contextFor(e, prev))).not.toThrow();
  });

  it("seals and verifies a chain of three batches with monotonic batch_seq + prev_batch_hash continuity", () => {
    const e = buildEmitter();
    const prev = new Map<string, AuditBatch | null>();

    const b0 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [makeEntry(e, "agent-a")],
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b0, contextFor(e, prev));
    prev.set(e.nodeCert.node_id, b0);

    const b1 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 1,
      entries: [makeEntry(e, "agent-b")],
      previous_batch: b0,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b1, contextFor(e, prev));
    prev.set(e.nodeCert.node_id, b1);

    const b2 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 2,
      entries: [makeEntry(e, "agent-c")],
      previous_batch: b1,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b2, contextFor(e, prev));
  });
});

describe("mesh/audit-batch — rollback + chain-discontinuity canaries (§8.3)", () => {
  it("detects batch_seq rollback (same emitter resubmitting an earlier sequence)", () => {
    const e = buildEmitter();
    const prev = new Map<string, AuditBatch | null>();
    const b0 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [makeEntry(e, "agent-a")],
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b0, contextFor(e, prev));
    prev.set(e.nodeCert.node_id, b0);
    const b1 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 1,
      entries: [makeEntry(e, "agent-b")],
      previous_batch: b0,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b1, contextFor(e, prev));
    prev.set(e.nodeCert.node_id, b1);

    // Attacker replays b0 — batch_seq=0 but we expect 2. Rollback canary fires.
    expect(() => verifyAuditBatch(b0, contextFor(e, prev))).toThrow(
      MeshRollbackDetectedError
    );
  });

  it("detects chain discontinuity (new batch_seq advances by 1 but prev_batch_hash wrong)", () => {
    const e = buildEmitter();
    const prev = new Map<string, AuditBatch | null>();
    const b0 = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [makeEntry(e, "agent-a")],
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    verifyAuditBatch(b0, contextFor(e, prev));
    prev.set(e.nodeCert.node_id, b0);

    // Attacker crafts a "b1" with a tampered prev_batch_hash that does not match
    // the canonical audit log's record of b0. We hand-forge because sealAuditBatch
    // always computes the correct hash.
    const fakeB0 = { ...b0, prev_batch_hash: "tampered-hash-bytes" };
    // Attacker signs a b1 that points at the fake prior.
    expect(() => {
      const b1 = sealAuditBatch({
        emitter_node: e.nodeCert.node_id,
        batch_seq: 1,
        entries: [makeEntry(e, "agent-b")],
        previous_batch: fakeB0,
        node_audit_chain_key: e.auditChainKey,
        node_private_key: e.nodeKeypair.privateKey,
      });
      verifyAuditBatch(b1, contextFor(e, prev));
    }).toThrow(MeshChainDiscontinuityError);
  });

  it("rejects first-batch claim with non-zero batch_seq", () => {
    const e = buildEmitter();
    expect(() =>
      sealAuditBatch({
        emitter_node: e.nodeCert.node_id,
        batch_seq: 5,
        entries: [makeEntry(e, "agent-a")],
        previous_batch: null,
        node_audit_chain_key: e.auditChainKey,
        node_private_key: e.nodeKeypair.privateKey,
      })
    ).toThrow(MeshAuditBatchError);
  });
});

describe("mesh/audit-batch — HKDF chain-proof protects against stolen signing key without master", () => {
  it("rejects a batch whose HKDF chain proof was produced with a wrong chain key", () => {
    const e = buildEmitter();
    const prev = new Map<string, AuditBatch | null>();
    // Attacker has the per-node signing key (nodeKeypair.privateKey) but NOT the
    // master-derived chain key. They compute a bogus chain key.
    const attackerChainKey = randomBytes(32);
    const bogus = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [makeEntry(e, "agent-a")],
      previous_batch: null,
      node_audit_chain_key: attackerChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    // Signature verifies (real per-node key) but HKDF proof fails (wrong chain key).
    expect(() => verifyAuditBatch(bogus, contextFor(e, prev))).toThrow(
      MeshAuditBatchError
    );
  });
});

describe("mesh/audit-batch — per-entry signature verification", () => {
  it("rejects a batch containing an entry signed by a foreign key", () => {
    const e = buildEmitter();
    const good = makeEntry(e, "agent-a");
    const impostorKeypair = generateKeypair();
    const badEntry = sealAuditEntry({
      emitter_node: e.nodeCert.node_id,
      emitter_agent: "agent-b",
      emitter_principal: "root",
      policy_version: 1,
      attestation_state: "verified",
      payload: { action: "tool_call" },
      node_private_key: impostorKeypair.privateKey,
    });
    const batch = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [good, badEntry],
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    const prev = new Map<string, AuditBatch | null>();
    expect(() => verifyAuditBatch(batch, contextFor(e, prev))).toThrow(
      MeshSignatureError
    );
  });

  it("rejects entry with unknown signature_scheme (crypto-agility at v1.0)", () => {
    const e = buildEmitter();
    const entry = makeEntry(e, "agent-a");
    const v1xEntry = {
      ...entry,
      signature_scheme: "ed25519+ml-dsa-v1",
    } as unknown as AuditEntry;
    const batch = sealAuditBatch({
      emitter_node: e.nodeCert.node_id,
      batch_seq: 0,
      entries: [v1xEntry],
      previous_batch: null,
      node_audit_chain_key: e.auditChainKey,
      node_private_key: e.nodeKeypair.privateKey,
    });
    const prev = new Map<string, AuditBatch | null>();
    expect(() => verifyAuditBatch(batch, contextFor(e, prev))).toThrow(
      MeshSignatureError
    );
  });

  it("v1.0 signature_scheme value is the only accepted one", () => {
    expect(SIGNATURE_SCHEME_V1).toBe("ed25519-v1");
  });
});
