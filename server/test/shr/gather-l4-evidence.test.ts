/**
 * gatherReputationEvidence (v0.9.1)
 *
 * End-to-end test that the helper assembles `L4Evidence` correctly from
 * a live ReputationStore + AuditLog, including the `verascore_linked`
 * signal derived from audit-log scanning.
 */

import { describe, it, expect } from "vitest";
import { gatherReputationEvidence } from "../../src/shr/tools.js";
import { ReputationStore } from "../../src/reputation/reputation-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";

function setup() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new ReputationStore(storage, masterKey);
  const encryptionKey = derivePurposeKey(masterKey, "identity-encryption");
  const { storedIdentity } = createIdentity("test", encryptionKey, "recovery-key");
  return { storage, masterKey, auditLog, store, identity: storedIdentity, encryptionKey };
}

describe("gatherReputationEvidence", () => {
  it("returns an empty evidence object for a fresh identity", async () => {
    const { store, auditLog, identity } = setup();
    const ev = await gatherReputationEvidence(store, auditLog, identity);
    expect(ev.attestation_count).toBe(0);
    expect(ev.verascore_linked).toBe(false);
    expect(ev.most_recent_attestation_at).toBeNull();
    expect(ev.dispute_count).toBe(0);
  });

  it("picks up recorded attestations for the identity", async () => {
    const { store, auditLog, identity, encryptionKey } = setup();
    await store.record(
      "txn-1",
      "did:key:cp",
      { type: "transaction", result: "completed" },
      "commerce",
      identity,
      encryptionKey,
      undefined,
      "verified-sovereign"
    );
    const ev = await gatherReputationEvidence(store, auditLog, identity);
    expect(ev.attestation_count).toBe(1);
    expect(ev.tier_distribution["verified-sovereign"]).toBe(1);
    expect(ev.most_recent_attestation_at).toBeTruthy();
  });

  it("marks verascore_linked=true when reputation_publish succeeded for this identity", async () => {
    const { store, auditLog, identity } = setup();
    await auditLog.append(
      "l4",
      "reputation_publish",
      identity.identity_id,
      undefined,
      "success"
    );
    const ev = await gatherReputationEvidence(store, auditLog, identity);
    expect(ev.verascore_linked).toBe(true);
  });

  it("does NOT flip verascore_linked on a failed reputation_publish", async () => {
    const { store, auditLog, identity } = setup();
    await auditLog.append(
      "l4",
      "reputation_publish",
      identity.identity_id,
      undefined,
      "failure"
    );
    const ev = await gatherReputationEvidence(store, auditLog, identity);
    expect(ev.verascore_linked).toBe(false);
  });

  it("ignores reputation_publish entries attributed to a different identity", async () => {
    const { store, auditLog, identity } = setup();
    await auditLog.append(
      "l4",
      "reputation_publish",
      "some-other-identity",
      undefined,
      "success"
    );
    const ev = await gatherReputationEvidence(store, auditLog, identity);
    expect(ev.verascore_linked).toBe(false);
  });
});
