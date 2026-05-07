/**
 * Sanctuary v1.2.x Activity feed per-action attestation projection.
 *
 * Asserts that `aggregateActivity` populates the optional `attestation`
 * field on every projected `HubActivityFeedEntry`:
 *   1. Successful audit entries render `state: "verified"`.
 *   2. Failed audit entries render `state: "degraded"`.
 *   3. Distinct entry ids derive distinct fragments.
 *   4. Fragment shape is `<4hex>..<2hex>` (matches Sprint Piece 2 gallery).
 *
 * Real AuditLog over MemoryStorage; no mocks at the projection layer.
 *
 * Note on integrity claims: the fragment is a deterministic projection of
 * the audit-chain entry id, NOT a per-event Ed25519 signature. The audit
 * chain itself is the integrity claim.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { aggregateActivity } from "../../src/hub/activity-feed.js";

const IDENTITY_ID = "operator-attestation-projection-001";

interface Rig {
  auditLog: AuditLog;
}

async function startRig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  return { auditLog };
}

describe("Activity feed: per-action attestation projection", () => {
  let rig: Rig;
  beforeEach(async () => (rig = await startRig()));
  afterEach(() => undefined);

  it("successful entries render attestation.state = 'verified'", async () => {
    rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.attestation).toBeDefined();
    expect(entries[0]!.attestation!.state).toBe("verified");
  });

  it("failed entries render attestation.state = 'degraded'", async () => {
    rig.auditLog.append("l2", "policy_deny", IDENTITY_ID, {}, "failure");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.attestation).toBeDefined();
    expect(entries[0]!.attestation!.state).toBe("degraded");
  });

  it("distinct entry ids derive distinct fragments", async () => {
    rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    // Force a different timestamp so the synthesized entry_id differs.
    await new Promise((resolve) => setTimeout(resolve, 5));
    rig.auditLog.append("l2", "approval_granted", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(2);
    const fragments = entries.map((e) => e.attestation!.fragment);
    expect(fragments[0]).not.toBe(fragments[1]);
  });

  it("fragment shape is '<4hex>..<2hex>' (6 hex chars + dots)", async () => {
    rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    const fragment = entries[0]!.attestation!.fragment;
    expect(fragment).toMatch(/^[0-9a-f]{4}\.\.[0-9a-f]{2}$/);
  });
});
