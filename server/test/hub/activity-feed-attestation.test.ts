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
import { AuditLog } from "../../src/operational/audit-log.js";
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
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
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
    await rig.auditLog.append("l2", "policy_deny", IDENTITY_ID, {}, "failure");
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
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    // Force a different timestamp so the synthesized entry_id differs.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await rig.auditLog.append("l2", "approval_granted", IDENTITY_ID, {}, "success");
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
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {}, "success");
    await rig.auditLog.flush();
    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    const fragment = entries[0]!.attestation!.fragment;
    expect(fragment).toMatch(/^[0-9a-f]{4}\.\.[0-9a-f]{2}$/);
  });

  it("forged unsigned Castle Wall entries do not attribute to a victim or render verified", async () => {
    await rig.auditLog.append(
      "l1",
      "egress_blocked",
      IDENTITY_ID,
      {
        agent_id: "victim-agent-b",
        dest_host: "evil.example",
        dest_ip: "203.0.113.99",
        dest_port: 443,
        dest_protocol: "tcp",
      },
      "success",
    );
    await rig.auditLog.flush();

    const entries = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { limit: 10 },
    );
    expect(entries).toHaveLength(1);
    expect(entries[0]!.agent_id).toBeUndefined();
    expect(entries[0]!.display_template_args).not.toContainEqual({
      kind: "agent_id",
      value: "victim-agent-b",
    });
    expect(entries[0]!.attestation!.state).toBe("degraded");

    const filtered = await aggregateActivity(
      { auditLog: rig.auditLog, identityId: IDENTITY_ID },
      { agent_id: "victim-agent-b", limit: 10 },
    );
    expect(filtered).toHaveLength(0);
  });
});
