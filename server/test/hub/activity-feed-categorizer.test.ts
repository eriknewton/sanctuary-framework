/**
 * Sanctuary v1.1 Activity feed categorizer regression suite.
 *
 * Asserts the `categorizeOperation` mapping (exercised through
 * `aggregateActivity`) routes lifecycle events per dashboard binding
 * addendum §1.2: bare verbs (`wrap`, `unwrap`, `lockdown`, `pause`,
 * `resume`, `restart`), agent-scope events (`agent_*`), and fortress
 * scope suffixed lifecycle forms (e.g. `fortress_lockdown_engaged`,
 * `fortress_lockdown_lifted`) all map to category `lifecycle`.
 *
 * Real AuditLog over MemoryStorage; no mocks at the projection layer.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { aggregateActivity } from "../../src/hub/activity-feed.js";

const IDENTITY_ID = "operator-categorizer-test-001";

interface Rig {
  auditLog: AuditLog;
}

async function startRig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  return { auditLog };
}

async function categoryFor(
  rig: Rig,
  layer: "l1" | "l2" | "l3" | "l4",
  operation: string,
): Promise<string | undefined> {
  await rig.auditLog.append(layer, operation, IDENTITY_ID, {});
  await rig.auditLog.flush();
  const entries = await aggregateActivity(
    { auditLog: rig.auditLog, identityId: IDENTITY_ID },
    { limit: 100 },
  );
  const match = entries.find((e) => e.display_template_id.includes(operation));
  return match?.category;
}

describe("Activity feed categorizer: lifecycle routing", () => {
  let rig: Rig;
  beforeEach(async () => (rig = await startRig()));
  afterEach(() => undefined);

  it("bare lifecycle verbs map to lifecycle", async () => {
    for (const verb of [
      "wrap",
      "unwrap",
      "lockdown",
      "pause",
      "resume",
      "restart",
    ]) {
      expect(await categoryFor(rig, "l2", verb)).toBe("lifecycle");
    }
  });

  it("agent-scope suffixed lifecycle events map to lifecycle", async () => {
    for (const op of [
      "agent_lockdown_engaged",
      "agent_unwrap_engaged",
      "agent_lockdown_lifted",
      "agent_policy_change_engaged",
    ]) {
      expect(await categoryFor(rig, "l2", op)).toBe("lifecycle");
    }
  });

  it("fortress-scope suffixed lifecycle events map to lifecycle", async () => {
    for (const op of [
      "fortress_lockdown_engaged",
      "fortress_lockdown_lifted",
      "fortress_unwrap_engaged",
    ]) {
      expect(await categoryFor(rig, "l2", op)).toBe("lifecycle");
    }
  });

  it("fortress-scope non-lifecycle events do NOT map to lifecycle", async () => {
    expect(await categoryFor(rig, "l2", "fortress_exit_bundle_exported")).toBe(
      "policy_decision",
    );
  });
});

describe("Activity feed categorizer: non-lifecycle bucket regressions", () => {
  let rig: Rig;
  beforeEach(async () => (rig = await startRig()));
  afterEach(() => undefined);

  it("privacy events map to privacy", async () => {
    expect(await categoryFor(rig, "l2", "privacy_event")).toBe("privacy");
  });

  it("egress events map to egress", async () => {
    expect(await categoryFor(rig, "l2", "egress_blocked")).toBe("egress");
  });

  it("policy_decision routes to policy_decision", async () => {
    expect(await categoryFor(rig, "l2", "policy_decision")).toBe(
      "policy_decision",
    );
  });

  it("config_-prefixed events map to config", async () => {
    expect(await categoryFor(rig, "l2", "config_change")).toBe("config");
  });

  it("approval events map to approval", async () => {
    expect(await categoryFor(rig, "l2", "tier1_approval_granted")).toBe(
      "approval",
    );
  });

  it("denial events map to denial", async () => {
    expect(await categoryFor(rig, "l2", "policy_deny")).toBe("denial");
  });

  it("handoff events map to handoff", async () => {
    expect(await categoryFor(rig, "l2", "handoff_created")).toBe("handoff");
  });
});
