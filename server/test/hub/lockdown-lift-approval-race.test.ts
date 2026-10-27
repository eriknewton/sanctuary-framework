import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { HubService, InMemoryLocalAgentRegistry, type HubAgentController } from "../../src/hub/index.js";
import type { HubAgentLockdownLiftControllerResult } from "../../src/hub/types.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";

const AGENT = "agent-alpha";
const IDENTITY = "operator-test";
const REFUSED = "agent_control_lockdown_lift_unsupported_not_locked_down";
const RESTORED: HubAgentLockdownLiftControllerResult = {
  outcome: "restored", new_status: "active", reload_confirmed: true,
  restored_rule_ids: ["allow-inference"], removed_rule_ids: [],
};

function barrier() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  return { promise, release };
}

function agent(): LocalAgentRecord {
  return {
    version: "1.1", agent_id: AGENT, identity_id: IDENTITY, harness: "openclaw",
    harness_version: "test", model_provider: { vendor: "test", model_id: "test", runs_locally: true },
    policy_id: "policy-test", channel_template_id: "request-approve-act",
    status: "locked_down", status_reason_class: "operator_lockdown",
    budget_summary: { last_refreshed_at: new Date().toISOString() },
    wrapped_at: new Date().toISOString(), last_activity_at: new Date().toISOString(),
    capabilities: { can_pause: true, can_resume: true, can_restart: true, can_unwrap: true,
      can_lockdown: true, can_chat: true, can_change_template: true },
  };
}

function rig(lift: HubAgentController["liftLockdown"]) {
  const registry = new InMemoryLocalAgentRegistry([agent()]);
  const writes = vi.spyOn(registry, "updateStatus");
  const liftLockdown = vi.fn(lift);
  // Real HubService -> inbox handler -> registry and AuditLog; only the actuator is injected.
  const auditLog = new AuditLog(new MemoryStorage(), randomBytes(32)); // AES-256 key, in memory only.
  const controller: HubAgentController = {
    supports: () => true, liftLockdown,
    pause: async () => "paused", resume: async () => "active", restart: async () => "active",
    unwrap: async () => "unwrapping", lockdown: async () => "locked_down",
    bindPolicy: async () => {}, bindChannelTemplate: async () => {},
  };
  const service = new HubService({
    identityId: IDENTITY, fortressId: "fortress-test", agentRegistry: registry,
    agentController: controller, now: () => new Date(),
    inboxSources: {
      listPendingApprovals: () => [], listRecentBlockedEgress: () => [], listRecentPrivacyEvents: () => [],
      listActiveBudgetWarnings: () => [], listActiveRecoveryPrompts: () => [], listRecentAgentErrors: () => [],
    },
    activitySources: { auditLog, identityId: IDENTITY },
    policyBudgetSources: { listPolicySummaries: () => [], listBudgetSummaries: () => [] },
  });
  return {
    service, registry, writes, liftLockdown, controller,
    async enqueue(agentId = AGENT) {
      const result = await service.controlAgent(agentId, "lockdown_lift");
      if (!("inbox_item_id" in result)) throw new Error("expected Tier 1 approval card");
      return result.inbox_item_id;
    },
    card(id: string) { return service.listInbox().find(item => item.item_id === id); },
    async rows() {
      await auditLog.flush();
      return (await auditLog.query({ identity_id: IDENTITY })).entries
        .filter(row => row.operation.startsWith("agent_lockdown_lift"))
        .map(row => ({ operation: row.operation, ...row.details }));
    },
  };
}

// Attach both outcomes immediately so intentional faults never become unhandled rejections.
function approve(r: ReturnType<typeof rig>, id: string) {
  return r.service.resolveInboxItem(id, "approve").then(
    value => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );
}

function expectPending(r: ReturnType<typeof rig>, id: string) {
  expect(r.card(id)).toMatchObject({ resolved: false });
  expect(r.card(id)).not.toHaveProperty("resolved_at");
  expect(r.card(id)).not.toHaveProperty("resolution_payload");
}

function lifted(id: string) {
  return expect.objectContaining({ operation: "agent_lockdown_lifted", operator_audit_id: id,
    agent_id: AGENT, outcome: "restored", reload_confirmed: true });
}
function refused(id: string) {
  return expect.objectContaining({ operation: "agent_lockdown_lift_refused", operator_audit_id: id,
    agent_id: AGENT, reason_code: REFUSED });
}
const refusal = { ok: false, error: { reasonCode: REFUSED } };

describe("two Tier 1 lockdown lift approvals for one agent", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-27T00:00:00.000Z"));
  });
  afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); });

  it("pins unchanged sequential behavior: the second card is refused and remains unresolved", async () => {
    const hold = barrier();
    const entered = barrier();
    const r = rig(async () => { entered.release(); await hold.promise; return RESTORED; });
    const first = await r.enqueue();
    const second = await r.enqueue();
    const approval = approve(r, first);
    await entered.promise;
    hold.release();
    expect(await approval).toMatchObject({ ok: true, value: { resolved: true, resolution_payload: { outcome: "restored" } } });
    expect(r.registry.get(AGENT)?.status).toBe("active");
    expect(await r.rows()).toEqual([lifted(first)]);
    expect(await approve(r, second)).toMatchObject(refusal);
    expect(r.liftLockdown).toHaveBeenCalledExactlyOnceWith(AGENT);
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    expect(await r.rows()).toHaveLength(2); // One successful card and one refused card.
    expect(await r.rows()).toEqual(expect.arrayContaining([lifted(first), refused(second)]));
    expectPending(r, second);
  });

  it("concurrent approvals restore once; late completion leaves the refused second card unresolved", async () => {
    const hold = barrier();
    const entered = barrier();
    const r = rig(async () => { entered.release(); await hold.promise; return RESTORED; });
    const first = await r.enqueue();
    const second = await r.enqueue();
    const winner = approve(r, first);
    const loser = approve(r, second);
    let losingResult: Awaited<typeof loser> | undefined;
    void loser.then(result => { losingResult = result; });
    await entered.promise;
    await vi.advanceTimersByTimeAsync(0); // Drain this tick's approvals without releasing the actuator.
    const callsWhileHeld = r.liftLockdown.mock.calls.length;
    const writesWhileHeld = r.writes.mock.calls.length;
    const resultWhileHeld = losingResult;
    const rowsWhileHeld = await r.rows();
    hold.release();
    const results = await Promise.all([winner, loser]);
    // On the base both approvals reached the actuator (two calls, two status writes); the fix admits exactly one.
    expect(callsWhileHeld).toBe(1);
    expect(r.liftLockdown).toHaveBeenCalledExactlyOnceWith(AGENT);
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    expect(writesWhileHeld).toBe(0);
    expect(resultWhileHeld).toMatchObject(refusal);
    expect(rowsWhileHeld).toEqual([refused(second)]);
    expect(results).toMatchObject([{ ok: true, value: { resolved: true, resolution_payload: { outcome: "restored" } } }, refusal]);
    expect(r.registry.get(AGENT)?.status).toBe("active");
    expectPending(r, second);
    expect(await r.rows()).toHaveLength(2); // The late winner adds only its own lifted row.
    expect(await r.rows()).toEqual(expect.arrayContaining([lifted(first), refused(second)]));
  });

  it("releases a faulted lift so the waiting second card can be approved again after its in-flight refusal", async () => {
    const hold = barrier();
    const entered = barrier();
    const fault = new Error("actuator unavailable");
    let attempts = 0;
    const r = rig(async () => {
      attempts += 1;
      if (attempts === 1) { entered.release(); await hold.promise; throw fault; }
      return RESTORED;
    });
    const first = await r.enqueue();
    const second = await r.enqueue();
    const failed = approve(r, first);
    const waiting = approve(r, second);
    await entered.promise;
    await vi.advanceTimersByTimeAsync(0);
    hold.release();
    expect(await failed).toEqual({ ok: false, error: fault });
    expect(await waiting).toMatchObject(refusal);
    expect(r.registry.get(AGENT)?.status).toBe("locked_down");
    expect(r.writes).not.toHaveBeenCalled();
    expect(r.liftLockdown).toHaveBeenCalledTimes(1);
    expectPending(r, first);
    expectPending(r, second);
    expect(await r.rows()).toEqual([refused(second)]); // Unexpected faults have no capability-refusal row.
    expect(await approve(r, second)).toMatchObject({ ok: true, value: { resolved: true, resolution_payload: { outcome: "restored" } } });
    expect(r.liftLockdown).toHaveBeenCalledTimes(2); // One failed attempt, one explicit retry.
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    expect(await r.rows()).toHaveLength(2);
    expect(await r.rows()).toEqual(expect.arrayContaining([refused(second), lifted(second)]));
    expectPending(r, first);
  });

  it("a late capability probe cannot admit the second approval after the first lift completes", async () => {
    const hold = barrier();
    const entered = barrier();
    const probe = barrier();
    const r = rig(async () => { entered.release(); await hold.promise; return RESTORED; });
    const first = await r.enqueue();
    const second = await r.enqueue();
    r.controller.supports = vi.fn<HubAgentController["supports"]>()
      .mockReturnValueOnce(true)
      .mockImplementationOnce(async () => { await probe.promise; return true; });
    const winner = approve(r, first);
    const loser = approve(r, second);
    await entered.promise;
    hold.release();
    const winningResult = await winner;
    probe.release();
    const losingResult = await loser;
    expect(winningResult).toMatchObject({ ok: true });
    expect(losingResult).toMatchObject(refusal);
    expect(r.liftLockdown).toHaveBeenCalledExactlyOnceWith(AGENT);
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    expectPending(r, second);
    expect(await r.rows()).toHaveLength(2); // One lifted row and one refusal after the delayed probe.
    expect(await r.rows()).toEqual(expect.arrayContaining([lifted(first), refused(second)]));
  });

  it("pins unchanged independence: another agent can restore while the first agent's lift is held", async () => {
    const hold = barrier();
    const entered = barrier();
    const otherAgent = "agent-beta";
    const r = rig(async agentId => {
      if (agentId === AGENT) { entered.release(); await hold.promise; }
      return RESTORED;
    });
    r.registry.put({ ...agent(), agent_id: otherAgent });
    const first = await r.enqueue();
    const other = await r.enqueue(otherAgent);
    const pending = approve(r, first);
    await entered.promise;
    let otherResult: Awaited<ReturnType<typeof approve>> | undefined;
    const independent = approve(r, other).then(result => { otherResult = result; return result; });
    await vi.advanceTimersByTimeAsync(0);
    const resultWhileHeld = otherResult;
    const otherStatusWhileHeld = r.registry.get(otherAgent)?.status;
    hold.release();
    await Promise.all([pending, independent]);
    expect(resultWhileHeld).toMatchObject({ ok: true, value: { resolved: true } });
    expect(otherStatusWhileHeld).toBe("active");
    expect(r.liftLockdown.mock.calls).toEqual([[AGENT], [otherAgent]]);
    expect(r.writes.mock.calls).toEqual([[otherAgent, "active"], [AGENT, "active"]]);
  });

  it("repeated admission waves never let a losing approval release another lift's claim", async () => {
    const hold = barrier();
    const entered = barrier();
    const r = rig(async () => { entered.release(); await hold.promise; return RESTORED; });
    const first = await r.enqueue();
    const second = await r.enqueue();
    const winner = approve(r, first);
    await entered.promise;
    const waves = 8; // Reuse one card across eight waves to expose retained or wrongly released claims.
    const losers: ReturnType<typeof approve>[] = [];
    for (let wave = 0; wave < waves; wave += 1) {
      losers.push(approve(r, second));
      await vi.advanceTimersByTimeAsync(0);
    }
    hold.release();
    const results = await Promise.all(losers);
    expect(await winner).toMatchObject({ ok: true });
    expect(r.liftLockdown).toHaveBeenCalledExactlyOnceWith(AGENT);
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    for (const result of results) expect(result).toMatchObject(refusal);
    const rows = await r.rows();
    expect(rows.filter(row => row.operation === "agent_lockdown_lift_refused")).toHaveLength(waves);
    expect(rows.filter(row => row.operation === "agent_lockdown_lifted")).toEqual([lifted(first)]);
    expectPending(r, second);
  });

  it("pins unchanged partial behavior: an unconfirmed lift leaves the second card able to restore", async () => {
    const hold = barrier();
    const entered = barrier();
    let attempts = 0;
    const r = rig(async () => {
      attempts += 1;
      if (attempts === 1) { entered.release(); await hold.promise; return { ...RESTORED, reload_confirmed: false }; }
      return RESTORED;
    });
    const first = await r.enqueue();
    const second = await r.enqueue();
    const partial = approve(r, first);
    await entered.promise;
    hold.release();
    expect(await partial).toMatchObject({ ok: true, value: { resolved: true, resolution_payload: { outcome: "partial" } } });
    expect(r.registry.get(AGENT)?.status).toBe("locked_down");
    expect(r.writes).not.toHaveBeenCalled();
    expect(await approve(r, second)).toMatchObject({ ok: true, value: { resolution_payload: { outcome: "restored" } } });
    expect(r.liftLockdown).toHaveBeenCalledTimes(2); // Partial attempt followed by confirmed restoration.
    expect(r.writes).toHaveBeenCalledExactlyOnceWith(AGENT, "active");
    expect(await r.rows()).toHaveLength(2);
    expect(await r.rows()).toEqual(expect.arrayContaining([
      expect.objectContaining({ operation: "agent_lockdown_lift_partial", operator_audit_id: first }), lifted(second),
    ]));
  });
});
