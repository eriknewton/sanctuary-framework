/**
 * WP-V1.3-7 Nu-1 Auto-Trigger Ladder regression suite.
 *
 * Coverage:
 *  - Rule-id derivation for sentinel + anomaly + honeypot.
 *  - Default config (Rung 1; empty overrides; default cancel-window).
 *  - Promote/demote lifecycle (1 -> 2 -> 3 -> 2 -> 1) + audit emission
 *    + floor/ceiling errors.
 *  - Threshold overrides + cancel-window updates + audit emission.
 *  - Rung 1 handleFinding: inbox_only outcome + history pending.
 *  - Rung 2 handleFinding: action_pending audit + listener event +
 *    cancel-window timer fires after expiry + ACTION_PROCEEDED.
 *  - Rung 2 cancel-before-expiry: operator cancels; timer is
 *    canceled; ACTION_CANCELED audit emitted; history outcome
 *    transitions to operator_canceled.
 *  - Rung 3 immediate: ACTION_PROCEEDED audit + listener event;
 *    history outcome auto_proceeded.
 *  - Rung 3 revocation: ACTION_REVOKED audit; history outcome
 *    transitions to operator_revoked.
 *  - Multi-fortress AAD isolation on the ThresholdConfigStore.
 *  - HTTP routes (6 routes) round-trip via a real http server bound
 *    to ephemeral port; all routes auth-gated; idempotent
 *    promote/demote.
 *  - CLI subcommands (rules list / show / promote / demote /
 *    set-threshold) exercised in-process.
 *  - History bounded ring buffer caps at 200 entries.
 *
 * Castle-walking: notify_operator is server-local. The dispatcher
 * + store make no outbound calls. The HTTP route handler reads/
 * writes the in-memory dispatcher + encrypted store only.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Writable } from "node:stream";

import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { bytesToString } from "../../src/core/encoding.js";
import type { SentinelFinding } from "../../src/sentinel/types.js";

import {
  ActionDispatcher,
  NotifyOperatorAction,
  AUTO_TRIGGER_AUDIT_OPS,
  deriveRuleId,
} from "../../src/auto-trigger/action-dispatcher.js";
import {
  ThresholdConfigStore,
  AUTO_TRIGGER_RULES_NAMESPACE,
} from "../../src/auto-trigger/threshold-config-store.js";
import {
  anomalyRuleId,
  sentinelRuleId,
  honeypotRuleId,
  defaultRuleConfig,
  appendHistory,
  actionTypeForRung,
  AutoTriggerError,
  MAX_HISTORY_PER_RULE,
  type ActionHistoryEntry,
  type RuleThresholdConfig,
} from "../../src/auto-trigger/types.js";
import {
  AUTO_TRIGGER_API_PREFIX,
  handleAutoTriggerRoute,
} from "../../src/auto-trigger/auto-trigger-routes.js";
import { runAutoTriggerCommand } from "../../src/cli/auto-trigger.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

/** Fake scheduler so cancel-window tests advance time deterministically. */
class FakeScheduler {
  private tasks = new Map<
    number,
    {
      fn: () => void | Promise<void>;
      due: number;
      canceled: boolean;
    }
  >();
  private next = 0;
  private now = 0;
  schedule = (
    fn: () => void | Promise<void>,
    delayMs: number,
  ): (() => void) => {
    const id = this.next++;
    this.tasks.set(id, { fn, due: this.now + delayMs, canceled: false });
    return () => {
      const t = this.tasks.get(id);
      if (t) t.canceled = true;
    };
  };
  /**
   * Advance simulated time by `ms`, fire every due task, and await any
   * Promise the task callback returned so async dispatcher logic
   * (e.g. expirePending) completes before the test continues.
   */
  async advance(ms: number): Promise<void> {
    this.now += ms;
    const pending: Array<Promise<void>> = [];
    for (const [id, t] of [...this.tasks.entries()]) {
      if (!t.canceled && t.due <= this.now) {
        this.tasks.delete(id);
        const result = t.fn();
        if (result && typeof (result as Promise<void>).then === "function") {
          pending.push(result as Promise<void>);
        }
      }
    }
    await Promise.all(pending);
  }
}

function makeRig(opts?: { fortressId?: string }) {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new ThresholdConfigStore({ storage, masterKey, fortressId });
  const action = new NotifyOperatorAction(auditLog, IDENTITY, fortressId);
  const scheduler = new FakeScheduler();
  const dispatcher = new ActionDispatcher({
    store,
    action,
    auditLog,
    fortressId,
    identityId: IDENTITY,
    schedule: scheduler.schedule,
  });
  return { storage, masterKey, auditLog, store, dispatcher, scheduler, fortressId };
}

function makeFinding(
  overrides: Partial<SentinelFinding> = {},
): SentinelFinding {
  return {
    finding_id: overrides.finding_id ?? `finding_${Math.random().toString(36).slice(2, 10)}`,
    sentinel_id: overrides.sentinel_id ?? "test-sentinel",
    severity: overrides.severity ?? "warn",
    summary: overrides.summary ?? "test finding",
    details: overrides.details ?? {},
    observed_at: overrides.observed_at ?? "2026-05-09T12:00:00.000Z",
    evidence_audit_ids: overrides.evidence_audit_ids ?? [],
    fortress_id: overrides.fortress_id ?? FORTRESS_A,
    ...(overrides.agent_id ? { agent_id: overrides.agent_id } : {}),
  };
}

describe("Nu-1: rule-id derivation + types helpers", () => {
  it("anomaly findings derive a composite rule_id from detector + classifier in details", () => {
    const finding = makeFinding({
      sentinel_id: "anomaly:per-agent-activity",
      details: {
        detector_id: "per-agent-activity",
        classifier_id: "cusum",
      },
    });
    expect(deriveRuleId(finding, "anomaly")).toBe(
      anomalyRuleId("per-agent-activity", "cusum"),
    );
  });

  it("sentinel findings derive a sentinel_ prefixed rule_id", () => {
    const finding = makeFinding({ sentinel_id: "egress-spike" });
    expect(deriveRuleId(finding, "sentinel")).toBe(
      sentinelRuleId("egress-spike"),
    );
  });

  it("honeypot findings derive a honeypot__-prefixed rule_id (collision-safe across rule types)", () => {
    const finding = makeFinding({ sentinel_id: "trap-credstuff-007" });
    expect(deriveRuleId(finding, "honeypot")).toBe(
      honeypotRuleId("trap-credstuff-007"),
    );
    expect(honeypotRuleId("trap-credstuff-007")).toBe(
      "honeypot__trap-credstuff-007",
    );
  });

  it("defaultRuleConfig returns Rung 1 with empty overrides + 60s window", () => {
    const config = defaultRuleConfig("r1", "sentinel", FORTRESS_A);
    expect(config.current_rung).toBe(1);
    expect(config.threshold_overrides).toEqual({});
    expect(config.cancel_window_seconds).toBe(60);
    expect(config.history).toEqual([]);
  });

  it("actionTypeForRung maps 1/2/3 to inbox_only / auto_with_cancel / auto_immediate", () => {
    expect(actionTypeForRung(1)).toBe("inbox_only");
    expect(actionTypeForRung(2)).toBe("auto_with_cancel");
    expect(actionTypeForRung(3)).toBe("auto_immediate");
  });

  it("appendHistory caps at MAX_HISTORY_PER_RULE (oldest dropped)", () => {
    const baseEntry: ActionHistoryEntry = {
      observed_at: "2026-05-09T12:00:00.000Z",
      rung_at_action: 1,
      action_type: "inbox_only",
      outcome: "pending",
      finding_id: "f0",
      severity: "info",
    };
    let history: ActionHistoryEntry[] = [];
    for (let i = 0; i < MAX_HISTORY_PER_RULE + 50; i += 1) {
      history = appendHistory(history, {
        ...baseEntry,
        finding_id: `f${i}`,
      });
    }
    expect(history.length).toBe(MAX_HISTORY_PER_RULE);
    expect(history[0]?.finding_id).toBe("f50");
    expect(history[history.length - 1]?.finding_id).toBe(
      `f${MAX_HISTORY_PER_RULE + 49}`,
    );
  });
});

describe("Nu-1: ThresholdConfigStore lifecycle", () => {
  it("promote 1 -> 2 -> 3 + demote 3 -> 2 -> 1 round-trips through the store", async () => {
    const { store } = makeRig();
    await store.getOrInit("rule-a", "sentinel");
    const r2 = await store.promote("rule-a", "sentinel");
    expect(r2.current_rung).toBe(2);
    expect(r2.last_promoted_at).toBeDefined();
    const r3 = await store.promote("rule-a", "sentinel");
    expect(r3.current_rung).toBe(3);
    const d2 = await store.demote("rule-a", "sentinel");
    expect(d2.current_rung).toBe(2);
    expect(d2.last_demoted_at).toBeDefined();
    const d1 = await store.demote("rule-a", "sentinel");
    expect(d1.current_rung).toBe(1);
  });

  it("promote at ceiling throws rung_ceiling; demote at floor throws rung_floor", async () => {
    const { store } = makeRig();
    await store.promote("rule-b", "sentinel");
    await store.promote("rule-b", "sentinel");
    // Now at rung 3.
    await expect(store.promote("rule-b", "sentinel")).rejects.toMatchObject({
      code: "rung_ceiling",
    });
    await store.demote("rule-b", "sentinel");
    await store.demote("rule-b", "sentinel");
    // Now back at rung 1.
    await expect(store.demote("rule-b", "sentinel")).rejects.toMatchObject({
      code: "rung_floor",
    });
  });

  it("updateConfig overrides + cancel_window persist and round-trip", async () => {
    const { store } = makeRig();
    const updated = await store.updateConfig("rule-c", "anomaly", {
      threshold_overrides: { warn_sigma: 2.5, alert_sigma: 4.5 },
      cancel_window_seconds: 120,
    });
    expect(updated.threshold_overrides).toEqual({
      warn_sigma: 2.5,
      alert_sigma: 4.5,
    });
    expect(updated.cancel_window_seconds).toBe(120);
    const reloaded = await store.get("rule-c");
    expect(reloaded?.threshold_overrides.warn_sigma).toBe(2.5);
    expect(reloaded?.cancel_window_seconds).toBe(120);
  });

  it("recordAction + updateActionOutcome track per-finding outcomes", async () => {
    const { store } = makeRig();
    const entry: ActionHistoryEntry = {
      observed_at: "2026-05-09T12:00:00.000Z",
      rung_at_action: 2,
      action_type: "auto_with_cancel",
      outcome: "pending",
      finding_id: "finding-xyz",
      severity: "warn",
    };
    const after = await store.recordAction("rule-d", "sentinel", entry);
    expect(after.history.length).toBe(1);
    expect(after.history[0]?.outcome).toBe("pending");
    const updated = await store.updateActionOutcome(
      "rule-d",
      "sentinel",
      "finding-xyz",
      "operator_canceled",
    );
    expect(updated.history[0]?.outcome).toBe("operator_canceled");
    const noop = await store.updateActionOutcome(
      "rule-d",
      "sentinel",
      "missing-finding",
      "auto_proceeded",
    );
    expect(noop.history[0]?.outcome).toBe("operator_canceled");
  });

  it("multi-fortress AAD isolation: state written under fortress A unreadable from B", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new ThresholdConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const storeB = new ThresholdConfigStore({
      storage,
      masterKey,
      fortressId: FORTRESS_B,
    });
    await storeA.promote("shared-id", "sentinel");
    const fromB = await storeB.get("shared-id");
    expect(fromB).toBeNull();
    const fromA = await storeA.get("shared-id");
    expect(fromA?.current_rung).toBe(2);
  });

  it("ciphertext does NOT contain plaintext rule_id or rung values", async () => {
    const { store, storage } = makeRig();
    await store.promote("very-distinctive-rule-id-abc-xyz", "sentinel");
    const metas = await storage.list(AUTO_TRIGGER_RULES_NAMESPACE);
    expect(metas.length).toBe(1);
    const raw = await storage.read(
      AUTO_TRIGGER_RULES_NAMESPACE,
      metas[0]!.key,
    );
    expect(raw).not.toBeNull();
    const asString = bytesToString(raw!);
    expect(asString).not.toContain("very-distinctive-rule-id-abc-xyz");
    expect(asString).toContain("alg");
  });
});

describe("Nu-1: ActionDispatcher routing per rung", () => {
  it("rung 1 (default): handleFinding emits NO action_pending and records history pending", async () => {
    const { dispatcher, auditLog, store } = makeRig();
    const finding = makeFinding({ sentinel_id: "stub" });
    const result = await dispatcher.handleFinding(finding, "sentinel");
    expect(result).toBe("inbox_only");
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_PENDING,
      ),
    ).toBe(false);
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.history.length).toBe(1);
    expect(config?.history[0]?.outcome).toBe("pending");
  });

  it("rung 2: handleFinding fires ACTION_PENDING; expiry fires ACTION_PROCEEDED + listener event", async () => {
    const { dispatcher, auditLog, store, scheduler } = makeRig();
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    const events: string[] = [];
    dispatcher.onEvent((e) => events.push(e.type));
    const finding = makeFinding({ sentinel_id: "stub", finding_id: "f1" });
    await dispatcher.handleFinding(finding, "sentinel");
    const auditBefore = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      auditBefore.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_PENDING,
      ),
    ).toBe(true);
    expect(events).toContain("action_pending");
    expect(dispatcher.listPending().length).toBe(1);
    // Advance past cancel-window (60s default).
    await scheduler.advance(61_000);
    const auditAfter = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      auditAfter.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_PROCEEDED,
      ),
    ).toBe(true);
    expect(events).toContain("action_proceeded");
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.history[0]?.outcome).toBe("auto_proceeded");
  });

  it("rung 2 cancel: operator cancels before window expires; ACTION_CANCELED + timer no-op", async () => {
    const { dispatcher, auditLog, store, scheduler } = makeRig();
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    const events: string[] = [];
    dispatcher.onEvent((e) => events.push(e.type));
    const finding = makeFinding({ sentinel_id: "stub", finding_id: "f2" });
    await dispatcher.handleFinding(finding, "sentinel");
    const canceled = await dispatcher.cancelPending("f2");
    expect(canceled).toBe(true);
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_CANCELED,
      ),
    ).toBe(true);
    expect(events).toContain("action_canceled");
    // Advance past what would have been the expiry; PROCEEDED must NOT fire.
    await scheduler.advance(61_000);
    const auditAfter = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      auditAfter.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_PROCEEDED,
      ),
    ).toBe(false);
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.history[0]?.outcome).toBe("operator_canceled");
  });

  it("rung 3: handleFinding fires ACTION_PROCEEDED immediately + history auto_proceeded", async () => {
    const { dispatcher, auditLog, store } = makeRig();
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    const events: string[] = [];
    dispatcher.onEvent((e) => events.push(e.type));
    const finding = makeFinding({ sentinel_id: "stub", finding_id: "f3" });
    const result = await dispatcher.handleFinding(finding, "sentinel");
    expect(result).toBe("auto_immediate");
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_PROCEEDED,
      ),
    ).toBe(true);
    expect(events).toContain("action_proceeded");
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.history[0]?.outcome).toBe("auto_proceeded");
  });

  it("rung 3 revoke: operator revokes a past action; ACTION_REVOKED + history operator_revoked", async () => {
    const { dispatcher, auditLog, store } = makeRig();
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    const events: string[] = [];
    dispatcher.onEvent((e) => events.push(e.type));
    const finding = makeFinding({ sentinel_id: "stub", finding_id: "f4" });
    await dispatcher.handleFinding(finding, "sentinel");
    await dispatcher.revokeAction(
      sentinelRuleId("stub"),
      "sentinel",
      "f4",
    );
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.ACTION_REVOKED,
      ),
    ).toBe(true);
    expect(events).toContain("action_revoked");
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.history[0]?.outcome).toBe("operator_revoked");
  });

  it("promote/demote emit RULE_PROMOTED / RULE_DEMOTED audit", async () => {
    const { dispatcher, auditLog } = makeRig();
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    await dispatcher.demoteRule(sentinelRuleId("stub"), "sentinel");
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.RULE_PROMOTED,
      ),
    ).toBe(true);
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.RULE_DEMOTED,
      ),
    ).toBe(true);
  });

  it("updateThresholds emits THRESHOLD_UPDATED audit + persists", async () => {
    const { dispatcher, auditLog, store } = makeRig();
    await dispatcher.updateThresholds(
      sentinelRuleId("stub"),
      "sentinel",
      {
        threshold_overrides: { warn_sigma: 2.5, alert_sigma: 4.0 },
        cancel_window_seconds: 90,
      },
    );
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === AUTO_TRIGGER_AUDIT_OPS.THRESHOLD_UPDATED,
      ),
    ).toBe(true);
    const config = await store.get(sentinelRuleId("stub"));
    expect(config?.threshold_overrides.warn_sigma).toBe(2.5);
    expect(config?.cancel_window_seconds).toBe(90);
  });

  it("cancelPending returns false for unknown finding_id (window already expired or never queued)", async () => {
    const { dispatcher } = makeRig();
    const result = await dispatcher.cancelPending("never-queued");
    expect(result).toBe(false);
  });

  it("revokeAction throws rule_not_found / pending_not_found on missing data", async () => {
    const { dispatcher } = makeRig();
    await expect(
      dispatcher.revokeAction("missing-rule", "sentinel", "f"),
    ).rejects.toMatchObject({ code: "rule_not_found" });
    await dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
    await expect(
      dispatcher.revokeAction(sentinelRuleId("stub"), "sentinel", "no-finding"),
    ).rejects.toMatchObject({ code: "pending_not_found" });
  });

  it("anomaly findings flow through with classifier-aware rule_id derivation", async () => {
    const { dispatcher, store } = makeRig();
    const finding = makeFinding({
      sentinel_id: "anomaly:per-agent-activity",
      details: {
        detector_id: "per-agent-activity",
        classifier_id: "cusum",
      },
    });
    await dispatcher.handleFinding(finding, "anomaly");
    const expectedRuleId = anomalyRuleId("per-agent-activity", "cusum");
    const config = await store.get(expectedRuleId);
    expect(config).not.toBeNull();
    expect(config?.rule_type).toBe("anomaly");
  });
});

describe("Nu-1: HTTP routes", () => {
  async function makeServer(rig: ReturnType<typeof makeRig>): Promise<{
    base: string;
    close: () => Promise<void>;
  }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleAutoTriggerRoute(
        {
          authConfig: { loopbackAutoAuth: true },
          store: rig.store,
          dispatcher: rig.dispatcher,
        },
        req,
        res,
      );
      if (!handled) res.writeHead(404).end();
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () =>
        new Promise<void>((resolve) =>
          server.close(() => resolve()),
        ),
    };
  }

  it("GET /api/auto-trigger/rules returns the list (empty initially, populated after promote)", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const empty = await fetch(`${base}${AUTO_TRIGGER_API_PREFIX}/rules`);
      expect(empty.status).toBe(200);
      const body0 = (await empty.json()) as {
        ok: boolean;
        data: { rules: unknown[] };
      };
      expect(body0.data.rules.length).toBe(0);

      await rig.dispatcher.promoteRule(
        sentinelRuleId("test-sentinel"),
        "sentinel",
      );

      const after = await fetch(`${base}${AUTO_TRIGGER_API_PREFIX}/rules`);
      const body1 = (await after.json()) as {
        ok: boolean;
        data: { rules: Array<{ rule_id: string; current_rung: number }> };
      };
      expect(body1.data.rules.length).toBe(1);
      expect(body1.data.rules[0]?.current_rung).toBe(2);
    } finally {
      await close();
    }
  });

  it("PATCH /api/auto-trigger/rules/:id updates overrides + window; rejects missing rule_type", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const badRes = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/r1`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            threshold_overrides: { warn_sigma: 2 },
          }),
        },
      );
      expect(badRes.status).toBe(400);

      const okRes = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/r1`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            rule_type: "anomaly",
            threshold_overrides: { warn_sigma: 2.5, alert_sigma: 5.0 },
            cancel_window_seconds: 30,
          }),
        },
      );
      expect(okRes.status).toBe(200);
      const body = (await okRes.json()) as {
        data: { rule: RuleThresholdConfig };
      };
      expect(body.data.rule.threshold_overrides.warn_sigma).toBe(2.5);
      expect(body.data.rule.cancel_window_seconds).toBe(30);
    } finally {
      await close();
    }
  });

  it("POST /api/auto-trigger/rules/:id/promote + /demote round-trip; ceiling/floor return 409", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      // Promote to 2 then 3.
      const p1 = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/promote`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule_type: "sentinel" }),
        },
      );
      expect(p1.status).toBe(200);
      const p2 = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/promote`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule_type: "sentinel" }),
        },
      );
      expect(p2.status).toBe(200);
      // Ceiling.
      const p3 = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/promote`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule_type: "sentinel" }),
        },
      );
      expect(p3.status).toBe(409);
      // Demote back to floor.
      await fetch(`${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/demote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_type: "sentinel" }),
      });
      await fetch(`${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/demote`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rule_type: "sentinel" }),
      });
      const floor = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/x/demote`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ rule_type: "sentinel" }),
        },
      );
      expect(floor.status).toBe(409);
    } finally {
      await close();
    }
  });

  it("POST /api/auto-trigger/cancel/:id cancels a real pending rung-2 action; 404 on unknown", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      await rig.dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
      const finding = makeFinding({
        sentinel_id: "stub",
        finding_id: "pending-via-http",
      });
      await rig.dispatcher.handleFinding(finding, "sentinel");
      const cancelRes = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/cancel/pending-via-http`,
        { method: "POST" },
      );
      expect(cancelRes.status).toBe(200);
      const unknown = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/cancel/never-queued`,
        { method: "POST" },
      );
      expect(unknown.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("GET /api/auto-trigger/rules/:id returns full detail with history; 404 on unknown", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      await rig.dispatcher.promoteRule(sentinelRuleId("stub"), "sentinel");
      const ok = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/${encodeURIComponent(sentinelRuleId("stub"))}`,
      );
      expect(ok.status).toBe(200);
      const body = (await ok.json()) as {
        data: { rule: RuleThresholdConfig };
      };
      expect(body.data.rule.current_rung).toBe(2);
      expect(body.data.rule.history).toEqual([]);

      const missing = await fetch(
        `${base}${AUTO_TRIGGER_API_PREFIX}/rules/does-not-exist`,
      );
      expect(missing.status).toBe(404);
    } finally {
      await close();
    }
  });
});

describe("Nu-1: CLI subcommands (in-process)", () => {
  class CollectStream extends Writable {
    chunks: Buffer[] = [];
    override _write(chunk: Buffer, _enc: string, cb: () => void): void {
      this.chunks.push(Buffer.from(chunk));
      cb();
    }
    get text(): string {
      return Buffer.concat(this.chunks).toString("utf8");
    }
  }

  function makeArgs(argv: string[], storagePath: string) {
    return {
      argv,
      out: new CollectStream(),
      err: new CollectStream(),
      passphrase: "cli-test-passphrase",
      storagePath,
    };
  }

  async function makeTmpStorage(): Promise<string> {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    return mkdtemp(join(tmpdir(), "nu1-cli-"));
  }

  it("rules list prints empty initially, then lists the rule after a promote", async () => {
    const dir = await makeTmpStorage();
    const promoteArgs = makeArgs(
      ["rules", "promote", "test-rule", "--rule-type", "sentinel"],
      dir,
    );
    const promoteCode = await runAutoTriggerCommand(promoteArgs);
    expect(promoteCode).toBe(0);
    expect(promoteArgs.out.text).toContain("Promoted test-rule -> rung 2");

    const listArgs = makeArgs(["rules", "list"], dir);
    const listCode = await runAutoTriggerCommand(listArgs);
    expect(listCode).toBe(0);
    expect(listArgs.out.text).toContain("test-rule");
    expect(listArgs.out.text).toContain("rung=2");
  });

  it("rules show prints JSON detail; missing rule errors", async () => {
    const dir = await makeTmpStorage();
    await runAutoTriggerCommand(
      makeArgs(
        ["rules", "promote", "rid", "--rule-type", "sentinel"],
        dir,
      ),
    );
    const showArgs = makeArgs(["rules", "show", "rid"], dir);
    const code = await runAutoTriggerCommand(showArgs);
    expect(code).toBe(0);
    const parsed = JSON.parse(showArgs.out.text);
    expect(parsed.current_rung).toBe(2);
    expect(parsed.rule_id).toBe("rid");

    const missArgs = makeArgs(["rules", "show", "missing"], dir);
    const missCode = await runAutoTriggerCommand(missArgs);
    expect(missCode).toBe(1);
    expect(missArgs.err.text).toContain("rule not found");
  });

  it("rules set-threshold applies overrides + cancel-window", async () => {
    const dir = await makeTmpStorage();
    const args = makeArgs(
      [
        "rules",
        "set-threshold",
        "rid",
        "--rule-type",
        "anomaly",
        "--warn-sigma",
        "2.5",
        "--alert-sigma",
        "5.0",
        "--cancel-window",
        "30",
      ],
      dir,
    );
    const code = await runAutoTriggerCommand(args);
    expect(code).toBe(0);
    expect(args.out.text).toMatch(/Updated rid/);
    const showArgs = makeArgs(["rules", "show", "rid"], dir);
    await runAutoTriggerCommand(showArgs);
    const parsed = JSON.parse(showArgs.out.text);
    expect(parsed.threshold_overrides.warn_sigma).toBe(2.5);
    expect(parsed.threshold_overrides.alert_sigma).toBe(5.0);
    expect(parsed.cancel_window_seconds).toBe(30);
  });

  it("rules promote rejects missing --rule-type", async () => {
    const dir = await makeTmpStorage();
    const args = makeArgs(["rules", "promote", "rid"], dir);
    const code = await runAutoTriggerCommand(args);
    expect(code).toBe(2);
    expect(args.err.text).toContain("--rule-type");
  });
});

// Suppress unused-import lint for AutoTriggerError when tests rely on
// the typed `code` field via toMatchObject (vitest reads instance.code
// directly without an explicit reference here).
void AutoTriggerError;
