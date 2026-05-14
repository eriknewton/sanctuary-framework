import { describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import { AuditLog, type AuditEntry } from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { runInboxCommand } from "../../src/cli/inbox.js";
import {
  UNIFIED_INBOX_AUDIT_OPS,
  UnifiedInboxBridge,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import { UnifiedInboxStore } from "../../src/principal-policy/unified-inbox-store.js";
import {
  INBOX_RETENTION_AUDIT_OPS,
  UnifiedInboxRetentionPolicy,
  UnifiedInboxRetentionPolicyStore,
  sweepUnifiedInboxRetention,
} from "../../src/principal-policy/unified-inbox-retention-policy.js";
import { UnifiedInboxPrefsStore } from "../../src/principal-policy/unified-inbox-prefs-store.js";
import { UnifiedInboxScheduler } from "../../src/principal-policy/unified-inbox-scheduler.js";
import { handleUnifiedInboxRoute } from "../../src/principal-policy/unified-inbox-routes.js";

const FORTRESS = "fortress_psi3";
const IDENTITY = "identity_psi3";

function rig(now = "2026-05-13T12:00:00.000Z", fortressId = FORTRESS) {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const store = new UnifiedInboxStore({
    storage,
    masterKey,
    fortressId,
    now: () => new Date(now),
  });
  const bridge = new UnifiedInboxBridge({
    auditLog,
    identityId: IDENTITY,
    fortressId,
    store,
    now: () => new Date(now),
  });
  return { storage, masterKey, auditLog, store, bridge };
}

async function auditEntries(auditLog: AuditLog): Promise<AuditEntry[]> {
  await auditLog.flush();
  return (await auditLog.query({ layer: "l2", limit: 500 })).entries;
}

function seed(bridge: UnifiedInboxBridge) {
  const a = bridge.ingestBlockedEgress({
    source_event_id: "block-a",
    destination_category: "api",
    block_reason_class: "egress_policy_deny",
    agent_id: "agent-a",
    observed_at: "2026-05-13T10:00:00.000Z",
  })!;
  const b = bridge.ingestBudgetWarning({
    source_event_id: "budget-b",
    bucket: "daily",
    used_fraction: 0.95,
    agent_id: "agent-b",
    observed_at: "2026-05-13T11:00:00.000Z",
  })!;
  const c = bridge.ingestRecoveryPrompt({
    source_event_id: "recovery-c",
    recovery_class: "exit_drill",
    observed_at: "2026-05-12T11:00:00.000Z",
  })!;
  return { a, b, c };
}

async function makeInboxServer(opts: {
  bridge: UnifiedInboxBridge;
  auditLog: AuditLog;
  policy: UnifiedInboxRetentionPolicy;
  policyStore: UnifiedInboxRetentionPolicyStore;
  prefsStore?: UnifiedInboxPrefsStore;
  fortressId?: string;
}): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = createServer(async (req, res) => {
    const handled = await handleUnifiedInboxRoute(
      {
        authConfig: { loopbackAutoAuth: true },
        bridge: opts.bridge,
        retentionPolicy: opts.policy,
        retentionPolicyStore: opts.policyStore,
        ...(opts.prefsStore ? { prefsStore: opts.prefsStore } : {}),
        auditLog: opts.auditLog,
        identityId: IDENTITY,
        fortressId: opts.fortressId ?? FORTRESS,
      },
      req,
      res,
    );
    if (!handled) res.writeHead(404).end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${addr.port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

async function withDashboardUrl<T>(base: string, fn: () => Promise<T>): Promise<T> {
  const previous = process.env.SANCTUARY_DASHBOARD_URL;
  process.env.SANCTUARY_DASHBOARD_URL = base;
  try {
    return await fn();
  } finally {
    if (previous === undefined) {
      delete process.env.SANCTUARY_DASHBOARD_URL;
    } else {
      process.env.SANCTUARY_DASHBOARD_URL = previous;
    }
  }
}

describe("Psi-3 unified inbox query API", () => {
  it("filters by single source class", () => {
    const { bridge } = rig();
    seed(bridge);
    expect(bridge.queryInbox({ source_class: "blocked_egress" })).toHaveLength(1);
  });

  it("filters by severity and agent id", () => {
    const { bridge } = rig();
    seed(bridge);
    const entries = bridge.queryInbox({
      severity: ["alert"],
      agent_id: ["agent-b"],
    });
    expect(entries.map((e) => e.source_event_id)).toEqual(["budget-b"]);
  });

  it("filters full text across summary and drill detail fields", () => {
    const { bridge } = rig();
    seed(bridge);
    expect(bridge.queryInbox({ full_text: "exit drill" })[0]!.source_class).toBe("recovery_prompt");
  });

  it("applies time range, limit, offset, and recency sort", () => {
    const { bridge } = rig();
    seed(bridge);
    const entries = bridge.queryInbox({
      time_range: {
        from: "2026-05-13T00:00:00.000Z",
        to: "2026-05-13T23:59:59.000Z",
      },
      limit: 1,
      offset: 1,
    });
    expect(entries.map((e) => e.source_event_id)).toEqual(["block-a"]);
  });

  it("counts without applying pagination", () => {
    const { bridge } = rig();
    seed(bridge);
    expect(bridge.countInbox({ limit: 1 })).toBe(3);
  });
});

describe("Psi-3 batch actions and snooze", () => {
  it("archives a batch with one correlation id and per-entry audit", async () => {
    const { bridge, auditLog } = rig();
    const { a, b } = seed(bridge);
    const result = bridge.archiveBatch([a.inbox_id, b.inbox_id]);
    expect(result.affected).toBe(2);
    expect(new Set(bridge.queryInbox({ state: ["archived"] }).map((e) => e.state))).toEqual(new Set(["archived"]));
    const archived = (await auditEntries(auditLog)).filter((e) => e.operation === UNIFIED_INBOX_AUDIT_OPS.ARCHIVED);
    expect(archived).toHaveLength(2);
    expect(new Set(archived.map((e) => e.details?.batch_correlation_id))).toEqual(new Set([result.batch_correlation_id]));
  });

  it("dismisses a batch and hides entries from default active queries", () => {
    const { bridge } = rig();
    const { a } = seed(bridge);
    expect(bridge.dismissBatch([a.inbox_id]).affected).toBe(1);
    expect(bridge.queryInbox().map((e) => e.inbox_id)).not.toContain(a.inbox_id);
    expect(bridge.queryInbox({ state: ["dismissed"] })[0]!.dismissed_at).toBeDefined();
  });

  it("snoozes entries until a deadline and shares a correlation id", async () => {
    const { bridge, auditLog } = rig();
    const { a } = seed(bridge);
    const result = bridge.snoozeBatch([a.inbox_id], "2026-05-13T16:00:00.000Z");
    expect(bridge.queryInbox()).not.toContainEqual(expect.objectContaining({ inbox_id: a.inbox_id }));
    expect(bridge.queryInbox({ state: ["snoozed"] })[0]!.snoozed_until).toBe("2026-05-13T16:00:00.000Z");
    const snoozed = (await auditEntries(auditLog)).find((e) => e.operation === UNIFIED_INBOX_AUDIT_OPS.SNOOZED)!;
    expect(snoozed.details?.batch_correlation_id).toBe(result.batch_correlation_id);
  });

  it("hard deletes only the selected inbox entries", async () => {
    const { bridge, store } = rig();
    const { a, b } = seed(bridge);
    await bridge.flushPersistence();
    expect(bridge.deleteBatch([a.inbox_id]).affected).toBe(1);
    await bridge.flushPersistence();
    await expect(store.get(a.inbox_id)).resolves.toBeNull();
    await expect(store.get(b.inbox_id)).resolves.not.toBeNull();
  });

  it("batch delete route requires explicit confirmation and leaves audit untouched when missing", async () => {
    const { storage, masterKey, bridge, auditLog } = rig();
    const { a } = seed(bridge);
    const policy = new UnifiedInboxRetentionPolicy();
    const policyStore = new UnifiedInboxRetentionPolicyStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const { base, close } = await makeInboxServer({
      bridge,
      auditLog,
      policy,
      policyStore,
    });
    try {
      const before = await auditEntries(auditLog);
      const res = await fetch(`${base}/api/inbox/unified/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete", entry_ids: [a.inbox_id] }),
      });
      expect(res.status).toBe(400);
      expect(bridge.get(a.inbox_id)).not.toBeNull();
      expect(await auditEntries(auditLog)).toHaveLength(before.length);

      const confirmed = await fetch(`${base}/api/inbox/unified/batch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          action: "delete",
          entry_ids: [a.inbox_id],
          confirm_delete: true,
        }),
      });
      expect(confirmed.status).toBe(200);
      expect(bridge.get(a.inbox_id)).toBeNull();
    } finally {
      await close();
    }
  });

  it("auto-resurfaces due snoozes and manual unsnooze clears a future snooze", () => {
    const { bridge } = rig();
    const { a, b } = seed(bridge);
    bridge.snoozeBatch([a.inbox_id], "2026-05-13T11:00:00.000Z");
    bridge.snoozeBatch([b.inbox_id], "2026-05-13T18:00:00.000Z");
    expect(bridge.resurfaceDueSnoozes(new Date("2026-05-13T12:00:00.000Z"))).toBe(1);
    expect(bridge.queryInbox().map((e) => e.inbox_id)).toContain(a.inbox_id);
    expect(bridge.unsnooze(b.inbox_id)?.state).toBe("active");
  });

  it("scheduler tick auto-resurfaces due snoozes through production wiring", () => {
    const { bridge } = rig();
    const { a } = seed(bridge);
    bridge.snoozeBatch([a.inbox_id], "2026-05-13T11:59:00.000Z");
    const scheduler = new UnifiedInboxScheduler({
      bridge,
      now: () => new Date("2026-05-13T12:00:00.000Z"),
    });
    expect(scheduler.tick()).toBe(1);
    expect(bridge.queryInbox().map((e) => e.inbox_id)).toContain(a.inbox_id);
  });

  it("scheduler start and stop are idempotent lifecycle operations", () => {
    const { bridge } = rig();
    const scheduler = new UnifiedInboxScheduler({
      bridge,
      intervalMs: 10_000,
    });
    expect(scheduler.isRunning()).toBe(false);
    scheduler.start();
    scheduler.start();
    expect(scheduler.isRunning()).toBe(true);
    scheduler.stop();
    scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });
});

describe("Psi-3 retention and isolation", () => {
  it("default retention deletes archived entries after 90 days", async () => {
    const { bridge, auditLog } = rig("2026-05-13T12:00:00.000Z");
    const { a } = seed(bridge);
    bridge.archiveBatch([a.inbox_id]);
    const result = await sweepUnifiedInboxRetention({
      bridge,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      now: new Date("2026-08-12T12:00:01.000Z"),
    });
    expect(result.archived_deleted).toBe(1);
  });

  it("default retention deletes dismissed entries after 30 days", async () => {
    const { bridge, auditLog } = rig("2026-05-13T12:00:00.000Z");
    const { a } = seed(bridge);
    bridge.dismissBatch([a.inbox_id]);
    const result = await sweepUnifiedInboxRetention({
      bridge,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      now: new Date("2026-06-13T12:00:01.000Z"),
    });
    expect(result.dismissed_deleted).toBe(1);
  });

  it("operator override changes retention per source class and state", async () => {
    const { bridge, auditLog } = rig("2026-05-13T12:00:00.000Z");
    const { a } = seed(bridge);
    bridge.archiveBatch([a.inbox_id]);
    const policy = new UnifiedInboxRetentionPolicy([
      { source_class: "blocked_egress", state: "archived", retain_for_days: 1 },
    ]);
    const result = await sweepUnifiedInboxRetention({
      bridge,
      policy,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      now: new Date("2026-05-15T12:00:01.000Z"),
    });
    expect(result.deleted).toBe(1);
  });

  it("CLI retention set persists across retention policy reload", async () => {
    const { storage, masterKey, auditLog, bridge } = rig();
    const policyStore = new UnifiedInboxRetentionPolicyStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const server = await makeInboxServer({
      bridge,
      auditLog,
      policy: await policyStore.load(),
      policyStore,
    });
    try {
      const out = { write: () => true } as unknown as NodeJS.WritableStream;
      const err = { write: () => true } as unknown as NodeJS.WritableStream;
      const code = await withDashboardUrl(server.base, () =>
        runInboxCommand({
          argv: [
            "retention",
            "set",
            "--source-class",
            "blocked_egress",
            "--state",
            "archived",
            "--days",
            "7",
          ],
          out,
          err,
        }),
      );
      expect(code).toBe(0);

      const reloaded = await policyStore.load();
      expect(reloaded.daysFor("blocked_egress", "archived")).toBe(7);
    } finally {
      await server.close();
    }
  });

  it("CLI retention set emits inbox_retention_policy_updated audit", async () => {
    const { storage, masterKey, auditLog, bridge } = rig();
    const policyStore = new UnifiedInboxRetentionPolicyStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const server = await makeInboxServer({
      bridge,
      auditLog,
      policy: await policyStore.load(),
      policyStore,
    });
    try {
      const out = { write: () => true } as unknown as NodeJS.WritableStream;
      const err = { write: () => true } as unknown as NodeJS.WritableStream;
      const code = await withDashboardUrl(server.base, () =>
        runInboxCommand({
          argv: [
            "retention",
            "set",
            "--source-class",
            "budget_warning",
            "--state",
            "dismissed",
            "--days",
            "14",
          ],
          out,
          err,
        }),
      );
      expect(code).toBe(0);
      const updated = (await auditEntries(auditLog)).find(
        (e) => e.operation === INBOX_RETENTION_AUDIT_OPS.POLICY_UPDATED,
      );
      expect(updated?.details).toMatchObject({
        fortress_id: FORTRESS,
        source_class: "budget_warning",
        state: "dismissed",
        retain_for_days: 14,
      });
    } finally {
      await server.close();
    }
  });

  it("retention sweep emits one summary audit event per fortress", async () => {
    const { bridge, auditLog } = rig();
    await sweepUnifiedInboxRetention({
      bridge,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      now: new Date("2026-05-13T12:00:00.000Z"),
    });
    const swept = (await auditEntries(auditLog)).filter((e) => e.operation === INBOX_RETENTION_AUDIT_OPS.SWEPT);
    expect(swept).toHaveLength(1);
    expect(swept[0]!.details?.fortress_id).toBe(FORTRESS);
  });

  it("preserves multi-fortress isolation in operations", () => {
    const a = rig("2026-05-13T12:00:00.000Z", "fortress-a");
    const b = rig("2026-05-13T12:00:00.000Z", "fortress-b");
    const entryA = seed(a.bridge).a;
    seed(b.bridge);
    a.bridge.archiveBatch([entryA.inbox_id]);
    expect(a.bridge.queryInbox({ state: ["archived"] })).toHaveLength(1);
    expect(b.bridge.queryInbox({ state: ["archived"] })).toHaveLength(0);
  });

  it("persists dashboard inbox filters in fortress-local encrypted prefs", async () => {
    const { storage, masterKey, auditLog, bridge } = rig();
    const policyStore = new UnifiedInboxRetentionPolicyStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const prefsStore = new UnifiedInboxPrefsStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
      operatorId: IDENTITY,
    });
    const server = await makeInboxServer({
      bridge,
      auditLog,
      policy: await policyStore.load(),
      policyStore,
      prefsStore,
    });
    try {
      const save = await fetch(`${server.base}/api/inbox/unified/prefs`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          filters: {
            search: "budget",
            source: "budget_warning",
            severity: "alert",
            agent: "agent-b",
            from: "2026-05-13",
            to: "2026-05-14",
          },
        }),
      });
      expect(save.status).toBe(200);

      const reloadedStore = new UnifiedInboxPrefsStore({
        storage,
        masterKey,
        fortressId: FORTRESS,
        operatorId: IDENTITY,
      });
      await server.close();

      const restarted = await makeInboxServer({
        bridge,
        auditLog,
        policy: await policyStore.load(),
        policyStore,
        prefsStore: reloadedStore,
      });
      try {
        const loaded = await fetch(`${restarted.base}/api/inbox/unified/prefs`);
        expect(loaded.status).toBe(200);
        const body = await loaded.json() as {
          data: { filters: Record<string, string> };
        };
        expect(body.data.filters).toMatchObject({
          search: "budget",
          source: "budget_warning",
          severity: "alert",
          agent: "agent-b",
          from: "2026-05-13",
          to: "2026-05-14",
        });
      } finally {
        await restarted.close();
      }
    } finally {
      await server.close().catch(() => undefined);
    }
  });

  it("Castle-walking remains pure local operations", async () => {
    const { bridge, auditLog } = rig();
    const { a } = seed(bridge);
    bridge.archiveBatch([a.inbox_id]);
    const ops = new Set((await auditEntries(auditLog)).map((e) => e.operation));
    expect([...ops].some((op) => op.startsWith("proxy_call:"))).toBe(false);
    expect(ops.has("intelligence_substrate_invoked")).toBe(false);
  });
});
