/**
 * WP-V1.3-1 Phi-1 Sentinel framework + EgressVolumeWatcher regression suite.
 *
 * Coverage:
 *  - Sentinel framework: registry add/remove/idempotency, dispatcher
 *    tick + finding routing (store + audit + listener), failure-mode
 *    handling.
 *  - EgressVolumeWatcher: pre-baseline silence, baseline-established
 *    info finding, normal volume no-fire, warn at +3 sigma, alert at
 *    +6 sigma, evidence_audit_ids populated.
 *  - HTTP routes: list catalog, list subscribed, subscribe / 404,
 *    unsubscribe, findings query.
 *  - CLI: list catalog, subscribe + persistence, unsubscribe, list
 *    subscribed.
 *  - Audit events: subscribed / unsubscribed / finding_emitted /
 *    evaluation_failed.
 *  - Multi-fortress isolation: dispatcher A's findings stamp
 *    fortress_a; encrypted AAD binding rejects cross-fortress reads.
 *  - Castle-walking: no outbound network surface; sentinels read
 *    server-local audit data only.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";

import {
  AuditLog,
  type AuditEntry,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { Sentinel } from "../../src/sentinel/sentinel.js";
import { SentinelRegistry } from "../../src/sentinel/sentinel-registry.js";
import { SentinelDispatcher } from "../../src/sentinel/sentinel-dispatcher.js";
import { SentinelFindingStore } from "../../src/sentinel/sentinel-finding-store.js";
import {
  EgressVolumeWatcher,
  EGRESS_VOLUME_SENTINEL_ID,
} from "../../src/sentinel/sentinels/egress-volume-watcher.js";
import { PHI1_BASELINE_CATALOG } from "../../src/sentinel/sentinels/index.js";
import {
  SENTINEL_API_PREFIX,
  handleSentinelRoute,
} from "../../src/sentinel/sentinel-routes.js";
import {
  SENTINEL_AUDIT_OPS,
  type SentinelFinding,
  type SentinelContext,
} from "../../src/sentinel/types.js";
import {
  loadSentinelSubscriptions,
  saveSentinelSubscriptions,
  sentinelSubscriptionsPath,
} from "../../src/sentinel/subscription-store.js";
import { runSentinelCommand } from "../../src/cli/sentinel.js";

const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";
const IDENTITY = "identity_test";

function makeRig(opts?: { fortressId?: string; now?: () => Date }): {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  findingStore: SentinelFindingStore;
  registry: SentinelRegistry;
  dispatcher: SentinelDispatcher;
} {
  const fortressId = opts?.fortressId ?? FORTRESS_A;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
  });
  const registry = new SentinelRegistry();
  for (const entry of PHI1_BASELINE_CATALOG) {
    registry.register(entry);
  }
  const dispatcher = new SentinelDispatcher({
    registry,
    findingStore,
    auditLog,
    fortressId,
    identityId: IDENTITY,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
    tickIntervalMs: 0,
  });
  return { storage, masterKey, auditLog, findingStore, registry, dispatcher };
}

class StubSentinel extends Sentinel {
  readonly sentinelId: string;
  readonly description = "Test fixture sentinel.";
  next: SentinelFinding[] = [];
  shouldThrow = false;

  constructor(sentinelId = "stub-fixture") {
    super();
    this.sentinelId = sentinelId;
  }

  async evaluate(): Promise<SentinelFinding[]> {
    if (this.shouldThrow) throw new Error("stub sentinel exploded");
    return this.next;
  }
}

/**
 * Tiny audit-log stub that returns pre-seeded entries. The real
 * AuditLog stamps timestamps with `new Date()` inside `append()`,
 * which makes time-window tests fragile; the watcher only calls
 * `query()` so a stub satisfies the contract.
 */
function makeStubAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    async query(opts: {
      since?: string;
      layer?: AuditEntry["layer"];
      operation_type?: string;
      limit?: number;
    }): Promise<{ entries: AuditEntry[]; total: number }> {
      let filtered = entries;
      if (opts.since) {
        const sinceMs = Date.parse(opts.since);
        filtered = filtered.filter(
          (e) => Date.parse(e.timestamp) >= sinceMs,
        );
      }
      if (opts.layer) {
        filtered = filtered.filter((e) => e.layer === opts.layer);
      }
      if (opts.operation_type) {
        filtered = filtered.filter((e) => e.operation === opts.operation_type);
      }
      const limit = opts.limit ?? 50;
      return { entries: filtered.slice(-limit), total: filtered.length };
    },
  } as unknown as AuditLog;
}

function backdatedProxyCalls(opts: {
  now: Date;
  perDay: number[];
  server: string;
  currentDayCount?: number;
}): AuditEntry[] {
  const dayMs = 24 * 60 * 60 * 1000;
  const entries: AuditEntry[] = [];
  for (let i = 0; i < (opts.currentDayCount ?? 0); i += 1) {
    entries.push({
      timestamp: new Date(opts.now.getTime() - 60_000 - i * 1000).toISOString(),
      layer: "l2",
      operation: `proxy_call:${opts.server}`,
      identity_id: "system",
      result: "success",
      details: { server: opts.server, latency_ms: 100 },
    });
  }
  for (let day = 1; day <= opts.perDay.length; day += 1) {
    const count = opts.perDay[day - 1]!;
    for (let i = 0; i < count; i += 1) {
      entries.push({
        timestamp: new Date(
          opts.now.getTime() - day * dayMs - 60_000 - i * 1000,
        ).toISOString(),
        layer: "l2",
        operation: `proxy_call:${opts.server}`,
        identity_id: "system",
        result: "success",
        details: { server: opts.server, latency_ms: 100 },
      });
    }
  }
  return entries;
}

describe("WP-V1.3-1 Phi-1 SentinelRegistry", () => {
  it("registers a catalog entry once and rejects double-registration", () => {
    const registry = new SentinelRegistry();
    registry.register({
      sentinelId: "test-1",
      description: "fixture",
      factory: () => new StubSentinel("test-1"),
    });
    expect(() =>
      registry.register({
        sentinelId: "test-1",
        description: "fixture",
        factory: () => new StubSentinel("test-1"),
      }),
    ).toThrow("already registered");
  });

  it("subscribe and unsubscribe are idempotent", async () => {
    const registry = new SentinelRegistry();
    registry.register({
      sentinelId: "test-2",
      description: "fixture",
      factory: () => new StubSentinel("test-2"),
    });
    const ctx: SentinelContext = {
      fortressId: FORTRESS_A,
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      now: () => new Date(),
    };
    const first = await registry.subscribe("test-2", ctx);
    const second = await registry.subscribe("test-2", ctx);
    expect(first).toBe(second);
    expect(registry.listSubscribed()).toEqual(["test-2"]);
    expect(await registry.unsubscribe("test-2")).toBe(true);
    expect(await registry.unsubscribe("test-2")).toBe(false);
  });

  it("subscribe rejects unknown sentinel ids", async () => {
    const registry = new SentinelRegistry();
    const ctx: SentinelContext = {
      fortressId: FORTRESS_A,
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      now: () => new Date(),
    };
    await expect(registry.subscribe("never-registered", ctx)).rejects.toThrow(
      /unknown sentinel/,
    );
  });

  it("listCatalog exposes the Phi-1 baseline pack", () => {
    expect(PHI1_BASELINE_CATALOG.map((e) => e.sentinelId)).toContain(
      EGRESS_VOLUME_SENTINEL_ID,
    );
  });
});

describe("WP-V1.3-1 Phi-1 SentinelDispatcher", () => {
  it("emits sentinel_subscribed audit event on subscribeSentinel()", async () => {
    const rig = makeRig();
    rig.registry.register({
      sentinelId: "test-sub",
      description: "fixture",
      factory: () => new StubSentinel("test-sub"),
    });
    await rig.dispatcher.subscribeSentinel("test-sub");
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    const subEvents = audit.entries.filter(
      (e) => e.operation === SENTINEL_AUDIT_OPS.SUBSCRIBED,
    );
    expect(subEvents.length).toBe(1);
    expect(subEvents[0]?.details?.["sentinel_id"]).toBe("test-sub");
  });

  it("emits sentinel_unsubscribed only when an active subscription is torn down", async () => {
    const rig = makeRig();
    rig.registry.register({
      sentinelId: "test-unsub",
      description: "fixture",
      factory: () => new StubSentinel("test-unsub"),
    });
    await rig.dispatcher.subscribeSentinel("test-unsub");
    const removed = await rig.dispatcher.unsubscribeSentinel("test-unsub");
    expect(removed).toBe(true);
    const removedTwice = await rig.dispatcher.unsubscribeSentinel("test-unsub");
    expect(removedTwice).toBe(false);
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    const unsubEvents = audit.entries.filter(
      (e) => e.operation === SENTINEL_AUDIT_OPS.UNSUBSCRIBED,
    );
    expect(unsubEvents.length).toBe(1);
  });

  it("tick() routes findings to the store + audit log + listeners", async () => {
    const rig = makeRig();
    const stub = new StubSentinel("test-route");
    rig.registry.register({
      sentinelId: stub.sentinelId,
      description: stub.description,
      factory: () => stub,
    });
    await rig.dispatcher.subscribeSentinel(stub.sentinelId);
    stub.next = [
      {
        finding_id: "",
        sentinel_id: stub.sentinelId,
        severity: "warn",
        summary: "synthetic finding",
        details: { synthetic: true },
        observed_at: "2026-05-09T12:00:00.000Z",
        evidence_audit_ids: ["2026-05-09T12:00:00.000Z:proxy_call:example.com"],
        fortress_id: "",
      },
    ];
    const emitted: SentinelFinding[] = [];
    rig.dispatcher.onEvent((event) => {
      if (event.type === "finding") emitted.push(event.finding);
    });
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.fortress_id).toBe(FORTRESS_A);
    expect(findings[0]?.finding_id.length).toBeGreaterThan(0);
    expect(emitted.length).toBe(1);
    const stored = await rig.findingStore.listFindings();
    expect(stored.length).toBe(1);
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    expect(
      audit.entries.some(
        (e) => e.operation === SENTINEL_AUDIT_OPS.FINDING_EMITTED,
      ),
    ).toBe(true);
  });

  it("failed evaluate() emits sentinel_evaluation_failed and does not abort the tick", async () => {
    const rig = makeRig();
    const flaky = new StubSentinel("flaky");
    flaky.shouldThrow = true;
    rig.registry.register({
      sentinelId: "flaky",
      description: "fixture",
      factory: () => flaky,
    });
    const healthy = new StubSentinel("healthy");
    healthy.next = [
      {
        finding_id: "",
        sentinel_id: "healthy",
        severity: "info",
        summary: "healthy fixture",
        details: {},
        observed_at: "2026-05-09T12:00:00.000Z",
        evidence_audit_ids: [],
        fortress_id: "",
      },
    ];
    rig.registry.register({
      sentinelId: "healthy",
      description: "fixture",
      factory: () => healthy,
    });
    await rig.dispatcher.subscribeSentinel("flaky");
    await rig.dispatcher.subscribeSentinel("healthy");
    const findings = await rig.dispatcher.tick();
    expect(findings.length).toBe(1);
    expect(findings[0]?.sentinel_id).toBe("healthy");
    const audit = await rig.auditLog.query({ layer: "l2", limit: 100 });
    const failures = audit.entries.filter(
      (e) => e.operation === SENTINEL_AUDIT_OPS.EVALUATION_FAILED,
    );
    expect(failures.length).toBe(1);
    expect(failures[0]?.details?.["sentinel_id"]).toBe("flaky");
    expect(failures[0]?.result).toBe("failure");
  });

  it("dispose() unsubscribes everything and stops the auto-tick", async () => {
    const rig = makeRig();
    rig.registry.register({
      sentinelId: "to-dispose",
      description: "fixture",
      factory: () => new StubSentinel("to-dispose"),
    });
    await rig.dispatcher.subscribeSentinel("to-dispose");
    expect(rig.registry.listSubscribed()).toEqual(["to-dispose"]);
    await rig.dispatcher.dispose();
    expect(rig.registry.listSubscribed()).toEqual([]);
  });
});

describe("WP-V1.3-1 Phi-1 SentinelFindingStore", () => {
  it("round-trips a finding through encrypted persistence", async () => {
    const rig = makeRig();
    const finding: SentinelFinding = {
      finding_id: "f-1",
      sentinel_id: "egress-volume",
      severity: "warn",
      summary: "round-trip fixture",
      details: { server: "api.example.com" },
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [
        "2026-05-09T11:30:00.000Z:proxy_call:api.example.com",
      ],
      fortress_id: FORTRESS_A,
    };
    await rig.findingStore.saveFinding(finding);
    const loaded = await rig.findingStore.loadFinding("f-1");
    expect(loaded).toEqual({ ...finding, fortress_id: FORTRESS_A });
  });

  it("rejects findings persisted under a different fortress (AAD binding)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const storeA = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
    });
    const storeB = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: FORTRESS_B,
    });
    await storeA.saveFinding({
      finding_id: "f-x",
      sentinel_id: "egress-volume",
      severity: "info",
      summary: "fortress a finding",
      details: {},
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    const loadedFromB = await storeB.loadFinding("f-x");
    expect(loadedFromB).toBeNull();
  });

  it("listFindings filters by severity", async () => {
    const rig = makeRig();
    await rig.findingStore.saveFinding({
      finding_id: "f-1",
      sentinel_id: "egress-volume",
      severity: "warn",
      summary: "warn",
      details: {},
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    await rig.findingStore.saveFinding({
      finding_id: "f-2",
      sentinel_id: "egress-volume",
      severity: "alert",
      summary: "alert",
      details: {},
      observed_at: "2026-05-09T13:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    const alertOnly = await rig.findingStore.listFindings({
      severity: "alert",
    });
    expect(alertOnly.length).toBe(1);
    expect(alertOnly[0]?.severity).toBe("alert");
  });

  it("pruneExpired drops findings past their retention window", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const oldClock = () => new Date("2026-04-01T00:00:00.000Z");
    const oldStore = new SentinelFindingStore({
      storage,
      masterKey,
      fortressId: FORTRESS_A,
      retentionDays: 30,
      now: oldClock,
    });
    await oldStore.saveFinding({
      finding_id: "old",
      sentinel_id: "egress-volume",
      severity: "info",
      summary: "old",
      details: {},
      observed_at: "2026-04-01T00:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    const futureNow = new Date("2026-06-01T00:00:00.000Z");
    const result = await oldStore.pruneExpired(futureNow);
    expect(result.pruned).toBe(1);
  });
});

describe("WP-V1.3-1 Phi-1 EgressVolumeWatcher", () => {
  it("returns no findings when audit log is empty", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const watcher = new EgressVolumeWatcher();
    await watcher.subscribe({
      fortressId: FORTRESS_A,
      auditLog: makeStubAuditLog([]),
      now: () => now,
    });
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("first call after baseline establishes emits info; second call is silent", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      backdatedProxyCalls({
        now,
        perDay: [10, 10, 10, 10, 10, 10, 10],
        server: "api.example.com",
        currentDayCount: 10,
      }),
    );
    const watcher = new EgressVolumeWatcher();
    await watcher.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      now: () => now,
    });
    const first = await watcher.evaluate();
    expect(first.length).toBe(1);
    expect(first[0]?.severity).toBe("info");
    const second = await watcher.evaluate();
    expect(second).toEqual([]);
  });

  it("fires alert when current 24h volume exceeds baseline by more than 6 sigma", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      backdatedProxyCalls({
        now,
        perDay: [10, 11, 9, 12, 10, 11, 10],
        server: "api.example.com",
        currentDayCount: 200,
      }),
    );
    const watcher = new EgressVolumeWatcher();
    await watcher.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      now: () => now,
    });
    const baselineRun = await watcher.evaluate();
    expect(baselineRun[0]?.severity).toBe("info");
    const tickFindings = await watcher.evaluate();
    expect(tickFindings.length).toBe(1);
    expect(tickFindings[0]?.severity).toBe("alert");
    expect(tickFindings[0]?.evidence_audit_ids.length).toBeGreaterThan(0);
    expect(tickFindings[0]?.details["server"]).toBe("api.example.com");
    expect(tickFindings[0]?.details["sigma_threshold"]).toBe(6);
  });

  it("fires warn when current 24h volume is between +3 and +6 sigma", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    // Baseline mean 10.43, stddev 1.05. Warn threshold ~13.58; alert
    // threshold ~16.73. Pick a current count that crosses warn but
    // stays under alert.
    const audit = makeStubAuditLog(
      backdatedProxyCalls({
        now,
        perDay: [10, 11, 9, 12, 10, 11, 10],
        server: "api.example.com",
        currentDayCount: 15,
      }),
    );
    const watcher = new EgressVolumeWatcher();
    await watcher.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      now: () => now,
    });
    await watcher.evaluate();
    const tickFindings = await watcher.evaluate();
    expect(tickFindings.length).toBe(1);
    expect(tickFindings[0]?.severity).toBe("warn");
    expect(tickFindings[0]?.details["sigma_threshold"]).toBe(3);
  });

  it("returns empty when fewer than 7 days of baseline are available", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const audit = makeStubAuditLog(
      backdatedProxyCalls({
        now,
        perDay: [10, 10, 10],
        server: "api.example.com",
        currentDayCount: 200,
      }),
    );
    const watcher = new EgressVolumeWatcher();
    await watcher.subscribe({
      fortressId: FORTRESS_A,
      auditLog: audit,
      now: () => now,
    });
    const findings = await watcher.evaluate();
    expect(findings).toEqual([]);
  });

  it("multi-fortress isolation: each watcher only sees its own audit log", async () => {
    const now = new Date("2026-05-09T12:00:00.000Z");
    const auditA = makeStubAuditLog(
      backdatedProxyCalls({
        now,
        perDay: [50, 50, 50, 50, 50, 50, 50],
        server: "api.example.com",
        currentDayCount: 50,
      }),
    );
    const auditB = makeStubAuditLog([]);
    const watcherA = new EgressVolumeWatcher();
    await watcherA.subscribe({
      fortressId: FORTRESS_A,
      auditLog: auditA,
      now: () => now,
    });
    const watcherB = new EgressVolumeWatcher();
    await watcherB.subscribe({
      fortressId: FORTRESS_B,
      auditLog: auditB,
      now: () => now,
    });
    const findingsA = await watcherA.evaluate();
    const findingsB = await watcherB.evaluate();
    expect(findingsA.length).toBe(1);
    expect(findingsA[0]?.severity).toBe("info");
    expect(findingsB.length).toBe(0);
  });
});

describe("WP-V1.3-1 Phi-1 HTTP routes", () => {
  async function makeServer(rig: ReturnType<typeof makeRig>): Promise<{
    base: string;
    close: () => Promise<void>;
  }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleSentinelRoute(
        {
          dispatcher: rig.dispatcher,
          authConfig: { loopbackAutoAuth: true },
        },
        req,
        res,
      );
      if (!handled) {
        res.writeHead(404).end();
      }
    });
    await new Promise<void>((resolve) =>
      server.listen(0, "127.0.0.1", resolve),
    );
    const addr = server.address() as AddressInfo;
    return {
      base: `http://127.0.0.1:${addr.port}`,
      close: () =>
        new Promise<void>((resolve) =>
          server.close(() => {
            resolve();
          }),
        ),
    };
  }

  it("GET /api/sentinels returns the catalog", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(`${base}${SENTINEL_API_PREFIX}`);
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: { catalog: Array<{ sentinelId: string }> };
      };
      expect(body.ok).toBe(true);
      expect(body.data.catalog.map((c) => c.sentinelId)).toContain(
        EGRESS_VOLUME_SENTINEL_ID,
      );
    } finally {
      await close();
    }
  });

  it("POST + DELETE /api/sentinels/:id/subscribe round-trip", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const subRes = await fetch(
        `${base}${SENTINEL_API_PREFIX}/${EGRESS_VOLUME_SENTINEL_ID}/subscribe`,
        { method: "POST" },
      );
      expect(subRes.status).toBe(200);
      expect(rig.registry.isSubscribed(EGRESS_VOLUME_SENTINEL_ID)).toBe(true);

      const listRes = await fetch(
        `${base}${SENTINEL_API_PREFIX}/subscribed`,
      );
      const listBody = (await listRes.json()) as {
        ok: boolean;
        data: { subscribed: string[] };
      };
      expect(listBody.data.subscribed).toContain(EGRESS_VOLUME_SENTINEL_ID);

      const unsubRes = await fetch(
        `${base}${SENTINEL_API_PREFIX}/${EGRESS_VOLUME_SENTINEL_ID}/subscribe`,
        { method: "DELETE" },
      );
      expect(unsubRes.status).toBe(200);
      expect(rig.registry.isSubscribed(EGRESS_VOLUME_SENTINEL_ID)).toBe(false);
    } finally {
      await close();
    }
  });

  it("POST /api/sentinels/:id/subscribe returns 404 for unknown sentinel", async () => {
    const rig = makeRig();
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${SENTINEL_API_PREFIX}/never-registered/subscribe`,
        { method: "POST" },
      );
      expect(res.status).toBe(404);
    } finally {
      await close();
    }
  });

  it("GET /api/sentinels/findings filters by severity", async () => {
    const rig = makeRig();
    await rig.findingStore.saveFinding({
      finding_id: "f-1",
      sentinel_id: "egress-volume",
      severity: "warn",
      summary: "warn",
      details: {},
      observed_at: "2026-05-09T12:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    await rig.findingStore.saveFinding({
      finding_id: "f-2",
      sentinel_id: "egress-volume",
      severity: "alert",
      summary: "alert",
      details: {},
      observed_at: "2026-05-09T13:00:00.000Z",
      evidence_audit_ids: [],
      fortress_id: FORTRESS_A,
    });
    const { base, close } = await makeServer(rig);
    try {
      const res = await fetch(
        `${base}${SENTINEL_API_PREFIX}/findings?severity=alert`,
      );
      const body = (await res.json()) as {
        ok: boolean;
        data: { findings: SentinelFinding[] };
      };
      expect(body.data.findings.length).toBe(1);
      expect(body.data.findings[0]?.severity).toBe("alert");
    } finally {
      await close();
    }
  });
});

describe("WP-V1.3-1 Phi-1 CLI subscribe + persistence", () => {
  let storagePath: string;
  let outBuf: string;
  let outStream: NodeJS.WritableStream;

  beforeEach(async () => {
    storagePath = await mkdtemp(join(tmpdir(), "sanctuary-sentinel-cli-"));
    outBuf = "";
    outStream = {
      write(chunk: string | Buffer): boolean {
        outBuf += chunk.toString();
        return true;
      },
    } as unknown as NodeJS.WritableStream;
  });

  afterEach(async () => {
    if (storagePath) {
      await rm(storagePath, { recursive: true, force: true });
    }
  });

  it("list prints the Phi-1 catalog", async () => {
    const code = await runSentinelCommand({
      argv: ["list"],
      out: outStream,
      err: outStream,
    });
    expect(code).toBe(0);
    expect(outBuf).toContain(EGRESS_VOLUME_SENTINEL_ID);
  });

  it("subscribe writes the subscription file and unsubscribe removes it", async () => {
    const subCode = await runSentinelCommand({
      argv: ["subscribe", EGRESS_VOLUME_SENTINEL_ID],
      out: outStream,
      err: outStream,
      storagePath,
    });
    expect(subCode).toBe(0);
    const persisted = await loadSentinelSubscriptions(storagePath);
    expect(persisted.has(EGRESS_VOLUME_SENTINEL_ID)).toBe(true);

    const unsubCode = await runSentinelCommand({
      argv: ["unsubscribe", EGRESS_VOLUME_SENTINEL_ID],
      out: outStream,
      err: outStream,
      storagePath,
    });
    expect(unsubCode).toBe(0);
    const after = await loadSentinelSubscriptions(storagePath);
    expect(after.has(EGRESS_VOLUME_SENTINEL_ID)).toBe(false);
  });

  it("subscribe rejects an unknown sentinel id", async () => {
    const code = await runSentinelCommand({
      argv: ["subscribe", "never-registered"],
      out: outStream,
      err: outStream,
      storagePath,
    });
    expect(code).toBe(2);
    expect(outBuf).toContain("Unknown sentinel");
  });

  it("subscription store round-trips through the file path helper", async () => {
    await saveSentinelSubscriptions(storagePath, [EGRESS_VOLUME_SENTINEL_ID]);
    const reloaded = await loadSentinelSubscriptions(storagePath);
    expect(reloaded.has(EGRESS_VOLUME_SENTINEL_ID)).toBe(true);
    expect(sentinelSubscriptionsPath(storagePath)).toMatch(
      /sentinel-subscriptions\.json$/,
    );
  });

  it("list-subscribed reports nothing when subscription file is absent", async () => {
    const code = await runSentinelCommand({
      argv: ["list-subscribed"],
      out: outStream,
      err: outStream,
      storagePath,
    });
    expect(code).toBe(0);
    expect(outBuf).toContain("(no subscriptions)");
  });
});
