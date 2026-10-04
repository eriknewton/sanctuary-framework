/**
 * Dashboard read routes return explicit unavailable responses under stalled reads.
 *
 * Coverage: route-level read deadlines, per-route in-flight caps, client-close
 * abort signaling, and the honest unavailable body for DSRD.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { EventEmitter } from "node:events";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { defaultConfig } from "../../src/config.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, type StoredIdentity } from "../../src/core/identity.js";
import { getClientScript } from "../../src/dashboard/v1_1/client.js";
import {
  UnifiedInboxBridge,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import { UnifiedInboxStore } from "../../src/principal-policy/unified-inbox-store.js";
import type {
  InboxFilterPrefs,
} from "../../src/principal-policy/unified-inbox-prefs-store.js";
import {
  DASHBOARD_CLIENT_READ_DEADLINE_MS,
  DASHBOARD_CLIENT_READ_DEADLINE_SECONDS,
  DASHBOARD_MILLISECONDS_PER_SECOND,
  DASHBOARD_RETRY_AFTER_SECONDS,
  DASHBOARD_READ_RESPONSE_DEADLINE_MS,
  getDashboardReadInFlightCount,
  respondWithBoundedDashboardRead,
  createDashboardReadFlightMap,
  type DashboardReadFlightMap,
} from "../../src/dashboard/read-response.js";

const TEST_AUTH_TOKEN = "dashboard-read-deadline-token";
// Definition: test wall-clock slack is expressed in seconds and converted for Date.now() comparisons.
const MILLISECONDS_PER_SECOND = 1000;
const DEADLINE_SLACK_SECONDS = 2;
const DEADLINE_SLACK_MS = DEADLINE_SLACK_SECONDS * MILLISECONDS_PER_SECOND;
const FAST_REFUSAL_HALF_SECOND_MS = MILLISECONDS_PER_SECOND / 2;
const TEST_HARNESS_SLACK_SECONDS = 3;
const TEST_HARNESS_TIMEOUT_MS =
  DASHBOARD_READ_RESPONSE_DEADLINE_MS +
  DEADLINE_SLACK_MS +
  FAST_REFUSAL_HALF_SECOND_MS +
  TEST_HARNESS_SLACK_SECONDS * MILLISECONDS_PER_SECOND;
const PRODUCER_START_POLL_MS = 10;
const PRODUCER_START_TIMEOUT_MS = 500;

class MockIncomingMessage extends EventEmitter {
  headers: Record<string, string> = {};
}

class MockServerResponse extends EventEmitter {
  headersSent = false;
  writableEnded = false;
  statusCode = 0;
  headers: Record<string, string> = {};
  body = "";

  setHeader(name: string, value: number | string | readonly string[]): this {
    this.headers[name] = Array.isArray(value) ? value.join(", ") : String(value);
    return this;
  }

  writeHead(statusCode: number, headers: Record<string, string> = {}): this {
    this.statusCode = statusCode;
    this.headersSent = true;
    for (const [name, value] of Object.entries(headers)) {
      this.headers[name] = value;
    }
    return this;
  }

  end(chunk?: string): this {
    if (chunk !== undefined) this.body += chunk;
    this.writableEnded = true;
    this.emit("close");
    return this;
  }

  json(): Record<string, unknown> {
    return JSON.parse(this.body) as Record<string, unknown>;
  }
}

// The direct-wrapper tests own one flight map, replaced after each test.
let directReadFlights = createDashboardReadFlightMap();

function directBoundedRead<T>(
  produce: (signal: AbortSignal) => Promise<{ status: number; body: T }>,
  operation = "direct_test_read",
): {
  req: MockIncomingMessage;
  res: MockServerResponse;
  handled: Promise<boolean>;
} {
  const req = new MockIncomingMessage();
  const res = new MockServerResponse();
  const handled = respondWithBoundedDashboardRead({
    route: "sovereignty",
    req: req as IncomingMessage,
    res: res as unknown as ServerResponse,
    operation,
    produce,
    readFlights: directReadFlights,
  });
  return { req, res, handled };
}

class TestIdentityManager {
  private identities = new Map<string, StoredIdentity>();
  private defaultId: string;

  constructor(private readonly masterKey: Uint8Array) {
    const encKey = derivePurposeKey(masterKey, "identity-encryption");
    const { publicIdentity, storedIdentity } = createIdentity(
      "dashboard-read-deadline",
      encKey,
      "recovery-key",
    );
    this.identities.set(publicIdentity.identity_id, storedIdentity);
    this.defaultId = publicIdentity.identity_id;
  }

  get(id: string): StoredIdentity | undefined {
    return this.identities.get(id);
  }

  getDefault(): StoredIdentity | undefined {
    return this.identities.get(this.defaultId);
  }

  getPrimaryIdentityId(): string {
    return this.defaultId;
  }

  list(): StoredIdentity[] {
    return [...this.identities.values()];
  }
}

async function startDashboardWithStalledReads(options: {
  auditLocked?: boolean;
  stallExclusiveEgress?: boolean;
  stallProducerKeyLoad?: boolean;
  prefsLoad?: ReturnType<typeof vi.fn>;
} = {}): Promise<{
  baseUrl: string;
  stop: () => Promise<void>;
  prefsLoad: ReturnType<typeof vi.fn>;
  enforcementRead: ReturnType<typeof vi.fn>;
  exclusiveEgressRead: ReturnType<typeof vi.fn>;
  producerKeyLoad: ReturnType<typeof vi.fn> | null;
  readFlightMap: DashboardReadFlightMap;
}> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const identityManager = new TestIdentityManager(masterKey);
  const port = await getFreePort();
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: TEST_AUTH_TOKEN,
    auto_open: false,
  });
  const prefsLoad =
    options.prefsLoad ?? vi.fn(() => new Promise<InboxFilterPrefs>(() => undefined));
  const enforcementRead = vi.fn(() => new Promise<never>(() => undefined));
  const exclusiveEgressRead = vi.fn(() => new Promise<never>(() => undefined));
  const producerKeyLoad =
    options.stallProducerKeyLoad === true
      ? vi.fn(() => new Promise<void>(() => undefined))
      : null;
  if (producerKeyLoad) {
    (dashboard as unknown as { ensureProducerKeyLoaded: () => Promise<void> })
      .ensureProducerKeyLoaded = producerKeyLoad;
  }

  dashboard.setDependencies({
    policy: {
      version: 1,
      tier1_always_approve: [],
      tier3_auto_allow: [],
      anomaly_thresholds: {
        new_namespace: true,
        unfamiliar_counterparty_window_days: 7,
        frequency_spike_multiplier: 5,
      },
      approval_channel: { type: "stderr", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => undefined, save: async () => undefined } as never,
    auditLog: (options.auditLocked === true ? null : auditLog) as never,
    identityManager: identityManager as never,
    shrOpts: {
      config: defaultConfig(),
      identityManager: identityManager as never,
      masterKey,
    },
    resolveEnforcementAvailability: enforcementRead,
  });

  const inboxStore = new UnifiedInboxStore({
    storage,
    masterKey,
    fortressId: "dashboard-read-deadline-fortress",
  });
  const bridge = new UnifiedInboxBridge({
    auditLog,
    identityId: "dashboard-read-deadline-identity",
    fortressId: "dashboard-read-deadline-fortress",
    store: inboxStore,
  });
  dashboard.setUnifiedInbox({
    bridge,
    prefsStore: {
      load: prefsLoad,
      save: vi.fn(),
    } as never,
  });
  if (options.stallExclusiveEgress === true) {
    dashboard.setExclusiveEgressPostureProvider(exclusiveEgressRead);
  }

  await dashboard.start();
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    stop: () => dashboard.stop(),
    prefsLoad,
    enforcementRead,
    exclusiveEgressRead,
    producerKeyLoad,
    readFlightMap: (dashboard as unknown as { readFlightMap: DashboardReadFlightMap })
      .readFlightMap,
  };
}

async function getFreePort(): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return port;
}

async function readJson(path: string, baseUrl: string): Promise<{
  elapsedMs: number;
  status: number;
  body: Record<string, unknown>;
}> {
  const started = Date.now();
  const res = await fetch(`${baseUrl}${path}`, {
    headers: { Authorization: `Bearer ${TEST_AUTH_TOKEN}` },
  });
  const body = await res.json() as Record<string, unknown>;
  return { elapsedMs: Date.now() - started, status: res.status, body };
}

async function waitForProducerStart(
  producer: ReturnType<typeof vi.fn>,
): Promise<void> {
  const deadline = Date.now() + PRODUCER_START_TIMEOUT_MS;
  while (producer.mock.calls.length === 0 && Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, PRODUCER_START_POLL_MS));
  }
}

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  directReadFlights = createDashboardReadFlightMap();
});

describe("dashboard bounded read responses", () => {
  it("GET /api/posture/home preserves the locked-audit posture_unavailable body", async () => {
    const rig = await startDashboardWithStalledReads({ auditLocked: true });
    try {
      const res = await readJson("/api/posture/home", rig.baseUrl);
      expect(res.status, JSON.stringify(res.body)).toBe(503);
      expect(res.body).toMatchObject({
        error: "posture_unavailable",
        reason: "audit log not unlocked; posture cannot be evidenced",
        origin_machine: expect.any(String),
      });
      expect(res.body.origin_machine).not.toBe("");
      expect(rig.enforcementRead).not.toHaveBeenCalled();
    } finally {
      await rig.stop();
    }
  });

  it("GET /api/inbox/unified/prefs returns unavailable within the server budget and caps retry waves", async () => {
    const rig = await startDashboardWithStalledReads();
    try {
      const first = await readJson("/api/inbox/unified/prefs", rig.baseUrl);
      expect(first.status, JSON.stringify(first.body)).toBe(503);
      expect(first.body).toMatchObject({
        ok: false,
        error: "dashboard_read_unavailable",
        route: "unified_inbox_prefs",
        reason: "deadline_exceeded",
      });
      expect(first.elapsedMs).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS + DEADLINE_SLACK_MS);
      expect(getDashboardReadInFlightCount("unified_inbox_prefs", rig.readFlightMap)).toBe(1);

      const retryStarted = Date.now();
      const retryA = await readJson("/api/inbox/unified/prefs", rig.baseUrl);
      const retryB = await readJson("/api/inbox/unified/prefs", rig.baseUrl);
      expect(Date.now() - retryStarted).toBeLessThan(FAST_REFUSAL_HALF_SECOND_MS);
      expect(retryA.status).toBe(503);
      expect(retryB.status).toBe(503);
      expect(retryA.body.reason).toBe("in_flight_limit");
      expect(retryB.body.reason).toBe("in_flight_limit");
      expect(rig.prefsLoad).toHaveBeenCalledTimes(1);
    } finally {
      await rig.stop();
    }
  }, TEST_HARNESS_TIMEOUT_MS);

  it("GET /api/posture/home returns unavailable within the server budget and caps retry waves", async () => {
    const rig = await startDashboardWithStalledReads();
    try {
      const first = await readJson("/api/posture/home", rig.baseUrl);
      expect(first.status, JSON.stringify(first.body)).toBe(503);
      expect(first.body).toMatchObject({
        ok: false,
        error: "dashboard_read_unavailable",
        route: "posture_home",
        reason: "deadline_exceeded",
      });
      expect(first.elapsedMs).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS + DEADLINE_SLACK_MS);
      expect(getDashboardReadInFlightCount("posture_home", rig.readFlightMap)).toBe(1);

      const retryStarted = Date.now();
      const retryA = await readJson("/api/posture/home", rig.baseUrl);
      const retryB = await readJson("/api/posture/home", rig.baseUrl);
      expect(Date.now() - retryStarted).toBeLessThan(FAST_REFUSAL_HALF_SECOND_MS);
      expect(retryA.status).toBe(503);
      expect(retryB.status).toBe(503);
      expect(retryA.body.reason).toBe("in_flight_limit");
      expect(retryB.body.reason).toBe("in_flight_limit");
      expect(rig.enforcementRead).toHaveBeenCalledTimes(1);
    } finally {
      await rig.stop();
    }
  }, TEST_HARNESS_TIMEOUT_MS);

  it("GET /api/posture/home budgets stalled producer-key loading and caps retry waves", async () => {
    const rig = await startDashboardWithStalledReads({
      stallProducerKeyLoad: true,
    });
    try {
      const first = await readJson("/api/posture/home", rig.baseUrl);
      expect(first.status, JSON.stringify(first.body)).toBe(503);
      expect(first.body).toMatchObject({
        ok: false,
        error: "dashboard_read_unavailable",
        route: "posture_home",
        reason: "deadline_exceeded",
        origin_machine: expect.any(String),
      });
      expect(first.elapsedMs).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS + DEADLINE_SLACK_MS);
      expect(getDashboardReadInFlightCount("posture_home", rig.readFlightMap)).toBe(1);

      const retryStarted = Date.now();
      const retryA = await readJson("/api/posture/home", rig.baseUrl);
      const retryB = await readJson("/api/posture/home", rig.baseUrl);
      expect(Date.now() - retryStarted).toBeLessThan(FAST_REFUSAL_HALF_SECOND_MS);
      expect(retryA.status).toBe(503);
      expect(retryB.status).toBe(503);
      expect(retryA.body).toMatchObject({
        reason: "in_flight_limit",
        origin_machine: expect.any(String),
      });
      expect(retryB.body).toMatchObject({
        reason: "in_flight_limit",
        origin_machine: expect.any(String),
      });
      expect(rig.producerKeyLoad).toHaveBeenCalledTimes(1);
      expect(rig.enforcementRead).not.toHaveBeenCalled();
    } finally {
      await rig.stop();
    }
  }, TEST_HARNESS_TIMEOUT_MS);

  it("keeps read flights scoped to their owning dashboard instance", async () => {
    let resolveFirst:
      | ((value: InboxFilterPrefs) => void)
      | undefined;
    let resolveSecond:
      | ((value: InboxFilterPrefs) => void)
      | undefined;
    const firstPrefsLoad = vi.fn(
      () =>
        new Promise<InboxFilterPrefs>((resolve) => {
          resolveFirst = resolve;
        }),
    );
    const secondPrefsLoad = vi.fn(
      () =>
        new Promise<InboxFilterPrefs>((resolve) => {
          resolveSecond = resolve;
        }),
    );
    const firstRig = await startDashboardWithStalledReads({
      prefsLoad: firstPrefsLoad,
    });
    const secondRig = await startDashboardWithStalledReads({
      prefsLoad: secondPrefsLoad,
    });
    try {
      const firstRead = readJson("/api/inbox/unified/prefs", firstRig.baseUrl);
      await waitForProducerStart(firstPrefsLoad);
      expect(firstPrefsLoad).toHaveBeenCalledTimes(1);
      const secondRead = readJson("/api/inbox/unified/prefs", secondRig.baseUrl);
      await waitForProducerStart(secondPrefsLoad);

      resolveFirst?.({
        search: "first-instance",
        source: "",
        severity: "",
        agent: "",
        from: "",
        to: "",
      });
      if (resolveSecond) {
        resolveSecond({
          search: "second-instance",
          source: "",
          severity: "",
          agent: "",
          from: "",
          to: "",
        });
      }

      const first = await firstRead;
      const second = await secondRead;
      expect(firstPrefsLoad).toHaveBeenCalledTimes(1);
      expect(secondPrefsLoad).toHaveBeenCalledTimes(1);
      expect(first.status).toBe(200);
      expect(second.status).toBe(200);
      expect((first.body.data as { filters: InboxFilterPrefs }).filters.search)
        .toBe("first-instance");
      expect((second.body.data as { filters: InboxFilterPrefs }).filters.search)
        .toBe("second-instance");
    } finally {
      await firstRig.stop();
      await secondRig.stop();
    }
  });

  it("GET /api/sovereignty returns unavailable within the server budget and caps retry waves", async () => {
    const rig = await startDashboardWithStalledReads({
      stallExclusiveEgress: true,
    });
    try {
      const first = await readJson("/api/sovereignty", rig.baseUrl);
      expect(first.status).toBe(503);
      expect(first.body).toMatchObject({
        ok: false,
        error: "dashboard_read_unavailable",
        route: "sovereignty",
        reason: "deadline_exceeded",
      });
      expect(first.elapsedMs).toBeLessThan(DASHBOARD_READ_RESPONSE_DEADLINE_MS + DEADLINE_SLACK_MS);
      expect(getDashboardReadInFlightCount("sovereignty", rig.readFlightMap)).toBe(1);

      const retryStarted = Date.now();
      const retryA = await readJson("/api/sovereignty", rig.baseUrl);
      const retryB = await readJson("/api/sovereignty", rig.baseUrl);
      expect(Date.now() - retryStarted).toBeLessThan(FAST_REFUSAL_HALF_SECOND_MS);
      expect(retryA.status).toBe(503);
      expect(retryB.status).toBe(503);
      expect(retryA.body.reason).toBe("in_flight_limit");
      expect(retryB.body.reason).toBe("in_flight_limit");
      expect(rig.exclusiveEgressRead).toHaveBeenCalledTimes(1);
    } finally {
      await rig.stop();
    }
  }, TEST_HARNESS_TIMEOUT_MS);

  it("shares one healthy producer result across concurrent callers", async () => {
    let resolveProducer:
      | ((value: { status: number; body: Record<string, unknown> }) => void)
      | undefined;
    const produce = vi.fn(
      () =>
        new Promise<{ status: number; body: Record<string, unknown> }>((resolve) => {
          resolveProducer = resolve;
        }),
    );

    const first = directBoundedRead(produce);
    await Promise.resolve();
    expect(produce).toHaveBeenCalledTimes(1);

    const second = directBoundedRead(produce);
    await Promise.resolve();
    expect(produce).toHaveBeenCalledTimes(1);

    resolveProducer?.({ status: 200, body: { ok: true, shared: "route-wide" } });
    await Promise.all([first.handled, second.handled]);

    expect(first.res.statusCode).toBe(200);
    expect(second.res.statusCode).toBe(200);
    expect(first.res.json()).toEqual({ ok: true, shared: "route-wide" });
    expect(second.res.json()).toEqual({ ok: true, shared: "route-wide" });
    expect(getDashboardReadInFlightCount("sovereignty", directReadFlights)).toBe(0);
  });

  it("refuses only overdue flights, suppresses late success, and starts fresh after producer settlement", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-10-04T00:00:00.000Z"));
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const resolvers: Array<
      (value: { status: number; body: Record<string, unknown> }) => void
    > = [];
    const produce = vi.fn(
      () =>
        new Promise<{ status: number; body: Record<string, unknown> }>((resolve) => {
          resolvers.push(resolve);
        }),
    );

    const first = directBoundedRead(produce, "late_completion_probe");
    await Promise.resolve();
    expect(produce).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(DASHBOARD_READ_RESPONSE_DEADLINE_MS);
    await first.handled;
    expect(first.res.statusCode).toBe(503);
    expect(first.res.json()).toMatchObject({
      error: "dashboard_read_unavailable",
      reason: "deadline_exceeded",
    });
    expect(getDashboardReadInFlightCount("sovereignty", directReadFlights)).toBe(1);

    const refused = directBoundedRead(produce, "late_completion_probe");
    await refused.handled;
    expect(refused.res.statusCode).toBe(503);
    expect(refused.res.json()).toMatchObject({
      error: "dashboard_read_unavailable",
      reason: "in_flight_limit",
    });
    expect(refused.res.headers["Retry-After"]).toBe(String(DASHBOARD_RETRY_AFTER_SECONDS));
    expect(produce).toHaveBeenCalledTimes(1);

    resolvers[0]?.({ status: 200, body: { ok: true, should_not_write: true } });
    await Promise.resolve();
    await Promise.resolve();
    expect(first.res.statusCode).toBe(503);
    expect(first.res.json()).toMatchObject({ reason: "deadline_exceeded" });
    expect(getDashboardReadInFlightCount("sovereignty", directReadFlights)).toBe(0);

    const fresh = directBoundedRead(produce, "late_completion_probe");
    await Promise.resolve();
    expect(produce).toHaveBeenCalledTimes(2);
    resolvers[1]?.({ status: 200, body: { ok: true, fresh: true } });
    await fresh.handled;
    expect(fresh.res.statusCode).toBe(200);
    expect(fresh.res.json()).toEqual({ ok: true, fresh: true });

    const logged = errors.mock.calls.map((call) => String(call[1] ?? call[0]));
    expect(logged.some((entry) =>
      entry.includes("deadline_exceeded") &&
      entry.includes("sovereignty") &&
      entry.includes("late_completion_probe"),
    )).toBe(true);
  });

  it("logs composition failures with route and operation but no response payload", async () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const probe = directBoundedRead(
      async () => {
        throw new Error("producer failed with token=secret-value");
      },
      "composition_probe",
    );

    await probe.handled;
    expect(probe.res.statusCode).toBe(503);
    expect(probe.res.json()).toMatchObject({
      error: "dashboard_read_unavailable",
      reason: "composition_failed",
    });

    const logged = errors.mock.calls.map((call) => String(call[1] ?? call[0]));
    expect(logged.some((entry) =>
      entry.includes("composition_failed") &&
      entry.includes("sovereignty") &&
      entry.includes("composition_probe"),
    )).toBe(true);
    expect(logged.join("\n")).not.toContain(probe.res.body);
  });

  it("does not abort or release the shared producer when one caller closes", async () => {
    let producerSignal: AbortSignal | undefined;
    const produce = vi.fn(
      (signal: AbortSignal) =>
        new Promise<{ status: number; body: Record<string, unknown> }>(() => {
          producerSignal = signal;
        }),
    );

    const probe = directBoundedRead(produce, "caller_close_probe");
    await Promise.resolve();
    probe.req.emit("aborted");
    await probe.handled;

    expect(producerSignal?.aborted).toBe(false);
    expect(getDashboardReadInFlightCount("sovereignty", directReadFlights)).toBe(1);
  });

  it("pins the client read deadline to the server derivation", () => {
    const client = getClientScript();
    const milliseconds = client.match(/const DASHBOARD_MILLISECONDS_PER_SECOND = (\d+);/);
    const seconds = client.match(/const DASHBOARD_READ_DEADLINE_SECONDS = (\d+);/);
    expect(milliseconds?.[1]).toBe(String(DASHBOARD_MILLISECONDS_PER_SECOND));
    expect(seconds?.[1]).toBe(String(DASHBOARD_CLIENT_READ_DEADLINE_SECONDS));
    expect(client).toContain(
      "const DASHBOARD_READ_DEADLINE_MS = DASHBOARD_READ_DEADLINE_SECONDS * DASHBOARD_MILLISECONDS_PER_SECOND;",
    );
    expect(
      Number(seconds?.[1]) * Number(milliseconds?.[1]),
    ).toBe(DASHBOARD_CLIENT_READ_DEADLINE_MS);
  });
});

describe("wrap dashboard servers keep their own bounded-read flights", () => {
  it("two startDashboardServer instances in one process never join each other's posture flight", async () => {
    const { startDashboardServer } = await import("../../src/dashboard/server.js");
    // Instance A's claim resolves after this delay so its flight is still open
    // when instance B is asked; 1500 ms sits well inside the 4 s read deadline.
    const SLOW_CLAIM_MS = 1500;
    const B_REQUEST_DELAY_MS = 150;
    const calls = { a: 0, b: 0 };
    async function startWrap(label: string, claim: () => unknown) {
      const storage = new MemoryStorage();
      const masterKey = generateRandomKey();
      const auditLog = new AuditLog(storage, masterKey);
      const identityManager = new TestIdentityManager(masterKey);
      const port = await getFreePort();
      const handle = await startDashboardServer({
        port,
        host: "127.0.0.1",
        authToken: TEST_AUTH_TOKEN,
        mode: "co-located",
        sources: {
          mode: "co-located",
          server_version: label,
          auditLog,
          identityManager,
          resolveProtectionClaimSubject: claim,
        } as never,
      });
      return { handle, base: `http://127.0.0.1:${port}`, origin: identityManager.getPrimaryIdentityId() };
    }
    const a = await startWrap("A", () => {
      calls.a += 1;
      return new Promise((resolve) => setTimeout(() => resolve(null), SLOW_CLAIM_MS));
    });
    const b = await startWrap("B", () => {
      calls.b += 1;
      return null;
    });
    try {
      const pendingA = readJson("/api/posture/home", a.base);
      await new Promise((resolve) => setTimeout(resolve, B_REQUEST_DELAY_MS));
      const fromB = await readJson("/api/posture/home", b.base);
      const fromA = await pendingA;
      expect(fromA.body.origin_machine).toBe(a.origin);
      expect(fromB.body.origin_machine).toBe(b.origin);
      expect(calls.b).toBe(1);
    } finally {
      await a.handle.stop();
      await b.handle.stop();
    }
  }, TEST_HARNESS_TIMEOUT_MS);
});

