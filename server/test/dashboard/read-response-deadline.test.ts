/**
 * Dashboard read routes return explicit unavailable responses under stalled reads.
 *
 * Coverage: route-level read deadlines, per-route in-flight caps, client-close
 * abort signaling, and the honest unavailable body for DSRD.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import type { AddressInfo } from "node:net";
import { randomBytes } from "node:crypto";

import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { defaultConfig } from "../../src/config.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import { createIdentity, type StoredIdentity } from "../../src/core/identity.js";
import {
  UnifiedInboxBridge,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import { UnifiedInboxStore } from "../../src/principal-policy/unified-inbox-store.js";
import type {
  InboxFilterPrefs,
} from "../../src/principal-policy/unified-inbox-prefs-store.js";
import {
  DASHBOARD_READ_RESPONSE_DEADLINE_MS,
  getDashboardReadInFlightCount,
  respondWithBoundedDashboardRead,
  resetDashboardReadInFlightForTests,
} from "../../src/dashboard/read-response.js";

const TEST_AUTH_TOKEN = "dashboard-read-deadline-token";
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
  stallExclusiveEgress?: boolean;
} = {}): Promise<{
  baseUrl: string;
  stop: () => Promise<void>;
  prefsLoad: ReturnType<typeof vi.fn>;
  enforcementRead: ReturnType<typeof vi.fn>;
  exclusiveEgressRead: ReturnType<typeof vi.fn>;
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
  const prefsLoad = vi.fn(() => new Promise<InboxFilterPrefs>(() => undefined));
  const enforcementRead = vi.fn(() => new Promise<never>(() => undefined));
  const exclusiveEgressRead = vi.fn(() => new Promise<never>(() => undefined));

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
    auditLog,
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

async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections?.();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

afterEach(() => {
  resetDashboardReadInFlightForTests();
});

describe("dashboard bounded read responses", () => {
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
      expect(getDashboardReadInFlightCount("unified_inbox_prefs")).toBe(1);

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
      expect(getDashboardReadInFlightCount("posture_home")).toBe(1);

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
      expect(getDashboardReadInFlightCount("sovereignty")).toBe(1);

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

  it("aborts cancellable route reads when the caller closes the request", async () => {
    let enteredProducer: (() => void) | undefined;
    const producerEntered = new Promise<void>((resolve) => {
      enteredProducer = resolve;
    });
    const aborted = new Promise<void>((resolve) => {
      const server = createServer((req: IncomingMessage, res: ServerResponse) => {
        void respondWithBoundedDashboardRead({
          route: "sovereignty",
          req,
          res,
          operation: "abort_probe",
          produce: async (signal) => {
            enteredProducer?.();
            signal.addEventListener("abort", () => {
              void closeServer(server).then(resolve);
            }, { once: true });
            return new Promise<never>(() => undefined);
          },
        });
      });
      server.listen(0, "127.0.0.1", () => {
        const port = (server.address() as AddressInfo).port;
      const req = httpRequest({
        hostname: "127.0.0.1",
        port,
        path: "/abort",
        method: "GET",
      });
        req.on("error", () => undefined);
        req.end();
        void producerEntered.then(() => req.destroy());
      });
    });

    await aborted;
    expect(getDashboardReadInFlightCount("sovereignty")).toBe(1);
  });
});
