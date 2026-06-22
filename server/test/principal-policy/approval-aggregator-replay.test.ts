/**
 * WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-3
 *
 * Regression suite for the replay surface: provenance enrichment
 * (enforcement_chain), at-rest payload persistence with boot-restore,
 * and the operator-facing /audit-trail, /payload, and /history routes.
 *
 * Coverage map (spawn prompt acceptance criteria):
 *   - Default enforcement_chain populates a single l2 step             (1)
 *   - Custom resolveEnforcementChain populates a richer chain          (2)
 *   - With payloadStore: ingest persists payload at-rest               (3)
 *   - With payloadStore: getFullPayload restores after fresh instance  (4)
 *   - Without payloadStore: getFullPayload returns null after restart  (5)
 *   - GET /:id/audit-trail returns aggregator-side audit entries       (6)
 *   - GET /:id/audit-trail emits AUDIT_TRAIL_VIEWED audit              (7)
 *   - GET /:id/audit-trail returns 404 on unknown id                   (8)
 *   - GET /:id/payload returns the payload + emits PAYLOAD_DECRYPTED   (9)
 *   - GET /:id/payload returns 404 on unknown id                       (10)
 *   - GET /history returns only resolved entries                       (11)
 *   - GET /history?status=approved filters by status                   (12)
 *   - GET /history emits REPLAYED audit                                (13)
 *   - /history rejects without bearer token                            (14)
 *   - Replay routes are read-only (entry status unchanged after view)  (15)
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

import {
  APPROVAL_AGGREGATOR_AUDIT_OPS,
  ApprovalAggregator,
  type ApprovalGateEvent,
  type EnforcementLayerEvent,
} from "../../src/principal-policy/approval-aggregator.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "../../src/principal-policy/approval-aggregator-routes.js";
import { AggregatorPayloadStore } from "../../src/principal-policy/aggregator-store.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const IDENTITY = "identity_test";
const FORTRESS = "fortress_test";

function makeRequestedEvent(
  overrides?: Partial<ApprovalGateEvent>,
): ApprovalGateEvent {
  return {
    phase: "requested",
    operation: "state_export",
    tier: 1,
    reason: "tier1_always_approve",
    context: { harness: "claude-code", agent_id: "agent-x", path: "/etc" },
    request_timestamp: "2026-05-09T12:00:00.000Z",
    correlation_id: "corr-1",
    ...overrides,
  };
}

interface Rig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  payloadStore: AggregatorPayloadStore;
  aggregator: ApprovalAggregator;
}

function makeRig(opts?: {
  resolveEnforcementChain?: (
    event: ApprovalGateEvent,
  ) => EnforcementLayerEvent[];
  withPayloadStore?: boolean;
}): Rig {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const payloadStore = new AggregatorPayloadStore({
    storage,
    masterKey,
    fortressId: FORTRESS,
  });
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
    resolveSourceContext: (event) => ({
      source_harness:
        (event.context["harness"] as string | undefined) ?? "claude-code",
      source_agent_id:
        (event.context["agent_id"] as string | undefined) ?? "agent-x",
    }),
    ...(opts?.withPayloadStore !== false ? { payloadStore } : {}),
    ...(opts?.resolveEnforcementChain !== undefined
      ? { resolveEnforcementChain: opts.resolveEnforcementChain }
      : {}),
  });
  return { storage, masterKey, auditLog, payloadStore, aggregator };
}

// ── Provenance enrichment ─────────────────────────────────────────────

describe("WP-V1.3-10 Upsilon-3 provenance enrichment", () => {
  it("populates a default enforcement_chain with a single l2 step", async () => {
    const { aggregator } = makeRig();
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry?.enforcement_chain).toBeDefined();
    expect(entry?.enforcement_chain?.length).toBe(1);
    expect(entry?.enforcement_chain?.[0]?.layer).toBe("l2");
    expect(entry?.enforcement_chain?.[0]?.event).toBe(
      "approval_required:state_export",
    );
  });

  it("uses a custom resolveEnforcementChain when provided (Castle Wall + cooperative MCP)", async () => {
    const customChain: EnforcementLayerEvent[] = [
      {
        layer: "l1",
        event: "egress_blocked:api.example.com",
        timestamp: "2026-05-09T11:59:59.500Z",
      },
      {
        layer: "l2",
        event: "approval_required:state_export",
        timestamp: "2026-05-09T12:00:00.000Z",
      },
    ];
    const { aggregator } = makeRig({
      resolveEnforcementChain: () => customChain,
    });
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry?.enforcement_chain).toEqual(customChain);
  });
});

// ── At-rest payload persistence + boot-restore ────────────────────────

describe("WP-V1.3-10 Upsilon-3 payload persistence", () => {
  it("persists the request payload via the at-rest store on ingest", async () => {
    const { aggregator, payloadStore } = makeRig();
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const stored = await payloadStore.loadPayload(entry!.aggregator_id);
    expect(stored).toEqual({
      harness: "claude-code",
      agent_id: "agent-x",
      path: "/etc",
    });
  });

  it("getFullPayload restores from the at-rest store on a fresh aggregator instance (boot-restore)", async () => {
    const { storage, masterKey } = makeRig();
    const auditLog1 = new AuditLog(storage, masterKey);
    const payloadStore1 = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const aggregator1 = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog: auditLog1,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      payloadStore: payloadStore1,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-x",
      }),
    });
    const entry = await aggregator1.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();

    // Simulate a server restart with a fresh aggregator + auditLog, same
    // storage backend + masterKey.
    const auditLog2 = new AuditLog(storage, masterKey);
    const payloadStore2 = new AggregatorPayloadStore({
      storage,
      masterKey,
      fortressId: FORTRESS,
    });
    const aggregator2 = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog: auditLog2,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      payloadStore: payloadStore2,
    });
    const restored = await aggregator2.getFullPayload(entry!.aggregator_id);
    expect(restored).toEqual({
      harness: "claude-code",
      agent_id: "agent-x",
      path: "/etc",
    });
  });

  it("without a payloadStore, getFullPayload returns null after a fresh aggregator instance (Upsilon-1 behavior preserved)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog1 = new AuditLog(storage, masterKey);
    const aggregator1 = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog: auditLog1,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-x",
      }),
    });
    const entry = await aggregator1.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();

    const auditLog2 = new AuditLog(storage, masterKey);
    const aggregator2 = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog: auditLog2,
      identityId: IDENTITY,
      fortressId: FORTRESS,
    });
    const restored = await aggregator2.getFullPayload(entry!.aggregator_id);
    expect(restored).toBeNull();
  });
});

// ── Replay route surface ──────────────────────────────────────────────

interface RouteRig {
  server: Server;
  url: string;
  aggregator: ApprovalAggregator;
  auditLog: AuditLog;
  authToken: string;
  stop: () => Promise<void>;
}

async function startRouteRig(): Promise<RouteRig> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const payloadStore = new AggregatorPayloadStore({
    storage,
    masterKey,
    fortressId: FORTRESS,
  });
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
    payloadStore,
    resolveSourceContext: (event) => ({
      source_harness:
        (event.context["harness"] as string | undefined) ?? "claude-code",
      source_agent_id:
        (event.context["agent_id"] as string | undefined) ?? "agent-x",
    }),
  });
  const authToken = "replay-test-token";
  const server = createServer((req, res) => {
    void handleApprovalInboxRoute(
      {
        authConfig: { loopbackAutoAuth: false, authToken },
        aggregator,
        operatorId: "operator_replay_test",
      },
      req,
      res,
    ).then((handled) => {
      if (!handled) {
        res.writeHead(404).end();
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    url: `http://127.0.0.1:${port}`,
    aggregator,
    auditLog,
    authToken,
    stop: () =>
      new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("WP-V1.3-10 Upsilon-3 replay routes", () => {
  let rig: RouteRig;

  beforeEach(async () => {
    rig = await startRouteRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  // /audit-trail
  it("GET /:id/audit-trail returns the aggregator-side audit entries", async () => {
    const entry = await rig.aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry!.aggregator_id}/audit-trail`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        entry: { aggregator_id: string };
        audit_trail: Array<{ operation: string }>;
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.entry.aggregator_id).toBe(entry!.aggregator_id);
    // The trail must include the AGGREGATED event from ingest.
    const ops = body.data.audit_trail.map((e) => e.operation);
    expect(ops).toContain(APPROVAL_AGGREGATOR_AUDIT_OPS.AGGREGATED);
  });

  it("GET /:id/audit-trail emits the AUDIT_TRAIL_VIEWED audit event", async () => {
    const entry = await rig.aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry!.aggregator_id}/audit-trail`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const audit = await rig.auditLog.query({ layer: "l2", limit: 200 });
    const viewed = audit.entries.filter(
      (e) => e.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.AUDIT_TRAIL_VIEWED,
    );
    expect(viewed.length).toBe(1);
    expect(viewed[0]?.identity_id).toBe("operator_replay_test");
    expect(viewed[0]?.details?.["aggregator_id"]).toBe(entry!.aggregator_id);
  });

  it("GET /:id/audit-trail returns 404 for an unknown aggregator_id", async () => {
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/aggregator-nonexistent/audit-trail`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(404);
  });

  // /payload
  it("GET /:id/payload returns the request payload and emits PAYLOAD_DECRYPTED audit", async () => {
    const entry = await rig.aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry!.aggregator_id}/payload`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        entry: { aggregator_id: string };
        request_payload: { path?: string };
      };
    };
    expect(body.data.request_payload.path).toBe("/etc");

    const audit = await rig.auditLog.query({ layer: "l2", limit: 200 });
    const decrypted = audit.entries.filter(
      (e) => e.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.PAYLOAD_DECRYPTED,
    );
    expect(decrypted.length).toBe(1);
    expect(decrypted[0]?.identity_id).toBe("operator_replay_test");
  });

  it("GET /:id/payload returns 404 for an unknown aggregator_id", async () => {
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/aggregator-nonexistent/payload`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(404);
  });

  // /history
  it("GET /history returns only resolved entries (excludes pending)", async () => {
    const pending = await rig.aggregator.ingest(makeRequestedEvent());
    const toResolve = await rig.aggregator.ingest(
      makeRequestedEvent({
        correlation_id: "corr-resolve",
        request_timestamp: "2026-05-09T12:00:01.000Z",
      }),
    );
    expect(pending).not.toBeNull();
    expect(toResolve).not.toBeNull();
    // Manually resolve the second.
    await rig.aggregator.resolve(
      toResolve!.aggregator_id,
      "approved",
      "operator",
    );

    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/history`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: {
        entries: Array<{ aggregator_id: string; status: string }>;
      };
    };
    expect(body.data.entries.length).toBe(1);
    expect(body.data.entries[0]?.aggregator_id).toBe(
      toResolve!.aggregator_id,
    );
    expect(body.data.entries[0]?.status).toBe("approved");
  });

  it("GET /history?status=approved filters by status", async () => {
    const a = await rig.aggregator.ingest(makeRequestedEvent());
    const b = await rig.aggregator.ingest(
      makeRequestedEvent({
        correlation_id: "corr-deny",
        request_timestamp: "2026-05-09T12:00:02.000Z",
      }),
    );
    expect(a).not.toBeNull();
    expect(b).not.toBeNull();
    await rig.aggregator.resolve(a!.aggregator_id, "approved", "op");
    await rig.aggregator.resolve(b!.aggregator_id, "denied", "op");

    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/history?status=approved`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { entries: Array<{ status: string; aggregator_id: string }> };
    };
    expect(body.data.entries.length).toBe(1);
    expect(body.data.entries[0]?.status).toBe("approved");
    expect(body.data.entries[0]?.aggregator_id).toBe(a!.aggregator_id);
  });

  it("GET /history emits the REPLAYED audit event", async () => {
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/history`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    expect(res.status).toBe(200);
    const audit = await rig.auditLog.query({ layer: "l2", limit: 200 });
    const replayed = audit.entries.filter(
      (e) => e.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.REPLAYED,
    );
    expect(replayed.length).toBe(1);
    expect(replayed[0]?.identity_id).toBe("operator_replay_test");
  });

  it("GET /history rejects without a valid bearer token", async () => {
    const res = await fetch(`${rig.url}${APPROVAL_INBOX_API_PREFIX}/history`);
    expect(res.status).toBe(401);
  });

  it("replay routes do not mutate entry status (read-only across audit-trail + payload reads)", async () => {
    const entry = await rig.aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const before = await rig.aggregator.getEntry(entry!.aggregator_id);
    expect(before?.status).toBe("pending");

    await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry!.aggregator_id}/audit-trail`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );
    await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry!.aggregator_id}/payload`,
      { headers: { authorization: `Bearer ${rig.authToken}` } },
    );

    const after = await rig.aggregator.getEntry(entry!.aggregator_id);
    expect(after?.status).toBe("pending");
    expect(after?.resolved_at).toBeUndefined();
    expect(after?.resolved_by).toBeUndefined();
  });
});
