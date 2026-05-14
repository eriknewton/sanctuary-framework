/**
 * WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-1
 * Regression suite for the approval aggregator + HTTP route surface.
 *
 * Acceptance map (spawn prompt):
 *   1. Round-trip ingest + list returns the aggregated entry.
 *   2. Deduplication: same dedup tuple produces one entry + dedupe audit.
 *   3. Resolve flow approve sets status + resolved_at + resolved_by + audit.
 *   4. Timeout: pending past TTL transitions to expired on next list.
 *   5. HTTP routes list / detail / approve / deny work; auth enforced;
 *      SSE delivers new entries to a connected listener.
 *   6. Multi-fortress isolation: aggregator A entries do not surface on B.
 *   7. ApprovalGate happy-path: gate behavior unchanged (deny / accept
 *      paths produce identical audit shape as before this PR).
 *   8. Castle-walking: gate denies on channel failure, aggregator captures
 *      the denial AND the audit event still fires.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";

import {
  APPROVAL_AGGREGATOR_AUDIT_OPS,
  ApprovalAggregator,
  type ApprovalGateEvent,
} from "../../src/principal-policy/approval-aggregator.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "../../src/principal-policy/approval-aggregator-routes.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  AutoApproveChannel,
  CallbackApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import type { PrincipalPolicy } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";

const IDENTITY = "identity_test";
const FORTRESS = "fortress_test";

function makePolicy(): PrincipalPolicy {
  return {
    version: 1,
    tier1_always_approve: ["state_export", "state_delete", "identity_rotate"],
    tier2_anomaly: {
      new_namespace_access: "log",
      new_counterparty: "log",
      frequency_spike_multiplier: 50,
      max_signs_per_minute: 1000,
      bulk_read_threshold: 1000,
      first_session_policy: "allow",
    },
    tier3_always_allow: [
      "state_read",
      "state_write",
      "state_list",
      "identity_create",
      "identity_list",
      "identity_sign",
      "identity_verify",
    ],
    approval_channel: { type: "stderr", timeout_seconds: 60, auto_deny: true },
  };
}

function makeFixedClock(seedMs: number): { now: () => Date; advance: (ms: number) => void } {
  let cursor = seedMs;
  return {
    now: () => new Date(cursor),
    advance: (ms) => {
      cursor += ms;
    },
  };
}

function makeRequestedEvent(
  overrides?: Partial<ApprovalGateEvent>,
): ApprovalGateEvent {
  return {
    phase: "requested",
    operation: "state_export",
    tier: 1,
    reason: "tier1_always_approve",
    context: { operation: "state_export", namespace: "demo" },
    request_timestamp: "2026-05-09T12:00:00.000Z",
    correlation_id: "corr-1",
    ...overrides,
  };
}

function makeResolvedEvent(
  overrides?: Partial<ApprovalGateEvent>,
): ApprovalGateEvent {
  return {
    phase: "resolved",
    operation: "state_export",
    tier: 1,
    reason: "tier1_always_approve",
    context: { operation: "state_export", namespace: "demo" },
    request_timestamp: "2026-05-09T12:00:00.000Z",
    correlation_id: "corr-1",
    resolution: {
      decision: "approve",
      decided_at: "2026-05-09T12:00:01.000Z",
      decided_by: "operator_dashboard",
    },
    ...overrides,
  };
}

interface AggregatorRig {
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  aggregator: ApprovalAggregator;
}

function makeAggregator(opts?: {
  pendingTtlMs?: number;
  now?: () => Date;
}): AggregatorRig {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
    pendingTtlMs: opts?.pendingTtlMs ?? 60_000,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
    resolveSourceContext: (event) => ({
      source_harness:
        (event.context["harness"] as string | undefined) ?? "claude-code",
      source_agent_id:
        (event.context["agent_id"] as string | undefined) ?? "agent-default",
    }),
  });
  return { storage, masterKey, auditLog, aggregator };
}

describe("WP-V1.3-10 Upsilon-1 ApprovalAggregator", () => {
  // 1. round-trip ingest + list
  it("ingests a requested event and returns it from list()", async () => {
    const { aggregator } = makeAggregator();
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    const listed = await aggregator.list();
    expect(listed.length).toBe(1);
    expect(listed[0]?.aggregator_id).toBe(entry?.aggregator_id);
    expect(listed[0]?.status).toBe("pending");
    expect(listed[0]?.source_harness).toBe("claude-code");
    expect(listed[0]?.source_agent_id).toBe("agent-default");
    expect(listed[0]?.policy_rule_id).toBe("tier1:state_export");
    expect(listed[0]?.action_summary).toBe("state_export (tier 1)");
    expect(listed[0]?.request_payload_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  // 2. dedup
  it("dedupes a second ingest of the same harness/agent/audit_id tuple and emits a deduped audit event", async () => {
    const { aggregator, auditLog } = makeAggregator();
    const first = await aggregator.ingest(makeRequestedEvent());
    expect(first).not.toBeNull();
    const second = await aggregator.ingest(
      makeRequestedEvent({ correlation_id: "corr-2" }),
    );
    expect(second).toBeNull();
    const listed = await aggregator.list();
    expect(listed.length).toBe(1);
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    const dedupedEvents = audit.entries.filter(
      (e) => e.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.DEDUPED,
    );
    expect(dedupedEvents.length).toBe(1);
    expect(dedupedEvents[0]?.details?.["correlation_id"]).toBe("corr-2");
  });

  // 3. resolve flow
  it("resolve() marks status approved + resolved_at + resolved_by + emits resolved audit event", async () => {
    const clock = makeFixedClock(Date.parse("2026-05-09T12:00:00.000Z"));
    const { aggregator, auditLog } = makeAggregator({ now: clock.now });
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
    clock.advance(1500);
    const resolved = await aggregator.resolve(
      entry!.aggregator_id,
      "approved",
      "operator_via_http",
    );
    expect(resolved.status).toBe("approved");
    expect(resolved.resolved_at).toBe("2026-05-09T12:00:01.500Z");
    expect(resolved.resolved_by).toBe("operator_via_http");
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    const resolvedEvents = audit.entries.filter(
      (e) => e.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.RESOLVED,
    );
    expect(resolvedEvents.length).toBe(1);
    expect(resolvedEvents[0]?.details?.["decision"]).toBe("approved");
    expect(resolvedEvents[0]?.details?.["decided_by"]).toBe("operator_via_http");
  });

  it("resolve() on an unknown id throws not_found", async () => {
    const { aggregator } = makeAggregator();
    await expect(
      aggregator.resolve("aggregator-nonexistent", "approved", "operator"),
    ).rejects.toThrow("approval-aggregator: not_found");
  });

  // 4. timeout / expiration
  it("transitions a pending entry past TTL to status=expired on next list()", async () => {
    const clock = makeFixedClock(Date.parse("2026-05-09T12:00:00.000Z"));
    const { aggregator } = makeAggregator({ pendingTtlMs: 1000, now: clock.now });
    await aggregator.ingest(makeRequestedEvent());
    clock.advance(2000);
    const listedExpired = await aggregator.list({ status: "expired" });
    expect(listedExpired.length).toBe(1);
    expect(listedExpired[0]?.resolved_by).toBe("system_ttl");
    const listedPending = await aggregator.list({ status: "pending" });
    expect(listedPending.length).toBe(0);
  });

  // 5. resolution from gate event records `timeout` on channel_failure
  it("records status=timeout when the gate's resolved event flags channel_failure", async () => {
    const { aggregator } = makeAggregator();
    await aggregator.ingest(makeRequestedEvent());
    const out = await aggregator.ingest(
      makeResolvedEvent({
        resolution: {
          decision: "deny",
          decided_at: "2026-05-09T12:00:05.000Z",
          decided_by: "channel_failure",
        },
      }),
    );
    expect(out?.status).toBe("timeout");
    expect(out?.resolved_by).toBe("channel_failure");
  });

  // 6. resolution path: approve event flows through ingest()
  it("resolved event with approve decision sets status=approved on the matching pending entry", async () => {
    const { aggregator } = makeAggregator();
    const reqEntry = await aggregator.ingest(makeRequestedEvent());
    expect(reqEntry?.status).toBe("pending");
    const resolved = await aggregator.ingest(makeResolvedEvent());
    expect(resolved?.aggregator_id).toBe(reqEntry?.aggregator_id);
    expect(resolved?.status).toBe("approved");
    expect(resolved?.resolved_by).toBe("operator_dashboard");
  });

  // 7. multi-fortress isolation
  it("two aggregators with separate storage backends do not share entries", async () => {
    const a = makeAggregator();
    const b = makeAggregator();
    await a.aggregator.ingest(
      makeRequestedEvent({
        context: { agent_id: "agent-a", harness: "claude-code" },
      }),
    );
    const aList = await a.aggregator.list();
    const bList = await b.aggregator.list();
    expect(aList.length).toBe(1);
    expect(bList.length).toBe(0);
  });

  // 8. hub-inbox cross-link
  it("attaches hub_inbox_item_id when resolveHubInboxItemId returns an id", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const aggregator = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-x",
      }),
      resolveHubInboxItemId: () => "tier1.unwrap.hub-item-42",
    });
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry?.hub_inbox_item_id).toBe("tier1.unwrap.hub-item-42");
  });

  // 9. listener emit
  it("notifies onEvent listeners on aggregated, resolved, and deduped phases", async () => {
    const { aggregator } = makeAggregator();
    const events: string[] = [];
    aggregator.onEvent((e) => events.push(e.type));
    await aggregator.ingest(makeRequestedEvent());
    await aggregator.ingest(makeRequestedEvent({ correlation_id: "corr-2" }));
    await aggregator.ingest(makeResolvedEvent());
    expect(events).toEqual(["aggregated", "deduped", "resolved"]);
  });

  // 10. listener exceptions are swallowed
  it("listener exceptions never propagate to ingest()", async () => {
    const { aggregator } = makeAggregator();
    aggregator.onEvent(() => {
      throw new Error("listener boom");
    });
    const entry = await aggregator.ingest(makeRequestedEvent());
    expect(entry).not.toBeNull();
  });
});

// ── ApprovalGate wire-up ───────────────────────────────────────────────

describe("WP-V1.3-10 Upsilon-1 ApprovalGate aggregator wire-up", () => {
  let storage: MemoryStorage;
  let masterKey: Uint8Array;
  let auditLog: AuditLog;
  let baseline: BaselineTracker;
  let aggregator: ApprovalAggregator;

  beforeEach(() => {
    storage = new MemoryStorage();
    masterKey = generateRandomKey();
    auditLog = new AuditLog(storage, masterKey);
    baseline = new BaselineTracker(storage, masterKey);
    aggregator = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-x",
      }),
    });
  });

  // 11. happy-path: gate accept produces aggregator approved entry + audit unchanged
  it("captures both `requested` and `resolved` lifecycle events on a tier1 approval", async () => {
    const policy = makePolicy();
    const channel = new AutoApproveChannel();
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);
    gate.setApprovalEventCallback((event) => {
      void aggregator.ingest(event as unknown as ApprovalGateEvent);
    });
    const result = await gate.evaluate("state_export", { namespace: "demo" });
    expect(result.allowed).toBe(true);
    // Drain the microtask queue so the aggregator ingest paths land.
    await new Promise((resolve) => setImmediate(resolve));
    const list = await aggregator.list({ status: "approved" });
    expect(list.length).toBe(1);
    expect(list[0]?.policy_rule_id).toBe("tier1:state_export");
    // Existing gate audit shape unchanged.
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    const gateApprove = audit.entries.find((e) =>
      e.operation.startsWith("gate_approve:state_export"),
    );
    expect(gateApprove).toBeDefined();
  });

  // 12. castle-walking: gate denies on channel failure, aggregator records timeout
  it("records status=timeout AND emits the gate_deny audit event when the channel throws", async () => {
    const policy = makePolicy();
    const channel = new CallbackApprovalChannel(async () => {
      throw new Error("network unreachable");
    });
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);
    gate.setApprovalEventCallback((event) => {
      void aggregator.ingest(event as unknown as ApprovalGateEvent);
    });
    const result = await gate.evaluate("state_export", { namespace: "demo" });
    expect(result.allowed).toBe(false);
    expect(result.approval_response?.decided_by).toBe("channel_failure");
    await new Promise((resolve) => setImmediate(resolve));
    const list = await aggregator.list({ status: "timeout" });
    expect(list.length).toBe(1);
    const audit = await auditLog.query({ layer: "l2", limit: 100 });
    const gateDeny = audit.entries.find((e) =>
      e.operation.startsWith("gate_deny:state_export"),
    );
    expect(gateDeny).toBeDefined();
  });

  // 13. tier3 path is unchanged: no aggregator entry for auto-allowed operations
  it("does not create an aggregator entry for tier3 auto-allow operations", async () => {
    const policy = makePolicy();
    const channel = new AutoApproveChannel();
    const gate = new ApprovalGate(policy, baseline, channel, auditLog);
    gate.setApprovalEventCallback((event) => {
      void aggregator.ingest(event as unknown as ApprovalGateEvent);
    });
    const result = await gate.evaluate("state_read", { namespace: "demo" });
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe(3);
    await new Promise((resolve) => setImmediate(resolve));
    const list = await aggregator.list();
    expect(list.length).toBe(0);
  });
});

// ── HTTP route surface ────────────────────────────────────────────────

interface RouteRig {
  server: Server;
  url: string;
  aggregator: ApprovalAggregator;
  authToken: string;
  stop: () => Promise<void>;
}

async function startRouteRig(opts?: { authToken?: string }): Promise<RouteRig> {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: FORTRESS,
    resolveSourceContext: () => ({
      source_harness: "claude-code",
      source_agent_id: "agent-x",
    }),
  });
  const authToken = opts?.authToken ?? "test-token";
  const server = createServer((req, res) => {
    void handleApprovalInboxRoute(
      {
        authConfig: { loopbackAutoAuth: false, authToken },
        aggregator,
        operatorId: "operator_test",
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
    authToken,
    stop: () =>
      new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("WP-V1.3-10 Upsilon-1 ApprovalAggregator HTTP routes", () => {
  let rig: RouteRig;

  beforeEach(async () => {
    rig = await startRouteRig();
  });

  afterEach(async () => {
  });

  // 14. auth gate enforced on list
  it("rejects requests without a valid bearer token (401)", async () => {
    const res = await fetch(`${rig.url}${APPROVAL_INBOX_API_PREFIX}`);
    expect(res.status).toBe(401);
  });

  // 15. list happy path
  it("lists pending entries through GET /api/approval-inbox", async () => {
    await rig.aggregator.ingest({
      phase: "requested",
      operation: "state_export",
      tier: 1,
      reason: "tier1",
      context: { harness: "claude-code", agent_id: "agent-x" },
      request_timestamp: "2026-05-09T12:00:00.000Z",
      correlation_id: "corr-1",
    });
    const res = await fetch(`${rig.url}${APPROVAL_INBOX_API_PREFIX}`, {
      headers: { authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { entries: Array<{ aggregator_id: string; status: string }> };
    };
    expect(body.ok).toBe(true);
    expect(body.data.entries.length).toBe(1);
    expect(body.data.entries[0]?.status).toBe("pending");
  });

  // 16. detail route returns request_payload through the audited accessor
  it("returns the original request payload via GET /:id and emits payload-decrypted audit", async () => {
    const entry = await rig.aggregator.ingest({
      phase: "requested",
      operation: "state_export",
      tier: 1,
      reason: "tier1",
      context: { harness: "claude-code", agent_id: "agent-x", path: "/etc" },
      request_timestamp: "2026-05-09T12:00:00.000Z",
      correlation_id: "corr-detail",
    });
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry?.aggregator_id}`,
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
    expect(body.data.entry.aggregator_id).toBe(entry?.aggregator_id);
    expect(body.data.request_payload.path).toBe("/etc");

    const audit = await rig.aggregator.getAuditTrail(entry!.aggregator_id, "operator_test");
    const decrypted = audit.filter(
      (event) => event.operation === APPROVAL_AGGREGATOR_AUDIT_OPS.PAYLOAD_DECRYPTED,
    );
    expect(decrypted.length).toBe(1);
  });

  // 17. POST /:id/approve route flips status
  it("POST /:id/approve flips an entry to approved and surfaces operator id on the audit event", async () => {
    const entry = await rig.aggregator.ingest({
      phase: "requested",
      operation: "state_export",
      tier: 1,
      reason: "tier1",
      context: { harness: "claude-code", agent_id: "agent-x" },
      request_timestamp: "2026-05-09T12:00:00.000Z",
      correlation_id: "corr-approve",
    });
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry?.aggregator_id}/approve`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${rig.authToken}` },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { entry: { status: string; resolved_by?: string } };
    };
    expect(body.data.entry.status).toBe("approved");
    expect(body.data.entry.resolved_by).toBe("operator_test");
  });

  // 18. POST /:id/deny route flips status to denied
  it("POST /:id/deny flips an entry to denied", async () => {
    const entry = await rig.aggregator.ingest({
      phase: "requested",
      operation: "state_export",
      tier: 1,
      reason: "tier1",
      context: { harness: "claude-code", agent_id: "agent-x" },
      request_timestamp: "2026-05-09T12:00:00.000Z",
      correlation_id: "corr-deny",
    });
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/${entry?.aggregator_id}/deny`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${rig.authToken}` },
      },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: boolean;
      data: { entry: { status: string } };
    };
    expect(body.data.entry.status).toBe("denied");
  });

  // 19. unknown id returns 404
  it("POST /:id/approve on an unknown aggregator_id returns 404", async () => {
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/aggregator-nonexistent/approve`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${rig.authToken}` },
      },
    );
    expect(res.status).toBe(404);
  });

  // 20. SSE stream delivers a snapshot + an aggregated event for a new entry
  it("GET /stream emits an initial snapshot and a follow-up aggregated event", async () => {
    const res = await fetch(
      `${rig.url}${APPROVAL_INBOX_API_PREFIX}/stream`,
      {
        headers: {
          authorization: `Bearer ${rig.authToken}`,
          accept: "text/event-stream",
        },
      },
    );
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/event-stream");

    const reader = res.body!.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let snapshotSeen = false;
    let aggregatedSeen = false;

    // Push a new entry on a microtask delay so the snapshot fires first.
    setTimeout(() => {
      void rig.aggregator.ingest({
        phase: "requested",
        operation: "state_export",
        tier: 1,
        reason: "tier1",
        context: { harness: "claude-code", agent_id: "agent-x" },
        request_timestamp: "2026-05-09T12:00:00.000Z",
        correlation_id: "corr-stream",
      });
    }, 50);

    const deadline = Date.now() + 3_000;
    while (Date.now() < deadline) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      if (buffer.includes("event: approval_inbox_snapshot")) snapshotSeen = true;
      if (buffer.includes("event: approval_inbox_aggregated")) {
        aggregatedSeen = true;
        break;
      }
    }
    await reader.cancel();

    expect(snapshotSeen).toBe(true);
    expect(aggregatedSeen).toBe(true);
  });
});
