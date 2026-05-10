/**
 * WP-V1.3-10 Cross-Harness Approval Inbox Upsilon-4
 *
 * Regression suite for the v1.4 mobile companion preview hook surface:
 *  - Sync API delta (added / changed / removed / multi-page).
 *  - Revision endpoint (initial + bump-after-mutation).
 *  - PushTriggerRegistry (in-process + signed webhook + opt-in default).
 *  - Federation event-class reservation (cross_harness_approval_*).
 *  - Multi-fortress isolation across revisions and pushes.
 *
 * Castle-walking discipline: every webhook test asserts that a
 * zero-registered-webhook fortress fires zero outbound calls. The
 * fetch implementation is stubbed; nothing in this suite touches a
 * real network endpoint.
 */

import { describe, it, expect } from "vitest";
import { createServer, type Server } from "node:http";
import { AddressInfo } from "node:net";
import { createHmac } from "node:crypto";

import {
  ApprovalAggregator,
  type ApprovalGateEvent,
} from "../../src/principal-policy/approval-aggregator.js";
import {
  APPROVAL_INBOX_API_PREFIX,
  handleApprovalInboxRoute,
} from "../../src/principal-policy/approval-aggregator-routes.js";
import {
  PushTriggerRegistry,
  PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS,
  signHmacSha256Hex,
  type PushEvent,
  type PushFetch,
} from "../../src/principal-policy/aggregator-push-trigger.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  RESERVED_EVENT_TYPE_PREFIXES,
  isReservedEventType,
} from "../../src/mesh/constants.js";

const IDENTITY = "identity_test";
const FORTRESS_A = "fortress_a";
const FORTRESS_B = "fortress_b";

function makeAggregator(opts?: {
  fortressId?: string;
  pendingTtlMs?: number;
  now?: () => Date;
}): {
  aggregator: ApprovalAggregator;
  storage: MemoryStorage;
  masterKey: Uint8Array;
  auditLog: AuditLog;
} {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const aggregator = new ApprovalAggregator({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
    fortressId: opts?.fortressId ?? FORTRESS_A,
    pendingTtlMs: opts?.pendingTtlMs ?? 60_000,
    ...(opts?.now !== undefined ? { now: opts.now } : {}),
    resolveSourceContext: (event) => ({
      source_harness:
        (event.context["harness"] as string | undefined) ?? "claude-code",
      source_agent_id:
        (event.context["agent_id"] as string | undefined) ?? "agent-default",
    }),
  });
  return { aggregator, storage, masterKey, auditLog };
}

function makeRequestedEvent(
  i: number,
  overrides?: Partial<ApprovalGateEvent>,
): ApprovalGateEvent {
  return {
    phase: "requested",
    operation: `state_export_${i}`,
    tier: 1,
    reason: "tier1_always_approve",
    context: {
      operation: `state_export_${i}`,
      namespace: `demo_${i}`,
      harness: "claude-code",
      agent_id: `agent-${i}`,
    },
    request_timestamp: `2026-05-09T12:00:0${i}.000Z`,
    correlation_id: `corr-${i}`,
    ...overrides,
  };
}

function makeResolvedEvent(
  i: number,
  decision: "approve" | "deny" = "approve",
): ApprovalGateEvent {
  return {
    phase: "resolved",
    operation: `state_export_${i}`,
    tier: 1,
    reason: "tier1_always_approve",
    context: {
      operation: `state_export_${i}`,
      namespace: `demo_${i}`,
      harness: "claude-code",
      agent_id: `agent-${i}`,
    },
    request_timestamp: `2026-05-09T12:00:0${i}.000Z`,
    correlation_id: `corr-${i}`,
    resolution: {
      decision,
      decided_at: `2026-05-09T12:00:0${i}.500Z`,
      decided_by: "operator_dashboard",
    },
  };
}

interface RecordedFetch {
  url: string;
  body: string;
  headers: Record<string, string>;
}

function makeRecordingFetch(): {
  calls: RecordedFetch[];
  fetchImpl: PushFetch;
} {
  const calls: RecordedFetch[] = [];
  const fetchImpl: PushFetch = async (url, init) => {
    calls.push({ url, body: init.body, headers: init.headers });
    return { ok: true };
  };
  return { calls, fetchImpl };
}

describe("WP-V1.3-10 Upsilon-4 Sync API + revision counter", () => {
  it("getRevision() returns 0 on a fresh aggregator", async () => {
    const { aggregator } = makeAggregator();
    const revision = await aggregator.getRevision();
    expect(revision).toBe(0);
  });

  it("getRevision() bumps to 1 after the first ingest, and to 2 after a resolve", async () => {
    const { aggregator } = makeAggregator();
    await aggregator.ingest(makeRequestedEvent(1));
    expect(await aggregator.getRevision()).toBe(1);
    await aggregator.ingest(makeResolvedEvent(1));
    expect(await aggregator.getRevision()).toBe(2);
  });

  it("getSync delta surfaces a newly-ingested entry under `added`", async () => {
    const { aggregator } = makeAggregator();
    const before = await aggregator.getSync({ sinceRevision: 0 });
    expect(before.added.length).toBe(0);
    expect(before.changed.length).toBe(0);
    expect(before.removed.length).toBe(0);
    expect(before.revision).toBe(0);

    const entry = await aggregator.ingest(makeRequestedEvent(1));
    const after = await aggregator.getSync({ sinceRevision: 0 });
    expect(after.added.length).toBe(1);
    expect(after.added[0]?.aggregator_id).toBe(entry?.aggregator_id);
    expect(after.added[0]?.created_at_revision).toBe(1);
    expect(after.added[0]?.last_modified_revision).toBe(1);
    expect(after.changed.length).toBe(0);
    expect(after.removed.length).toBe(0);
    expect(after.revision).toBe(1);
  });

  it("getSync delta surfaces a status transition under `changed`, not `added`, when the entry pre-existed at sinceRevision", async () => {
    const { aggregator } = makeAggregator();
    const entry = await aggregator.ingest(makeRequestedEvent(1));
    const snapshot = await aggregator.getSync({ sinceRevision: 0 });
    expect(snapshot.added.length).toBe(1);
    const cursor = snapshot.revision;

    await aggregator.ingest(makeResolvedEvent(1));
    const delta = await aggregator.getSync({ sinceRevision: cursor });
    expect(delta.added.length).toBe(0);
    expect(delta.changed.length).toBe(1);
    expect(delta.changed[0]?.aggregator_id).toBe(entry?.aggregator_id);
    expect(delta.changed[0]?.status).toBe("approved");
    expect(delta.removed.length).toBe(0);
  });

  it("getSync delta surfaces a deleted entry under `removed` and the entry no longer appears in subsequent list()", async () => {
    const { aggregator } = makeAggregator();
    const entry = await aggregator.ingest(makeRequestedEvent(1));
    const cursor = (await aggregator.getSync({ sinceRevision: 0 })).revision;

    const deleted = await aggregator.deleteEntry(entry!.aggregator_id);
    expect(deleted).toBe(true);

    const delta = await aggregator.getSync({ sinceRevision: cursor });
    expect(delta.removed).toContain(entry?.aggregator_id);
    expect(delta.added.length).toBe(0);
    expect(delta.changed.length).toBe(0);

    const listed = await aggregator.list();
    expect(listed.find((e) => e.aggregator_id === entry?.aggregator_id)).toBeUndefined();
  });

  it("getSync respects a low limit and the next call (with the prior revision) returns the rest", async () => {
    const { aggregator } = makeAggregator();
    for (let i = 1; i <= 5; i += 1) {
      await aggregator.ingest(makeRequestedEvent(i));
    }
    const firstPage = await aggregator.getSync({ sinceRevision: 0, limit: 2 });
    expect(firstPage.added.length).toBe(2);
    expect(firstPage.revision).toBe(5);
    // Next page MUST start from before the first page's truncated cap, since
    // the truncated entries were never observed by the consumer. Use the
    // sinceRevision corresponding to the second-to-last delivered entry.
    const lastSeenRevision =
      firstPage.added[firstPage.added.length - 1]?.last_modified_revision ?? 0;
    const secondPage = await aggregator.getSync({
      sinceRevision: lastSeenRevision,
      limit: 10,
    });
    expect(secondPage.added.length).toBe(3);
    const allIds = new Set([
      ...firstPage.added.map((e) => e.aggregator_id),
      ...secondPage.added.map((e) => e.aggregator_id),
    ]);
    expect(allIds.size).toBe(5);
  });

  it("getRevision survives a process restart by re-anchoring to max(last_modified_revision)", async () => {
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const auditLog = new AuditLog(storage, masterKey);
    const aggregatorA = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS_A,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-1",
      }),
    });
    await aggregatorA.ingest(makeRequestedEvent(1));
    await aggregatorA.ingest(makeRequestedEvent(2));
    expect(await aggregatorA.getRevision()).toBe(2);

    const aggregatorB = new ApprovalAggregator({
      storage,
      masterKey,
      auditLog,
      identityId: IDENTITY,
      fortressId: FORTRESS_A,
      resolveSourceContext: () => ({
        source_harness: "claude-code",
        source_agent_id: "agent-1",
      }),
    });
    expect(await aggregatorB.getRevision()).toBe(2);
  });
});

describe("WP-V1.3-10 Upsilon-4 PushTriggerRegistry", () => {
  it("fires an in-process handler on aggregated events, with the entry truncated to 80 chars", async () => {
    const { aggregator } = makeAggregator();
    const registry = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    const events: PushEvent[] = [];
    registry.registerInProcess((e) => events.push(e));
    registry.subscribeToAggregator(aggregator);

    await aggregator.ingest(makeRequestedEvent(1));
    expect(events.length).toBe(1);
    expect(events[0]?.aggregator_id).toBeTypeOf("string");
    expect(events[0]?.source_harness).toBe("claude-code");
    expect(events[0]?.source_agent_id).toBe("agent-1");
    expect(events[0]?.urgency).toBe("tier1");
    expect(events[0]?.fortress_id).toBe(FORTRESS_A);
    expect(events[0]!.action_summary.length).toBeLessThanOrEqual(
      PUSH_EVENT_ACTION_SUMMARY_MAX_CHARS,
    );
  });

  it("does NOT fire on resolved/deduped/removed events (mobile notifications are about new pending approvals only)", async () => {
    const { aggregator } = makeAggregator();
    const registry = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    const events: PushEvent[] = [];
    registry.registerInProcess((e) => events.push(e));
    registry.subscribeToAggregator(aggregator);

    const entry = await aggregator.ingest(makeRequestedEvent(1));
    expect(events.length).toBe(1);
    // Resolve via gate event: should NOT add a new push event.
    await aggregator.ingest(makeResolvedEvent(1));
    expect(events.length).toBe(1);
    // Deduped second ingest: should NOT add a new push event.
    await aggregator.ingest(makeRequestedEvent(1, { correlation_id: "corr-dup" }));
    expect(events.length).toBe(1);
    // Delete the entry: should NOT add a new push event (mobile sync API
    // surfaces removals as a delta, not as a notification).
    await aggregator.deleteEntry(entry!.aggregator_id);
    expect(events.length).toBe(1);
  });

  it("with zero registered webhooks, fires zero outbound HTTP calls (no-outbound-by-default)", async () => {
    const { calls, fetchImpl } = makeRecordingFetch();
    const { aggregator } = makeAggregator();
    const registry = new PushTriggerRegistry({
      fortressId: FORTRESS_A,
      fetchImpl,
    });
    registry.subscribeToAggregator(aggregator);
    await aggregator.ingest(makeRequestedEvent(1));
    await aggregator.ingest(makeRequestedEvent(2));
    expect(calls.length).toBe(0);
    expect(registry.listWebhooks().length).toBe(0);
  });

  it("signs each outbound webhook with HMAC-SHA256 using the per-fortress secret", async () => {
    const { calls, fetchImpl } = makeRecordingFetch();
    const { aggregator } = makeAggregator();
    const registry = new PushTriggerRegistry({
      fortressId: FORTRESS_A,
      fetchImpl,
    });
    const SECRET = "fortress-a-secret";
    registry.registerWebhook({
      url: "https://example.test/webhook",
      secret: SECRET,
    });
    registry.subscribeToAggregator(aggregator);

    await aggregator.ingest(makeRequestedEvent(1));
    // Allow microtask queue to drain webhook fan-out.
    await new Promise((resolve) => setImmediate(resolve));
    expect(calls.length).toBe(1);
    expect(calls[0]?.url).toBe("https://example.test/webhook");
    const expectedSig = createHmac("sha256", SECRET)
      .update(calls[0]!.body)
      .digest("hex");
    expect(calls[0]?.headers["X-Sanctuary-Signature"]).toBe(expectedSig);
    expect(calls[0]?.headers["X-Sanctuary-Event"]).toBe(
      "cross_harness_approval_aggregated",
    );
    expect(calls[0]?.headers["Content-Type"]).toBe("application/json");
  });

  it("rejects a webhook registration with an empty url or empty secret", () => {
    const registry = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    expect(() =>
      registry.registerWebhook({ url: "", secret: "secret" }),
    ).toThrow();
    expect(() =>
      registry.registerWebhook({ url: "https://example.test", secret: "" }),
    ).toThrow();
  });

  it("listWebhooks() exposes URLs without secret material", () => {
    const registry = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    registry.registerWebhook({ url: "https://a.test", secret: "secret-a" });
    registry.registerWebhook({ url: "https://b.test", secret: "secret-b" });
    const view = registry.listWebhooks();
    expect(view).toEqual([{ url: "https://a.test" }, { url: "https://b.test" }]);
    expect(JSON.stringify(view)).not.toContain("secret-a");
    expect(JSON.stringify(view)).not.toContain("secret-b");
  });

  it("signHmacSha256Hex helper matches the existing approval-channel webhook signing shape", () => {
    const body = '{"hello":"world"}';
    const secret = "shared-secret";
    const expected = createHmac("sha256", secret).update(body).digest("hex");
    expect(signHmacSha256Hex(body, secret)).toBe(expected);
  });
});

describe("WP-V1.3-10 Upsilon-4 Federation event-class wiring", () => {
  it("registers cross_harness_approval_ as a reserved event-type prefix", () => {
    expect(RESERVED_EVENT_TYPE_PREFIXES).toContain("cross_harness_approval_");
  });

  it("isReservedEventType() returns true for v1.4 mobile-companion event names", () => {
    expect(isReservedEventType("cross_harness_approval_aggregated")).toBe(true);
    expect(isReservedEventType("cross_harness_approval_resolved")).toBe(true);
    expect(isReservedEventType("cross_harness_approval_payload_decrypted")).toBe(true);
  });

  it("a mocked v1.4 mobile consumer subscribes to push events and receives a federation-shaped payload", async () => {
    interface FederationEnvelope {
      event_type: string;
      payload: PushEvent;
    }
    const mobileInbox: FederationEnvelope[] = [];
    const { aggregator } = makeAggregator();
    const registry = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    // Mocked v1.4 mobile consumer: in v1.4 the wiring is over libp2p mesh.
    // For v1.3, the in-process bridge proves the shape is compatible.
    registry.registerInProcess((event) => {
      mobileInbox.push({
        event_type: "cross_harness_approval_aggregated",
        payload: event,
      });
    });
    registry.subscribeToAggregator(aggregator);

    await aggregator.ingest(makeRequestedEvent(1));
    expect(mobileInbox.length).toBe(1);
    expect(mobileInbox[0]?.event_type).toBe("cross_harness_approval_aggregated");
    expect(isReservedEventType(mobileInbox[0]!.event_type)).toBe(true);
    expect(mobileInbox[0]?.payload.aggregator_id).toBeTypeOf("string");
    expect(mobileInbox[0]?.payload.fortress_id).toBe(FORTRESS_A);
  });
});

describe("WP-V1.3-10 Upsilon-4 multi-fortress isolation", () => {
  it("revision counters and push events do not cross fortresses", async () => {
    const a = makeAggregator({ fortressId: FORTRESS_A });
    const b = makeAggregator({ fortressId: FORTRESS_B });
    const registryA = new PushTriggerRegistry({ fortressId: FORTRESS_A });
    const registryB = new PushTriggerRegistry({ fortressId: FORTRESS_B });
    const eventsA: PushEvent[] = [];
    const eventsB: PushEvent[] = [];
    registryA.registerInProcess((e) => eventsA.push(e));
    registryB.registerInProcess((e) => eventsB.push(e));
    registryA.subscribeToAggregator(a.aggregator);
    registryB.subscribeToAggregator(b.aggregator);

    await a.aggregator.ingest(makeRequestedEvent(1));
    await a.aggregator.ingest(makeRequestedEvent(2));

    expect(await a.aggregator.getRevision()).toBe(2);
    expect(await b.aggregator.getRevision()).toBe(0);
    expect(eventsA.length).toBe(2);
    expect(eventsA.every((e) => e.fortress_id === FORTRESS_A)).toBe(true);
    expect(eventsB.length).toBe(0);
  });
});

describe("WP-V1.3-10 Upsilon-4 HTTP routes", () => {
  async function makeServer(aggregator: ApprovalAggregator): Promise<{
    base: string;
    close: () => Promise<void>;
  }> {
    const server: Server = createServer(async (req, res) => {
      const handled = await handleApprovalInboxRoute(
        {
          aggregator,
          authConfig: { loopbackAutoAuth: true },
        },
        req,
        res,
      );
      if (!handled) {
        res.writeHead(404).end();
      }
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address() as AddressInfo;
    const base = `http://127.0.0.1:${addr.port}`;
    return {
      base,
      close: () =>
        new Promise<void>((resolve) =>
          server.close(() => {
            resolve();
          }),
        ),
    };
  }

  it("GET /api/approval-inbox/revision returns the current revision", async () => {
    const { aggregator } = makeAggregator();
    const { base, close } = await makeServer(aggregator);
    try {
      const r0 = await fetch(`${base}${APPROVAL_INBOX_API_PREFIX}/revision`);
      expect(r0.status).toBe(200);
      expect(await r0.json()).toEqual({ ok: true, data: { revision: 0 } });
      await aggregator.ingest(makeRequestedEvent(1));
      const r1 = await fetch(`${base}${APPROVAL_INBOX_API_PREFIX}/revision`);
      expect(await r1.json()).toEqual({ ok: true, data: { revision: 1 } });
    } finally {
      await close();
    }
  });

  it("GET /api/approval-inbox/sync returns a delta JSON shape", async () => {
    const { aggregator } = makeAggregator();
    const { base, close } = await makeServer(aggregator);
    try {
      await aggregator.ingest(makeRequestedEvent(1));
      const res = await fetch(
        `${base}${APPROVAL_INBOX_API_PREFIX}/sync?since_revision=0`,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        ok: boolean;
        data: {
          revision: number;
          added: Array<{ aggregator_id: string; status: string }>;
          changed: unknown[];
          removed: string[];
        };
      };
      expect(body.ok).toBe(true);
      expect(body.data.revision).toBe(1);
      expect(body.data.added.length).toBe(1);
      expect(body.data.added[0]?.status).toBe("pending");
      expect(body.data.changed).toEqual([]);
      expect(body.data.removed).toEqual([]);
    } finally {
      await close();
    }
  });
});
