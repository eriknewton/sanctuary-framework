/**
 * Sanctuary v1.1 dashboard. Live Tier 1 approval cards for a generic wrap.
 *
 * CAPABILITY UNDER TEST: when a fortress started by a generic `sanctuary
 * protect` (no named agent in the local-agent registry, no Castle Wall agent
 * controller) holds a Tier 1 operation for the operator, the v1.1 dashboard's
 * approvals surfaces must show that hold and must be able to clear it.
 *
 * Both v1.1 approval surfaces read exactly ONE source. The Overview tile's
 * "approvals waiting" count and the Talk-screen "Waiting on you" rail are both
 * computed from the unresolved `approval_pending` items of `GET
 * /api/hub/inbox` (`state.inbox` in server/src/dashboard/v1_1/client.ts), and
 * the rail's Approve / Deny buttons POST back to
 * `/api/hub/inbox/:item_id/{approve,deny}`. `GET /api/pending` is the
 * independent second reader of the same hold, so the two readers disagreeing
 * about a live hold is the observable this file pins.
 *
 * WIRED-CONSUMER RIG (AGENTS.md assurance rule 4), and EXACTLY what it wires:
 * a real `DashboardApprovalChannel` serving over real HTTP, real
 * `buildV11Bindings(...)` output attached through `setV11Bindings(...)`, and
 * the real `HubService` those bindings carry, reached over the real
 * `/api/hub/*` routes. Nothing writes
 * `<storagePath>/state/_hub/local-agents.json`, so the hub agent registry
 * rehydrates empty, which is the generic-wrap condition this file is about.
 *
 * What the rig does NOT build, so no assertion here may be read as covering
 * it: `server/src/index.ts` also composes storage + master key, the substrate
 * selector, the identity manager, the reputation store, policy/config loading,
 * and the sentinel bindings, none of which are constructed here. The holds are
 * raised two ways, and only one of them is the production caller: most cases
 * call the channel's own `requestApproval(...)` directly, which is the blocked
 * tool call's promise but not the classification in front of it; the
 * `ApprovalGate` case below drives one hold through the real gate so the Tier 1
 * classification and the durable decision audit row are proven for a
 * hub-resolved hold rather than assumed.
 *
 * Register: defect.v11-dashboard-live-tier1-cards-not-surfaced-for-generic-wrap
 */

import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { DashboardApprovalChannel } from "../../../src/principal-policy/dashboard.js";
import {
  buildV11Bindings,
  type V11Bindings,
} from "../../../src/dashboard/v1_1/wiring.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { OperatorAuthorizationSpentStore } from "../../../src/v1/operator-authorization-spent-store.js";
import {
  HUB_API_PREFIX,
  HUB_INBOX_DEFAULT_LIMIT,
} from "../../../src/hub/constants.js";
import { charterApprovalItemId } from "../../../src/hub/charter-approval-bridge.js";
import { ApprovalGate } from "../../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../../src/principal-policy/baseline.js";
import { DEFAULT_POLICY } from "../../../src/principal-policy/loader.js";
import type { ApprovalResponse } from "../../../src/principal-policy/types.js";
import { getFreePort } from "../../helpers/free-port.js";

const IDENTITY_ID = "op-generic-wrap";
const FORTRESS_ID = "fortress-generic-wrap";

/**
 * The approval-channel timeout doubles as the test's own upper bound: a hold
 * that is never decided auto-denies (SEC-002) and the awaited promise settles,
 * so no assertion can hang on a stuck rig.
 */
const CHANNEL_TIMEOUT_SECONDS = 20;

interface Rig {
  dashboard: DashboardApprovalChannel;
  baseUrl: string;
  authToken: string;
  auditLog: AuditLog;
  baseline: BaselineTracker;
  /** The live v1.1 bindings, so a test can reach the same hub the routes use. */
  bindings: V11Bindings;
  /** Build a second, independent binding set for rebind/detach cases. */
  buildSpareBindings: () => V11Bindings;
  stop: () => Promise<void>;
}

async function startRig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const baseline = new BaselineTracker(storage, masterKey);
  const authToken = `generic-wrap-cards-${randomBytes(8).toString("hex")}`;
  const port = await getFreePort();
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-generic-wrap-"));

  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: CHANNEL_TIMEOUT_SECONDS,
    auth_token: authToken,
    auto_open: false,
  });

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
      approval_channel: { type: "dashboard", timeout_seconds: 30 },
    } as never,
    baseline: { load: async () => {}, save: async () => {} } as never,
    auditLog,
  });
  await dashboard.setOperatorAuthorizationSpentStore(
    OperatorAuthorizationSpentStore.durableFromBoot(storage, masterKey),
  );

  // Deliberately NO writePersistedLocalAgents call: a generic wrap registers
  // no named agent, so the hub agent registry rehydrates empty. Any inbox
  // admission that depends on a registry row would be invisible here, which
  // is the point of this rig.
  const buildSpareBindings = (): V11Bindings =>
    buildV11Bindings({
      identityId: IDENTITY_ID,
      fortressId: FORTRESS_ID,
      auditLog,
      storagePath,
      warnProducerKeyUnavailable: () => {},
    });
  const bindings = buildSpareBindings();
  dashboard.setV11Bindings(bindings);

  await dashboard.start();
  return {
    dashboard,
    baseUrl: `http://127.0.0.1:${port}`,
    authToken,
    auditLog,
    baseline,
    bindings,
    buildSpareBindings,
    stop: async () => {
      await dashboard.stop();
      await rm(storagePath, { recursive: true, force: true });
    },
  };
}

/** Raise the Tier 1 hold a generic `--wrap` fixture raises: `memory_insert`. */
function raiseMemoryInsertHold(
  rig: Rig,
  passageId: string,
): Promise<ApprovalResponse> {
  return rig.dashboard.requestApproval({
    operation: "memory_insert",
    tier: 1,
    reason: '"memory_insert" is a Tier 1 operation (always requires approval)',
    context: {
      operation: "memory_insert",
      args_summary: {
        text_redacted: true,
        text_bytes: 92,
        passage_id: passageId,
        tag_count: 3,
      },
    },
    timestamp: new Date().toISOString(),
  });
}

async function getJson(
  rig: Rig,
  path: string,
  opts?: { bearer?: boolean },
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${rig.baseUrl}${path}`, {
    headers:
      opts?.bearer === false
        ? {}
        : { Authorization: `Bearer ${rig.authToken}` },
  });
  return { status: res.status, body: await res.json() };
}

interface InboxItemShape {
  item_id: string;
  kind: string;
  tier?: string;
  resolved: boolean;
  identity_id: string;
  display_template_id: string;
  operation_category?: string;
}

function inboxItems(body: unknown): InboxItemShape[] {
  const data = (body as { data?: { items?: unknown } }).data;
  const items = data?.items;
  return Array.isArray(items) ? (items as InboxItemShape[]) : [];
}

function unresolvedApprovals(body: unknown): InboxItemShape[] {
  // Mirrors the client's own filter (client.ts `pendingApprovalItems`): the
  // Overview count and the rail both drop resolved rows.
  return inboxItems(body).filter(
    (i) => i.kind === "approval_pending" && !i.resolved,
  );
}

/**
 * Poll the hub inbox until it reports at least `count` unresolved approvals.
 * The dashboard client polls rather than blocking, so a poll here is the
 * faithful consumer shape; the bound is the channel timeout, which denies the
 * hold and settles the awaited promise if the rig ever wedges.
 */
async function waitForUnresolvedApprovals(
  rig: Rig,
  count: number,
  timeoutMs = 4000,
): Promise<InboxItemShape[]> {
  const deadline = Date.now() + timeoutMs;
  let last: InboxItemShape[] = [];
  for (;;) {
    const { body } = await getJson(rig, `${HUB_API_PREFIX}/inbox`);
    last = unresolvedApprovals(body);
    if (last.length >= count) return last;
    if (Date.now() >= deadline) return last;
    await new Promise((r) => setTimeout(r, 50));
  }
}

describe("generic wrap Tier 1 holds reach the v1.1 approvals surfaces", () => {
  let rig: Rig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("surfaces a live memory_insert hold in the hub inbox, not only in /api/pending", async () => {
    const decision = raiseMemoryInsertHold(rig, "release182_generic_1");

    const pending = await getJson(rig, "/api/pending");
    expect(pending.status).toBe(200);
    expect(
      (pending.body as Array<{ operation: string; tier: number }>).map(
        (p) => `${p.operation}:${p.tier}`,
      ),
    ).toEqual(["memory_insert:1"]);

    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);
    expect(cards[0]!.tier).toBe("tier1");
    expect(cards[0]!.identity_id).toBe(IDENTITY_ID);
    // A template id the dashboard catalog does not know renders as
    // "[unrecognized template: ...]" on a live card, so pin the namespace.
    expect(cards[0]!.display_template_id).toMatch(
      /^approval_pending\.tier1\./,
    );

    // Clear the hold so the rig's awaited promise settles inside the test.
    const approve = await fetch(
      `${rig.baseUrl}${HUB_API_PREFIX}/inbox/${encodeURIComponent(cards[0]!.item_id)}/approve`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${rig.authToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    expect(approve.status).toBe(200);
    await decision;
  });

  it("clears the underlying hold when the rail's Approve lands", async () => {
    const decision = raiseMemoryInsertHold(rig, "release182_generic_2");
    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);

    const res = await fetch(
      `${rig.baseUrl}${HUB_API_PREFIX}/inbox/${encodeURIComponent(cards[0]!.item_id)}/approve`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${rig.authToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    expect(res.status).toBe(200);

    // The blocked call is released with the operator's decision. A card that
    // flipped `resolved` without reaching the channel would leave this
    // promise pending until the channel's own timeout auto-denied it.
    const outcome = await decision;
    expect(outcome.decision).toBe("approve");
    expect(outcome.decided_by).toBe("human");

    const after = await getJson(rig, "/api/pending");
    expect(after.body).toEqual([]);
    expect(unresolvedApprovals((await getJson(rig, `${HUB_API_PREFIX}/inbox`)).body)).toEqual([]);
  });

  it("denies the underlying hold when the rail's Deny lands", async () => {
    const decision = raiseMemoryInsertHold(rig, "release182_generic_3");
    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);

    const res = await fetch(
      `${rig.baseUrl}${HUB_API_PREFIX}/inbox/${encodeURIComponent(cards[0]!.item_id)}/deny`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${rig.authToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    expect(res.status).toBe(200);

    const outcome = await decision;
    expect(outcome.decision).toBe("deny");
    expect(outcome.decided_by).toBe("human");
  });

  it("gives a loopback-position caller the count-only marker, never the rows", async () => {
    // Same disclosure bound `GET /api/pending` and the snapshot already hold:
    // a co-resident agent with loopback position but no operator bearer
    // learns how many approvals are waiting and nothing else.
    rig.dashboard.setAutoAuthLocalhost(true);
    const decision = raiseMemoryInsertHold(rig, "release182_generic_4");
    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);

    const positionOnly = await getJson(rig, `${HUB_API_PREFIX}/inbox`, {
      bearer: false,
    });
    expect(positionOnly.status).toBe(200);
    const data = (positionOnly.body as { data: Record<string, unknown> }).data;
    expect(data.pending_approvals_redacted).toBe(true);
    expect(data.pending_approvals_count).toBe(1);
    expect(inboxItems(positionOnly.body)).toEqual([]);

    const approve = await fetch(
      `${rig.baseUrl}${HUB_API_PREFIX}/inbox/${encodeURIComponent(cards[0]!.item_id)}/approve`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${rig.authToken}`,
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    expect(approve.status).toBe(200);
    await decision;
  });
});

/**
 * POST one rail action and return the raw response, so a case can assert on a
 * refusal status as easily as on a success.
 */
function postInboxAction(
  rig: Rig,
  itemId: string,
  action: "approve" | "deny" | "dismiss",
): Promise<Response> {
  return fetch(
    `${rig.baseUrl}${HUB_API_PREFIX}/inbox/${encodeURIComponent(itemId)}/${action}`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${rig.authToken}`,
        "Content-Type": "application/json",
      },
      body: "{}",
    },
  );
}

/**
 * A hand-built bridge that records how it was called. Used to pin the CONTRACT
 * the hub holds the Charter queue to (a bounded list, a keyed get), which a
 * result-only assertion cannot distinguish from "projected everything, then
 * sliced".
 */
function countingBridge(recordCount: number) {
  const calls = { listLimits: [] as number[], gets: [] as string[] };
  const records = Array.from({ length: recordCount }, (_, i) => ({
    id: `hold-${i}`,
    operation: "memory_insert",
    tier: 1 as const,
    created_at: new Date(Date.UTC(2026, 8, 6, 0, 0, i % 60)).toISOString(),
  }));
  return {
    calls,
    bridge: {
      list: (limit: number) => {
        calls.listLimits.push(limit);
        return records.slice(0, Math.max(0, limit));
      },
      get: (approvalId: string) => {
        calls.gets.push(approvalId);
        return records.find((r) => r.id === approvalId) ?? null;
      },
      resolve: () => true,
    },
  };
}

describe("live Charter holds are projected under the caller's stated bound", () => {
  let rig: Rig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("passes the request page size down to the queue instead of projecting every hold", async () => {
    // Replaces the channel-installed bridge on the SAME hub the routes use, so
    // the assertion is about what `HubService` asks its queue for, on the real
    // `/api/hub/inbox` path.
    const counting = countingBridge(1_000);
    rig.bindings.hubService.setCharterApprovalBridge(counting.bridge);

    const paged = await getJson(rig, `${HUB_API_PREFIX}/inbox?limit=5`);
    expect(paged.status).toBe(200);
    expect(inboxItems(paged.body)).toHaveLength(5);
    expect(counting.calls.listLimits).toEqual([5]);

    // No `limit` is the v1.1 client's own call shape.
    const defaulted = await getJson(rig, `${HUB_API_PREFIX}/inbox`);
    expect(inboxItems(defaulted.body)).toHaveLength(HUB_INBOX_DEFAULT_LIMIT);
    expect(counting.calls.listLimits).toEqual([5, HUB_INBOX_DEFAULT_LIMIT]);
  });

  it("resolves a card by key, never by scanning the queue", async () => {
    const counting = countingBridge(1_000);
    rig.bindings.hubService.setCharterApprovalBridge(counting.bridge);

    const res = await postInboxAction(
      rig,
      charterApprovalItemId("hold-900"),
      "approve",
    );
    expect(res.status).toBe(200);
    expect(counting.calls.gets).toEqual(["hold-900"]);
    // A scan would have shown up here as a list call made to find the record.
    expect(counting.calls.listLimits).toEqual([]);
  });
});

describe("the reserved Charter item-id namespace is not a naming convention", () => {
  let rig: Rig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("refuses a reserved id on a hub with no bridge installed", async () => {
    // A hub built but never handed to a channel: exactly the state a
    // composition root leaves behind when the v1.1 surface is off.
    const bridgeless = rig.buildSpareBindings().hubService;
    await expect(
      bridgeless.resolveInboxItem(charterApprovalItemId("forged"), "approve"),
    ).rejects.toThrow(/inbox item/);
    // The refusal is a not-found, not a store write that succeeds next time.
    await expect(
      bridgeless.resolveInboxItem(charterApprovalItemId("forged"), "approve"),
    ).rejects.toThrow(/inbox item/);
  });

  it("stops resolving through a hub that is no longer the channel's binding", async () => {
    const firstHub = rig.bindings.hubService;
    const decision = raiseMemoryInsertHold(rig, "rebind_1");
    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);
    expect(firstHub.listInbox()).toHaveLength(1);

    // Rebinding hands the surface to a different hub. The old object may still
    // be held by a caller; it must no longer reach this channel's queue.
    const secondBindings = rig.buildSpareBindings();
    rig.dashboard.setV11Bindings(secondBindings);

    expect(firstHub.listInbox()).toEqual([]);
    await expect(
      firstHub.resolveInboxItem(cards[0]!.item_id, "approve"),
    ).rejects.toThrow(/inbox item/);

    // The incoming hub has the hold, and deciding there still releases the
    // blocked caller.
    expect(secondBindings.hubService.listInbox()).toHaveLength(1);
    const res = await postInboxAction(rig, cards[0]!.item_id, "approve");
    expect(res.status).toBe(200);
    const outcome = await decision;
    expect(outcome.decision).toBe("approve");
    expect(outcome.decided_by).toBe("human");
  });

  it("detaches on unbind, so an unbound hub cannot decide a live hold", async () => {
    const firstHub = rig.bindings.hubService;
    const decision = raiseMemoryInsertHold(rig, "unbind_1");
    await waitForUnresolvedApprovals(rig, 1);

    rig.dashboard.setV11Bindings(null);
    expect(firstHub.listInbox()).toEqual([]);

    // The hold itself is untouched: `/api/pending` is a different reader and
    // still shows it, and the legacy decision route still releases the caller.
    const pending = await getJson(rig, "/api/pending");
    const rows = pending.body as Array<{ id: string }>;
    expect(rows).toHaveLength(1);
    const res = await fetch(`${rig.baseUrl}/api/approve/${rows[0]!.id}`, {
      method: "POST",
      headers: { Authorization: `Bearer ${rig.authToken}` },
    });
    expect(res.status).toBe(200);
    expect((await decision).decision).toBe("approve");
  });
});

describe("a hub-resolved hold is a real gate decision", () => {
  let rig: Rig;

  beforeEach(async () => {
    rig = await startRig();
  });

  afterEach(async () => {
    await rig.stop();
  });

  it("classifies, holds, and audits a memory_insert driven through the real ApprovalGate", async () => {
    // The one case in this file that goes through the production classifier
    // rather than calling `requestApproval` directly, so the Tier 1 verdict and
    // the durable decision row are proven rather than assumed for the rail.
    const gate = new ApprovalGate(
      DEFAULT_POLICY,
      rig.baseline,
      rig.dashboard,
      rig.auditLog,
    );
    const evaluation = gate.evaluate("memory_insert", {
      namespace: "company-brain",
      text: "quarterly planning note",
    });

    const cards = await waitForUnresolvedApprovals(rig, 1);
    expect(cards).toHaveLength(1);
    expect(cards[0]!.tier).toBe("tier1");

    const res = await postInboxAction(rig, cards[0]!.item_id, "approve");
    expect(res.status).toBe(200);

    const result = await evaluation;
    expect(result.tier).toBe(1);
    expect(result.approval_required).toBe(true);
    expect(result.allowed).toBe(true);
    expect(result.approval_response?.decided_by).toBe("human");

    // The gate awaits its own append before returning, so the row is durable
    // by the time the evaluation settles; querying earlier would race the write.
    const audit = await rig.auditLog.query({
      layer: "l2",
      operation_type: "gate_approve:memory_insert",
      limit: 10,
    });
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.details).toMatchObject({
      tier: 1,
      decided_by: "human",
    });
  });
});
