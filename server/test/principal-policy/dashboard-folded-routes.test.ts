/**
 * Dashboard-fold PR-2 — the wrap dashboard's B-only API groups, folded onto
 * the ONE surviving surface (the principal-policy dashboard) under ITS auth.
 *
 * Ratified decisions exercised here (2026-08-02):
 *  - Decision 2: A's stricter auth everywhere — the wrap surface's tokenless
 *    fail-open reads do NOT carry over. A tokenless read on the folded routes
 *    is DENIED when a bearer token is configured (no loopback auto-auth
 *    unless explicitly enabled, which these rigs never enable).
 *  - Decision 3: approvals are LIVE on the folded surface — the alias routes
 *    resolve the REAL pending map (the same waiter `requestApproval` blocks
 *    on), not a read-only stub.
 *  - Decision 4: wire-shape — A keeps `/api/approve/:id` + `/api/deny/:id`;
 *    the wrap's `/api/approvals/:id/(allow|deny)` is an alias onto the same
 *    decision handler.
 *  - Decision 5: `POST /api/templates/:name/init` (custody-class signing
 *    mutation) sits behind BOTH the operator bearer token AND a Tier-1
 *    human-approval gate; it fails CLOSED (denied ⇒ no signed event).
 */

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { absentFleetRoster } from "../../src/principal-policy/fleet-roster.js";
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

const TOKEN = "folded-routes-test-token-0123456789abcdef";

const STUB_POLICY = {
  version: 1,
  tier1_always_approve: [],
  tier3_auto_allow: [],
  anomaly_thresholds: {
    new_namespace: true,
    unfamiliar_counterparty_window_days: 7,
    frequency_spike_multiplier: 5,
  },
  approval_channel: { type: "stderr", timeout_seconds: 30 },
} as never;

const STUB_BASELINE = {
  load: async () => {},
  save: async () => {},
  getProfile: () => ({}),
} as never;

interface Rig {
  channel: DashboardApprovalChannel;
  base: string;
  bearer: Record<string, string>;
  stop: () => Promise<void>;
}

async function startRig(opts?: {
  isAgentWrapped?: (agentId: string) => Promise<boolean>;
  fleetRoster?: () => FleetRoster | Promise<FleetRoster>;
}): Promise<Rig> {
  let channel: DashboardApprovalChannel | undefined;
  let port = 0;
  await bindWithRetry(async () => {
    port = randomTestPort();
    channel = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 30,
      auto_deny: true,
      auth_token: TOKEN,
    });
    channel.setDependencies({
      policy: STUB_POLICY,
      baseline: STUB_BASELINE,
      auditLog: new AuditLog(new MemoryStorage(), generateRandomKey()),
      ...(opts?.fleetRoster ? { fleetRoster: opts.fleetRoster } : {}),
      ...(opts?.isAgentWrapped
        ? { templateInit: { isAgentWrapped: opts.isAgentWrapped } }
        : {}),
    });
    await channel.start();
  });
  return {
    channel: channel!,
    base: `http://127.0.0.1:${port}`,
    bearer: { Authorization: `Bearer ${TOKEN}` },
    stop: async () => channel!.stop(),
  };
}

/** Poll /api/pending until a pending request with the given operation appears. */
async function awaitPending(
  rig: Rig,
  operation: string,
  timeoutMs = 5000,
): Promise<{ id: string; operation: string }> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const res = await fetch(`${rig.base}/api/pending`, {
      headers: rig.bearer,
    });
    if (res.status === 200) {
      const list = (await res.json()) as { id: string; operation: string }[];
      const hit = list.find((p) => p.operation === operation);
      if (hit) return hit;
    }
    if (Date.now() > deadline) {
      throw new Error(`no pending "${operation}" request within ${timeoutMs}ms`);
    }
    await new Promise((r) => setTimeout(r, 25));
  }
}

describe("dashboard-fold PR-2: folded wrap-surface routes on the main dashboard", () => {
  const rigs: Rig[] = [];
  afterEach(async () => {
    for (const rig of rigs.splice(0)) await rig.stop();
  });

  // ── Decision 2: A's auth posture, never the wrap surface's fail-open ──

  it("DENIES a tokenless read on GET /api/fleet/roster (the wrap surface's fail-open does NOT carry over)", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/fleet/roster`);
    expect(res.status).toBe(401);
  });

  it("DENIES a tokenless read on GET /api/templates", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/templates`);
    expect(res.status).toBe(401);
  });

  it("serves GET /api/fleet/roster to the operator bearer — injected wrap provider when wired", async () => {
    const injected: FleetRoster = {
      ...absentFleetRoster(),
      available: true,
      fortress_id: "folded-fortress",
    };
    const rig = await startRig({ fleetRoster: () => injected });
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/fleet/roster`, {
      headers: rig.bearer,
    });
    expect(res.status).toBe(200);
    const roster = (await res.json()) as FleetRoster;
    expect(roster.fortress_id).toBe("folded-fortress");
    expect(roster.available).toBe(true);
  });

  it("serves the honest absent roster when federation is unprovisioned and nothing is injected", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/fleet/roster`, {
      headers: rig.bearer,
    });
    expect(res.status).toBe(200);
    const roster = (await res.json()) as FleetRoster;
    expect(roster.available).toBe(false);
    expect(roster.nodes).toEqual([]);
  });

  // ── Templates: read-only registry routes ──────────────────────────────

  it("serves the template registry list to the operator bearer", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/templates`, {
      headers: rig.bearer,
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      templates: { metadata: { name: string } }[];
    };
    expect(body.templates.length).toBeGreaterThan(0);
    expect(body.templates.map((t) => t.metadata.name)).toContain(
      "research-assistant",
    );
  });

  it("serves a single template entry and 404s an unknown name", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const hit = await fetch(`${rig.base}/api/templates/research-assistant`, {
      headers: rig.bearer,
    });
    expect(hit.status).toBe(200);
    expect(
      ((await hit.json()) as { metadata: { name: string } }).metadata.name,
    ).toBe("research-assistant");
    const miss = await fetch(
      `${rig.base}/api/templates/definitely-not-a-template`,
      { headers: rig.bearer },
    );
    expect(miss.status).toBe(404);
    expect(((await miss.json()) as { error: string }).error).toBe(
      "template_not_found",
    );
  });

  // ── Decisions 3 + 4: approvals LIVE via the aliased wire shape ────────

  it("POST /api/approvals/:id/allow resolves the SAME pending approval the channel is blocking on", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const decisionPromise = rig.channel.requestApproval({
      operation: "state_export",
      tier: 1,
      reason: "alias wire-shape test",
      context: {},
      timestamp: new Date().toISOString(),
    });
    const pending = await awaitPending(rig, "state_export");
    const res = await fetch(
      `${rig.base}/api/approvals/${pending.id}/allow`,
      { method: "POST", headers: rig.bearer },
    );
    expect(res.status).toBe(200);
    const decision = await decisionPromise;
    expect(decision.decision).toBe("approve");
    expect(decision.decided_by).toBe("human");
  });

  it("POST /api/approvals/:id/deny denies through the same handler", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const decisionPromise = rig.channel.requestApproval({
      operation: "key_rotation",
      tier: 1,
      reason: "alias deny test",
      context: {},
      timestamp: new Date().toISOString(),
    });
    const pending = await awaitPending(rig, "key_rotation");
    const res = await fetch(
      `${rig.base}/api/approvals/${pending.id}/deny`,
      { method: "POST", headers: rig.bearer },
    );
    expect(res.status).toBe(200);
    const decision = await decisionPromise;
    expect(decision.decision).toBe("deny");
  });

  it("DENIES a tokenless alias POST and leaves the approval pending (mutations never ride network position)", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const decisionPromise = rig.channel.requestApproval({
      operation: "state_import",
      tier: 1,
      reason: "tokenless alias must not decide",
      context: {},
      timestamp: new Date().toISOString(),
    });
    const pending = await awaitPending(rig, "state_import");
    const res = await fetch(
      `${rig.base}/api/approvals/${pending.id}/allow`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
    // Still pending: the tokenless caller decided nothing.
    const stillThere = await awaitPending(rig, "state_import");
    expect(stillThere.id).toBe(pending.id);
    // Clean up: deny with the bearer so the rig tears down without a timer.
    await fetch(`${rig.base}/api/approvals/${pending.id}/deny`, {
      method: "POST",
      headers: rig.bearer,
    });
    await decisionPromise;
  });

  it("404s an unknown approval id through the alias (same handler as /api/approve/:id)", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/approvals/no-such-id/allow`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(res.status).toBe(404);
  });

  // ── Decision 5: template init behind the Tier-1 gate ──────────────────

  it("REJECTS tokenless POST /api/templates/:name/init (fail-closed custody-class gate)", async () => {
    const rig = await startRig({ isAgentWrapped: async () => true });
    rigs.push(rig);
    const res = await fetch(
      `${rig.base}/api/templates/research-assistant/init`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "wrapped-agent" }),
      },
    );
    expect(res.status).toBe(401);
    // Nothing was enqueued for approval: the gate rejected before Tier-1.
    const pendingRes = await fetch(`${rig.base}/api/pending`, {
      headers: rig.bearer,
    });
    expect(((await pendingRes.json()) as unknown[]).length).toBe(0);
  });

  it("executes template init ONLY after an explicit Tier-1 approval", async () => {
    const rig = await startRig({ isAgentWrapped: async () => true });
    rigs.push(rig);

    const initPromise = fetch(
      `${rig.base}/api/templates/research-assistant/init`,
      {
        method: "POST",
        headers: { ...rig.bearer, "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "wrapped-agent" }),
      },
    );

    // The mutation is parked on a REAL pending Tier-1 approval.
    const pending = await awaitPending(rig, "template_init");

    // Approve through A's canonical wire shape (decision 4: both shapes hit
    // the same handler; the sibling tests cover the alias).
    const approve = await fetch(`${rig.base}/api/approve/${pending.id}`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(approve.status).toBe(200);

    const initRes = await initPromise;
    expect(initRes.status).toBe(200);
    const body = (await initRes.json()) as {
      agent_id: string;
      signed_event_id: string;
      template_name: string;
    };
    expect(body.agent_id).toBe("wrapped-agent");
    expect(body.template_name).toBe("research-assistant");
    expect(body.signed_event_id).toBeTruthy();
  });

  it("fails CLOSED when the Tier-1 approval is denied: 403, no signed event", async () => {
    const rig = await startRig({ isAgentWrapped: async () => true });
    rigs.push(rig);

    const initPromise = fetch(
      `${rig.base}/api/templates/research-assistant/init`,
      {
        method: "POST",
        headers: { ...rig.bearer, "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "wrapped-agent" }),
      },
    );

    const pending = await awaitPending(rig, "template_init");
    // Deny via the ALIAS shape — decision 4's wire both ways.
    const deny = await fetch(`${rig.base}/api/approvals/${pending.id}/deny`, {
      method: "POST",
      headers: rig.bearer,
    });
    expect(deny.status).toBe(200);

    const initRes = await initPromise;
    expect(initRes.status).toBe(403);
    const body = (await initRes.json()) as Record<string, unknown>;
    // Generic denial (invariant 7) and NO signed-event material.
    expect(body).toEqual({ error: "approval_denied" });
  });

  it("cheap validation rejects BEFORE the Tier-1 gate: unknown template and orphan agent enqueue nothing", async () => {
    const rig = await startRig({ isAgentWrapped: async () => false });
    rigs.push(rig);

    const unknown = await fetch(
      `${rig.base}/api/templates/definitely-not-a-template/init`,
      {
        method: "POST",
        headers: { ...rig.bearer, "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "wrapped-agent" }),
      },
    );
    expect(unknown.status).toBe(404);

    const orphan = await fetch(
      `${rig.base}/api/templates/research-assistant/init`,
      {
        method: "POST",
        headers: { ...rig.bearer, "Content-Type": "application/json" },
        body: JSON.stringify({ agent_name: "never-wrapped" }),
      },
    );
    expect(orphan.status).toBe(400);
    expect(((await orphan.json()) as { error: string }).error).toBe(
      "orphan_agent_id",
    );

    const pendingRes = await fetch(`${rig.base}/api/pending`, {
      headers: rig.bearer,
    });
    expect(((await pendingRes.json()) as unknown[]).length).toBe(0);
  });

  // ── Decision 3: /api/status stays honest on the folded surface ────────

  it("reports decision_capable honestly on /api/status (co-located true; no hardcoded false)", async () => {
    const rig = await startRig();
    rigs.push(rig);
    const res = await fetch(`${rig.base}/api/status`, { headers: rig.bearer });
    expect(res.status).toBe(200);
    const status = (await res.json()) as {
      decision_capable: boolean;
      standalone_mode: boolean;
    };
    // This rig is a live approval channel (requestApproval + handleDecision
    // both work in-process — the alias tests above PROVE it), and it is not
    // in standalone mode, so the honest answer is true.
    expect(status.standalone_mode).toBe(false);
    expect(status.decision_capable).toBe(true);
  });
});
