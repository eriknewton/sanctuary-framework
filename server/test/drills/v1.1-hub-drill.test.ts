/**
 * Sanctuary v1.1 Acceptance Drill - Pillar 2: Operator Hub.
 *
 * Proves the operator-confirms-twice Tier 1 pattern end-to-end through the
 * real http server + handleHubRoute, against a real `InMemoryLocalAgentRegistry`,
 * real `AuditLog`, and a real `HubService`. The drill exercises:
 *
 *   1. Pause + resume via per-agent control endpoints (synchronous).
 *   2. Tier 1 fortress-wide lockdown via the dashboard top-bar endpoint
 *      (`/api/hub/fortress/lockdown`, the recommended dashboard binding per
 *      addendum §1.1 + §8.1):
 *      a. POST returns 202 + inbox_item_id; controller is NOT called yet,
 *         agent status unchanged.
 *      b. The new inbox item appears with operation_category=lockdown.
 *      c. POST .../inbox/<id>/approve iterates the controller across all
 *         agents and emits one fortress-level `lifecycle` activity entry.
 *   3. Activity feed reflects the lifecycle event with `category=lifecycle`.
 *   4. Privacy event seeded into the audit log appears under
 *      `category=privacy`.
 *   5. Cross-fortress query parameter is rejected with 422 HubLocalOnlyError.
 *   6. Unauthenticated request is rejected with 401.
 *
 * Acceptance checklist mapping: Pillar 2 of
 * `server/docs/v1.1-acceptance-checklist.md`.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { HUB_API_PREFIX } from "../../src/hub/constants.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubInboxSources,
} from "../../src/hub/index.js";
import type {
  HubApprovalPendingItem,
  HubInboxItem,
} from "../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentStatus } from "../../src/contracts/v1.1/constants.js";
import type { AuthConfig } from "../../src/console/auth-middleware.js";

const IDENTITY_ID = "did:example:operator-drill-hub";
const FORTRESS_ID = "fortress-drill-hub";

function makeAgent(agentId: string): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: agentId,
    identity_id: IDENTITY_ID,
    harness: "openclaw",
    harness_version: "0.10.6",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4-7",
      runs_locally: false,
    },
    policy_id: "policy-drill",
    channel_template_id: "request-approve-act",
    status: "active",
    budget_summary: {
      daily: { unit: "tokens", cap: 100_000, used: 25_000, soft_warn: 0.8 },
      monthly: { unit: "usd", cap: 100, used: 12, soft_warn: 0.75 },
      last_refreshed_at: "2026-04-25T00:00:00.000Z",
    },
    last_activity_at: "2026-04-25T00:00:00.000Z",
    wrapped_at: "2026-04-20T00:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: true,
      can_change_template: true,
    },
  };
}

class StubAgentController implements HubAgentController {
  calls: Array<{ action: string; agentId: string }> = [];
  async pause(agentId: string): Promise<HubAgentStatus> {
    this.calls.push({ action: "pause", agentId });
    return "paused";
  }
  async resume(agentId: string): Promise<HubAgentStatus> {
    this.calls.push({ action: "resume", agentId });
    return "active";
  }
  async restart(agentId: string): Promise<HubAgentStatus> {
    this.calls.push({ action: "restart", agentId });
    return "active";
  }
  async unwrap(agentId: string): Promise<HubAgentStatus> {
    this.calls.push({ action: "unwrap", agentId });
    return "unwrapping";
  }
  async lockdown(agentId: string): Promise<HubAgentStatus> {
    this.calls.push({ action: "lockdown", agentId });
    return "locked_down";
  }
  async bindPolicy(agentId: string): Promise<void> {
    this.calls.push({ action: "bindPolicy", agentId });
  }
  async bindChannelTemplate(agentId: string): Promise<void> {
    this.calls.push({ action: "bindChannelTemplate", agentId });
  }
}

function emptyInboxSources(): HubInboxSources {
  return {
    listPendingApprovals: () => [],
    listRecentBlockedEgress: () => [],
    listRecentPrivacyEvents: () => [],
    listActiveBudgetWarnings: () => [],
    listActiveRecoveryPrompts: () => [],
    listRecentAgentErrors: () => [],
  };
}

interface DrillRig {
  url: string;
  service: HubService;
  registry: InMemoryLocalAgentRegistry;
  controller: StubAgentController;
  auditLog: AuditLog;
  authToken: string;
  stop: () => Promise<void>;
}

async function startDrillRig(): Promise<DrillRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);

  const registry = new InMemoryLocalAgentRegistry([makeAgent("agent-drill-alpha")]);
  const controller = new StubAgentController();

  const service = new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    agentRegistry: registry,
    inboxSources: emptyInboxSources(),
    activitySources: { auditLog, identityId: IDENTITY_ID },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: controller,
    // Fortress-scope export not exercised in the hub drill; the exit drill
    // exercises the export path with a real bundle. The fortress lockdown
    // endpoint requires no extra dep.
  });

  const authToken = "drill-token-hub";
  const authConfig: AuthConfig = { loopbackAutoAuth: false, authToken };

  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const handled = await handleHubRoute(
          { authConfig, service },
          req,
          res,
        );
        if (!handled) {
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ ok: false, error: "not_found", path: req.url }),
          );
        }
      } catch (err) {
        try {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({ ok: false, error: (err as Error).message }),
          );
        } catch {
          // socket already closed
        }
      }
    },
  );

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const addr = server.address();
  if (!addr || typeof addr !== "object") throw new Error("no address");
  const url = `http://127.0.0.1:${addr.port}`;

  return {
    url,
    service,
    registry,
    controller,
    auditLog,
    authToken,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function withAuth(headers: HeadersInit, token: string): HeadersInit {
  return { ...headers, Authorization: `Bearer ${token}` };
}

describe("v1.1 acceptance drill - Pillar 2: operator hub end-to-end", () => {
  let rig: DrillRig;

  beforeEach(async () => {
    rig = await startDrillRig();
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("pause -> resume -> Tier 1 lockdown (approve) -> activity reflects engagement; cross-fortress query rejected; unauth rejected", async () => {
    // Step 1: synchronous pause + resume.
    const pauseRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-drill-alpha/pause`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(pauseRes.status).toBe(200);
    expect(rig.registry.get("agent-drill-alpha")!.status).toBe("paused");

    const resumeRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-drill-alpha/resume`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(resumeRes.status).toBe(200);
    expect(rig.registry.get("agent-drill-alpha")!.status).toBe("active");

    // Step 2a: Tier 1 fortress-wide lockdown enqueue. Returns 202 + a
    // single inbox_item_id (one item regardless of agent count, per the
    // fortress endpoint contract).
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(enqueueRes.status).toBe(202);
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: {
        inbox_item_id: string;
        status: "approval_pending";
        operation_category: "lockdown";
        fortress_scope: true;
      };
    };
    expect(enqueueBody.data.status).toBe("approval_pending");
    expect(enqueueBody.data.operation_category).toBe("lockdown");
    expect(enqueueBody.data.fortress_scope).toBe(true);

    // Controller has NOT been called for lockdown yet.
    const lockdownCallsBeforeApproval = rig.controller.calls.filter(
      (c) => c.action === "lockdown",
    );
    expect(lockdownCallsBeforeApproval.length).toBe(0);
    // Registry status NOT changed.
    expect(rig.registry.get("agent-drill-alpha")!.status).toBe("active");

    // Step 2b: inbox shows the pending fortress-scope item (no agent_id).
    const inboxRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    const inbox = (await inboxRes.json()) as {
      ok: true;
      data: { items: HubInboxItem[] };
    };
    const pending = inbox.data.items.find(
      (i): i is HubApprovalPendingItem =>
        i.kind === "approval_pending" &&
        i.item_id === enqueueBody.data.inbox_item_id,
    );
    expect(pending).toBeDefined();
    expect(pending!.tier).toBe("tier1");
    expect(pending!.operation_category).toBe("lockdown");
    expect(pending!.agent_id).toBeUndefined();
    expect(pending!.display_template_id).toBe(
      "approval_pending.tier1.fortress_lockdown",
    );

    // Step 2c: operator approves via inbox. NOW controller fires across
    // every wrapped agent and registry flips to locked_down.
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    const lockdownCalls = rig.controller.calls.filter(
      (c) => c.action === "lockdown",
    );
    expect(lockdownCalls.length).toBe(1);
    expect(rig.registry.get("agent-drill-alpha")!.status).toBe("locked_down");

    // Re-approving the same Tier 1 item is a 409 (already resolved).
    const reApproveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(reApproveRes.status).toBe(409);

    // Step 3: activity feed reflects the fortress lockdown engagement.
    // The fortress lockdown handler emits a single audit entry with
    // operation `fortress_lockdown_engaged`; the activity-feed
    // categorizer routes it to `lifecycle` per dashboard binding
    // addendum §1.2.
    await rig.auditLog.flush();
    const activityRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const activityBody = (await activityRes.json()) as {
      ok: true;
      data: {
        entries: Array<{ category: string; display_template_id: string }>;
      };
    };
    const lockdownActivity = activityBody.data.entries.find((entry) =>
      entry.display_template_id.includes("fortress_lockdown_engaged"),
    );
    expect(lockdownActivity).toBeDefined();
    expect(lockdownActivity!.category).toBe("lifecycle");

    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{ category: string; display_template_id: string }>;
      };
    };
    expect(
      lifecycleBody.data.entries.some((entry) =>
        entry.display_template_id.includes("fortress_lockdown_engaged"),
      ),
    ).toBe(true);

    // Step 4: privacy event seeded into the same audit log surfaces under
    // category=privacy.
    await rig.auditLog.append("l2", "privacy_event", IDENTITY_ID, {
      version: "1.1",
      kind: "filtered",
      event_id: "drill-priv-evt-1",
      emitted_at: "2026-04-25T01:00:00.000Z",
      policy_id: "drill-policy",
      identity_id: IDENTITY_ID,
      agent_id: "agent-drill-alpha",
      destination_category: "inference",
      field_decisions: [],
      outbound_payload_hash: "0".repeat(64),
      payload_hash_alg: "hmac-sha256-fortress-keyed-v1",
    });
    await rig.auditLog.flush();
    const privacyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=privacy&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const privacyBody = (await privacyRes.json()) as {
      ok: true;
      data: { entries: Array<{ category: string }> };
    };
    expect(privacyBody.data.entries.length).toBeGreaterThan(0);
    for (const entry of privacyBody.data.entries) {
      expect(entry.category).toBe("privacy");
    }

    // Step 5: cross-fortress query parameter is rejected (local-only
    // enforcement, HubLocalOnlyError 422).
    const crossRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox?fortress_id=other-fortress-001`,
      { headers: withAuth({}, rig.authToken) },
    );
    expect(crossRes.status).toBe(422);
    const crossBody = (await crossRes.json()) as { ok: false; error: string };
    expect(crossBody.error).toBe("HubLocalOnlyError");

    // Step 6: unauthenticated request rejected with 401.
    const noAuthRes = await fetch(`${rig.url}${HUB_API_PREFIX}/agents`);
    expect(noAuthRes.status).toBe(401);
  });

  it("Tier 1 fortress lockdown deny does NOT call the controller and leaves agents active", async () => {
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(enqueueRes.status).toBe(202);
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };

    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);

    // Controller never called for lockdown; status unchanged.
    const lockdownCalls = rig.controller.calls.filter(
      (c) => c.action === "lockdown",
    );
    expect(lockdownCalls.length).toBe(0);
    expect(rig.registry.get("agent-drill-alpha")!.status).toBe("active");
  });
});
