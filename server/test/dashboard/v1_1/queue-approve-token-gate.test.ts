/**
 * Sanctuary v1.1 Dashboard. Wave 1 approvals-queue token-gate test.
 *
 * EXPLICIT SECURITY GATE (HIGH, non-negotiable; from the dashboard design
 * review). The wave-1 redesign turns the pending Tier-1 approvals into a
 * click-to-clear queue in the right rail (each tile has its own Approve /
 * Deny pair). The design review flagged exactly one build rule:
 *
 *   Every Approve/Deny in the new UI (the rail queue AND any future inline
 *   action) MUST issue the IDENTICAL operator-bearer-token-gated request the
 *   existing inbox path uses:
 *     POST /api/hub/inbox/:id/approve  /  .../deny
 *   through the requireToken chokepoint in server/src/hub/api-router.ts.
 *   NEVER a loopback auto-auth shortcut, NEVER a new weaker path. #823 closed
 *   exactly this hole (default-deny on every non-GET hub mutation).
 *
 * This file proves two things, end to end against the real hub router:
 *
 *  1. STRUCTURE: the queue tile in the client script emits its Approve /
 *     Deny buttons with the SAME data-action="inbox-approve" / "inbox-deny"
 *     hooks the inbox rows use, so the dispatcher routes them through
 *     onInboxAction -> api("/inbox/:id/approve|deny", {method:"POST"}). There
 *     is no second, weaker approve path in the client. The bearer is read
 *     from sessionStorage at runtime (api()), never embedded in served HTML.
 *
 *  2. ENFORCEMENT: a TOKENLESS POST to /api/hub/inbox/:id/approve (and
 *     .../deny) is REJECTED with 401 EVEN with loopback auto-auth ON, while
 *     the same request WITH the operator bearer is accepted. This is the
 *     guarantee that a co-resident agent on loopback cannot clear an approval
 *     by mere network position. A regression that routed the queue action
 *     through a loopback-auto-auth or otherwise un-gated path would let a
 *     tokenless approve through and fail this test.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { getClientScript } from "../../../src/dashboard/v1_1/client.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { HUB_API_PREFIX, HUB_INBOX_TEMPLATE_NAMESPACES } from "../../../src/hub/constants.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubInboxSources,
} from "../../../src/hub/index.js";
import type {
  HubApprovalPendingItem,
  HubInboxItem,
} from "../../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../../src/contracts/v1.1/local-agent-records.js";
import type { AuthConfig } from "../../../src/console/auth-middleware.js";

const IDENTITY_ID = "operator-token-gate";
const FORTRESS_ID = "fortress-token-gate";
const TOKEN = "operator-bearer-secret";

function makeAgent(): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: "agent-alpha",
    identity_id: IDENTITY_ID,
    harness: "openclaw",
    harness_version: "0.10.6",
    model_provider: { vendor: "anthropic", model_id: "claude-opus-4-7", runs_locally: false },
    policy_id: "policy-default",
    channel_template_id: "request-approve-act",
    status: "active",
    status_reason_class: "running_nominal",
    wrapped_at: "2026-04-25T00:00:00.000Z",
    last_seen_at: "2026-04-25T01:00:00.000Z",
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_lockdown: true,
      can_unwrap: true,
    },
  } as LocalAgentRecord;
}

/**
 * One pending Tier-1 approval. resolved flips to true once a decision lands.
 * The controller is a no-op: the test asserts the AUTH gate, not the
 * downstream side effect, so a stub controller keeps the rig minimal.
 */
function makePendingApproval(): HubApprovalPendingItem {
  return {
    version: "1.1",
    identity_id: IDENTITY_ID,
    agent_id: "agent-alpha",
    created_at: "2026-04-25T01:00:00.000Z",
    resolved: false,
    item_id: "approval-1",
    kind: "approval_pending",
    display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.state_export`,
    display_template_args: [
      { kind: "agent_id", value: "agent-alpha" },
      { kind: "tier", value: "tier1" },
    ],
    tier: "tier1",
    operation_category: "state_export",
  } as HubApprovalPendingItem;
}

const stubController: HubAgentController = {
  // The router resolves the inbox item without touching the controller for a
  // state_export approval; these are present only to satisfy the type.
  pause: async () => ({ status: "ok" }),
  resume: async () => ({ status: "ok" }),
  restart: async () => ({ status: "ok" }),
  lockdown: async () => ({ status: "ok" }),
  unwrap: async () => ({ status: "ok" }),
} as unknown as HubAgentController;

interface Rig {
  url: string;
  approvals: HubApprovalPendingItem[];
  stop: () => Promise<void>;
}

/**
 * Start a hub server with loopback auto-auth ON and an operator token
 * configured. This is the #823 scenario: a co-resident loopback caller. The
 * default-deny mutation gate must still require the bearer for the approve /
 * deny decision.
 */
async function startRig(): Promise<Rig> {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  const approvals: HubApprovalPendingItem[] = [makePendingApproval()];

  const inboxSources: HubInboxSources = {
    listPendingApprovals: () => approvals,
    listRecentBlockedEgress: () => [],
    listRecentPrivacyEvents: () => [],
    listActiveBudgetWarnings: () => [],
    listActiveRecoveryPrompts: () => [],
    listRecentAgentErrors: () => [],
  };

  const service = new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    agentRegistry: new InMemoryLocalAgentRegistry([makeAgent()]),
    inboxSources,
    activitySources: { auditLog, identityId: IDENTITY_ID },
    policyBudgetSources: { listPolicySummaries: () => [], listBudgetSummaries: () => [] },
    agentController: stubController,
  });

  // loopback auto-auth ON + a token configured: a GET may auto-auth on
  // loopback, but a non-GET mutation must STILL require the bearer.
  const authConfig: AuthConfig = { loopbackAutoAuth: true, authToken: TOKEN };

  const server: Server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const handled = await handleHubRoute({ authConfig, service }, req, res);
      if (!handled) {
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "not_found" }));
      }
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: (err as Error).message }));
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const addr = server.address();
  if (!addr || typeof addr !== "object") throw new Error("no address");

  return {
    url: `http://127.0.0.1:${addr.port}`,
    approvals,
    stop: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

describe("wave 1 approvals queue: client routes Approve/Deny through the gated inbox path", () => {
  it("queue tiles emit the SAME data-action hooks the inbox rows use (no second approve path)", () => {
    const src = getClientScript();
    // The rail queue tile renderer exists and emits inbox-approve / inbox-deny
    // on the tile, so the dispatcher routes them through onInboxAction.
    expect(src).toContain("function renderApprovalTile");
    expect(src).toContain('data-action="inbox-approve"');
    expect(src).toContain('data-action="inbox-deny"');
    // onInboxAction issues exactly one approve/deny path: the gated POST.
    expect(src).toContain('api("/inbox/" + encodeURIComponent(itemId) + "/" + action, { method: "POST"');
    // No loopback/auto-auth shortcut and no second, weaker approve endpoint:
    // the only approve/deny issuer is api() with the runtime sessionStorage
    // bearer. (The dashboard never embeds the token in served HTML; api()
    // reads TOKEN from sessionStorage.)
    expect(src).not.toContain("auto-auth");
    expect(src).not.toContain("autoAuth");
  });
});

describe("wave 1 approvals queue: a tokenless approve/deny is REJECTED at the chokepoint (#823)", () => {
  let rig: Rig;
  beforeEach(async () => { rig = await startRig(); });
  afterEach(async () => { await rig.stop(); });

  it("rejects a TOKENLESS POST .../approve with 401 even with loopback auto-auth on", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    // The approval must NOT have been resolved by the unauthenticated call.
    expect(rig.approvals[0]!.resolved).toBe(false);
  });

  it("rejects a TOKENLESS POST .../deny with 401 even with loopback auto-auth on", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox/approval-1/deny`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    expect(rig.approvals[0]!.resolved).toBe(false);
  });

  it("rejects a WRONG bearer with 401 (the token is actually checked, not merely present)", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer not-the-operator-token" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    expect(rig.approvals[0]!.resolved).toBe(false);
  });

  it("accepts the approve ONLY with the correct operator bearer (the gate is not a blanket deny)", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${TOKEN}` },
      body: "{}",
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { item: HubInboxItem } };
    expect(body.data.item.item_id).toBe("approval-1");
    expect(body.data.item.resolved).toBe(true);
  });
});
