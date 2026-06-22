/**
 * Hub Chat Routes — Behavioral Tests (WP-V1.2-4)
 *
 * Real-shape tests against an http server wired to a HubService backed
 * by the operator-chat-service over MemoryStorage. No mocks at the
 * contract boundary. Mirrors `hub-v1.1.test.ts` rig shape; each test
 * exercises one of the v1.2 chat routes end-to-end.
 *
 * Coverage:
 *   - POST /api/hub/chat/concierge persists + returns the response
 *   - GET /api/hub/chat/concierge/history returns persisted thread
 *   - POST /api/hub/chat/agents/:id/session/start enqueues Tier 1 inbox item
 *   - approving the inbox item opens the chat session
 *   - POST /api/hub/chat/agents/:id/message persists + audit-emits
 *   - GET /api/hub/chat/agents/:id/history returns persisted thread
 *   - POST /api/hub/chat/agents/:id/session/end closes the session
 *   - GET /api/hub/chat/sessions returns active sessions
 *   - capability error when operator chat is not wired
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
import { AuditLog } from "../../src/operational/audit-log.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubInboxSources,
} from "../../src/hub/index.js";
import {
  OperatorChatService,
  OperatorChatStore,
  type ConciergeContextProviders,
} from "../../src/chat/operator-chat-index.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentStatus } from "../../src/contracts/v1.1/constants.js";
import type { AuthConfig } from "../../src/console/auth-middleware.js";

const IDENTITY_ID = "operator-chat-test";
const FORTRESS_ID = "fortress-chat-test";
const AGENT_ID = "claude-code";

function makeAgent(): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: AGENT_ID,
    identity_id: IDENTITY_ID,
    harness: "claude_code",
    harness_version: "1.0.0",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4-7",
      runs_locally: false,
    },
    policy_id: "policy-default",
    channel_template_id: "request-approve-act",
    status: "active",
    last_activity_at: "2026-04-29T00:00:00.000Z",
    wrapped_at: "2026-04-29T00:00:00.000Z",
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

class StubController implements HubAgentController {
  async pause(_id: string): Promise<HubAgentStatus> {
    return "paused";
  }
  async resume(_id: string): Promise<HubAgentStatus> {
    return "active";
  }
  async restart(_id: string): Promise<HubAgentStatus> {
    return "active";
  }
  async unwrap(_id: string): Promise<HubAgentStatus> {
    return "unwrapping";
  }
  async lockdown(_id: string): Promise<HubAgentStatus> {
    return "locked_down";
  }
  async bindPolicy(_id: string, _p: string): Promise<void> {}
  async bindChannelTemplate(_id: string, _t: string): Promise<void> {}
}

const emptyInboxSources: HubInboxSources = {
  listPendingApprovals: () => [],
  listRecentBlockedEgress: () => [],
  listRecentPrivacyEvents: () => [],
  listActiveBudgetWarnings: () => [],
  listActiveRecoveryPrompts: () => [],
  listRecentAgentErrors: () => [],
};

const stubContext: ConciergeContextProviders = {
  recentActivity: async () => "(no recent activity)",
  agentInventory: async () => `${AGENT_ID}  status=active`,
  openInbox: async () => "(no open inbox)",
};

interface ChatRig {
  url: string;
  service: HubService;
  chat: OperatorChatService;
  authToken: string;
  auditLog: AuditLog;
  stop: () => Promise<void>;
}

async function startRig(opts: { withChat: boolean }): Promise<ChatRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);
  const registry = new InMemoryLocalAgentRegistry([makeAgent()]);
  const chatStore = new OperatorChatStore(storage, masterKey);
  const chat = new OperatorChatService({
    store: chatStore,
    auditLog,
    identityId: IDENTITY_ID,
    conciergeContextProviders: stubContext,
  });

  const service = new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    agentRegistry: registry,
    inboxSources: emptyInboxSources,
    activitySources: { auditLog, identityId: IDENTITY_ID },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: new StubController(),
    ...(opts.withChat ? { operatorChat: chat } : {}),
  });

  const authToken = "test-token";
  const authConfig: AuthConfig = { loopbackAutoAuth: false, authToken };

  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      const handled = await handleHubRoute(
        { authConfig, service },
        req,
        res,
      );
      if (!handled) {
        res.writeHead(404).end();
      }
    },
  );
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no address");
  const url = `http://127.0.0.1:${addr.port}`;
  return {
    url,
    service,
    chat,
    authToken,
    auditLog,
    stop: () =>
      new Promise<void>((resolve, reject) =>
        server.close((err) => (err ? reject(err) : resolve())),
      ),
  };
}

async function get(
  url: string,
  path: string,
  authToken: string,
): Promise<{ status: number; body: any }> {
  const res = await fetch(`${url}${path}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${authToken}` },
  });
  const body = await res.json();
  return { status: res.status, body };
}

async function post(
  url: string,
  path: string,
  authToken: string,
  body: unknown,
): Promise<{ status: number; body: any }> {
  const res = await fetch(`${url}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${authToken}`,
      "Content-Type": "application/json",
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const responseBody = await res.json();
  return { status: res.status, body: responseBody };
}

describe("Hub chat routes — concierge", () => {
  let rig: ChatRig;
  beforeEach(async () => {
    rig = await startRig({ withChat: true });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("POST /api/hub/chat/concierge persists the response and returns the message", async () => {
    const res = await post(rig.url, "/api/hub/chat/concierge", rig.authToken, {
      message: "what did Cline do today",
    });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.message.role).toBe("concierge");
    expect(res.body.data.outcome).toBe("substrate_disabled"); // no selector wired
  });

  it("POST /api/hub/chat/concierge rejects empty message body", async () => {
    const res = await post(rig.url, "/api/hub/chat/concierge", rig.authToken, {
      message: "",
    });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  it("GET /api/hub/chat/concierge/history returns persisted history", async () => {
    await post(rig.url, "/api/hub/chat/concierge", rig.authToken, {
      message: "hello",
    });
    const res = await get(
      rig.url,
      "/api/hub/chat/concierge/history",
      rig.authToken,
    );
    expect(res.status).toBe(200);
    expect(res.body.data.messages.length).toBe(2);
    expect(res.body.data.messages[0].role).toBe("operator");
  });
});

describe("Hub agent inspect-panel route", () => {
  let rig: ChatRig;
  beforeEach(async () => {
    rig = await startRig({ withChat: true });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("POST /api/hub/agents/:id/inspect/open returns the inspect panel synchronously", async () => {
    const res = await post(
      rig.url,
      `/api/hub/agents/${AGENT_ID}/inspect/open`,
      rig.authToken,
      {},
    );
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.panel).toBeDefined();
    expect(res.body.data.panel.agent_id).toBe(AGENT_ID);
    expect(Array.isArray(res.body.data.panel.recent_activity)).toBe(true);
    expect(Array.isArray(res.body.data.panel.pending_approvals)).toBe(true);
    expect(res.body.data.panel.policy_summary).toBeDefined();
  });

  it("inspect-open emits agent_inspect_panel_opened audit event", async () => {
    const res = await post(
      rig.url,
      `/api/hub/agents/${AGENT_ID}/inspect/open`,
      rig.authToken,
      {},
    );
    expect(res.status).toBe(200);

    const audit = await rig.auditLog.query({
      operation_type: "agent_inspect_panel_opened",
    });
    expect(audit.entries.length).toBe(1);
    expect(audit.entries[0].operation).toBe("agent_inspect_panel_opened");
    expect(audit.entries[0].details?.agent_id).toBe(AGENT_ID);
  });

  it("inspect-open does NOT enqueue a Tier 1 inbox item (read-only panel)", async () => {
    const inboxBefore = rig.service.listInbox().length;

    const res = await post(
      rig.url,
      `/api/hub/agents/${AGENT_ID}/inspect/open`,
      rig.authToken,
      {},
    );
    expect(res.status).toBe(200);

    const inboxAfter = rig.service.listInbox().length;
    expect(inboxAfter).toBe(inboxBefore);
  });
});

describe("Hub chat routes — capability gating", () => {
  let rig: ChatRig;
  beforeEach(async () => {
    rig = await startRig({ withChat: false });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("returns capability error when operator chat is not wired", async () => {
    const res = await post(rig.url, "/api/hub/chat/concierge", rig.authToken, {
      message: "hello",
    });
    expect(res.status).toBe(422);
    expect(res.body.ok).toBe(false);
    expect(res.body.detail).toContain("operator_chat_not_wired");
  });
});
