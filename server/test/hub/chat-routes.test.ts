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
import { AuditLog } from "../../src/l2-operational/audit-log.js";
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

describe("Hub chat routes — direct-agent", () => {
  let rig: ChatRig;
  beforeEach(async () => {
    rig = await startRig({ withChat: true });
  });
  afterEach(async () => {
    await rig.stop();
  });

  it("POST /api/hub/chat/agents/:id/session/start opens the session synchronously (click-to-chat)", async () => {
    const res = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    // v1.2.x click-to-chat: 200 with session record, NOT 202 + inbox item.
    // The operator's click is the affirmative action; no Tier 1 inbox ask.
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.data.session).toBeDefined();
    expect(res.body.data.session.agent_id).toBe(AGENT_ID);
    expect(res.body.data.session.session_id).toMatch(/^chat-session-/);
    // approval_inbox_item_id is null on the click-to-chat path; the
    // deprecated requestDirectAgentSession path populates it with the
    // resolved Tier 1 item id.
    expect(res.body.data.session.approval_inbox_item_id).toBeNull();
  });

  it("session-start emits direct_agent_session_open with null approval_inbox_item_id", async () => {
    const startRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    expect(startRes.status).toBe(200);

    // The session-open audit event fired with approval_inbox_item_id:
    // null because no Tier 1 inbox item was created on the click-to-
    // chat path.
    const audit = await rig.auditLog.query({
      operation_type: "direct_agent_session_open",
    });
    expect(audit.entries.length).toBe(1);
    expect(audit.entries[0].operation).toBe("direct_agent_session_open");
    expect(audit.entries[0].details?.kind).toBe("direct_agent_session_open");
    expect(audit.entries[0].details?.approval_inbox_item_id).toBeNull();

    // After session-open, an active session is listed.
    const sessionRes = await get(
      rig.url,
      "/api/hub/chat/sessions",
      rig.authToken,
    );
    expect(sessionRes.status).toBe(200);
    expect(sessionRes.body.data.sessions.length).toBe(1);
    expect(sessionRes.body.data.sessions[0].agent_id).toBe(AGENT_ID);
  });

  it("session-start does NOT enqueue a Tier 1 inbox item (click-is-confirmation)", async () => {
    // Filter inbox items to direct_agent_session_open Tier 1 approvals; the
    // count should stay 0 across session-start (no inbox routing on the
    // click-to-chat path).
    const inboxBefore = rig.service
      .listInbox()
      .filter((i) =>
        i.kind === "approval_pending" &&
        i.operation_category === "direct_agent_session_open",
      ).length;
    expect(inboxBefore).toBe(0);

    const res = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    expect(res.status).toBe(200);

    const inboxAfter = rig.service
      .listInbox()
      .filter((i) =>
        i.kind === "approval_pending" &&
        i.operation_category === "direct_agent_session_open",
      ).length;
    expect(inboxAfter).toBe(0);
  });

  it("POST /api/hub/chat/agents/:id/message persists the operator message", async () => {
    const startRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    const sessionId = startRes.body.data.session.session_id as string;

    const sendRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/message`,
      rig.authToken,
      {
        session_id: sessionId,
        message: "draft the dashboard PR review please",
      },
    );
    expect(sendRes.status).toBe(200);
    expect(sendRes.body.data.message.role).toBe("operator");

    const historyRes = await get(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/history`,
      rig.authToken,
    );
    expect(historyRes.body.data.messages.length).toBe(1);
    expect(historyRes.body.data.messages[0].body).toBe(
      "draft the dashboard PR review please",
    );
  });

  it("POST /api/hub/chat/agents/:id/session/end closes the session", async () => {
    const startRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    const sessionId = startRes.body.data.session.session_id as string;

    const endRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/end`,
      rig.authToken,
      { session_id: sessionId },
    );
    expect(endRes.status).toBe(200);
    expect(endRes.body.data.session.close_reason).toBe("operator_close");

    // No active sessions after close.
    const sessionRes = await get(
      rig.url,
      "/api/hub/chat/sessions",
      rig.authToken,
    );
    expect(sessionRes.body.data.sessions.length).toBe(0);
  });

  it("rejects message send when session does not belong to the agent", async () => {
    const startRes = await post(
      rig.url,
      `/api/hub/chat/agents/${AGENT_ID}/session/start`,
      rig.authToken,
      {},
    );
    const sessionId = startRes.body.data.session.session_id as string;

    // POST to a different agent path with this session_id.
    const sendRes = await post(
      rig.url,
      `/api/hub/chat/agents/some-other-agent/message`,
      rig.authToken,
      { session_id: sessionId, message: "hello" },
    );
    // The agent doesn't exist in the registry; expect HubNotFoundError or
    // session-mismatch validation.
    expect([400, 404]).toContain(sendRes.status);
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
