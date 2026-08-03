/**
 * Sanctuary v1.1 — Operator Hub API regression suite (Prompt 5).
 *
 * Real-shape tests against an http server wired to a HubService backed by
 * the in-memory agent registry, real AuditLog over MemoryStorage, and
 * stub source callbacks for the inbox kinds. No mocks at the contract
 * boundary — every endpoint is fetched over the network.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";

import { MemoryStorage } from "../../src/storage/memory.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { producerSigningBytes } from "../../src/castle-wall/runtime/producer-signature.js";
import {
  CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY,
  CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
  CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_KID_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY,
  CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
  CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY,
} from "../../src/castle-wall/constants.js";
import {
  HUB_AGENT_CONTROL_ACTIONS,
  HUB_API_PREFIX,
  HUB_INBOX_TEMPLATE_NAMESPACES,
  HUB_TIER_1_AGENT_CONTROL_ACTIONS,
  HUB_VERSION,
} from "../../src/hub/constants.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubInboxSources,
  type HubAgentRegistrySource,
  type HubBudgetSummary,
  type HubPolicySummary,
} from "../../src/hub/index.js";
import {
  readPersistedLocalAgents,
  writePersistedLocalAgents,
} from "../../src/hub/agent-registry-persistence.js";
import type {
  HubAgentErrorItem,
  HubApprovalPendingItem,
  HubBlockedEgressItem,
  HubBudgetWarningItem,
  HubInboxItem,
  HubPrivacyEventItem,
  HubRecoveryPromptItem,
} from "../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentStatus } from "../../src/contracts/v1.1/constants.js";
import type { AuthConfig } from "../../src/console/auth-middleware.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";

// ─────────────────────────────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────────────────────────────

const IDENTITY_ID = "operator-test-001";
const FORTRESS_ID = "fortress-test-001";
const PRODUCER_PRIV = ed25519.utils.randomPrivateKey();
const PRODUCER_PUB_B64 = toBase64url(ed25519.getPublicKey(PRODUCER_PRIV));
const SIGNED_AT_MS = 1_777_777_777_777;

function toBase64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function withProducerSignature(entry: AuditEntry, identityId: string): AuditEntry {
  const seq = typeof entry.details?.seq === "number" ? entry.details.seq : 31;
  const body = JSON.stringify({
    timestamp: entry.timestamp,
    layer: entry.layer,
    operation: entry.operation,
    identity_id: identityId,
    result: entry.result,
    details: entry.details ?? {},
  });
  const sig = ed25519.sign(
    producerSigningBytes(body, SIGNED_AT_MS, seq),
    PRODUCER_PRIV,
  );
  return {
    ...entry,
    identity_id: identityId,
    details: {
      ...(entry.details ?? {}),
      seq,
      [CASTLE_WALL_PRODUCER_SIG_DETAIL_KEY]: toBase64url(sig),
      [CASTLE_WALL_PRODUCER_KID_DETAIL_KEY]:
        CASTLE_WALL_PRODUCER_SIG_KEY_ID_V1,
      [CASTLE_WALL_PRODUCER_SIGNED_CANONICAL_DETAIL_KEY]: body,
      [CASTLE_WALL_PRODUCER_CAPTURED_AT_MS_DETAIL_KEY]: SIGNED_AT_MS,
      [CASTLE_WALL_EVIDENCE_BASIS_DETAIL_KEY]:
        CASTLE_WALL_EVIDENCE_BASIS_PRODUCER_SIGNED,
    },
  };
}

function makeAgent(
  overrides: Partial<LocalAgentRecord> = {},
): LocalAgentRecord {
  const base: LocalAgentRecord = {
    version: "1.1",
    agent_id: "agent-alpha",
    identity_id: IDENTITY_ID,
    harness: "openclaw",
    harness_version: "0.10.6",
    model_provider: {
      vendor: "anthropic",
      model_id: "claude-opus-4-7",
      runs_locally: false,
    },
    policy_id: "policy-default",
    channel_template_id: "request-approve-act",
    status: "active",
    budget_summary: {
      daily: { unit: "tokens", cap: 100_000, used: 25_000, soft_warn: 0.8 },
      monthly: { unit: "usd", cap: 100, used: 12, soft_warn: 0.75 },
      last_refreshed_at: "2026-04-25T00:00:00.000Z",
    },
    // Fresh activity so an "active" agent reads genuinely live. The hub
    // read-projection ages a stale `active` (last_activity_at past the liveness
    // window) down to `unknown`; this fixture models a currently-live agent, so
    // its activity must be recent. See contracts/v1.1/liveness.ts.
    last_activity_at: new Date().toISOString(),
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
  return { ...base, ...overrides };
}

class StubAgentController implements HubAgentController {
  calls: Array<{ action: string; agentId: string; arg?: unknown }> = [];

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
  async bindPolicy(agentId: string, policyId: string): Promise<void> {
    this.calls.push({ action: "bindPolicy", agentId, arg: policyId });
  }
  async bindChannelTemplate(agentId: string, templateId: string): Promise<void> {
    this.calls.push({
      action: "bindChannelTemplate",
      agentId,
      arg: templateId,
    });
  }
}

interface InboxSourceState {
  approvals: HubApprovalPendingItem[];
  blockedEgress: HubBlockedEgressItem[];
  privacy: HubPrivacyEventItem[];
  budget: HubBudgetWarningItem[];
  recovery: HubRecoveryPromptItem[];
  agentErrors: HubAgentErrorItem[];
}

function makeInboxSources(state: InboxSourceState): HubInboxSources {
  return {
    listPendingApprovals: () => state.approvals,
    listRecentBlockedEgress: () => state.blockedEgress,
    listRecentPrivacyEvents: () => state.privacy,
    listActiveBudgetWarnings: () => state.budget,
    listActiveRecoveryPrompts: () => state.recovery,
    listRecentAgentErrors: () => state.agentErrors,
  };
}

function makeEmptyInboxState(): InboxSourceState {
  return {
    approvals: [],
    blockedEgress: [],
    privacy: [],
    budget: [],
    recovery: [],
    agentErrors: [],
  };
}

// Helpers to build a fully-populated inbox state.
function seedInboxState(): InboxSourceState {
  const baseHeader = {
    version: "1.1" as const,
    identity_id: IDENTITY_ID,
    agent_id: "agent-alpha",
    created_at: "2026-04-25T01:00:00.000Z",
    resolved: false,
  };
  return {
    approvals: [
      {
        ...baseHeader,
        item_id: "approval-1",
        kind: "approval_pending",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.approval_pending}.tier1.state_export`,
        display_template_args: [
          { kind: "agent_id", value: "agent-alpha" },
          { kind: "tier", value: "tier1" },
        ],
        tier: "tier1",
        operation_category: "state_export",
      },
    ],
    blockedEgress: [
      {
        ...baseHeader,
        item_id: "egress-1",
        kind: "blocked_egress",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.blocked_egress}.policy_deny`,
        display_template_args: [
          { kind: "destination_category", value: "inference" },
        ],
        destination_category: "inference",
        block_reason_class: "egress_policy_deny",
      },
    ],
    privacy: [
      {
        ...baseHeader,
        item_id: "privacy-1",
        kind: "privacy_event",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.privacy_event}.denied`,
        display_template_args: [
          { kind: "destination_category", value: "tool-api" },
        ],
        privacy_event_id: "audit-priv-001",
        privacy_event_kind: "denied",
      },
    ],
    budget: [
      {
        ...baseHeader,
        item_id: "budget-1",
        kind: "budget_warning",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.budget_warning}.soft_warn`,
        display_template_args: [{ kind: "count", value: 80 }],
        bucket: "daily",
        severity: "soft_warn",
        used_fraction: 0.81,
      },
    ],
    recovery: [
      {
        ...baseHeader,
        item_id: "recovery-1",
        kind: "recovery_prompt",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.recovery_prompt}.exit_drill`,
        display_template_args: [{ kind: "agent_id", value: "agent-alpha" }],
        recovery_class: "exit_drill",
      },
    ],
    agentErrors: [
      {
        ...baseHeader,
        item_id: "error-1",
        kind: "agent_error",
        display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.agent_error}.E_HARNESS_TIMEOUT`,
        display_template_args: [{ kind: "agent_id", value: "agent-alpha" }],
        error_class: "E_HARNESS_TIMEOUT",
        agent_still_active: true,
      },
    ],
  };
}

// ─────────────────────────────────────────────────────────────────────
// Test rig: starts a real http server bound to handleHubRoute
// ─────────────────────────────────────────────────────────────────────

interface TestRig {
  url: string;
  service: HubService;
  registry: HubAgentRegistrySource;
  controller: StubAgentController;
  inboxState: InboxSourceState;
  auditLog: AuditLog;
  authToken: string;
  stop: () => Promise<void>;
}

interface RigOptions {
  authConfig?: AuthConfig;
  policySummaries?: HubPolicySummary[];
  budgetSummaries?: HubBudgetSummary[];
  pinnedProducerKeyB64url?: string | null;
  subjectFortressId?: string | null;
}

async function startRig(options: RigOptions = {}): Promise<TestRig> {
  const storage = new MemoryStorage();
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);

  const registry = new InMemoryLocalAgentRegistry([makeAgent()]);
  const controller = new StubAgentController();
  const inboxState = makeEmptyInboxState();
  const policySummaries = options.policySummaries ?? [];
  const budgetSummaries = options.budgetSummaries ?? [];

  const service = new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    agentRegistry: registry,
    inboxSources: makeInboxSources(inboxState),
    activitySources: {
      auditLog,
      identityId: IDENTITY_ID,
      pinnedProducerKeyB64url: options.pinnedProducerKeyB64url ?? null,
      subjectFortressId: options.subjectFortressId ?? FORTRESS_ID,
    },
    policyBudgetSources: {
      listPolicySummaries: () => policySummaries,
      listBudgetSummaries: () => budgetSummaries,
    },
    agentController: controller,
  });

  const authToken = options.authConfig?.authToken ?? "test-token-abc";
  const authConfig: AuthConfig = options.authConfig ?? {
    loopbackAutoAuth: false,
    authToken,
  };

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
          // socket already gone
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
    inboxState,
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

async function withTmpFortress<T>(
  fn: (storagePath: string) => Promise<T>,
): Promise<T> {
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-hub-refresh-"));
  try {
    return await fn(storagePath);
  } finally {
    await rm(storagePath, { recursive: true, force: true });
  }
}

function makeRefreshService(storagePath: string): HubService {
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, randomBytes(32));
  return new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    agentRegistry: new InMemoryLocalAgentRegistry(),
    readPersistedLocalAgents: () => readPersistedLocalAgents(storagePath),
    inboxSources: makeInboxSources(makeEmptyInboxState()),
    activitySources: { auditLog, identityId: IDENTITY_ID },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: new StubAgentController(),
  });
}

// ═════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════

describe("Hub API constants", () => {
  it("HUB_VERSION reads 1.1.0", () => {
    expect(HUB_VERSION).toBe("1.1.0");
  });

  it("every control action surface mirrors a Tier 1 entry where applicable", () => {
    for (const action of HUB_TIER_1_AGENT_CONTROL_ACTIONS) {
      expect(DEFAULT_POLICY.tier1_always_approve).toContain(action);
    }
    // policy_change is not a control action token but lands as Tier 1 too.
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("policy_change");
  });

  it("exposes exactly five agent-control actions", () => {
    expect([...HUB_AGENT_CONTROL_ACTIONS]).toEqual([
      "pause",
      "resume",
      "restart",
      "unwrap",
      "lockdown",
    ]);
  });
});

describe("Hub agent listing persisted refresh (Finding BB)", () => {
  it("refreshes records written after dashboard boot before listing", async () => {
    await withTmpFortress(async (storagePath) => {
      const service = makeRefreshService(storagePath);
      const wrappedAfterBoot = makeAgent({ agent_id: "agent-after-boot" });

      writePersistedLocalAgents(storagePath, [wrappedAfterBoot]);

      expect(service.listAgents().map((agent) => agent.agent_id)).toEqual([
        "agent-after-boot",
      ]);
    });
  });

  it("merges multiple persisted records wrapped sequentially after boot", async () => {
    await withTmpFortress(async (storagePath) => {
      const service = makeRefreshService(storagePath);
      const first = makeAgent({
        agent_id: "agent-claude-code",
        harness: "claude-code",
      });
      const second = makeAgent({
        agent_id: "agent-openclaw",
        harness: "openclaw",
      });

      writePersistedLocalAgents(storagePath, [first]);
      expect(service.listAgents().map((agent) => agent.agent_id)).toEqual([
        "agent-claude-code",
      ]);

      writePersistedLocalAgents(storagePath, [first, second]);
      expect(service.listAgents().map((agent) => agent.agent_id)).toEqual([
        "agent-claude-code",
        "agent-openclaw",
      ]);
    });
  });

  it("is idempotent when listing repeatedly with unchanged persisted state", async () => {
    await withTmpFortress(async (storagePath) => {
      const service = makeRefreshService(storagePath);
      const record = makeAgent({ agent_id: "agent-idempotent" });
      writePersistedLocalAgents(storagePath, [record]);

      const first = service.listAgents().map((agent) => agent.agent_id);
      const second = service.listAgents().map((agent) => agent.agent_id);

      expect(second).toEqual(first);
      expect(second).toEqual(["agent-idempotent"]);
    });
  });
});

describe("Hub inbox happy path (Test 1)", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
    Object.assign(rig.inboxState, seedInboxState());
  });
  afterEach(async () => rig.stop());

  it("returns one item per inbox kind with correct discriminator", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: { items: HubInboxItem[] };
    };
    const kinds = new Set(body.data.items.map((i) => i.kind));
    expect(kinds).toEqual(
      new Set([
        "approval_pending",
        "blocked_egress",
        "privacy_event",
        "budget_warning",
        "recovery_prompt",
        "agent_error",
      ]),
    );
    expect(body.data.items.length).toBe(6);
    for (const item of body.data.items) {
      expect(item.version).toBe("1.1");
      expect(item.identity_id).toBe(IDENTITY_ID);
      expect(typeof item.display_template_id).toBe("string");
      expect(Array.isArray(item.display_template_args)).toBe(true);
    }
  });
});

describe("Hub inbox approve / deny (Test 2)", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig();
    Object.assign(rig.inboxState, seedInboxState());
  });
  afterEach(async () => rig.stop());

  it("POST .../approve flips an approval-pending item to resolved", async () => {
    // Source items are not Tier-1 hub-enqueued, so approve resolves
    // without a controller call.
    const seedRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(seedRes.status).toBe(200);

    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    const approveBody = (await approveRes.json()) as {
      ok: true;
      data: { item: HubInboxItem };
    };
    expect(approveBody.data.item.resolved).toBe(true);
    expect(approveBody.data.item.resolved_at).toBeDefined();

    // Subsequent GET reflects the resolution.
    const afterRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    const after = (await afterRes.json()) as {
      ok: true;
      data: { items: HubInboxItem[] };
    };
    const item = after.data.items.find((i) => i.item_id === "approval-1");
    expect(item?.resolved).toBe(true);
  });

  it("POST .../deny flips a blocked-egress item via dismiss", async () => {
    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/egress-1/dismiss`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);
    const body = (await denyRes.json()) as {
      ok: true;
      data: { item: HubInboxItem };
    };
    expect(body.data.item.resolved).toBe(true);
  });

  it("re-resolving a resolved item returns 409", async () => {
    await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    await fetch(`${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`, {
      method: "POST",
      headers: withAuth({}, rig.authToken),
    });
    const second = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(second.status).toBe(409);
  });
});

// SECURITY (loopback-no-autoauth-for-approvals): even with loopback
// auto-auth ON, the hub inbox approve/deny DECISION must require the
// operator token, because the co-resident agent shares loopback. Inbox
// dismiss (housekeeping) and read-only routes keep the auto-auth
// convenience.
describe("Hub inbox: loopback auto-auth does not gate approve/deny", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({
      authConfig: { loopbackAutoAuth: true, authToken: "operator-token" },
    });
    Object.assign(rig.inboxState, seedInboxState());
  });
  afterEach(async () => rig.stop());

  it("rejects a tokenless loopback POST .../approve (401) even with auto-auth on", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
    // The approval must remain unresolved: the gate held.
    const after = (await (
      await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
        headers: withAuth({}, rig.authToken),
      })
    ).json()) as { data: { items: HubInboxItem[] } };
    expect(
      after.data.items.find((i) => i.item_id === "approval-1")?.resolved,
    ).toBe(false);
  });

  it("rejects a tokenless loopback POST .../deny (401) even with auto-auth on", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/approval-1/deny`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
  });

  it("accepts POST .../approve WITH the valid operator token (200)", async () => {
    await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/approval-1/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as { data: { item: HubInboxItem } };
    expect(body.data.item.resolved).toBe(true);
  });

  it("redacts approval_pending inbox items from tokenless loopback GET /inbox without hiding other inbox kinds", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: {
        items: HubInboxItem[];
        pending_approvals_redacted?: true;
        pending_approvals_count?: number;
      };
    };

    expect(body.data.pending_approvals_redacted).toBe(true);
    expect(body.data.pending_approvals_count).toBe(1);
    expect(body.data.items.some((item) => item.kind === "approval_pending")).toBe(false);
    expect(body.data.items.some((item) => item.kind === "blocked_egress")).toBe(true);
    const encoded = JSON.stringify(body);
    expect(encoded).not.toContain("approval-1");
    expect(encoded).not.toContain("state_export");
  });

  it("CONTROL: serves full approval_pending inbox items with an operator bearer", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: {
        items: HubInboxItem[];
        pending_approvals_redacted?: true;
      };
    };

    expect(body.data.pending_approvals_redacted).toBeUndefined();
    expect(body.data.items).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          item_id: "approval-1",
          kind: "approval_pending",
          operation_category: "state_export",
        }),
      ]),
    );
  });

  // #800 follow-on (operational-mutation chokepoint): inbox DISMISS is an
  // operational mutation (it changes operator-visible inbox state), so it
  // now requires the operator bearer even on loopback - the prior
  // "housekeeping stays tokenless" carve-out is retired in favor of a
  // fail-closed bias on every inbox mutation. A tokenless loopback dismiss
  // is rejected; the dismiss with the operator bearer succeeds.
  it("rejects a tokenless loopback inbox DISMISS (401) even with auto-auth on", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/egress-1/dismiss`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
  });

  it("accepts inbox DISMISS WITH the valid operator token (200)", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/egress-1/dismiss`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(200);
  });
});

describe("Hub agent registry list (Test 3)", () => {
  let rig: TestRig;

  beforeEach(async () => (rig = await startRig()));
  afterEach(async () => rig.stop());

  it("returns wrapped agents with full LocalAgentRecord shape", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/agents`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: { agents: LocalAgentRecord[] };
    };
    expect(body.data.agents.length).toBe(1);
    const a = body.data.agents[0]!;
    expect(a.version).toBe("1.1");
    expect(a.identity_id).toBe(IDENTITY_ID);
    expect(a.harness).toBe("openclaw");
    expect(a.policy_id).toBe("policy-default");
    expect(a.budget_summary.daily?.cap).toBe(100_000);
    expect(a.capabilities.can_pause).toBe(true);
  });

  it("ages a stale active agent to unknown in the list (seam #10 liveness)", async () => {
    // Seed an agent whose stored status is `active` but whose last activity is
    // far in the past: a crashed/dead agent. The list read-projection must age
    // it to `unknown` so the fleet view stops showing "Running / protected".
    rig.registry.put(
      makeAgent({
        agent_id: "agent-dead",
        status: "active",
        last_activity_at: "2020-01-01T00:00:00.000Z",
      }),
    );
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/agents`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: { agents: LocalAgentRecord[] };
    };
    const dead = body.data.agents.find((x) => x.agent_id === "agent-dead");
    const alpha = body.data.agents.find((x) => x.agent_id === "agent-alpha");
    expect(dead?.status).toBe("unknown");
    // The freshly-seeded default agent (recent activity) stays active.
    expect(alpha?.status).toBe("active");
  });

  it("GET /api/hub/agents/:id returns the record + status snapshot", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha`,
      { headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      ok: true;
      data: {
        agent: LocalAgentRecord;
        snapshot: { agent_id: string; status: HubAgentStatus };
      };
    };
    expect(body.data.agent.agent_id).toBe("agent-alpha");
    expect(body.data.snapshot.agent_id).toBe("agent-alpha");
    expect(body.data.snapshot.status).toBe("active");
  });
});

describe("Hub agent control endpoints (Test 4)", () => {
  let rig: TestRig;

  beforeEach(async () => (rig = await startRig()));
  afterEach(async () => rig.stop());

  it("pause then resume flips status and records both calls", async () => {
    const pauseRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/pause`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(pauseRes.status).toBe(200);
    const pauseBody = (await pauseRes.json()) as {
      ok: true;
      data: { prior_status: string; new_status: string };
    };
    expect(pauseBody.data.prior_status).toBe("active");
    expect(pauseBody.data.new_status).toBe("paused");

    const resumeRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/resume`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const resumeBody = (await resumeRes.json()) as {
      ok: true;
      data: { prior_status: string; new_status: string };
    };
    expect(resumeBody.data.prior_status).toBe("paused");
    expect(resumeBody.data.new_status).toBe("active");

    expect(rig.controller.calls.map((c) => c.action)).toEqual([
      "pause",
      "resume",
    ]);
  });

  it("Tier 1 lockdown does NOT execute synchronously; enqueues approval", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: true;
      data: {
        agent_id: string;
        inbox_item_id: string;
        status: string;
        operation_category: string;
      };
    };
    expect(body.data.status).toBe("approval_pending");
    expect(body.data.operation_category).toBe("lockdown");
    // No controller call yet — still pending.
    expect(rig.controller.calls.length).toBe(0);

    // Approving fires the controller call.
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(body.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    expect(rig.controller.calls.map((c) => c.action)).toEqual(["lockdown"]);
  });

  it("Tier 1 lockdown approval emits agent_lockdown_engaged lifecycle activity", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);

    await rig.auditLog.flush();
    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{
          category: string;
          agent_id?: string;
          display_template_id: string;
        }>;
      };
    };
    const engaged = lifecycleBody.data.entries.find((e) =>
      e.display_template_id.includes("agent_lockdown_engaged"),
    );
    expect(engaged).toBeDefined();
    expect(engaged!.category).toBe("lifecycle");
    expect(engaged!.agent_id).toBeUndefined();
  });

  it("Tier 1 unwrap approval emits agent_unwrap_engaged lifecycle activity", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/unwrap`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);

    await rig.auditLog.flush();
    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{
          category: string;
          display_template_id: string;
        }>;
      };
    };
    expect(
      lifecycleBody.data.entries.some((e) =>
        e.display_template_id.includes("agent_unwrap_engaged"),
      ),
    ).toBe(true);
  });

  it("Tier 1 lockdown denial does NOT emit agent_lockdown_engaged lifecycle activity", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);

    await rig.auditLog.flush();
    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{ display_template_id: string }>;
      };
    };
    expect(
      lifecycleBody.data.entries.some((e) =>
        e.display_template_id.includes("agent_lockdown_engaged"),
      ),
    ).toBe(false);
  });

  it("Tier 1 unwrap denial does NOT call the controller", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/unwrap`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const deny = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(deny.status).toBe(200);
    expect(rig.controller.calls.length).toBe(0);
  });

  it("policy bind enqueues Tier 1 inbox item, not synchronous", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/policy`,
      {
        method: "POST",
        headers: withAuth(
          { "Content-Type": "application/json" },
          rig.authToken,
        ),
        body: JSON.stringify({ policy_id: "policy-strict-001" }),
      },
    );
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: true;
      data: { operation_category: string; status: string };
    };
    expect(body.data.operation_category).toBe("policy_change");
    expect(body.data.status).toBe("approval_pending");
    expect(rig.controller.calls.length).toBe(0);
  });

  it("Tier 1 policy_change approval emits agent_policy_change_engaged lifecycle activity", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/policy`,
      {
        method: "POST",
        headers: withAuth(
          { "Content-Type": "application/json" },
          rig.authToken,
        ),
        body: JSON.stringify({ policy_id: "policy-strict-001" }),
      },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    expect(rig.controller.calls.map((c) => c.action)).toEqual(["bindPolicy"]);

    await rig.auditLog.flush();
    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{
          category: string;
          agent_id?: string;
          display_template_id: string;
        }>;
      };
    };
    const engaged = lifecycleBody.data.entries.find((e) =>
      e.display_template_id.includes("agent_policy_change_engaged"),
    );
    expect(engaged).toBeDefined();
    expect(engaged!.category).toBe("lifecycle");
    expect(engaged!.agent_id).toBeUndefined();
  });

  it("Tier 1 policy_change denial does NOT emit agent_policy_change_engaged lifecycle activity", async () => {
    const enqueue = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/policy`,
      {
        method: "POST",
        headers: withAuth(
          { "Content-Type": "application/json" },
          rig.authToken,
        ),
        body: JSON.stringify({ policy_id: "policy-strict-001" }),
      },
    );
    const enqueueBody = (await enqueue.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);
    expect(rig.controller.calls.length).toBe(0);

    await rig.auditLog.flush();
    const lifecycleRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?category=lifecycle&limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const lifecycleBody = (await lifecycleRes.json()) as {
      ok: true;
      data: {
        entries: Array<{ display_template_id: string }>;
      };
    };
    expect(
      lifecycleBody.data.entries.some((e) =>
        e.display_template_id.includes("agent_policy_change_engaged"),
      ),
    ).toBe(false);
  });

  it("template bind is Tier 1 and updates the record only after approval", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/template`,
      {
        method: "POST",
        headers: withAuth(
          { "Content-Type": "application/json" },
          rig.authToken,
        ),
        body: JSON.stringify({ template_id: "read-then-report" }),
      },
    );
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: true;
      data: { inbox_item_id: string; proposed_template_id: string };
    };
    expect(body.data.proposed_template_id).toBe("read-then-report");
    expect(rig.controller.calls).toEqual([]);

    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(body.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    expect(rig.controller.calls).toEqual([
      {
        action: "bindChannelTemplate",
        agentId: "agent-alpha",
        arg: "read-then-report",
      },
    ]);
    const agentRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha`,
      { headers: withAuth({}, rig.authToken) },
    );
    const agentBody = (await agentRes.json()) as {
      ok: true;
      data: { agent: LocalAgentRecord };
    };
    expect(agentBody.data.agent.channel_template_id).toBe("read-then-report");
  });
});

describe("Hub agent-control custody routes require bearer under loopback auto-auth", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({
      authConfig: { loopbackAutoAuth: true, authToken: "operator-token" },
    });
  });
  afterEach(async () => rig.stop());

  it("rejects a tokenless loopback agent-control POST before the handler runs", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/pause`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
    expect(rig.controller.calls).toEqual([]);
  });

  it("rejects session or cookie without bearer on agent-control POSTs", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/restart?session=short-lived`,
      {
        method: "POST",
        headers: { Cookie: "sanctuary_session=short-lived" },
      },
    );
    expect(res.status).toBe(401);
    expect(rig.controller.calls).toEqual([]);
  });

  it("accepts the valid bearer and reaches the agent-control handler", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/pause`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(200);
    expect(rig.controller.calls.map((c) => c.action)).toEqual(["pause"]);
  });

  it("keeps loopback auto-auth for non-custody read routes", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/agents`);
    expect(res.status).toBe(200);
  });
});

describe("Hub policy/template bind custody routes require bearer under loopback auto-auth", () => {
  // bindAgentPolicy / bindAgentChannelTemplate enqueue Tier-1 `policy_change`
  // approvals; a co-resident loopback caller must not enqueue them tokenless.
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({
      authConfig: { loopbackAutoAuth: true, authToken: "operator-token" },
    });
  });
  afterEach(async () => rig.stop());

  it("rejects a tokenless loopback agent policy-bind POST before the handler runs", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/policy`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(res.status).toBe(401);
  });

  it("rejects a tokenless loopback agent template-bind POST before the handler runs", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/template`,
      { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" },
    );
    expect(res.status).toBe(401);
  });

  it("rejects session/cookie without bearer on a policy-bind POST", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/agent-alpha/policy?session=short-lived`,
      {
        method: "POST",
        headers: {
          Cookie: "sanctuary_session=short-lived",
          "Content-Type": "application/json",
        },
        body: "{}",
      },
    );
    expect(res.status).toBe(401);
  });
});

describe("Hub activity feed pagination (Test 5)", () => {
  let rig: TestRig;

  beforeEach(async () => {
    rig = await startRig({
      pinnedProducerKeyB64url: PRODUCER_PUB_B64,
      subjectFortressId: FORTRESS_ID,
    });
  });
  afterEach(async () => rig.stop());

  it("respects since + limit", async () => {
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {
      agent_id: "agent-alpha",
    });
    await new Promise((r) => setTimeout(r, 5));
    const cutoff = new Date().toISOString();
    await new Promise((r) => setTimeout(r, 5));
    await rig.auditLog.append("l2", "egress_blocked", IDENTITY_ID, {
      agent_id: "agent-alpha",
    });
    await rig.auditLog.append("l2", "privacy_event", IDENTITY_ID, {
      agent_id: "agent-alpha",
    });
    await rig.auditLog.flush();

    const all = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?limit=10`,
      { headers: withAuth({}, rig.authToken) },
    );
    const allBody = (await all.json()) as {
      ok: true;
      data: { entries: Array<{ category: string; emitted_at: string }> };
    };
    expect(allBody.data.entries.length).toBe(3);
    const categories = allBody.data.entries.map((e) => e.category).sort();
    expect(categories).toContain("egress");
    expect(categories).toContain("privacy");

    const sinceRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?since=${encodeURIComponent(cutoff)}&limit=10`,
      { headers: withAuth({}, rig.authToken) },
    );
    const sinceBody = (await sinceRes.json()) as {
      ok: true;
      data: { entries: Array<{ category: string }> };
    };
    expect(sinceBody.data.entries.length).toBe(2);

    const limited = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?limit=1`,
      { headers: withAuth({}, rig.authToken) },
    );
    const limitedBody = (await limited.json()) as {
      ok: true;
      data: { entries: unknown[] };
    };
    expect(limitedBody.data.entries.length).toBe(1);
  });

  it("filter by agent_id and category narrows results", async () => {
    const betaSubject = `${FORTRESS_ID}/uid-504`;
    rig.registry.put(
      makeAgent({
        agent_id: "agent-beta",
        protection_subject: betaSubject,
      }),
    );
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {
      agent_id: "agent-alpha",
    });
    await rig.auditLog.append("l2", "policy_decision", IDENTITY_ID, {
      agent_id: "agent-beta",
    });
    const signed = withProducerSignature({
      timestamp: new Date().toISOString(),
      layer: "l2",
      operation: "agent_upstream_call",
      identity_id: "agent-beta",
      result: "success",
      details: {
        agent_id: "agent-beta",
      },
    }, betaSubject);
    await rig.auditLog.appendCritical({
      timestamp: signed.timestamp,
      layer: signed.layer,
      operation: signed.operation,
      identity_id: signed.identity_id,
      result: signed.result,
      details: signed.details,
    });
    await rig.auditLog.flush();

    const filtered = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?agent_id=agent-beta&category=egress`,
      { headers: withAuth({}, rig.authToken) },
    );
    const body = (await filtered.json()) as {
      ok: true;
      data: { entries: Array<{ agent_id?: string; category: string }> };
    };
    expect(body.data.entries.length).toBe(1);
    expect(body.data.entries[0]!.agent_id).toBe("agent-beta");
    expect(body.data.entries[0]!.category).toBe("egress");
  });

  it("unsigned unlisted agent rows attribute nothing and stay unfilterable", async () => {
    await rig.auditLog.append("l2", "zzz_unknown_op", IDENTITY_ID, {
      agent_id: "victim-agent-b",
    });
    await rig.auditLog.flush();

    const all = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?limit=10`,
      { headers: withAuth({}, rig.authToken) },
    );
    const allBody = (await all.json()) as {
      ok: true;
      data: {
        entries: Array<{
          agent_id?: string;
          attestation?: { state: string };
        }>;
      };
    };
    expect(allBody.data.entries).toHaveLength(1);
    expect(allBody.data.entries[0]!.agent_id).toBeUndefined();
    expect(allBody.data.entries[0]!.attestation!.state).toBe("degraded");

    const filtered = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?agent_id=victim-agent-b&limit=10`,
      { headers: withAuth({}, rig.authToken) },
    );
    const filteredBody = (await filtered.json()) as {
      ok: true;
      data: { entries: unknown[] };
    };
    expect(filteredBody.data.entries).toHaveLength(0);
  });
});

describe("Hub authorization (Test 6)", () => {
  let rig: TestRig;

  beforeEach(async () => (rig = await startRig()));
  afterEach(async () => rig.stop());

  it("rejects unauthenticated requests with 401", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`);
    expect(res.status).toBe(401);
  });

  it("rejects bad token with 401", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/agents`, {
      headers: { Authorization: "Bearer wrong-token" },
    });
    expect(res.status).toBe(401);
  });

  it("loopback auto-auth lets localhost pass without token", async () => {
    const loopbackRig = await startRig({
      authConfig: { loopbackAutoAuth: true, authToken: "irrelevant" },
    });
    try {
      const res = await fetch(
        `${loopbackRig.url}${HUB_API_PREFIX}/agents`,
      );
      expect(res.status).toBe(200);
    } finally {
      await loopbackRig.stop();
    }
  });
});

describe("No raw secret in inbox (Test 7)", () => {
  let rig: TestRig;
  const MAGIC_SECRET = "PLAINTEXT_API_KEY_sk_supersecret_1234";

  beforeEach(async () => {
    rig = await startRig();
    // Agent emits an error containing the magic string. The inbox source
    // is responsible for sanitization; this test asserts the contract:
    // raw error text MUST NOT cross the wire. The agent_error item
    // carries an error_class token + typed args, never the raw string.
    rig.inboxState.agentErrors.push({
      version: "1.1",
      item_id: "error-secret-1",
      kind: "agent_error",
      identity_id: IDENTITY_ID,
      agent_id: "agent-alpha",
      created_at: "2026-04-25T01:00:00.000Z",
      display_template_id: `${HUB_INBOX_TEMPLATE_NAMESPACES.agent_error}.E_HARNESS_FAILURE`,
      display_template_args: [{ kind: "agent_id", value: "agent-alpha" }],
      resolved: false,
      error_class: "E_HARNESS_FAILURE",
      agent_still_active: false,
    });
  });
  afterEach(async () => rig.stop());

  it("inbox response body never contains the magic plaintext string", async () => {
    const res = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(MAGIC_SECRET);
    expect(text).toContain("E_HARNESS_FAILURE");
    expect(text).toContain("display_template_id");
    expect(text).toContain("display_template_args");
  });

  it("registry shape rejects forbidden secret-shaped fields on put", () => {
    const reg = new InMemoryLocalAgentRegistry();
    expect(() =>
      reg.put({
        ...makeAgent(),
        // @ts-expect-error — intentionally simulating bad backend code
        api_key: "abc",
      }),
    ).toThrow(/forbidden secret-shaped field/);
  });
});

describe("Local-only enforcement (Test 8)", () => {
  let rig: TestRig;

  beforeEach(async () => (rig = await startRig()));
  afterEach(async () => rig.stop());

  it("rejects fortress_id query parameter with 422", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox?fortress_id=other-fortress-001`,
      { headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { ok: false; error: string };
    expect(body.error).toBe("HubLocalOnlyError");
  });

  it("rejects peer_id query parameter on agents listing", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents?peer_id=peer-001`,
      { headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(422);
  });

  it("rejects remote_fortress_id query parameter on activity feed", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?remote_fortress_id=rf-001`,
      { headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(422);
  });
});

describe("Hub policy + budget summaries", () => {
  it("returns the injected summary list", async () => {
    const policySummaries: HubPolicySummary[] = [
      {
        policy_id: "policy-default",
        display_label: "Default channel",
        bound_at: "2026-04-25T00:00:00.000Z",
        agent_count: 1,
        channel_template_id: "request-approve-act",
      },
    ];
    const budgetSummaries: HubBudgetSummary[] = [
      {
        bucket_id: "daily-tokens",
        display_label: "Daily tokens",
        unit: "tokens",
        cap: 100_000,
        used: 25_000,
        last_refreshed_at: "2026-04-25T00:00:00.000Z",
      },
    ];
    const rig = await startRig({ policySummaries, budgetSummaries });
    try {
      const policiesRes = await fetch(
        `${rig.url}${HUB_API_PREFIX}/policies`,
        { headers: withAuth({}, rig.authToken) },
      );
      const policiesBody = (await policiesRes.json()) as {
        ok: true;
        data: { policies: HubPolicySummary[] };
      };
      expect(policiesBody.data.policies).toEqual(policySummaries);

      const budgetsRes = await fetch(
        `${rig.url}${HUB_API_PREFIX}/budgets`,
        { headers: withAuth({}, rig.authToken) },
      );
      const budgetsBody = (await budgetsRes.json()) as {
        ok: true;
        data: { budgets: HubBudgetSummary[] };
      };
      expect(budgetsBody.data.budgets).toEqual(budgetSummaries);
    } finally {
      await rig.stop();
    }
  });
});

describe("Hub source-file contract scans", () => {
  const srcFiles = [
    "constants.ts",
    "errors.ts",
    "types.ts",
    "agent-registry.ts",
    "inbox-store.ts",
    "inbox-aggregator.ts",
    "activity-feed.ts",
    "hub-service.ts",
    "api-router.ts",
    "index.ts",
  ];

  it("no concordia or verascore imports in hub source files", async () => {
    const dir = join(
      new URL(".", import.meta.url).pathname,
      "..",
      "..",
      "src",
      "hub",
    );
    for (const f of srcFiles) {
      const content = await readFile(join(dir, f), "utf-8");
      expect(content).not.toMatch(/from\s+["'].*concordia/i);
      expect(content).not.toMatch(/from\s+["'].*verascore/i);
    }
  });

  it("no em-dash characters in any hub source file", async () => {
    const dir = join(
      new URL(".", import.meta.url).pathname,
      "..",
      "..",
      "src",
      "hub",
    );
    for (const f of srcFiles) {
      const content = await readFile(join(dir, f), "utf-8");
      expect(content).not.toContain("—");
    }
  });

  it("no MLS dead claims in any hub source file", async () => {
    const dir = join(
      new URL(".", import.meta.url).pathname,
      "..",
      "..",
      "src",
      "hub",
    );
    for (const f of srcFiles) {
      const content = await readFile(join(dir, f), "utf-8");
      expect(content).not.toMatch(/\bMLS\b|RFC\s*9420/);
    }
  });

  it("no UBAI dead claims in any hub source file", async () => {
    const dir = join(
      new URL(".", import.meta.url).pathname,
      "..",
      "..",
      "src",
      "hub",
    );
    for (const f of srcFiles) {
      const content = await readFile(join(dir, f), "utf-8");
      expect(content).not.toMatch(/\bUBAI\b|Universal Basic AI|Universal Basic Intelligence/);
    }
  });
});
