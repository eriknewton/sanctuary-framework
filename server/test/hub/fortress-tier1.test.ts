/**
 * Sanctuary v1.1 — Fortress-scope Tier 1 endpoints regression suite.
 *
 * Covers the two endpoints added by this PR:
 *   POST /api/hub/fortress/lockdown
 *   POST /api/hub/fortress/exit-bundle/export
 *
 * One inbox item per call. Tier 1 handler iterates fortress-wide on
 * approve. Stacked fortress items are rejected. Cross-fortress params
 * still rejected. The dashboard's prior /agents/all/* call paths route
 * here via the routing-layer sentinel alias.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";

import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { exportExitBundle, verifyExitBundle } from "../../src/exit/index.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import { HUB_API_PREFIX } from "../../src/hub/constants.js";
import {
  HubService,
  InMemoryLocalAgentRegistry,
  handleHubRoute,
  type HubAgentController,
  type HubFortressExportResult,
  type HubInboxSources,
} from "../../src/hub/index.js";
import type {
  HubApprovalPendingItem,
  HubInboxItem,
} from "../../src/contracts/v1.1/hub-events.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import type { HubAgentStatus } from "../../src/contracts/v1.1/constants.js";
import type { AuthConfig } from "../../src/console/auth-middleware.js";
import { readLockdownStatus } from "../../src/lockdown/status.js";

const IDENTITY_ID = "operator-fortress-001";
const FORTRESS_ID = "fortress-test-fortress-001";

function makeAgent(
  agentId: string,
  overrides: Partial<LocalAgentRecord> = {},
): LocalAgentRecord {
  const base: LocalAgentRecord = {
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
    policy_id: "policy-default",
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
  return { ...base, ...overrides };
}

class StubAgentController implements HubAgentController {
  calls: Array<{ action: string; agentId: string }> = [];
  failingAgents: Set<string> = new Set();

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
    if (this.failingAgents.has(agentId)) {
      throw new Error(`harness refused lockdown for ${agentId}`);
    }
    return "locked_down";
  }
  async bindPolicy(agentId: string, policyId: string): Promise<void> {
    this.calls.push({ action: "bindPolicy", agentId });
    void policyId;
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

interface TestRig {
  url: string;
  service: HubService;
  registry: InMemoryLocalAgentRegistry;
  controller: StubAgentController;
  auditLog: AuditLog;
  authToken: string;
  storagePath: string;
  fortressExportCalls: number;
  fortressExportResult: HubFortressExportResult;
  stop: () => Promise<void>;
}

interface RigOptions {
  agentIds?: string[];
  fortressExportImpl?: () => Promise<HubFortressExportResult>;
  authConfig?: AuthConfig;
}

async function startRig(options: RigOptions = {}): Promise<TestRig> {
  const storage = new MemoryStorage();
  const storagePath = await mkdtemp(join(tmpdir(), "sanctuary-lockdown-"));
  const masterKey = randomBytes(32);
  const auditLog = new AuditLog(storage, masterKey);

  const agentIds = options.agentIds ?? ["agent-alpha"];
  const registry = new InMemoryLocalAgentRegistry(
    agentIds.map((id) => makeAgent(id)),
  );
  const controller = new StubAgentController();

  let fortressExportCalls = 0;
  const defaultExportResult: HubFortressExportResult = {
    bundle_dir: "/tmp/sanctuary-fortress-bundle-test",
    manifest_hash:
      "0000000000000000000000000000000000000000000000000000000000000000",
    artifact_count: 7,
  };
  const exportImpl =
    options.fortressExportImpl ?? (async () => defaultExportResult);

  const service = new HubService({
    identityId: IDENTITY_ID,
    fortressId: FORTRESS_ID,
    storagePath,
    agentRegistry: registry,
    inboxSources: emptyInboxSources(),
    activitySources: { auditLog, identityId: IDENTITY_ID },
    policyBudgetSources: {
      listPolicySummaries: () => [],
      listBudgetSummaries: () => [],
    },
    agentController: controller,
    fortressExportBundle: async () => {
      fortressExportCalls++;
      return exportImpl();
    },
  });

  const authToken = options.authConfig?.authToken ?? "test-token-fortress";
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

  const rig: TestRig = {
    url,
    service,
    registry,
    controller,
    auditLog,
    authToken,
    storagePath,
    get fortressExportCalls() {
      return fortressExportCalls;
    },
    fortressExportResult: defaultExportResult,
    stop: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
      await rm(storagePath, { recursive: true, force: true });
    },
  };
  return rig;
}

function withAuth(headers: HeadersInit, token: string): HeadersInit {
  return { ...headers, Authorization: `Bearer ${token}` };
}

// ═════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════

describe("Fortress lockdown happy path (Test 1)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({
      agentIds: ["agent-alpha", "agent-beta", "agent-gamma"],
    });
  });
  afterEach(async () => rig.stop());

  it("creates exactly one inbox item; approve locks down all three agents and emits one fortress-level activity entry", async () => {
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
    expect(enqueueBody.data.fortress_scope).toBe(true);
    expect(enqueueBody.data.operation_category).toBe("lockdown");
    expect(enqueueBody.data.status).toBe("approval_pending");

    // Exactly ONE inbox item created (not three).
    const inboxRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    const inbox = (await inboxRes.json()) as {
      ok: true;
      data: { items: HubInboxItem[] };
    };
    const fortressLockdownItems = inbox.data.items.filter(
      (i) =>
        i.kind === "approval_pending" &&
        i.operation_category === "lockdown" &&
        i.agent_id === undefined,
    );
    expect(fortressLockdownItems.length).toBe(1);
    // Item carries no agent_id (fortress-scope distinguisher).
    expect(fortressLockdownItems[0]!.agent_id).toBeUndefined();
    expect(fortressLockdownItems[0]!.display_template_id).toBe(
      "approval_pending.tier1.fortress_lockdown",
    );

    // No controller call yet — Tier 1 deferred.
    expect(rig.controller.calls.length).toBe(0);

    // Approve via inbox.
    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);

    // All three agents locked down.
    const lockdownCalls = rig.controller.calls.filter(
      (c) => c.action === "lockdown",
    );
    expect(lockdownCalls.length).toBe(3);
    const calledAgentIds = lockdownCalls.map((c) => c.agentId).sort();
    expect(calledAgentIds).toEqual([
      "agent-alpha",
      "agent-beta",
      "agent-gamma",
    ]);

    // Registry status updated.
    for (const id of ["agent-alpha", "agent-beta", "agent-gamma"]) {
      const record = rig.registry.get(id)!;
      expect(record.status).toBe("locked_down");
      expect(record.status_reason_class).toBe("operator_lockdown");
    }
    await expect(readLockdownStatus(rig.storagePath)).resolves.toMatchObject({
      active: true,
      reason: "operator_lockdown",
    });

    // Exactly ONE fortress-level activity entry emitted (not three per-agent).
    await rig.auditLog.flush();
    const activityRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/activity?limit=20`,
      { headers: withAuth({}, rig.authToken) },
    );
    const activity = (await activityRes.json()) as {
      ok: true;
      data: { entries: Array<{ display_template_id: string }> };
    };
    const lockdownActivity = activity.data.entries.filter((e) =>
      e.display_template_id.includes("fortress_lockdown_engaged"),
    );
    expect(lockdownActivity.length).toBe(1);
  });
});

describe("Fortress lockdown deny path (Test 2)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({
      agentIds: ["agent-alpha", "agent-beta", "agent-gamma"],
    });
  });
  afterEach(async () => rig.stop());

  it("deny does NOT call the controller and leaves all agents active", async () => {
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };
    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);

    // No controller calls.
    expect(
      rig.controller.calls.filter((c) => c.action === "lockdown").length,
    ).toBe(0);
    // No agent status changed.
    for (const id of ["agent-alpha", "agent-beta", "agent-gamma"]) {
      const record = rig.registry.get(id)!;
      expect(record.status).toBe("active");
    }
  });
});

describe("Fortress lockdown partial failure (Test 3)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({
      agentIds: ["agent-alpha", "agent-beta", "agent-gamma"],
    });
    rig.controller.failingAgents.add("agent-beta");
  });
  afterEach(async () => rig.stop());

  it("locks down two agents, leaves the failing one active, emits one agent_error inbox item per failure, and resolves the original fortress lockdown item", async () => {
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };

    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);

    expect(rig.registry.get("agent-alpha")!.status).toBe("locked_down");
    expect(rig.registry.get("agent-beta")!.status).toBe("active");
    expect(rig.registry.get("agent-gamma")!.status).toBe("locked_down");

    // Original fortress lockdown item resolved (not retried).
    const inboxRes = await fetch(`${rig.url}${HUB_API_PREFIX}/inbox`, {
      headers: withAuth({}, rig.authToken),
    });
    const inbox = (await inboxRes.json()) as {
      ok: true;
      data: { items: HubInboxItem[] };
    };
    const original = inbox.data.items.find(
      (i) => i.item_id === enqueueBody.data.inbox_item_id,
    );
    expect(original?.resolved).toBe(true);

    // Exactly one new agent_error item describes the failed lockdown.
    const errorItems = inbox.data.items.filter(
      (i) =>
        i.kind === "agent_error" && i.agent_id === "agent-beta",
    );
    expect(errorItems.length).toBe(1);
  });
});

describe("Fortress lockdown stacked rejection (Test 4)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ agentIds: ["agent-alpha"] });
  });
  afterEach(async () => rig.stop());

  it("rejects a second fortress lockdown with 409 while the first is pending; allows another after the first resolves", async () => {
    const first = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(first.status).toBe(202);
    const firstBody = (await first.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };

    const second = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(second.status).toBe(409);
    const secondBody = (await second.json()) as {
      ok: false;
      error: string;
    };
    expect(secondBody.error).toBe("HubConflictError");

    // Resolve the first.
    await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(firstBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );

    // Now a fresh fortress lockdown is allowed.
    const third = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(third.status).toBe(202);
  });
});

describe("Fortress exit-bundle export happy path (Test 5)", () => {
  const tempDirs: string[] = [];
  let rig: TestRig;

  beforeEach(async () => {
    // Wire a real exportExitBundle through the fortressExportBundle
    // callback so we can assert manifest signature verifies.
    const bundleStorage = new MemoryStorage();
    const bundleMasterKey = generateRandomKey();
    const bundleAuditLog = new AuditLog(bundleStorage, bundleMasterKey);
    const bundleStateStore = new StateStore(bundleStorage, bundleMasterKey);
    const { tools: l1Tools, identityManager } = createL1Tools(
      bundleStateStore,
      bundleStorage,
      bundleMasterKey,
      "recovery-key",
      bundleAuditLog,
    );
    await identityManager.load();
    const { reputationStore } = createL4Tools(
      bundleStorage,
      bundleMasterKey,
      identityManager,
      bundleAuditLog,
    );
    const sourceIdentity = await l1Tools
      .find((t) => t.name === "identity_create")!
      .handler({ label: "fortress-source-agent" });
    const sourceIdentityId = (
      JSON.parse(sourceIdentity.content[0]!.text) as {
        identity_id: string;
      }
    ).identity_id;
    await bundleAuditLog.append("l2", "wrap", sourceIdentityId, {
      agent_id: "agent-alpha",
    });

    const fortressExportImpl = async (): Promise<HubFortressExportResult> => {
      const bundleDir = await mkdtemp(
        join(tmpdir(), "sanctuary-fortress-bundle-"),
      );
      tempDirs.push(bundleDir);
      const exported = await exportExitBundle({
      unpartitionedLegacyExport: true,
        bundleDir,
        storage: bundleStorage,
        masterKey: bundleMasterKey,
        identityManager,
        auditLog: bundleAuditLog,
        reputationStore,
        policy: DEFAULT_POLICY,
        config: defaultConfig(),
        keySource: "recovery-key",
      });
      return {
        bundle_dir: bundleDir,
        manifest_hash: exported.manifest_hash,
        artifact_count: exported.artifact_count,
      };
    };

    rig = await startRig({
      agentIds: ["agent-alpha"],
      fortressExportImpl,
    });
  });
  afterEach(async () => {
    await rig.stop();
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("approve runs exportExitBundle, attaches bundle_dir + manifest_hash to resolution, and the manifest verifies", async () => {
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/exit-bundle/export`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(enqueueRes.status).toBe(202);
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: {
        inbox_item_id: string;
        status: "approval_pending";
        operation_category: "exit_bundle_export";
        fortress_scope: true;
      };
    };
    expect(enqueueBody.data.fortress_scope).toBe(true);
    expect(enqueueBody.data.operation_category).toBe("exit_bundle_export");

    // Callback not invoked until approval.
    expect(rig.fortressExportCalls).toBe(0);

    const approveRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/approve`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(approveRes.status).toBe(200);
    const approveBody = (await approveRes.json()) as {
      ok: true;
      data: { item: HubApprovalPendingItem };
    };

    // exportExitBundle ran exactly once.
    expect(rig.fortressExportCalls).toBe(1);

    // Resolution payload carries bundle_dir + manifest_hash + artifact_count.
    const payload = approveBody.data.item.resolution_payload;
    expect(payload).toBeDefined();
    expect(typeof payload!.bundle_dir).toBe("string");
    expect(typeof payload!.manifest_hash).toBe("string");
    expect((payload!.manifest_hash ?? "").length).toBeGreaterThan(16);
    expect(typeof payload!.artifact_count).toBe("number");
    expect((payload!.artifact_count ?? 0)).toBeGreaterThan(0);

    // Manifest signature verifies (sanity check; PR #70 owns the primitive).
    const verified = await verifyExitBundle(payload!.bundle_dir!);
    expect(verified.passed).toBe(true);
  });
});

describe("Fortress exit-bundle export deny (Test 6)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ agentIds: ["agent-alpha"] });
  });
  afterEach(async () => rig.stop());

  it("deny does NOT invoke the export callback", async () => {
    const enqueueRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/exit-bundle/export`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    const enqueueBody = (await enqueueRes.json()) as {
      ok: true;
      data: { inbox_item_id: string };
    };

    const denyRes = await fetch(
      `${rig.url}${HUB_API_PREFIX}/inbox/${encodeURIComponent(enqueueBody.data.inbox_item_id)}/deny`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(denyRes.status).toBe(200);
    expect(rig.fortressExportCalls).toBe(0);
  });
});

describe("Fortress endpoints reject cross-fortress params (Test 7)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ agentIds: ["agent-alpha"] });
  });
  afterEach(async () => rig.stop());

  it("rejects fortress_id query parameter on /fortress/lockdown with 422", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown?fortress_id=other`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { ok: false; error: string };
    expect(body.error).toBe("HubLocalOnlyError");
  });

  it("rejects peer_id query parameter on /fortress/exit-bundle/export with 422", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/exit-bundle/export?peer_id=peer-001`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(422);
  });
});

describe("Fortress endpoints authorization (Test 8)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ agentIds: ["agent-alpha"] });
  });
  afterEach(async () => rig.stop());

  it("rejects unauthenticated request to /fortress/lockdown with 401", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/lockdown`,
      { method: "POST" },
    );
    expect(res.status).toBe(401);
  });

  it("rejects bad token on /fortress/exit-bundle/export with 401", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/fortress/exit-bundle/export`,
      {
        method: "POST",
        headers: { Authorization: "Bearer wrong-token" },
      },
    );
    expect(res.status).toBe(401);
  });
});

describe("Fortress endpoints sentinel /agents/all alias (Test 9)", () => {
  let rig: TestRig;
  beforeEach(async () => {
    rig = await startRig({ agentIds: ["agent-alpha", "agent-beta"] });
  });
  afterEach(async () => rig.stop());

  it("POST /api/hub/agents/all/lockdown delegates to fortress lockdown handler", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/all/lockdown`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: true;
      data: {
        inbox_item_id: string;
        fortress_scope: true;
        operation_category: "lockdown";
      };
    };
    expect(body.data.fortress_scope).toBe(true);
    expect(body.data.operation_category).toBe("lockdown");
  });

  it("POST /api/hub/agents/all/exit-bundle/export delegates to fortress export handler", async () => {
    const res = await fetch(
      `${rig.url}${HUB_API_PREFIX}/agents/all/exit-bundle/export`,
      { method: "POST", headers: withAuth({}, rig.authToken) },
    );
    expect(res.status).toBe(202);
    const body = (await res.json()) as {
      ok: true;
      data: { fortress_scope: true; operation_category: "exit_bundle_export" };
    };
    expect(body.data.fortress_scope).toBe(true);
    expect(body.data.operation_category).toBe("exit_bundle_export");
  });
});
