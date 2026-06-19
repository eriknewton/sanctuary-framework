import { describe, expect, it, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { LocalAgentRecord } from "../../src/contracts/v1.1/local-agent-records.js";
import {
  handlePostureRoute,
  POSTURE_API_PREFIX,
  POSTURE_HOME_PATH,
  type PostureRouteDeps,
} from "../../src/principal-policy/posture-routes.js";
import type { DetectedHarness } from "../../src/principal-policy/posture.js";

const FORTRESS = "fortress:test";

function wrappedAgent(id: string, harness: string): LocalAgentRecord {
  return {
    version: "1.1",
    agent_id: id,
    identity_id: FORTRESS,
    harness: harness as LocalAgentRecord["harness"],
    model_provider: { vendor: "anthropic", model_id: "claude", runs_locally: false },
    policy_id: "p1",
    status: "active",
    budget_summary: { last_refreshed_at: new Date().toISOString() },
    last_activity_at: new Date().toISOString(),
    wrapped_at: new Date().toISOString(),
    capabilities: {
      can_pause: true,
      can_resume: true,
      can_restart: true,
      can_unwrap: true,
      can_lockdown: true,
      can_chat: false,
      can_change_template: false,
    },
  };
}

const servers: Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (s) => new Promise<void>((resolve) => s.close(() => resolve())),
    ),
  );
});

async function serve(deps: PostureRouteDeps): Promise<string> {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${req.headers.host}`);
    const handled = await handlePostureRoute(
      deps,
      req,
      res,
      url,
      req.method ?? "GET",
    );
    if (!handled) res.writeHead(404).end();
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address() as AddressInfo;
  return `http://127.0.0.1:${addr.port}`;
}

function baseDeps(log: AuditLog | null, agents: LocalAgentRecord[]): PostureRouteDeps {
  const detected: DetectedHarness[] = [
    { platform: "cursor", harness: "cursor", config_path: "/home/u/.cursor/mcp.json" },
  ];
  return {
    auditLog: log,
    originMachine: FORTRESS,
    listAgents: () => agents,
    detectInstalledHarnesses: async () => detected,
    listReachRules: () => [
      {
        rule_id: "curated-anthropic-api",
        host: ["api.anthropic.com"],
        disposition: "allow",
        enforcing_layer: "castle_wall",
      },
    ],
    platform: "darwin",
  };
}

function newLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

describe("posture route layer", () => {
  it("serves the posture home HTML at /posture", async () => {
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_HOME_PATH}`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const body = await res.text();
    expect(body).toContain("Sovereignty Posture");
    // Never-fake-green discipline visible in the renderer.
    expect(body).toContain("/api/posture/home");
  });

  it("composes the home payload (G1+G2+G4 + honest protection split)", async () => {
    const log = newLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(now - 30_000).toISOString(),
    });
    const base = await serve(baseDeps(log, [wrappedAgent("a1", "claude_code")]));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/home`);
    expect(res.status).toBe(200);
    const body = await res.json();
    // #634 honest split: an active agent is "protection requested" (policy
    // intent), but enforcement is NOT confirmed per-agent, so the confirmed
    // count is 0 and the agent row never claims green enforcement even though
    // the machine-level wall is armed.
    expect(body.protection_requested_count).toBe(1);
    expect(body.enforcement_confirmed_count).toBe(0);
    expect(body.protected_agent_count).toBeUndefined();
    expect(body.agents).toHaveLength(1);
    expect(body.agents[0].policy_protected).toBe(true);
    expect(body.agents[0].enforcement_active).toBe("unknown");
    expect(body.castle_wall.arm_state).toBe("armed");
    expect(body.unwrapped.unwrapped[0].harness).toBe("cursor");
    expect(body.digest.kernel_allows).toBe(1);
    expect(body.origin_machine).toBe(FORTRESS);
  });

  it("serves the feature-health panel and includes it in the home payload", async () => {
    const log = newLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(now - 30_000).toISOString(),
    });
    const base = await serve(baseDeps(log, []));

    const panelRes = await fetch(`${base}${POSTURE_API_PREFIX}/feature-health`);
    expect(panelRes.status).toBe(200);
    const panel = await panelRes.json();
    const cw = panel.rows.find(
      (r: { feature_id: string }) => r.feature_id === "castle_wall_egress",
    );
    expect(cw.status).toBe("active");
    // Event-driven features with no activity are non-green unconfirmed.
    const broker = panel.rows.find(
      (r: { feature_id: string }) => r.feature_id === "secret_broker",
    );
    expect(broker.status).toBe("unconfirmed");
    expect(panel.disclosure.broken_zero_undetectable_for_event_driven).toBe(true);

    // The home payload carries the same panel.
    const homeRes = await fetch(`${base}${POSTURE_API_PREFIX}/home`);
    const home = await homeRes.json();
    expect(home.feature_health.rows.length).toBe(panel.rows.length);
  });

  it("serves per-agent reach (G5) and 404s an unknown agent", async () => {
    const base = await serve(baseDeps(newLog(), [wrappedAgent("a1", "claude_code")]));
    const ok = await fetch(`${base}${POSTURE_API_PREFIX}/reach/a1`);
    expect(ok.status).toBe(200);
    const reach = await ok.json();
    expect(reach.agent_id).toBe("a1");
    expect(reach.destinations.some((d: { destination: string }) => d.destination === "api.anthropic.com")).toBe(true);

    const missing = await fetch(`${base}${POSTURE_API_PREFIX}/reach/nope`);
    expect(missing.status).toBe(404);
  });

  it("fails closed with 503 when the audit log is not unlocked (never empty-green)", async () => {
    const base = await serve(baseDeps(null, []));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/castle-wall`);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe("posture_unavailable");
  });

  it("404s an unknown /api/posture path within the namespace", async () => {
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/does-not-exist`);
    expect(res.status).toBe(404);
  });

  it("returns 400 (not 500) for a malformed percent-encoded agent id, with origin_machine", async () => {
    const base = await serve(baseDeps(newLog(), []));
    // %ZZ is not valid percent-encoding; decodeURIComponent throws.
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/reach/%ZZ`);
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_agent_id");
    expect(body.origin_machine).toBe(FORTRESS);
  });

  it("error payloads carry origin_machine (/v1-compatible shape)", async () => {
    const base = await serve(baseDeps(null, []));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/home`);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.origin_machine).toBe(FORTRESS);
  });
});
