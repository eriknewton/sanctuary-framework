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
  POSTURE_AGENT_PATH_PREFIX,
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
  it("no longer owns the /posture home HTML (served pre-auth by the dashboard)", async () => {
    // Delta Review A3 remediation: the `/posture` home shell is now served by
    // the dashboard BEFORE its auth gate (byte-for-byte the same shell as `/`),
    // so `/` and `/posture` are one surface under one auth contract. The route
    // layer therefore no longer serves the `/posture` HTML — it falls through
    // (this harness 404s an unhandled path). The shell content itself is pinned
    // by `posture-home-html.test.ts` + the dashboard/v1.1 routing tests.
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_HOME_PATH}`);
    expect(res.status).toBe(404);
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

    // The home payload carries the same panel, so the Home surface can render
    // the feature-health rows without a second fetch (Slice 2).
    const homeRes = await fetch(`${base}${POSTURE_API_PREFIX}/home`);
    const home = await homeRes.json();
    expect(home.feature_health.rows.length).toBe(panel.rows.length);
    // Each row carries a status the surface maps to a chip; a quiet event-driven
    // feature is honestly non-green ("unconfirmed"), never reported as active.
    const homeBroker = home.feature_health.rows.find(
      (r: { feature_id: string }) => r.feature_id === "secret_broker",
    );
    expect(homeBroker.status).toBe("unconfirmed");
    expect(homeBroker.status).not.toBe("active");
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

  it("reach reports enforcement_confirmed=false when enforcement is not confirmed (#641)", async () => {
    // The default per-agent read has no live enforcement signal, so the reach
    // payload must say enforcement is NOT confirmed - the renderer keys all
    // OS-enforcement coloring + the default-deny claim on this flag.
    const base = await serve(baseDeps(newLog(), [wrappedAgent("a1", "claude_code")]));
    const reach = await (await fetch(`${base}${POSTURE_API_PREFIX}/reach/a1`)).json();
    expect(reach.enforcement_confirmed).toBe(false);
    // A configured wall rule is present (the test override supplies one), but
    // enforcement is still not confirmed: configured != enforced.
    expect(reach.has_wall_policy).toBe(true);
  });

  it("with no enabled curated manifest, reach reports the honest no-wall gap, not a fabricated default-deny (#641)", async () => {
    // Build deps WITHOUT a listReachRules override and WITHOUT enabled curated
    // rule ids - the production default-off shape. The curated catalog must NOT
    // be mapped wholesale into a fabricated kernel-enforced default-deny.
    const deps: PostureRouteDeps = {
      auditLog: newLog(),
      originMachine: FORTRESS,
      listAgents: () => [wrappedAgent("a1", "claude_code")],
      detectInstalledHarnesses: async () => [],
      platform: "darwin",
    };
    const base = await serve(deps);
    const reach = await (await fetch(`${base}${POSTURE_API_PREFIX}/reach/a1`)).json();
    // No enabled ruleset readable => honest red gap, never a default-deny claim.
    expect(reach.has_wall_policy).toBe(false);
    expect(reach.default_deny).toBe(false);
    expect(reach.destinations).toHaveLength(0);
    expect(reach.enforcement_confirmed).toBe(false);
  });

  it("reach sources rules from the operator's ENABLED curated ids, not the whole catalog (#641)", async () => {
    // When the operator has enabled exactly one curated rule, reach reflects
    // that one rule - never the full curated set. Rules on disk are still only
    // CONFIGURATION (enforcement_confirmed stays false).
    const deps: PostureRouteDeps = {
      auditLog: newLog(),
      originMachine: FORTRESS,
      listAgents: () => [wrappedAgent("a1", "claude_code")],
      detectInstalledHarnesses: async () => [],
      listEnabledCuratedRuleIds: () => ["curated-anthropic-api"],
      platform: "darwin",
    };
    const base = await serve(deps);
    const reach = await (await fetch(`${base}${POSTURE_API_PREFIX}/reach/a1`)).json();
    expect(reach.has_wall_policy).toBe(true);
    const dests = reach.destinations.map((d: { destination: string }) => d.destination);
    expect(dests).toContain("api.anthropic.com");
    // The non-enabled curated entries (e.g. OpenAI) must NOT appear.
    expect(dests).not.toContain("api.openai.com");
    // Still configuration, not confirmed enforcement.
    expect(reach.enforcement_confirmed).toBe(false);
  });

  it("serves the per-agent drill-down HTML at /posture/agent/:id (Slice 4)", async () => {
    const base = await serve(baseDeps(newLog(), [wrappedAgent("a1", "claude_code")]));
    const res = await fetch(`${base}${POSTURE_AGENT_PATH_PREFIX}a1`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
    const body = await res.text();
    // The shell renders the Standing + reach sections and reuses the existing
    // reach endpoint client-side (no duplicated shaper on the surface).
    expect(body).toContain("Standing");
    expect(body).toContain("Effective reach");
    expect(body).toContain("/api/posture/reach/");
    expect(body).toContain("/api/posture/home");
    // Never-fake-green discipline visible in the renderer: green is keyed on
    // confirmed enforcement, not policy intent.
    expect(body).toContain('enforcement_active === "active"');
  });

  it("serves the agent drill-down shell even when the audit log is locked (it is a static page)", async () => {
    // The shell is served before the audit-null guard, mirroring /posture, so a
    // locked vault still renders the page; its data fetches fail honestly.
    const base = await serve(baseDeps(null, []));
    const res = await fetch(`${base}${POSTURE_AGENT_PATH_PREFIX}whoever`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
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

  it("GET /api/posture/composition reports the gate flag ON when composition is enabled", async () => {
    const base = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: true,
    });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/composition`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.composition_enabled).toBe(true);
    expect(body.origin_machine).toBe(FORTRESS);
    // ONLY the gate flag + origin_machine - no Concordia/Verascore data.
    expect(Object.keys(body).sort()).toEqual(
      ["composition_enabled", "origin_machine"].sort(),
    );
  });

  it("GET /api/posture/composition reports OFF (honest default) when the flag is absent/false", async () => {
    // Absent compositionEnabled is treated as the honest default-off; the flag is
    // config, never evidence, so `false` is the truthful answer, not amber.
    const baseOff = await serve(baseDeps(newLog(), []));
    const offRes = await fetch(`${baseOff}${POSTURE_API_PREFIX}/composition`);
    expect(offRes.status).toBe(200);
    expect((await offRes.json()).composition_enabled).toBe(false);

    const baseExplicit = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: false,
    });
    const explicitRes = await fetch(
      `${baseExplicit}${POSTURE_API_PREFIX}/composition`,
    );
    expect((await explicitRes.json()).composition_enabled).toBe(false);
  });

  it("GET /api/posture/composition is config, not evidence: served even when the audit log is locked", async () => {
    // The gate flag carries no audit-derived evidence, so a locked vault must NOT
    // 503 it (unlike the evidence-bearing posture routes).
    const base = await serve({ ...baseDeps(null, []), compositionEnabled: true });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/composition`);
    expect(res.status).toBe(200);
    expect((await res.json()).composition_enabled).toBe(true);
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

  // ── Phase 2: query-privacy (Opacity) ───────────────────────────────

  it("includes an honest query-privacy section in the home payload (Tier A unconfirmed when quiet, Tier B never green)", async () => {
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/home`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.query_privacy).toBeDefined();
    // Overclaim guard: header stripping is metadata hygiene, NEVER anonymity.
    expect(body.query_privacy.header_strip_is_anonymity).toBe(false);
    // No header-strip evidence on a fresh log -> Tier A unconfirmed (not green).
    const tierA = body.query_privacy.rows.find((r: { tier: string }) => r.tier === "A");
    expect(tierA.status).toBe("unconfirmed");
    // Tier B PII rewrite is never green from config (emitter unwired).
    const tierB = body.query_privacy.rows.find((r: { tier: string }) => r.tier === "B");
    expect(tierB.status).not.toBe("active");
  });

  it("mounts the previously-orphaned /api/query-anonymity/stats behind the posture router", async () => {
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}/api/query-anonymity/stats`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.window).toBe("24h");
    expect(body.total_outbound_calls).toBe(0);
    expect(body.total_headers_stripped).toBe(0);
  });

  it("fails closed with 503 on the stats endpoint when the audit log is locked (never empty-green)", async () => {
    const base = await serve(baseDeps(null, []));
    const res = await fetch(`${base}/api/query-anonymity/stats`);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toBe("query_privacy_unavailable");
    expect(body.origin_machine).toBe(FORTRESS);
  });
});
