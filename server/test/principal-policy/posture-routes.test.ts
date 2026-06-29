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
import type { FleetRoster } from "../../src/principal-policy/fleet-roster.js";

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

  it("home digest reflects a just-appended entry with NO stale lag (eager-read never-stale-green, #714)", async () => {
    // The home route composes its reads through the AuditLog EAGER path (bounded
    // cost on a long chain). This guards the honesty side of that change: an
    // entry appended through the SAME log instance must be visible to the very
    // next home read, and the chain must stay honestly verified - no stale-green,
    // no lag waiting out a re-verify throttle.
    const log = newLog();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(Date.now() - 30_000).toISOString(),
    });
    const base = await serve(baseDeps(log, []));

    const first = await (await fetch(`${base}${POSTURE_API_PREFIX}/home`)).json();
    expect(first.digest.total_operations).toBe(1);
    expect(first.digest.chain_verified).toBe(true);
    expect(first.digest.integrity_finding_count).toBe(0);

    // Append a second entry through the same instance, then re-read the board.
    await log.appendCritical({
      layer: "l1",
      operation: "egress_blocked",
      identity_id: FORTRESS,
      result: "failure",
      details: { cw_source: "castle_wall_audit_consumer" },
      timestamp: new Date(Date.now() - 15_000).toISOString(),
    });
    const second = await (await fetch(`${base}${POSTURE_API_PREFIX}/home`)).json();
    // Immediately reflected - the eager view is maintained on append, not lazily
    // cached. No throttle wait, no stale count.
    expect(second.digest.total_operations).toBe(2);
    expect(second.digest.chain_verified).toBe(true);
    expect(second.digest.integrity_finding_count).toBe(0);
  });

  it("home reports chain_verified=false (never green) when the on-disk chain is tampered (#714 eager path)", async () => {
    // Out-of-band tamper detected at load is surfaced honestly through the eager
    // home read: chain_verified=false with a finding, never a clean green board.
    const storage = new MemoryStorage();
    const masterKey = generateRandomKey();
    const writer = new AuditLog(storage, masterKey);
    for (let i = 0; i < 5; i++) {
      await writer.appendCritical({
        layer: "l1",
        operation: "egress_allowed",
        identity_id: FORTRESS,
        result: "success",
        details: { cw_source: "castle_wall_audit_consumer" },
      });
    }
    await writer.flush();
    // Corrupt an on-disk entry's ciphertext directly (bypassing the server).
    const keys = (await storage.list("_audit"))
      .map((m) => m.key)
      .sort((a, b) => a.localeCompare(b));
    const victim = keys[2]!;
    const raw = await storage.read("_audit", victim);
    const env = JSON.parse(new TextDecoder().decode(raw!));
    env.encrypted_payload_bytes = String(env.encrypted_payload_bytes)
      .split("")
      .reverse()
      .join("");
    await storage.write(
      "_audit",
      victim,
      new TextEncoder().encode(JSON.stringify(env)),
    );

    // A fresh reader (the dashboard's log) loads + full-verifies on first read;
    // the eager home read must report the tampered chain as NOT verified.
    const reader = new AuditLog(storage, masterKey, { integrityMode: "lenient" });
    const base = await serve(baseDeps(reader, []));
    const home = await (await fetch(`${base}${POSTURE_API_PREFIX}/home`)).json();
    expect(home.digest.chain_verified).toBe(false);
    expect(home.digest.integrity_finding_count).toBeGreaterThan(0);
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

// ── Recognition + portability panel (P5): impartiality contract ──────────────
//
// These four tests encode the four hard impartiality constraints from the
// Recognition_Panel_Scope_2026-06-19 scope. Each one is a defect if it fails:
//   1. No score is ever fetched or rendered.
//   2. The panel does not render when composition is off (absent, not greyed).
//   3. Counterparty verification is labeled LOCAL bridge crypto, never
//      "by Concordia / Verascore".
//   4. Never-fake-green: rows are amber unless evidence is present; a tainted
//      read fails closed.
describe("posture recognition panel — impartiality contract", () => {
  // Seed bridge receipt + reputation_publish evidence on an audit log so the
  // shaper has real counts to render (no score is ever among them).
  async function seedBridgeEvidence(log: AuditLog): Promise<void> {
    await log.appendCritical({
      layer: "l3",
      operation: "bridge_commit",
      identity_id: FORTRESS,
      result: "success",
      details: { bridge_commitment_id: "bc-1", session_id: "s-1" },
    });
    // One verify TRUE and one verify FALSE — the panel must split them honestly.
    await log.append("l3", "bridge_verify", FORTRESS, {
      bridge_commitment_id: "bc-1",
      session_id: "s-1",
      valid: true,
    });
    await log.append("l3", "bridge_verify", FORTRESS, {
      bridge_commitment_id: "bc-2",
      session_id: "s-2",
      valid: false,
    });
    await log.appendCritical({
      layer: "l4",
      operation: "bridge_attest",
      identity_id: FORTRESS,
      result: "success",
      details: { bridge_commitment_id: "bc-1", session_id: "s-1" },
    });
  }

  // IMPARTIALITY TEST 1: no score is fetched or rendered. The payload carries
  // counterparty-receipt counts and local reputation EVIDENCE (counts), but
  // never a `score` field, and the reputation evidence is counts-only.
  it("impartiality-1-no-score: never fetches or renders any vendor reputation score", async () => {
    const log = newLog();
    await seedBridgeEvidence(log);
    const base = await serve({
      ...baseDeps(log, []),
      compositionEnabled: true,
      gatherRecognitionReputation: async () => ({
        attestation_count: 3,
        tier_distribution: {} as Record<string, number>,
        most_recent_attestation_at: new Date().toISOString(),
        dispute_count: 0,
        verascore_linked: true,
      }),
    });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/recognition`);
    expect(res.status).toBe(200);
    const body = await res.json();
    // No `score` anywhere on the payload — not at the top level and not on the
    // reputation evidence block. The only Verascore reference is a LOCAL boolean.
    const json = JSON.stringify(body);
    expect(json).not.toContain('"score"');
    expect(body.reputation_evidence).not.toHaveProperty("score");
    expect(body.reputation_evidence.verascore_linked).toBe(true);
    expect(typeof body.reputation_evidence.verascore_linked).toBe("boolean");
    // The evidence is counts only.
    expect(body.reputation_evidence.attestation_count).toBe(3);
  });

  // IMPARTIALITY TEST 2: the panel does not render when composition is off — the
  // endpoint 404s (absent), so the page omits the panel rather than greying it.
  it("impartiality-2-gated-off: returns 404 (panel absent) when composition is off", async () => {
    // Default-off (compositionEnabled absent).
    const baseOff = await serve(baseDeps(newLog(), []));
    const offRes = await fetch(`${baseOff}${POSTURE_API_PREFIX}/recognition`);
    expect(offRes.status).toBe(404);
    const offBody = await offRes.json();
    expect(offBody.error).toBe("recognition_unavailable");
    expect(offBody.origin_machine).toBe(FORTRESS);

    // Explicit false also 404s.
    const baseExplicit = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: false,
    });
    const explicitRes = await fetch(
      `${baseExplicit}${POSTURE_API_PREFIX}/recognition`,
    );
    expect(explicitRes.status).toBe(404);

    // ON renders the panel.
    const baseOn = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: true,
    });
    const onRes = await fetch(`${baseOn}${POSTURE_API_PREFIX}/recognition`);
    expect(onRes.status).toBe(200);
    expect((await onRes.json()).composition_enabled).toBe(true);
  });

  // IMPARTIALITY TEST 3: counterparty verification is LOCAL bridge crypto. The
  // payload's verification basis is the frozen local-crypto constant, and the
  // payload never labels verification "by Concordia" or "by Verascore".
  it("impartiality-3-local-verification: counterparty verification is local bridge crypto, never 'by Concordia/Verascore'", async () => {
    const log = newLog();
    await seedBridgeEvidence(log);
    const base = await serve({
      ...baseDeps(log, []),
      compositionEnabled: true,
    });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/recognition`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.receipts.verification_basis).toBe("local_bridge_crypto");
    // Honest verify split from the seeded evidence.
    expect(body.receipts.verified_true).toBe(1);
    expect(body.receipts.verified_false).toBe(1);
    expect(body.receipts.attested).toBe(1);
    // The payload must never claim verification was performed BY Concordia or
    // BY Verascore (it is local bridge crypto).
    const json = JSON.stringify(body).toLowerCase();
    expect(json).not.toContain("by concordia");
    expect(json).not.toContain("by verascore");
    expect(json).not.toContain("verified by concordia");
    expect(json).not.toContain("verified by verascore");
  });

  // IMPARTIALITY TEST 4: never fake green. The reputation row is amber unless
  // real attestation evidence is present; a locked audit log 503s (never an
  // empty-but-green payload).
  it("impartiality-4-never-fake-green: reputation amber from absence; locked audit fails closed", async () => {
    // (a) No reputation evidence wired → amber, never green.
    const baseNoEvidence = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: true,
    });
    const noEvRes = await fetch(
      `${baseNoEvidence}${POSTURE_API_PREFIX}/recognition`,
    );
    expect(noEvRes.status).toBe(200);
    const noEvBody = await noEvRes.json();
    expect(noEvBody.reputation_evidence).toBeNull();
    expect(noEvBody.reputation_state).toBe("amber");

    // (b) Zero-attestation evidence is still amber (not green from a wired-but-
    // empty store).
    const baseEmpty = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: true,
      gatherRecognitionReputation: async () => ({
        attestation_count: 0,
        tier_distribution: {} as Record<string, number>,
        most_recent_attestation_at: null,
        dispute_count: 0,
        verascore_linked: false,
      }),
    });
    const emptyRes = await fetch(`${baseEmpty}${POSTURE_API_PREFIX}/recognition`);
    expect((await emptyRes.json()).reputation_state).toBe("amber");

    // (c) Locked audit log → 503 fail-closed (the panel is evidence-bearing).
    const baseLocked = await serve({
      ...baseDeps(null, []),
      compositionEnabled: true,
    });
    const lockedRes = await fetch(
      `${baseLocked}${POSTURE_API_PREFIX}/recognition`,
    );
    expect(lockedRes.status).toBe(503);
    expect((await lockedRes.json()).error).toBe("posture_unavailable");

    // (d) Present evidence (>=1 attestation) earns green.
    const basePresent = await serve({
      ...baseDeps(newLog(), []),
      compositionEnabled: true,
      gatherRecognitionReputation: async () => ({
        attestation_count: 2,
        tier_distribution: {} as Record<string, number>,
        most_recent_attestation_at: new Date().toISOString(),
        dispute_count: 0,
        verascore_linked: false,
      }),
    });
    const presentRes = await fetch(
      `${basePresent}${POSTURE_API_PREFIX}/recognition`,
    );
    expect((await presentRes.json()).reputation_state).toBe("present");
  });
});

describe("GET /api/posture/fleet — Fleet Console Slice 1 route", () => {
  function fleetRosterFixture(): FleetRoster {
    return {
      available: true,
      enabled: true,
      fortress_id: FORTRESS,
      node_id: "home-mac",
      eviction_serial: 0,
      nodes: [
        {
          node_id: "node-1",
          label: null,
          trust_state: "admitted",
          trust_evaluable: true,
          reach: "recent",
          node_mode: "local",
          provider_in_trust_boundary: false,
          last_sync_received_at: "2026-06-24T11:59:00.000Z",
          policy: {
            version: 7,
            hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            hash_algorithm: "sha256-base64url",
            applied_at: "2026-06-24T11:59:00.000Z",
            source_event_id: "operator:fortress:test:7",
            drift_state: "in_sync",
          },
          first_seen: "2026-06-24T11:00:00.000Z",
          last_seen: "2026-06-24T11:59:00.000Z",
        },
      ],
      summary: { total: 1, admitted: 1, revoked: 0, untrusted: 0 },
      sync_health: {
        reachable: 1,
        stale: 0,
        never: 0,
        oldest_last_sync: "2026-06-24T11:59:00.000Z",
        freshness_window_ms: 300_000,
      },
      policy_distribution: {
        available: true,
        operator_policy: {
          version: 7,
          hash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          hash_algorithm: "sha256-base64url",
          applied_at: "2026-06-24T11:58:00.000Z",
          source_event_id: "operator:fortress:test:7",
        },
        summary: { in_sync: 1, drifted: 0, unknown: 0 },
      },
    };
  }

  it("404s within the namespace when federation is not wired (no fleetRoster dep)", async () => {
    // No `fleetRoster` supplied: the panel is ABSENT (additive), not broken.
    const base = await serve(baseDeps(newLog(), []));
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/fleet`);
    expect(res.status).toBe(404);
    const body = (await res.json()) as { error: string; origin_machine: string };
    expect(body.error).toBe("fleet_unavailable");
    expect(body.origin_machine).toBe(FORTRESS);
  });

  it("serves the supplied roster verbatim (thin presenter, no re-derivation)", async () => {
    const base = await serve({
      ...baseDeps(newLog(), []),
      fleetRoster: () => fleetRosterFixture(),
    });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/fleet`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as FleetRoster;
    expect(body.available).toBe(true);
    expect(body.nodes.map((n) => [n.node_id, n.trust_state])).toEqual([
      ["node-1", "admitted"],
    ]);
    expect(body.summary).toEqual({ total: 1, admitted: 1, revoked: 0, untrusted: 0 });
    expect(body.policy_distribution.summary).toEqual({
      in_sync: 1,
      drifted: 0,
      unknown: 0,
    });
  });

  it("503s when the audit log is locked (same fail-closed gate as the other panels)", async () => {
    // The route is wrapped in runEagerReads on the audit log; a null log 503s
    // before the roster builds, never an empty-green payload.
    const base = await serve({
      ...baseDeps(null, []),
      fleetRoster: () => fleetRosterFixture(),
    });
    const res = await fetch(`${base}${POSTURE_API_PREFIX}/fleet`);
    expect(res.status).toBe(503);
    expect((await res.json()).error).toBe("posture_unavailable");
  });
});
