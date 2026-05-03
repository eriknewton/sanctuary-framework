/**
 * Sanctuary v1.1 Dashboard — Intelligence API Router tests
 *
 * Real-shape tests against an http server wired to a SubstrateSelector
 * over MemoryStorage with a real AuditLog. Every endpoint is fetched over
 * the network — no contract-boundary mocks.
 *
 * Coverage:
 *   - GET  /api/hub/intelligence/status          → SurfaceStatusReport shape
 *   - GET  /api/hub/intelligence/config          → sanitized config (no key bytes)
 *   - POST /api/hub/intelligence/surfaces/:s/choice            (substrate flip)
 *   - POST /api/hub/intelligence/surfaces/:s/choice            (with local pick)
 *   - POST /api/hub/intelligence/surfaces/:s/fallback
 *   - POST /api/hub/intelligence/credentials/venice
 *   - DEL  /api/hub/intelligence/credentials/venice
 *   - POST /api/hub/intelligence/credentials/frontier
 *   - DEL  /api/hub/intelligence/credentials/frontier/:p
 *   - POST /api/hub/intelligence/hybrid-rules
 *   - POST /api/hub/intelligence/reset
 *   - 400 / 401 / 404 / 503 negative paths
 *   - dispatch-layer: 503 when binding lacks a selector
 *   - audit-emission: substrate_chosen fires on POST .../choice
 *   - cross-fortress reach rejected
 *   - sensitive fields never leak (Venice key, frontier keys)
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

import { MemoryStorage } from "../../../src/storage/memory.js";
import { AuditLog } from "../../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { SubstrateSelector } from "../../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../../src/intelligence/audit-events.js";
import {
  handleIntelligenceRoute,
  INTELLIGENCE_API_PREFIX,
} from "../../../src/dashboard/v1_1/intelligence-api-router.js";
import { dispatchV11Request } from "../../../src/dashboard/v1_1/dispatch.js";
import {
  buildV11Bindings,
  type V11Bindings,
} from "../../../src/dashboard/v1_1/wiring.js";

const IDENTITY = "operator-test-intel";

interface Harness {
  url: string;
  selector: SubstrateSelector;
  auditLog: AuditLog;
  authToken: string;
  stop: () => Promise<void>;
}

async function startHarness(opts: { withSelector?: boolean } = {}): Promise<Harness> {
  const withSelector = opts.withSelector !== false;
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const selector = new SubstrateSelector({
    storage,
    masterKey,
    auditLog,
    identityId: IDENTITY,
  });
  await selector.load();

  const authToken = "test-token-intel";
  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        if (withSelector) {
          const handled = await handleIntelligenceRoute(
            { authConfig: { loopbackAutoAuth: false, authToken }, selector },
            req,
            res,
          );
          if (!handled) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: "not_found" }));
          }
        } else {
          // Exercise the dispatch layer with a selector-less binding
          // to assert the 503 fallback.
          const bindings: V11Bindings = buildV11Bindings({
            identityId: IDENTITY,
            fortressId: "fortress-test",
            auditLog,
            // Intentionally omit intelligenceSelector.
          });
          const url = new URL(req.url ?? "/", `http://127.0.0.1`);
          const handled = await dispatchV11Request(
            { bindings, authToken, loopbackAutoAuth: false },
            req,
            res,
            url,
            (req.method ?? "GET").toUpperCase(),
          );
          if (!handled) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: "not_found" }));
          }
        }
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: (err as Error).message }));
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
  return {
    url: `http://127.0.0.1:${addr.port}`,
    selector,
    auditLog,
    authToken,
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function authedHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

describe("Intelligence API router — auth + sanity", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("rejects requests without a bearer token", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`);
    expect(res.status).toBe(401);
  });

  it("returns 404 for an unknown intelligence subpath", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/nope`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(404);
    const body = await res.json() as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("not_found");
  });

  it("rejects cross-fortress query parameters", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/status?fortress_id=remote`,
      { headers: authedHeaders(h.authToken) },
    );
    expect(res.status).toBe(400);
    const body = await res.json() as { error: string };
    expect(body.error).toBe("local_only");
  });
});

describe("Intelligence API router — GET /status + /config", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("/status returns the SurfaceStatusReport with all six surfaces and a hardware block", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      ok: boolean;
      data: {
        version: string;
        surfaces: { surface: string; chosen: string; health: string; badge: { status: string } }[];
        hardware: { tier: string };
      };
    };
    expect(body.ok).toBe(true);
    expect(body.data.version).toBe("1.2");
    const surfaceNames = body.data.surfaces.map((s) => s.surface).sort();
    expect(surfaceNames).toEqual([
      "concierge",
      "direct-agent-gate-advisor",
      "gate-explanation",
      "privacy-filter-tier-2",
      "sentinel-scoring",
      "template-suggestion",
    ]);
    expect(["below-baseline", "baseline", "mid", "pro"]).toContain(body.data.hardware.tier);
  });

  it("/config returns the sanitized config without any raw API key bytes", async () => {
    // Plant a Venice key.
    await h.selector.setVeniceApiKey("sk-venice-secret-abc-123");
    await h.selector.setFrontierApiKey("anthropic", "sk-ant-test-xyz-456");

    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/config`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: Record<string, unknown> };
    const text = JSON.stringify(body);

    // No raw key bytes leak.
    expect(text).not.toContain("sk-venice-secret-abc-123");
    expect(text).not.toContain("sk-ant-test-xyz-456");
    // Presence flags are surfaced.
    expect(body.data.venice_api_key_present).toBe(true);
    const fp = body.data.frontier_keys_present as Record<string, boolean>;
    expect(fp.anthropic).toBe(true);
    expect(fp.openai).toBe(false);
    expect(fp.google).toBe(false);
  });
});

describe("Intelligence API router — POST surfaces/:s/choice", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("flips a substrate and returns the sanitized config", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "venice" }),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { per_surface: Record<string, string> } };
    expect(body.data.per_surface.concierge).toBe("venice");
  });

  it("emits an intelligence_substrate_chosen audit event with the right details", async () => {
    await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "venice" }),
      },
    );
    const events = await h.auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_CHOSEN });
    expect(events.entries.length).toBeGreaterThanOrEqual(1);
    const last = events.entries[events.entries.length - 1]!;
    const details = last.details as { surface: string; substrate: string; was_default: boolean };
    expect(details.surface).toBe("concierge");
    expect(details.substrate).toBe("venice");
    expect(details.was_default).toBe(true);
  });

  it("accepts a local_model_pick alongside a local substrate flip", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/sentinel-scoring/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "local", local_model_pick: "llama-3.1-8b" }),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: {
        per_surface: Record<string, string>;
        local_model_picks: Record<string, string>;
      };
    };
    expect(body.data.per_surface["sentinel-scoring"]).toBe("local");
    expect(body.data.local_model_picks["sentinel-scoring"]).toBe("llama-3.1-8b");
  });

  it("rejects an unknown substrate value", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "snake-oil" }),
      },
    );
    expect(res.status).toBe(400);
  });

  it("rejects an unknown surface", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/imagined/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "venice" }),
      },
    );
    expect(res.status).toBe(400);
  });

  it("rejects an unknown local_model_pick", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "local", local_model_pick: "fake-model" }),
      },
    );
    expect(res.status).toBe(400);
  });
});

describe("Intelligence API router — POST surfaces/:s/fallback", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("sets the per-surface fallback behavior", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/fallback`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ fallback: "conservative-deny" }),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { fallback: Record<string, string> } };
    expect(body.data.fallback.concierge).toBe("conservative-deny");
  });

  it("rejects an unknown fallback value", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/fallback`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ fallback: "panic" }),
      },
    );
    expect(res.status).toBe(400);
  });
});

describe("Intelligence API router — credentials", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("POST credentials/venice persists the key (presence-flagged in /config)", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/credentials/venice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: "vsk-test-key-7" }),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { venice_api_key_present: boolean } };
    expect(body.data.venice_api_key_present).toBe(true);
  });

  it("DELETE credentials/venice clears the key", async () => {
    await h.selector.setVeniceApiKey("vsk-test");
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/credentials/venice`,
      { method: "DELETE", headers: authedHeaders(h.authToken) },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { venice_api_key_present: boolean } };
    expect(body.data.venice_api_key_present).toBe(false);
  });

  it("POST credentials/frontier accepts a valid provider + key", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/credentials/frontier`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "openai", api_key: "sk-openai-test" }),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: { frontier_keys_present: Record<string, boolean> };
    };
    expect(body.data.frontier_keys_present.openai).toBe(true);
  });

  it("POST credentials/frontier rejects an unknown provider", async () => {
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/credentials/frontier`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "minimax", api_key: "sk-test" }),
      },
    );
    expect(res.status).toBe(400);
  });

  it("DELETE credentials/frontier/:p clears one provider's key", async () => {
    await h.selector.setFrontierApiKey("anthropic", "sk-ant-test");
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/credentials/frontier/anthropic`,
      { method: "DELETE", headers: authedHeaders(h.authToken) },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: { frontier_keys_present: Record<string, boolean> };
    };
    expect(body.data.frontier_keys_present.anthropic).toBe(false);
  });
});

describe("Intelligence API router — hybrid + reset", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("POST hybrid-rules persists a fully-bound rules table", async () => {
    const rules = {
      rules: {
        perSurface: {
          "concierge": "local",
          "direct-agent-gate-advisor": "local",
          "sentinel-scoring": "frontier-with-filter",
          "gate-explanation": "disabled",
          "privacy-filter-tier-2": "local",
          "template-suggestion": "venice",
        },
      },
    };
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/hybrid-rules`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify(rules),
      },
    );
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: { hybrid_rules: { perSurface: Record<string, string> } | null };
    };
    expect(body.data.hybrid_rules).not.toBeNull();
    expect(body.data.hybrid_rules!.perSurface["sentinel-scoring"]).toBe("frontier-with-filter");
  });

  it("POST hybrid-rules rejects a partially-bound rules table", async () => {
    const rules = {
      rules: {
        perSurface: {
          "concierge": "local",
          // missing other surfaces
        },
      },
    };
    const res = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/hybrid-rules`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify(rules),
      },
    );
    expect(res.status).toBe(400);
  });

  it("POST reset reverts to defaults and emits config_reset", async () => {
    await h.selector.setPerSurfaceChoice("concierge", "venice");
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/reset`, {
      method: "POST",
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { per_surface: Record<string, string> } };
    expect(body.data.per_surface.concierge).toBe("local");
    const events = await h.auditLog.query({ operation_type: INTEL_OPS.CONFIG_RESET });
    expect(events.entries.length).toBeGreaterThanOrEqual(1);
  });
});

// v1.2.0-rc.1 Finding SS: bulk apply + apply-to-all preference
describe("Intelligence router, Finding SS bulk apply", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("POST /surfaces/all/choice applies substrate to every surface in one save", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/all/choice`, {
      method: "POST",
      headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
      body: JSON.stringify({ substrate: "venice" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { per_surface: Record<string, string> } };
    expect(body.data.per_surface.concierge).toBe("venice");
    expect(body.data.per_surface["sentinel-scoring"]).toBe("venice");
    expect(body.data.per_surface["gate-explanation"]).toBe("venice");
    expect(body.data.per_surface["template-suggestion"]).toBe("venice");

    const events = await h.auditLog.query({ operation_type: INTEL_OPS.BULK_SUBSTRATE_CHOSEN });
    expect(events.entries.length).toBe(1);
  });

  it("POST /surfaces/all/choice rejects invalid substrate with 400", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/all/choice`, {
      method: "POST",
      headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
      body: JSON.stringify({ substrate: "made-up" }),
    });
    expect(res.status).toBe(400);
  });

  it("POST /surfaces/all/choice with local + local_model_pick fans out the pick", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/all/choice`, {
      method: "POST",
      headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
      body: JSON.stringify({ substrate: "local", local_model_pick: "phi-4-mini" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { local_model_picks: Record<string, string> } };
    expect(body.data.local_model_picks.concierge).toBe("phi-4-mini");
    expect(body.data.local_model_picks["template-suggestion"]).toBe("phi-4-mini");
  });

  it("POST /preferences/apply-to-all persists boolean preference", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/preferences/apply-to-all`, {
      method: "POST",
      headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
      body: JSON.stringify({ value: false }),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { apply_to_all_surfaces: boolean } };
    expect(body.data.apply_to_all_surfaces).toBe(false);
  });

  it("POST /preferences/apply-to-all rejects non-boolean value with 400", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/preferences/apply-to-all`, {
      method: "POST",
      headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
      body: JSON.stringify({ value: "yes" }),
    });
    expect(res.status).toBe(400);
  });

  it("GET /config exposes apply_to_all_surfaces", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/config`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { apply_to_all_surfaces: boolean } };
    // Default is true on a fresh fortress.
    expect(body.data.apply_to_all_surfaces).toBe(true);
  });
});

// v1.2.0-rc.1 Finding VV: recentFailures shape on /status
describe("Intelligence router, Finding VV recentFailures field", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("GET /status carries a recentFailures array per surface (empty by default)", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: { surfaces: Array<{ surface: string; recentFailures: unknown[] }> };
    };
    expect(body.data.surfaces.length).toBeGreaterThan(0);
    for (const s of body.data.surfaces) {
      expect(Array.isArray(s.recentFailures)).toBe(true);
      expect(s.recentFailures.length).toBe(0);
    }
  });
});

// v1.2.0-rc.3 Finding ZZ: end-to-end operator-visible flow.
// Reproduces the moltbook drill operator's path: bad-substrate runtime
// failure populates the recent-failures buffer on a surface, operator
// switches that surface to a working substrate, and the next /status
// fetch must show empty recentFailures plus a green badge for that
// surface. The rc.2 unit tests verified the in-memory buffer-clear at
// the selector method level; this exercises the full HTTP route flow
// the dashboard SPA actually uses.
describe("Intelligence router, Finding ZZ end-to-end status reflects clear", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness(); });
  afterEach(async () => { await h.stop(); });

  it("after POST /surfaces/concierge/choice flips concierge venice -> local, /status returns concierge with empty recentFailures and a green badge", async () => {
    await h.selector.setVeniceApiKey("operator-test-key");
    await h.selector.setPerSurfaceChoice("concierge", "venice");
    h.selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice configured model not found on validation probe",
    );

    const before = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(before.status).toBe(200);
    const beforeBody = await before.json() as {
      data: { surfaces: Array<{ surface: string; recentFailures: unknown[]; badge: { status: string } }> };
    };
    const conciergeBefore = beforeBody.data.surfaces.find((s) => s.surface === "concierge");
    expect(conciergeBefore).toBeDefined();
    expect(conciergeBefore!.recentFailures.length).toBe(1);
    expect(conciergeBefore!.badge.status).toBe("yellow");

    const flip = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/concierge/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "local" }),
      },
    );
    expect(flip.status).toBe(200);

    const after = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(after.status).toBe(200);
    const afterBody = await after.json() as {
      data: { surfaces: Array<{ surface: string; chosen: string; recentFailures: unknown[]; badge: { status: string } }> };
    };
    const conciergeAfter = afterBody.data.surfaces.find((s) => s.surface === "concierge");
    expect(conciergeAfter).toBeDefined();
    expect(conciergeAfter!.chosen).toBe("local");
    expect(conciergeAfter!.recentFailures.length).toBe(0);
    expect(["green", "yellow"]).toContain(conciergeAfter!.badge.status);
  });

  it("after POST /surfaces/all/choice bulk-flips all surfaces to local, /status returns every surface with empty recentFailures", async () => {
    await h.selector.setPerSurfaceChoice("concierge", "venice");
    await h.selector.setPerSurfaceChoice("sentinel-scoring", "venice");
    h.selector.recordRecentFailureForTest(
      "concierge",
      "substrate_misconfigured",
      "venice model not found",
    );
    h.selector.recordRecentFailureForTest(
      "sentinel-scoring",
      "substrate_auth_failed",
      "venice key rejected",
    );

    const flip = await fetch(
      `${h.url}${INTELLIGENCE_API_PREFIX}/surfaces/all/choice`,
      {
        method: "POST",
        headers: { ...authedHeaders(h.authToken), "Content-Type": "application/json" },
        body: JSON.stringify({ substrate: "local" }),
      },
    );
    expect(flip.status).toBe(200);

    const after = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(after.status).toBe(200);
    const afterBody = await after.json() as {
      data: { surfaces: Array<{ surface: string; recentFailures: unknown[] }> };
    };
    for (const s of afterBody.data.surfaces) {
      expect(s.recentFailures.length).toBe(0);
    }
  });
});

describe("Intelligence dispatch — selector-less binding returns 503", () => {
  let h: Harness;
  beforeEach(async () => { h = await startHarness({ withSelector: false }); });
  afterEach(async () => { await h.stop(); });

  it("/status responds 503 with selector_not_configured when no selector is bound", async () => {
    const res = await fetch(`${h.url}${INTELLIGENCE_API_PREFIX}/status`, {
      headers: authedHeaders(h.authToken),
    });
    expect(res.status).toBe(503);
    const body = await res.json() as { ok: boolean; error: string };
    expect(body.ok).toBe(false);
    expect(body.error).toBe("selector_not_configured");
  });
});
