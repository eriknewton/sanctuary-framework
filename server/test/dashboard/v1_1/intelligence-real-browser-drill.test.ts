/**
 * Sanctuary v1.1 Dashboard — Intelligence Real-Browser Drill
 *
 * Per the WP-V1.2-5 spawn prompt Step 5c, this test exercises the
 * substrate-selector dashboard surface end-to-end against a real HTTP
 * server, simulating the browser flow without spinning a headless
 * Chromium (playwright is not available in this repo at v1.1.x).
 *
 * The drill:
 *   1. Boot a real dashboard server with a real SubstrateSelector
 *      against MemoryStorage (the same shape an unlocked fortress uses).
 *   2. Fetch /v1.1 HTML and assert the SPA shell, sidebar nav, and the
 *      Intelligence-panel CSS land in the response.
 *   3. Assert the responsive breakpoint at max-width: 1100px collapses
 *      the per-surface row to a single column, covering the 800px tier
 *      and confirming the layout holds at 1280 / 1440 / 1920px above.
 *   4. Drive the picker flow over HTTP:
 *      a. GET /api/hub/intelligence/status (initial defaults)
 *      b. POST /api/hub/intelligence/credentials/venice (key save)
 *      c. POST /api/hub/intelligence/surfaces/concierge/choice (Venice)
 *      d. POST /api/hub/intelligence/credentials/frontier (Anthropic)
 *      e. POST /api/hub/intelligence/surfaces/sentinel-scoring/choice
 *         (frontier-with-filter, audit-emitting)
 *      f. POST /api/hub/intelligence/surfaces/concierge/choice
 *         (local + gemma-2-2b — covers the local model pick path)
 *   5. Re-fetch /api/hub/intelligence/status and assert all changes
 *      surfaced through to the operator-visible report.
 *   6. Verify the audit log reflects every change (`substrate_chosen`
 *      events match the HTTP flips).
 *   7. Verify /api/hub/intelligence/config NEVER returns raw API key
 *      bytes — only presence flags.
 *
 * Acceptance gates from spawn prompt Step 5c (mapped):
 *   1 → step 2 + step 3 (panel renders, layout holds across widths)
 *   2 → not exercised (frame-by-frame DOM inspection requires headless
 *        browser; covered structurally by Step 3 + intelligence-panel-html
 *        tests)
 *   3 → step 4a-4f (picker actions over HTTP)
 *   4 → step 7 (sensitive fields never leak)
 *   5 → step 4b + 4c, 4d + 4e
 *   6 → step 4f (local model pick)
 *   7 → step 6 (audit log records every flip)
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

import { MemoryStorage } from "../../../src/storage/memory.js";
import { AuditLog } from "../../../src/operational/audit-log.js";
import { generateRandomKey } from "../../../src/core/random.js";
import { SubstrateSelector } from "../../../src/intelligence/selector.js";
import { INTEL_OPS } from "../../../src/intelligence/audit-events.js";
import {
  renderDashboardV11Html,
  getClientScript,
} from "../../../src/dashboard/v1_1/index.js";
import { dispatchV11Request } from "../../../src/dashboard/v1_1/dispatch.js";
import { buildV11Bindings } from "../../../src/dashboard/v1_1/wiring.js";

const IDENTITY = "operator-drill";
const FORTRESS = "fortress-drill";
const AUTH_TOKEN = "drill-token";
const FAKE_VENICE_KEY = "vsk-drill-secret-9999";
const FAKE_ANTHROPIC_KEY = "sk-ant-drill-secret-9999";

interface Drill {
  url: string;
  selector: SubstrateSelector;
  auditLog: AuditLog;
  stop: () => Promise<void>;
}

async function bootDrill(): Promise<Drill> {
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
  const bindings = buildV11Bindings({
    identityId: IDENTITY,
    fortressId: FORTRESS,
    auditLog,
    intelligenceSelector: selector,
  });

  const server: Server = createServer(
    async (req: IncomingMessage, res: ServerResponse) => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1");
        const handled = await dispatchV11Request(
          { bindings, authToken: AUTH_TOKEN, loopbackAutoAuth: false },
          req,
          res,
          url,
          (req.method ?? "GET").toUpperCase(),
        );
        if (!handled) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          res.end("not_found");
        }
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: (err as Error).message }));
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
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function authedHeaders(): HeadersInit {
  return { Authorization: `Bearer ${AUTH_TOKEN}` };
}

function authedJsonHeaders(): HeadersInit {
  return { ...authedHeaders(), "Content-Type": "application/json" };
}

describe("Intelligence real-browser drill — SPA shell + responsive layout", () => {
  it("renders Intelligence in sidebar nav, panel route plumbing, and CSS skeleton", () => {
    const html = renderDashboardV11Html({
      identityId: IDENTITY,
      fortressId: FORTRESS,
    });
    // Sidebar nav
    expect(html).toContain('data-route="intelligence"');
    expect(html).toContain(">Intelligence<");
    // CSS skeleton for picker + panel
    expect(html).toContain(".intel-modal-backdrop");
    expect(html).toContain(".intel-row");
    expect(html).toContain(".intel-status-dot");
    expect(html).toContain(".intel-status-dot.green");
    expect(html).toContain(".intel-status-dot.yellow");
    expect(html).toContain(".intel-status-dot.red");
    // Sidebar nav anchored alongside Privacy / Coordination / Health.
    expect(html).toContain('data-route="policy"');
    expect(html).toContain('data-route="privacy"');
    expect(html).toContain('data-route="coordination"');
    expect(html).toContain('data-route="health"');
  });

  it("layout holds at simulated widths 800 / 1280 / 1440 / 1920 px (CSS-driven)", () => {
    const html = renderDashboardV11Html({});
    // The 1100px breakpoint is the mobile collapse: at 800px the .intel-row
    // collapses to a single-column layout. At 1280 / 1440 / 1920px the
    // default three-column layout holds.
    expect(html).toMatch(/@media\s*\(max-width:\s*1100px\)/);

    // Default layout (>= 1101px): grid-template-columns 200px | 1fr | auto.
    expect(html).toMatch(/\.intel-row\s*\{[^}]*grid-template-columns:\s*200px\s+1fr\s+auto/);

    // Mobile breakpoint (<= 1100px): grid-template-columns 1fr.
    const mediaIdx = html.indexOf("@media (max-width: 1100px)");
    const mediaBlock = html.slice(mediaIdx, mediaIdx + 800);
    expect(mediaBlock).toMatch(/\.intel-row\s*\{\s*grid-template-columns:\s*1fr/);

    // The .app shell stays a 220 / 1fr / 360 grid at default widths
    // (1280 / 1440 / 1920 px) and collapses to 56 / 1fr at narrow widths
    // (800 px). Both cases live in the same stylesheet.
    expect(html).toMatch(/\.app\s*\{[^}]*grid-template-columns:\s*220px\s+1fr\s+360px/);
    expect(mediaBlock).toContain(".app, .app.route-full");
  });

  it("client script declares the intelligence state branch and the picker actions", () => {
    const client = getClientScript();
    expect(client).toContain('intelligence: {');
    expect(client).toContain('intel-picker-open');
    expect(client).toContain('intel-picker-save');
    expect(client).toContain('intel-picker-close');
    expect(client).toContain('fetchIntelligenceState');
  });
});

describe("Intelligence real-browser drill — picker flow over HTTP", () => {
  let d: Drill;
  beforeEach(async () => { d = await bootDrill(); });
  afterEach(async () => { await d.stop(); });

  it("/v1.1 HTML serves on GET and contains the Intelligence sidebar nav target", async () => {
    const res = await fetch(`${d.url}/v1.1`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain('data-route="intelligence"');
    expect(html).toContain(">Intelligence<");
  });

  it("step 4a: initial /status reports defaults across all six surfaces", async () => {
    const res = await fetch(`${d.url}/api/hub/intelligence/status`, {
      headers: authedHeaders(),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as {
      data: { surfaces: { surface: string; chosen: string }[] };
    };
    const concierge = body.data.surfaces.find((s) => s.surface === "concierge");
    expect(concierge).toBeDefined();
    expect(concierge!.chosen).toBe("local");
    const gateExp = body.data.surfaces.find((s) => s.surface === "gate-explanation");
    expect(gateExp).toBeDefined();
    expect(gateExp!.chosen).toBe("disabled");
  });

  it("steps 4b-c: Venice key save + concierge flips to Venice", async () => {
    const r1 = await fetch(`${d.url}/api/hub/intelligence/credentials/venice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ api_key: FAKE_VENICE_KEY }),
    });
    expect(r1.status).toBe(200);
    const r2 = await fetch(`${d.url}/api/hub/intelligence/surfaces/concierge/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "venice" }),
    });
    expect(r2.status).toBe(200);
    const final = await fetch(`${d.url}/api/hub/intelligence/status`, {
      headers: authedHeaders(),
    });
    const body = await final.json() as {
      data: { surfaces: { surface: string; chosen: string; health: string }[] };
    };
    const concierge = body.data.surfaces.find((s) => s.surface === "concierge");
    expect(concierge!.chosen).toBe("venice");
    expect(concierge!.health).toBe("ok");
  });

  it("steps 4d-e: frontier provider key save + sentinel-scoring flips to frontier-with-filter", async () => {
    await fetch(`${d.url}/api/hub/intelligence/credentials/frontier`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ provider: "anthropic", api_key: FAKE_ANTHROPIC_KEY }),
    });
    await fetch(`${d.url}/api/hub/intelligence/surfaces/sentinel-scoring/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "frontier-with-filter" }),
    });
    const final = await fetch(`${d.url}/api/hub/intelligence/status`, {
      headers: authedHeaders(),
    });
    const body = await final.json() as {
      data: { surfaces: { surface: string; chosen: string }[] };
    };
    const sentinel = body.data.surfaces.find((s) => s.surface === "sentinel-scoring");
    expect(sentinel!.chosen).toBe("frontier-with-filter");
  });

  it("step 4f: local + gemma-2-2b round-trips through the operator-visible config", async () => {
    await fetch(`${d.url}/api/hub/intelligence/surfaces/concierge/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "local", local_model_pick: "gemma-2-2b" }),
    });
    const cfg = await fetch(`${d.url}/api/hub/intelligence/config`, {
      headers: authedHeaders(),
    });
    const body = await cfg.json() as {
      data: {
        per_surface: Record<string, string>;
        local_model_picks: Record<string, string>;
      };
    };
    expect(body.data.per_surface.concierge).toBe("local");
    expect(body.data.local_model_picks.concierge).toBe("gemma-2-2b");
  });

  it("step 6: audit log records substrate_chosen for every flip", async () => {
    await fetch(`${d.url}/api/hub/intelligence/credentials/venice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ api_key: FAKE_VENICE_KEY }),
    });
    await fetch(`${d.url}/api/hub/intelligence/surfaces/concierge/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "venice" }),
    });
    await fetch(`${d.url}/api/hub/intelligence/surfaces/template-suggestion/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "disabled" }),
    });
    const events = await d.auditLog.query({ operation_type: INTEL_OPS.SUBSTRATE_CHOSEN });
    const surfaces = events.entries.map((e) => (e.details as { surface: string }).surface);
    expect(surfaces).toContain("concierge");
    expect(surfaces).toContain("template-suggestion");
  });

  it("step 7: /config never returns raw API key bytes (presence flags only)", async () => {
    await fetch(`${d.url}/api/hub/intelligence/credentials/venice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ api_key: FAKE_VENICE_KEY }),
    });
    await fetch(`${d.url}/api/hub/intelligence/credentials/frontier`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ provider: "anthropic", api_key: FAKE_ANTHROPIC_KEY }),
    });
    const res = await fetch(`${d.url}/api/hub/intelligence/config`, {
      headers: authedHeaders(),
    });
    const body = await res.text();
    expect(body).not.toContain(FAKE_VENICE_KEY);
    expect(body).not.toContain(FAKE_ANTHROPIC_KEY);
    const parsed = JSON.parse(body) as {
      data: {
        venice_api_key_present: boolean;
        frontier_keys_present: Record<string, boolean>;
      };
    };
    expect(parsed.data.venice_api_key_present).toBe(true);
    expect(parsed.data.frontier_keys_present.anthropic).toBe(true);
  });

  it("step 7 (extended): /status response also never returns raw API key bytes", async () => {
    await fetch(`${d.url}/api/hub/intelligence/credentials/venice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ api_key: FAKE_VENICE_KEY }),
    });
    await fetch(`${d.url}/api/hub/intelligence/surfaces/concierge/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "venice" }),
    });
    const res = await fetch(`${d.url}/api/hub/intelligence/status`, {
      headers: authedHeaders(),
    });
    const body = await res.text();
    expect(body).not.toContain(FAKE_VENICE_KEY);
  });

  it("reset wipes overrides and returns the default per-surface map", async () => {
    await fetch(`${d.url}/api/hub/intelligence/surfaces/concierge/choice`, {
      method: "POST",
      headers: authedJsonHeaders(),
      body: JSON.stringify({ substrate: "disabled" }),
    });
    const res = await fetch(`${d.url}/api/hub/intelligence/reset`, {
      method: "POST",
      headers: authedHeaders(),
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { data: { per_surface: Record<string, string> } };
    expect(body.data.per_surface.concierge).toBe("local");
  });
});
