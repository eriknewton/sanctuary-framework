/**
 * Sanctuary MCP Server — v0.10.5 dashboard route-table regression
 *
 * Field signal that drove this release: v0.10.4 fixed identity loading on a
 * real per-tenant install (`Identities loaded: 8` on Mini1), but every
 * panel in the browser stayed on "Loading…" and the status bar flashed
 * blue in a retry loop. Coordinator's source-level pass found the cause:
 * the dashboard HTML's SSE setup pointed at `/api/events`, but Stack A's
 * server mounts SSE at `/events`. The retry loop is an EventSource trying
 * to reconnect to a 404 endpoint forever.
 *
 * The acceptance shape mirrors v0.10.4's lesson: do NOT mock the route
 * table. Boot the real dashboard, fetch the real HTML, parse out every
 * fetch + EventSource target, then HTTP-request each one against the
 * running server. The test must fail on `v0.10.4` HEAD (because
 * `/api/events` returns 404) and pass after the fix.
 */
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import { persistUserProvidedPassphrase } from "../src/wrap/passphrase.js";
import { IdentityManager } from "../src/cognitive/tools.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../src/core/key-derivation.js";
import { createIdentity } from "../src/core/identity.js";
import { stringToBytes } from "../src/core/encoding.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { bindWithRetry, randomTestPort } from "./util/port-collision-retry.js";

/**
 * Retry-safe wrapper around `startStandaloneDashboard` for tests.
 * Sigma-7: delegates to the canonical `bindWithRetry` + `randomTestPort`
 * helpers in test/util/port-collision-retry.ts. DashboardApprovalChannel
 * embeds the port in selfOrigin and one-click session URLs, so we must
 * know the port before bind (Sigma-6 rule option 2 / bindWithRetry).
 */
async function startWithRetry(
  options: Parameters<typeof startStandaloneDashboard>[0]
): Promise<{ dashboard: DashboardApprovalChannel; port: number }> {
  return bindWithRetry(async () => {
    const port = randomTestPort();
    const dashboard = await startStandaloneDashboard({ ...options, port });
    return { dashboard, port };
  });
}

async function seedTenant(storagePath: string, passphrase: string): Promise<void> {
  await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
  await persistUserProvidedPassphrase(passphrase, {
    storagePath,
    platformOverride: "linux",
    // Force fallback-file path; never touch a real Secret Service on a
    // developer's Linux host (see dashboard-standalone-v010-4.test.ts for
    // the full rationale).
    exec: async () => ({ stdout: "", stderr: "", code: 1 }),
  });
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const { key: mk, params } = await deriveMasterKey(passphrase);
  await storage.write("_meta", "key-params", stringToBytes(JSON.stringify(params)));
  const idEncKey = derivePurposeKey(mk, "identity-encryption");
  const mgr = new IdentityManager(storage, mk);
  await mgr.load();
  const { storedIdentity } = createIdentity("v010-5-id", idEncKey, "passphrase");
  await mgr.save(storedIdentity);
}

/**
 * Extract every fetch / EventSource target URL embedded in the dashboard HTML.
 *
 * The HTML is a generated string with literal endpoint strings — we don't
 * try to JS-parse it; a regex sweep is sufficient and matches what the
 * coordinator did by hand. Returns the set of distinct path strings, with
 * variable concatenation evaluated where it's a constant prefix
 * (`API_BASE + '/api/foo'` → `/api/foo`).
 */
function extractCalledPaths(html: string): { fetches: string[]; eventSources: string[] } {
  const fetches = new Set<string>();
  const eventSources = new Set<string>();

  // fetch('<path>'  OR  fetch(API_BASE + '<path>'  OR  fetch("<path>"  ...
  const fetchRe = /\bfetch\(\s*(?:API_BASE\s*\+\s*)?['"]([^'"]+)['"]/g;
  let m: RegExpExecArray | null;
  while ((m = fetchRe.exec(html)) !== null) {
    fetches.add(m[1]!);
  }

  // fetchAPI('<endpoint>')  → endpoint already starts with /api/...
  const fetchApiRe = /\bfetchAPI\(\s*['"]([^'"]+)['"]/g;
  while ((m = fetchApiRe.exec(html)) !== null) {
    fetches.add(m[1]!);
  }

  // new EventSource(API_BASE + '<path>'  OR  new EventSource('<path>'
  const esRe = /\bnew\s+EventSource\(\s*(?:API_BASE\s*\+\s*)?['"]([^'"]+)['"]/g;
  while ((m = esRe.exec(html)) !== null) {
    eventSources.add(m[1]!);
  }

  // Also catch the fortress-view variant where the URL is built up into a
  // local variable: `const url = API_BASE + '<path>' + ...`. The endpoint
  // we care about is the literal path between the quotes.
  const fortressUrlRe = /API_BASE\s*\+\s*['"](\/[^'"+]+)['"][\s\+]/g;
  while ((m = fortressUrlRe.exec(html)) !== null) {
    // Heuristic: only treat as an EventSource path if `EventSource` appears
    // on the next ~5 lines after the URL definition. Otherwise it's a
    // regular fetch concatenation that the fetchRe already captured.
    const tail = html.slice(m.index, m.index + 400);
    if (/EventSource\(/.test(tail)) {
      eventSources.add(m[1]!);
    }
  }

  return { fetches: [...fetches], eventSources: [...eventSources] };
}

describe("v0.10.5: dashboard panels populate — route table matches HTML calls", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-v010-5-"));
    process.env.VITEST = "true";
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
    await rm(root, { recursive: true, force: true }).catch(() => {});
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
  });

  it("REGRESSION: every fetch + EventSource target in the served legacy dashboard HTML maps to a mounted route", async () => {
    await seedTenant(root, "v010-5-passphrase");
    process.env.SANCTUARY_STORAGE_PATH = root;

    const started = await startWithRetry({
      passphrase: "v010-5-passphrase",
      host: "127.0.0.1",
    });
    dashboard = started.dashboard;
    const port = started.port;

    // v1.1.7: the v0.10.5 SSE-URL regression canary protects the legacy
    // (Stack A) dashboard's HTML↔route-table parity. Legacy HTML moved
    // from `/` to `/v1.0` at v1.1.7; the canary follows it.
    const indexRes = await fetch(`http://127.0.0.1:${port}/v1.0`);
    expect(indexRes.status).toBe(200);
    const html = await indexRes.text();

    const { fetches, eventSources } = extractCalledPaths(html);

    // Sanity: we must have actually parsed something. If the regex broke
    // and we got an empty list, the assertions below would all pass
    // vacuously. Fail fast in that case.
    expect(fetches.length + eventSources.length).toBeGreaterThan(3);

    const failures: { path: string; kind: string; status: number }[] = [];

    // For every fetch target: GET it. Skip POST-only routes (we can tell
    // from the path — /auth/session and /api/approve/:id are POST; we
    // keep them in the list for visibility but don't fail on 405).
    for (const path of fetches) {
      // Skip routes with route-param placeholders like /:id or /<id> that
      // are constructed at call time — those aren't literal in the HTML
      // and our regex won't have captured them as concrete paths anyway.
      if (path.includes(":")) continue;
      const url = `http://127.0.0.1:${port}${path}`;
      const res = await fetch(url, { method: "GET" });
      // 200/204 = mounted and worked. 401 = mounted but auth required
      // (fine — means the route exists). 405 = wrong method (fine,
      // route exists). 404 = the failure mode we're testing for.
      if (res.status === 404) {
        failures.push({ path, kind: "fetch", status: res.status });
      }
    }

    // For every EventSource target: GET with Accept: text/event-stream
    // and immediately abort the body. A 200 response means the SSE
    // endpoint is mounted and would stream events.
    for (const path of eventSources) {
      if (path.includes(":")) continue;
      const url = `http://127.0.0.1:${port}${path}`;
      const controller = new AbortController();
      try {
        const res = await fetch(url, {
          method: "GET",
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        });
        if (res.status === 404) {
          failures.push({ path, kind: "EventSource", status: res.status });
        }
        controller.abort();
      } catch (err) {
        if ((err as Error).name !== "AbortError") {
          throw err;
        }
      }
    }

    if (failures.length > 0) {
      const summary = failures
        .map((f) => `  ${f.kind} -> ${f.path} returned ${f.status}`)
        .join("\n");
      throw new Error(
        `Dashboard HTML calls ${failures.length} route(s) that the server does not mount:\n${summary}\n\n` +
          `This is the v0.10.5 failure mode — UI loads, panels never populate, ` +
          `because the routes the page tries to call return 404.`
      );
    }
  }, 30000);

  it("dashboard SSE endpoint returns text/event-stream at the URL the HTML actually calls", async () => {
    // Direct, narrow assertion of the specific symptom Mini1 reported:
    // EventSource retry loop. The HTML's SSE URL must be a 200 with
    // event-stream content, not a 404.
    await seedTenant(root, "v010-5-sse-pass");
    process.env.SANCTUARY_STORAGE_PATH = root;

    const started = await startWithRetry({
      passphrase: "v010-5-sse-pass",
      host: "127.0.0.1",
    });
    dashboard = started.dashboard;
    const port = started.port;

    // v1.1.7: legacy dashboard moved from `/` to `/v1.0`.
    const indexRes = await fetch(`http://127.0.0.1:${port}/v1.0`);
    const html = await indexRes.text();
    const { eventSources } = extractCalledPaths(html);

    expect(eventSources.length).toBeGreaterThan(0);

    for (const path of eventSources) {
      if (path.includes(":")) continue;
      const controller = new AbortController();
      const url = `http://127.0.0.1:${port}${path}`;
      try {
        const res = await fetch(url, {
          method: "GET",
          headers: { Accept: "text/event-stream" },
          signal: controller.signal,
        });
        expect(res.status, `${path} should be a mounted SSE endpoint, got ${res.status}`).toBe(200);
        const ct = res.headers.get("content-type") ?? "";
        expect(ct, `${path} response content-type`).toContain("text/event-stream");
      } finally {
        controller.abort();
      }
    }
  }, 15000);

  it("/api/sovereignty returns a non-empty layers shape on a tenant with at least one wrapped identity", async () => {
    // Smoke test that one of the panel-populating fetches actually returns
    // useful data, not just an empty 200. If the v0.10.5 fix is right, the
    // sovereignty panel should be the first thing to populate.
    await seedTenant(root, "v010-5-sov-pass");
    process.env.SANCTUARY_STORAGE_PATH = root;

    const started = await startWithRetry({
      passphrase: "v010-5-sov-pass",
      host: "127.0.0.1",
    });
    dashboard = started.dashboard;
    const port = started.port;

    const res = await fetch(`http://127.0.0.1:${port}/api/sovereignty`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveProperty("score");
    expect(body).toHaveProperty("layers");
    expect(body.layers).toHaveProperty("l1");
    expect(body.layers).toHaveProperty("l2");
    expect(body.layers).toHaveProperty("l3");
    expect(body.layers).toHaveProperty("l4");
    expect(body.federation).toEqual(
      expect.objectContaining({
        operator_cloud_nodes: 0,
        provider_in_trust_boundary: false,
        tee_attested: false,
      }),
    );
    expect(body.federation.trust_boundary).toEqual(
      expect.objectContaining({
        version: "operator-cloud-trust-boundary-v1",
        operator_cloud_nodes: 0,
        provider_in_trust_boundary: false,
        tee_attested: false,
      }),
    );
  }, 15000);

  it("/api/sovereignty is NOT green-on-presence: an unarmed tenant gets a configured (not active-green) L1/L3 and a non-full score", async () => {
    // Green-on-presence honesty regression (parity with the 2026-06-17
    // /api/posture/* + /v1 rollup fix). A freshly seeded tenant has NO Castle
    // Wall enforcement evidence in its audit log (no egress_allowed/blocked,
    // no operator_decision), so the canonical buildCastleWallPosture reader
    // yields arm_state "unknown". The legacy /api/sovereignty surface must
    // reflect that VERDICT, not the SHR's static capability `active`:
    //   - L1 (the enforcing layer) renders the neutral "configured", NEVER
    //     green "active".
    //   - L3 (ZK / selective disclosure) likewise renders "configured", not a
    //     green live pill (relabel of the capability `active`).
    //   - the aggregate score does NOT reach a high green / "full" reading.
    //   - live_enforcement surfaces the real arm-state the green rests on.
    await seedTenant(root, "v010-5-sov-honest-pass");
    process.env.SANCTUARY_STORAGE_PATH = root;

    const started = await startWithRetry({
      passphrase: "v010-5-sov-honest-pass",
      host: "127.0.0.1",
    });
    dashboard = started.dashboard;
    const port = started.port;

    const res = await fetch(`http://127.0.0.1:${port}/api/sovereignty`);
    expect(res.status).toBe(200);
    const body = await res.json();

    // The live wall is unproven on a fresh tenant — never "armed".
    expect(body.live_enforcement).toBeDefined();
    expect(body.live_enforcement.castle_wall_arm_state).not.toBe("armed");
    expect(body.live_enforcement.castle_wall_arm_state).toBe("unknown");

    // L1 + L3 live pills must NOT be the green "active" — green means a verdict.
    expect(body.layers.l1.status).not.toBe("active");
    expect(body.layers.l1.status).toBe("configured");
    expect(body.layers.l3.status).not.toBe("active");
    expect(body.layers.l3.status).toBe("configured");

    // The SHR capability is preserved separately (the build DOES support these),
    // so a consumer can still tell capability from live enforcement.
    expect(body.layers.l1.capability_status).toBe("active");
    expect(body.layers.l3.capability_status).toBe("active");

    // Without a fresh wall verdict the aggregate is neither full nor high-green.
    expect(body.overall_level).not.toBe("full");
    expect(body.score).toBeLessThan(70);
  }, 15000);
});
