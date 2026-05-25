/**
 * Sanctuary MCP Server — v0.10.6 dashboard client-side reload loop regression
 *
 * Field signal that drove this release: v0.10.5 shipped the SSE URL fix
 * cleanly (`/api/events` -> `/events`, broken `EventSource` headers option
 * removed). Mac Mini verification confirmed every documented endpoint
 * returns real data — `/events` streams, `/api/sovereignty-profile` is 200,
 * `/api/proxy/servers` is 200. But the browser still didn't render: dozens
 * of identical 82.91 KB `127.0.0.1` document requests stacked at page-open,
 * zero `fetch(...)` or `EventSource(...)` traffic. A tight reload loop.
 *
 * Coordinator's source-level diagnosis: `initialize()` in dashboard-html.ts
 * unconditionally calls `redirectToLogin()` when `sessionStorage.authToken`
 * is empty, which sets `window.location.href = '/'`. On a fresh tab at
 * `127.0.0.1:PORT/`, `sessionStorage` is always empty. The server serves
 * the dashboard HTML (not the login page) because `isAuthenticated()`
 * recognizes loopback callers under `_autoAuthLocalhost`. Server-side
 * loopback auto-auth, no client-side mirror. Infinite redirect.
 *
 * The v0.10.5 regression test regex-extracted URLs from the HTML string
 * and HTTP-requested each directly. All routes returned non-4xx and the
 * test passed — correctly. But Node has no `sessionStorage`, so the test
 * never exercised the client-side `initialize()` path where empty
 * sessionStorage triggers the redirect before any fetch fires. Test-
 * coverage gap, not test-correctness bug.
 *
 * v0.10.6 closes the gap. The HTML must embed a `LOOPBACK_AUTH` constant
 * that mirrors the server's `_autoAuthLocalhost` decision, and
 * `initialize()` must gate on both `AUTH_TOKEN` and `LOOPBACK_AUTH`.
 *
 * This test must FAIL on v0.10.5 HEAD (`dcfa4c8`) and PASS after the fix.
 */
import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import { persistUserProvidedPassphrase } from "../src/wrap/passphrase.js";
import { IdentityManager } from "../src/l1-cognitive/tools.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { deriveMasterKey, derivePurposeKey } from "../src/core/key-derivation.js";
import { createIdentity } from "../src/core/identity.js";
import { stringToBytes } from "../src/core/encoding.js";
import { generateDashboardHTML } from "../src/principal-policy/dashboard-html.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { bindWithRetry, randomTestPort } from "./util/port-collision-retry.js";

/**
 * Sigma-7: delegates to the canonical bindWithRetry + randomTestPort
 * helpers. DashboardApprovalChannel embeds the port in selfOrigin and
 * one-click session URLs, so we must know the port before bind.
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
  const { storedIdentity } = createIdentity("v010-6-id", idEncKey, "passphrase");
  await mgr.save(storedIdentity);
}

describe("v0.10.6: dashboard HTML must not reload-loop under loopback auto-auth", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let root: string;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-v010-6-"));
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

  it("REGRESSION: booted against a real loopback tenant, served HTML embeds LOOPBACK_AUTH = true", async () => {
    // This is the field-shape assertion: boot the dashboard exactly the way
    // `sanctuary dashboard` does on Mini1, fetch `/` with no auth header,
    // and assert the emitted HTML contains `LOOPBACK_AUTH = true`.
    //
    // Pre-fix, the constant doesn't exist and this regex returns null.
    // Post-fix, loopback auto-auth is on (the tenant decrypted one identity
    // AND the host is 127.0.0.1), so the constant is embedded as `true`.
    await seedTenant(root, "v010-6-passphrase");
    process.env.SANCTUARY_STORAGE_PATH = root;

    const started = await startWithRetry({
      passphrase: "v010-6-passphrase",
      host: "127.0.0.1",
    });
    dashboard = started.dashboard;
    const port = started.port;

    // v1.1.7: legacy dashboard moved from `/` to `/v1.0`. The LOOPBACK_AUTH
    // constant is embedded in the legacy generated HTML; this canary follows
    // the legacy surface to its new URL.
    const res = await fetch(`http://127.0.0.1:${port}/v1.0`);
    expect(res.status).toBe(200);
    const html = await res.text();

    const loopbackMatch = /\bconst\s+LOOPBACK_AUTH\s*=\s*(true|false)\s*;/.exec(html);
    expect(
      loopbackMatch,
      "dashboard HTML must emit `const LOOPBACK_AUTH = <bool>;` alongside AUTH_TOKEN " +
        "so the client-side init gate can mirror the server's loopback auto-auth decision. " +
        "Missing this constant is the v0.10.5 reload-loop bug."
    ).not.toBeNull();
    expect(
      loopbackMatch![1],
      "with _autoAuthLocalhost enabled (loopback host + >=1 identity loaded), LOOPBACK_AUTH must be true"
    ).toBe("true");
  }, 20000);

  it("initialize() gates its redirect on LOOPBACK_AUTH, not just AUTH_TOKEN", async () => {
    // Purely a static check against the generator — protects against the
    // regression where someone adds the constant but forgets to gate on it.
    // No tenant boot needed: call generateDashboardHTML() directly with a
    // synthetic options bag.
    const html = generateDashboardHTML({
      timeoutSeconds: 60,
      serverVersion: "0.10.6-test",
      loopbackAutoAuth: true,
    } as Parameters<typeof generateDashboardHTML>[0]);

    // The gate must reference LOOPBACK_AUTH. Accept either order of the
    // operands and any surrounding whitespace. The body below is the exact
    // v0.10.5 buggy shape (`if (!AUTH_TOKEN)`) — that must NOT be present
    // on its own; it has to be ANDed with `!LOOPBACK_AUTH`.
    const gateRe =
      /if\s*\(\s*(?:!AUTH_TOKEN\s*&&\s*!LOOPBACK_AUTH|!LOOPBACK_AUTH\s*&&\s*!AUTH_TOKEN)\s*\)/;
    expect(
      gateRe.test(html),
      "initialize() must gate redirectToLogin() on BOTH !AUTH_TOKEN AND !LOOPBACK_AUTH. " +
        "The v0.10.5 buggy form was `if (!AUTH_TOKEN) { redirectToLogin(); return; }` — " +
        "on a fresh loopback tab with empty sessionStorage, that triggers an infinite reload loop."
    ).toBe(true);
  });

  it("initialize() does NOT redirect on loopback boot (auth gate lets init proceed)", async () => {
    // End-to-end shape: generate HTML with loopbackAutoAuth=true, then
    // execute the gate logic in a tiny evaluator that stubs the browser
    // APIs used by the gate. We're not running the whole HTML through
    // jsdom (deps weight); we're running the specific 2-line gate against
    // realistic inputs.
    //
    // Pre-fix: even with loopbackAutoAuth=true passed as an option, the
    // generator ignores it (no such param), the HTML still has
    // `if (!AUTH_TOKEN)`, and our simulator records a redirect attempt.
    // Post-fix: the gate evaluates `!AUTH_TOKEN && !LOOPBACK_AUTH` = false,
    // no redirect fires, and the simulator sees `didRedirect === false`.
    const html = generateDashboardHTML({
      timeoutSeconds: 60,
      serverVersion: "0.10.6-test",
      loopbackAutoAuth: true,
    } as Parameters<typeof generateDashboardHTML>[0]);

    // Pull the AUTH_TOKEN / LOOPBACK_AUTH constant lines and the gate line
    // out of the generated HTML, compose a tiny snippet, and exec it.
    // sessionStorage is empty (the fresh-tab case) so AUTH_TOKEN === ''.
    const authTokenLine = /const\s+AUTH_TOKEN\s*=[^;]+;/.exec(html)?.[0];
    const loopbackLine = /const\s+LOOPBACK_AUTH\s*=[^;]+;/.exec(html)?.[0];
    expect(authTokenLine, "HTML must define AUTH_TOKEN").toBeDefined();
    expect(loopbackLine, "HTML must define LOOPBACK_AUTH").toBeDefined();

    const gateMatch =
      /if\s*\(\s*(?:!AUTH_TOKEN\s*&&\s*!LOOPBACK_AUTH|!LOOPBACK_AUTH\s*&&\s*!AUTH_TOKEN|!AUTH_TOKEN)\s*\)\s*\{\s*redirectToLogin\(\)\s*;\s*return\s*;\s*\}/.exec(
        html
      );
    expect(gateMatch, "HTML must contain the init gate shape").not.toBeNull();

    const simulated = `
      const sessionStorage = { getItem: () => null };
      ${authTokenLine}
      ${loopbackLine}
      let didRedirect = false;
      function redirectToLogin() { didRedirect = true; }
      function runGate() { ${gateMatch![0]} return "proceeded"; }
      const outcome = runGate();
      return JSON.stringify({ didRedirect, outcome });
    `;

    // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
    const runner = new Function(simulated);
    const result = JSON.parse(runner() as string);

    expect(
      result.didRedirect,
      "with loopbackAutoAuth=true and empty sessionStorage, init() must NOT redirect. " +
        "This is the v0.10.5 reload-loop bug: pre-fix, the gate is `if (!AUTH_TOKEN)` " +
        "which always fires on a fresh tab and triggers `window.location.href = '/'`, " +
        "which reloads to the same URL, which hits the same gate, forever."
    ).toBe(false);
    expect(result.outcome).toBe("proceeded");
  });

  it("loopbackAutoAuth=false => AUTH_TOKEN still guards init (remote-deployment regression)", async () => {
    // The flip side: for a non-loopback deployment (or a loopback deployment
    // with no identities loaded), loopbackAutoAuth is false, and the gate
    // must STILL redirect to login when AUTH_TOKEN is empty. Otherwise we'd
    // be exposing the dashboard HTML unconditionally.
    const html = generateDashboardHTML({
      timeoutSeconds: 60,
      serverVersion: "0.10.6-test",
      loopbackAutoAuth: false,
    } as Parameters<typeof generateDashboardHTML>[0]);

    const authTokenLine = /const\s+AUTH_TOKEN\s*=[^;]+;/.exec(html)?.[0];
    const loopbackLine = /const\s+LOOPBACK_AUTH\s*=[^;]+;/.exec(html)?.[0];
    expect(authTokenLine).toBeDefined();
    expect(loopbackLine).toBeDefined();

    const gateMatch =
      /if\s*\(\s*(?:!AUTH_TOKEN\s*&&\s*!LOOPBACK_AUTH|!LOOPBACK_AUTH\s*&&\s*!AUTH_TOKEN|!AUTH_TOKEN)\s*\)\s*\{\s*redirectToLogin\(\)\s*;\s*return\s*;\s*\}/.exec(
        html
      );
    expect(gateMatch).not.toBeNull();

    const simulated = `
      const sessionStorage = { getItem: () => null };
      ${authTokenLine}
      ${loopbackLine}
      let didRedirect = false;
      function redirectToLogin() { didRedirect = true; }
      function runGate() { ${gateMatch![0]} return "proceeded"; }
      const outcome = runGate();
      return JSON.stringify({ didRedirect, outcome });
    `;

    // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
    const runner = new Function(simulated);
    const result = JSON.parse(runner() as string);

    expect(
      result.didRedirect,
      "with loopbackAutoAuth=false and empty sessionStorage, init() MUST redirect to login. " +
        "Otherwise remote/non-loopback deployments would skip auth entirely."
    ).toBe(true);
  });
});
