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
import { IdentityManager } from "../src/cognitive/tools.js";
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

  it("C1 Finding 4: status bar carries a clickable Fleet Switcher link to /fleet", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 60,
      serverVersion: "0.10.6-test",
      loopbackAutoAuth: true,
    } as Parameters<typeof generateDashboardHTML>[0]);
    // A real anchor to /fleet, discoverable without typing the URL.
    expect(html).toMatch(/<a[^>]+href="\/fleet"[^>]*>/);
    expect(html).toContain("Fleet");
    // It sits in the status bar so an operator sees it on landing.
    const barMatch = html.match(/<div class="status-bar-right">[\s\S]*?<\/div>\s*<\/div>/);
    expect(barMatch).toBeTruthy();
    expect(barMatch![0]).toContain('href="/fleet"');
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

  // legacy-dashboard-approval-route: the legacy /v1.0 dashboard approve/deny
  // buttons formerly called the GET-only `fetchAPI` helper, but the server
  // dispatches approval DECISIONS on POST (and requires the operator token
  // even on loopback auto-auth, per PR #525). A GET 404s, so the buttons
  // were dead. They must instead emit a token-bearing POST so they hit the
  // same token-gated decision surface as the v1.1 fortress view.
  describe("legacy dashboard approve/deny buttons emit a token-bearing POST", () => {
    const html = generateDashboardHTML({
      timeoutSeconds: 60,
      serverVersion: "approval-route-test",
      loopbackAutoAuth: true,
    } as Parameters<typeof generateDashboardHTML>[0]);

    it("defines a POST helper that attaches the operator bearer token", () => {
      // A helper that issues method:'POST' with the AUTH_TOKEN bearer header.
      const postHelperRe =
        /async\s+function\s+postAPI\s*\([\s\S]*?method:\s*'POST'[\s\S]*?'Authorization':\s*'Bearer\s*'\s*\+\s*AUTH_TOKEN/;
      expect(
        postHelperRe.test(html),
        "the legacy dashboard must define a POST helper that sends the operator " +
          "bearer token, so approval decisions go through the #525 requireToken gate."
      ).toBe(true);
    });

    it("approve/deny click handlers call the POST helper, not the GET fetchAPI", () => {
      // Approve handler routes through postAPI('/api/approve/...').
      expect(
        /postAPI\(\s*`\/api\/approve\//.test(html),
        "the approve button must POST to /api/approve/:id via the token-bearing helper."
      ).toBe(true);
      // Deny handler routes through postAPI('/api/deny/...').
      expect(
        /postAPI\(\s*`\/api\/deny\//.test(html),
        "the deny button must POST to /api/deny/:id via the token-bearing helper."
      ).toBe(true);
      // Regression guard: the dead GET path (fetchAPI against the decision
      // routes) must be gone — a GET 404s and the button never approves.
      expect(
        /fetchAPI\(\s*`\/api\/approve\//.test(html),
        "the approve button must NOT use the GET-only fetchAPI (it 404s against the POST-only route)."
      ).toBe(false);
      expect(
        /fetchAPI\(\s*`\/api\/deny\//.test(html),
        "the deny button must NOT use the GET-only fetchAPI (it 404s against the POST-only route)."
      ).toBe(false);
    });

    // Token-required-by-design recovery (codex MUST-FIX follow-up): on a
    // fresh loopback-auto-auth session the page is admitted WITHOUT a token,
    // so AUTH_TOKEN === '' and the approval POST hits the server's
    // requireToken gate and returns 401. A redirect to '/' is a DEAD END
    // under loopback auto-auth (the server serves the dashboard, never the
    // login form), so postAPI must instead prompt for the operator token,
    // persist it, and RETRY the decision once with that token — keeping the
    // action token-gated while giving the operator a real path to approve.
    function extractPostAPI(): string {
      const postFn = /async function postAPI\(endpoint\)\s*\{[\s\S]*?\n {4}\}/.exec(html);
      expect(postFn, "HTML must define the postAPI helper").not.toBeNull();
      return postFn![0];
    }

    it("on 401, postAPI prompts for the operator token and RETRIES the POST with it", () => {
      const simulated = `
        const API_BASE = '';
        const AUTH_TOKEN = '';
        const stored = {};
        const sessionStorage = {
          getItem: (k) => stored[k] || null,
          setItem: (k, v) => { stored[k] = v; },
          removeItem: (k) => { delete stored[k]; },
        };
        let didRedirect = false;
        function redirectToLogin() { didRedirect = true; }
        const window = { prompt: () => 'operator-token-xyz', location: { href: '' } };
        const calls = [];
        async function fetch(url, opts) {
          const token = opts.headers['Authorization'].replace('Bearer ', '');
          calls.push({ method: opts.method, token });
          // First (tokenless) attempt 401s; the retry WITH the token succeeds.
          if (!token) return { status: 401, ok: false, json: async () => ({}) };
          return { status: 200, ok: true, json: async () => ({ ok: true }) };
        }
        ${extractPostAPI()}
        return (async () => {
          const result = await postAPI('/api/approve/abc');
          return JSON.stringify({
            calls, didRedirect, result, storedToken: stored.authToken,
          });
        })();
      `;
      // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
      const runner = new Function(simulated);
      return (runner() as Promise<string>).then((raw) => {
        const out = JSON.parse(raw);
        // Both calls were POSTs (never a GET), and the retry carried the token.
        expect(out.calls.map((c: { method: string }) => c.method)).toEqual(["POST", "POST"]);
        expect(out.calls[0].token, "first attempt is the empty AUTH_TOKEN").toBe("");
        expect(
          out.calls[1].token,
          "the retry must carry the operator-entered token, going THROUGH the requireToken gate."
        ).toBe("operator-token-xyz");
        expect(out.storedToken, "the entered token is persisted for subsequent calls").toBe(
          "operator-token-xyz"
        );
        expect(out.didRedirect, "a successful retry must not redirect").toBe(false);
        expect(out.result).toEqual({ ok: true });
      });
    });

    it("on a rejected token, postAPI re-prompts (no dead-end redirect) and succeeds with a valid token", () => {
      const simulated = `
        const API_BASE = '';
        const AUTH_TOKEN = '';
        const stored = {};
        const sessionStorage = {
          getItem: (k) => stored[k] || null,
          setItem: (k, v) => { stored[k] = v; },
          removeItem: (k) => { delete stored[k]; },
        };
        let didRedirect = false;
        function redirectToLogin() { didRedirect = true; }
        // First prompt yields a bad token, second yields the valid one.
        const answers = ['bad-token', 'good-token'];
        let pi = 0;
        const window = { prompt: () => answers[pi++], location: { href: '' } };
        const calls = [];
        async function fetch(url, opts) {
          const token = opts.headers['Authorization'].replace('Bearer ', '');
          calls.push(token);
          if (token === 'good-token') return { status: 200, ok: true, json: async () => ({ ok: true }) };
          return { status: 401, ok: false, json: async () => ({}) };
        }
        ${extractPostAPI()}
        return (async () => {
          const result = await postAPI('/api/deny/abc');
          return JSON.stringify({ calls, didRedirect, result, storedToken: stored.authToken });
        })();
      `;
      // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
      const runner = new Function(simulated);
      return (runner() as Promise<string>).then((raw) => {
        const out = JSON.parse(raw);
        // tokenless -> 401, bad-token -> 401, good-token -> 200.
        expect(out.calls).toEqual(["", "bad-token", "good-token"]);
        expect(out.didRedirect, "the re-prompt path must NOT dead-end via redirect").toBe(false);
        expect(out.storedToken).toBe("good-token");
        expect(out.result).toEqual({ ok: true });
      });
    });

    it("on 401, dismissing the token prompt leaves the op pending (safe no-op, never auto-approve)", () => {
      const simulated = `
        const API_BASE = '';
        const AUTH_TOKEN = '';
        const stored = {};
        const sessionStorage = {
          getItem: (k) => stored[k] || null,
          setItem: (k, v) => { stored[k] = v; },
          removeItem: (k) => { delete stored[k]; },
        };
        let didRedirect = false;
        function redirectToLogin() { didRedirect = true; }
        // Operator cancels the prompt.
        const window = { prompt: () => null, location: { href: '' } };
        let callCount = 0;
        async function fetch(url, opts) {
          callCount++;
          return { status: 401, ok: false, json: async () => ({}) };
        }
        ${extractPostAPI()}
        return (async () => {
          const result = await postAPI('/api/approve/abc');
          return JSON.stringify({ callCount, result, storedToken: stored.authToken || null });
        })();
      `;
      // eslint-disable-next-line @typescript-eslint/no-implied-eval, no-new-func
      const runner = new Function(simulated);
      return (runner() as Promise<string>).then((raw) => {
        const out = JSON.parse(raw);
        // Exactly one (tokenless) attempt, no retry, no decision recorded.
        expect(out.callCount, "no retry when the operator dismisses the prompt").toBe(1);
        expect(out.result, "dismissed prompt => no decision (op stays pending)").toBeNull();
        expect(out.storedToken).toBeNull();
      });
    });
  });
});
