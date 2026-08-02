/**
 * Dashboard-fold PR-3 — the mobile companion PWA on the ONE surviving
 * surface (ratified decision 7, 2026-08-02).
 *
 * The `/m/*` shell moves from the retired wrap-spawned dashboard onto the
 * principal-policy dashboard. Contract mirrored from the wrap surface
 * (test/dashboard/mobile.test.ts): the shell/manifest/service-worker are
 * TOKENLESS static assets (they carry no operator data; the client runs its
 * own auth and sends the bearer only to the already-gated /api routes), the
 * shell ships a strict same-origin CSP, the manifest is scoped to /m/, and
 * the service worker is scope-limited via Service-Worker-Allowed.
 */

import { describe, it, expect, afterEach } from "vitest";
import { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import { MOBILE_COMPANION_CSP } from "../../src/dashboard/mobile.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

const TOKEN = "mobile-pwa-fold-test-token-0123456789abcdef";

describe("dashboard-fold PR-3: mobile companion PWA served by the main dashboard", () => {
  let channel: DashboardApprovalChannel | undefined;
  let base = "";

  async function startRig(): Promise<void> {
    await bindWithRetry(async () => {
      const port = randomTestPort();
      channel = new DashboardApprovalChannel({
        port,
        host: "127.0.0.1",
        timeout_seconds: 30,
        auto_deny: true,
        // A bearer token IS configured: the tokenless assertions below prove
        // the PWA shell is deliberately public (client-side auth), not that
        // auth is disabled.
        auth_token: TOKEN,
      });
      await channel.start();
      base = `http://127.0.0.1:${port}`;
    });
  }

  afterEach(async () => {
    await channel?.stop();
    channel = undefined;
  });

  it("serves the shell at /m and /m/ as HTML under the strict same-origin CSP, tokenless", async () => {
    await startRig();
    for (const path of ["/m", "/m/"]) {
      const res = await fetch(`${base}${path}`);
      expect(res.status, `${path} must serve tokenless`).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/html");
      expect(res.headers.get("content-security-policy")).toBe(
        MOBILE_COMPANION_CSP,
      );
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
      expect(res.headers.get("referrer-policy")).toBe("no-referrer");
      const html = await res.text();
      expect(html.toLowerCase()).toContain("<!doctype html>");
    }
  });

  it("serves a valid web manifest scoped to /m/", async () => {
    await startRig();
    const res = await fetch(`${base}/m/manifest.webmanifest`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain(
      "application/manifest+json",
    );
    const manifest = (await res.json()) as {
      start_url: string;
      scope: string;
    };
    expect(manifest.start_url).toBe("/m/");
    expect(manifest.scope).toBe("/m/");
  });

  it("serves the service worker scope-limited to /m/", async () => {
    await startRig();
    const res = await fetch(`${base}/m/sw.js`);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/javascript");
    expect(res.headers.get("service-worker-allowed")).toBe("/m/");
  });

  it("keeps the PWA's DATA routes behind the auth gate (shell public, data gated)", async () => {
    await startRig();
    // The shell is public…
    const shell = await fetch(`${base}/m`);
    expect(shell.status).toBe(200);
    // …but the pending-approvals read the PWA polls is still 401 tokenless.
    const pending = await fetch(`${base}/api/pending`);
    expect(pending.status).toBe(401);
    // And 200 with the operator bearer.
    const authed = await fetch(`${base}/api/pending`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(authed.status).toBe(200);
  });
});
