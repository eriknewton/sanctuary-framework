/**
 * Dashboard-fold fix round 1, F1 — a protect-started dashboard never sits
 * tokenless-open on the folded read routes (ratified decision 2).
 *
 * The protect starter (src/cli.ts startOwnedDashboard closure) passes
 * `mintAuthTokenIfAbsent: true` into the REAL standalone boot. This suite
 * exercises that exact option against the real `startStandaloneDashboard`:
 *
 *  - default fortress config (no dashboard.auth_token anywhere) => a token
 *    is MINTED, so a tokenless GET on a folded read route is DENIED. The
 *    rig is a first-run fortress (no persisted identity yet), so v0.10.2
 *    loopback auto-auth is NOT engaged and the 401 discriminates the token
 *    posture itself. (Post-unlock loopback auto-auth for an operator whose
 *    passphrase already proved custody is A's separate, documented
 *    affordance and is unchanged.)
 *  - an operator-CONFIGURED token always wins: the mint flag never
 *    replaces it.
 *
 * The manually-run `sanctuary dashboard` path does not set the flag and
 * keeps its pre-existing posture (out of fold scope).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startStandaloneDashboard } from "../../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../../src/principal-policy/dashboard.js";
import {
  bindWithRetry,
  randomTestPort,
} from "../util/port-collision-retry.js";

describe("dashboard-fold F1: protect-started dashboard auth posture", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let tempDir = "";
  let escrowDir = "";
  let discoveryOptions: { root: string; home: string; env: Record<string, string> };

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-f1-auth-"));
    escrowDir = await mkdtemp(join(tmpdir(), "sanctuary-f1-escrow-"));
    const discoveryRoot = join(tempDir, "discovery-root");
    const discoveryHome = join(tempDir, "discovery-home");
    await mkdir(discoveryRoot, { recursive: true, mode: 0o700 });
    await mkdir(discoveryHome, { recursive: true, mode: 0o700 });
    discoveryOptions = { root: discoveryRoot, home: discoveryHome, env: {} };
    process.env.VITEST = "true";
    process.env.SANCTUARY_RECOVERY_OUT = join(escrowDir, "recovery.txt");
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    await rm(escrowDir, { recursive: true, force: true }).catch(() => {});
    delete process.env.SANCTUARY_RECOVERY_OUT;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
  });

  async function bootProtectShaped(opts?: {
    authToken?: string;
  }): Promise<number> {
    return bindWithRetry(async () => {
      const port = randomTestPort();
      dashboard = await startStandaloneDashboard({
        storagePath: join(tempDir, ".sanctuary"),
        passphrase: "f1-test-passphrase",
        port,
        host: "127.0.0.1",
        noConfirm: true,
        distressPort: 0,
        discoveryOptions,
        // The protect starter's exact posture (src/cli.ts closure):
        mintAuthTokenIfAbsent: true,
        ...(opts?.authToken !== undefined ? { authToken: opts.authToken } : {}),
      });
      return port;
    });
  }

  it("DENIES a tokenless GET /api/fleet/roster on a default-config protect-started dashboard", async () => {
    const port = await bootProtectShaped();
    for (const path of ["/api/fleet/roster", "/api/templates", "/api/pending"]) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`);
      expect(res.status, `${path} must not be tokenless-open`).toBe(401);
    }
  });

  it("never replaces an operator-configured token with a minted one", async () => {
    const configured = "operator-configured-token-0123456789abcdef";
    const port = await bootProtectShaped({ authToken: configured });
    // The configured token authorizes the folded read...
    const ok = await fetch(`http://127.0.0.1:${port}/api/fleet/roster`, {
      headers: { Authorization: `Bearer ${configured}` },
    });
    expect(ok.status).toBe(200);
    // ...and a tokenless read is still denied (no silent fail-open).
    const anon = await fetch(`http://127.0.0.1:${port}/api/fleet/roster`);
    expect(anon.status).toBe(401);
  });
});
