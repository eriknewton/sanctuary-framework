/**
 * Sanctuary Dashboard — Slice 2 (park-not-exit + launchd LaunchAgent) tests.
 *
 * Covers the ratified Slice 2 acceptance surface:
 *   - park serves the honest LOCKED surface and NO protected state;
 *   - the in-process unlock door lights up the read surface (locked -> serving)
 *     WITHOUT a restart;
 *   - a TOKENLESS unlock is rejected EVEN on loopback (custody carve-out);
 *   - a WRONG-token unlock is rejected (fail-closed);
 *   - a WRONG-credential unlock fails closed and stays parked;
 *   - park eliminates the crash-loop: a locked-start process STAYS UP;
 *   - the user-domain LaunchAgent plist generator/validator forbidden-env guard
 *     and well-formed checks (the single-owner SMAppService unit is Swift-side;
 *     its plist contract is unit-tested here).
 *
 * The fortress is seeded with a REAL custody envelope via the production
 * `establishMaster` first-run path; the passphrase is NOT persisted to keychain
 * or the fallback file, so a no-credential restart finds no credential and
 * parks (the supervised LaunchAgent scenario). No mocks of custody.
 */

import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import {
  generateDashboardLaunchAgentPlist,
  dashboardLaunchAgentWellFormed,
  DASHBOARD_LAUNCHAGENT_LABEL,
} from "../src/cli/dashboard-launchagent.js";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { establishMaster } from "../src/core/master-custody.js";
import { IdentityManager } from "../src/cognitive/tools.js";
import { createIdentity } from "../src/core/identity.js";
import { derivePurposeKey } from "../src/core/key-derivation.js";
import {
  bindWithRetry,
  randomTestPort,
} from "./util/port-collision-retry.js";

const PASSPHRASE = "slice2-park-correct-horse-battery";

/**
 * Seed a wrapped fortress with a REAL custody envelope (production
 * establishMaster first-run) + one identity. The passphrase is NOT persisted
 * anywhere discoverable, so a later no-credential boot cannot auto-unlock and
 * must park.
 */
async function seedWrappedFortress(storagePath: string): Promise<void> {
  await mkdir(join(storagePath, "state"), { recursive: true, mode: 0o700 });
  const storage = new FilesystemStorage(join(storagePath, "state"));
  const custody = await establishMaster({
    storage,
    passphrase: PASSPHRASE,
    firstRun: { installMode: "headless", mintRecoveryKey: false },
    storagePathHint: storagePath,
  });
  const idEncKey = derivePurposeKey(custody.masterKey, "identity-encryption");
  const mgr = new IdentityManager(storage, custody.masterKey);
  await mgr.load();
  const { storedIdentity } = createIdentity("seeded-0", idEncKey, "passphrase");
  await mgr.save(storedIdentity);
}

async function startOnFreePort(
  options: Omit<Parameters<typeof startStandaloneDashboard>[0], "port"> = {},
): Promise<{ dashboard: DashboardApprovalChannel; port: number }> {
  return bindWithRetry(async () => {
    const port = randomTestPort();
    const dashboard = await startStandaloneDashboard({ ...options, port });
    return { dashboard, port };
  });
}

describe("Slice 2: park-not-exit (server lifecycle)", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let root: string;
  let storagePath: string;
  let originalHome: string | undefined;

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "sanctuary-slice2-park-"));
    storagePath = join(root, "tenant");
    process.env.VITEST = "true";
    originalHome = process.env.HOME;
    // Isolate tenant discovery from the developer's real ~/.sanctuary.
    process.env.HOME = root;
    process.env.SANCTUARY_STORAGE_PATH = storagePath;
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
    delete process.env.SANCTUARY_RECOVERY_KEY;
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
  });

  it("parks (does not throw) on a locked start with --allow-park and serves /api/health up", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-health";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    expect(dashboard.isParked()).toBe(true);

    // /api/health is up (the listener bound) and unauthenticated, exactly as
    // when unlocked: "the listener is up" is true in both states.
    const health = await fetch(`http://127.0.0.1:${result.port}/api/health`);
    expect(health.status).toBe(200);
    const healthBody = await health.json();
    expect(healthBody.ok).toBe(true);
    expect(healthBody).toHaveProperty("instance");
    expect(healthBody).toHaveProperty("since");
  });

  it("--allow-park auto-generates and stderr-surfaces an operator token for unlock", async () => {
    await seedWrappedFortress(storagePath);
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
      dashboard = result.dashboard;
      const output = stderr.mock.calls.map((call) => call.join(" ")).join("\n");
      const tokenMatch = output.match(/Operator token: ([a-f0-9]{64})/);
      expect(tokenMatch).not.toBeNull();
      const token = tokenMatch![1]!;

      const tokenless = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ passphrase: PASSPHRASE }),
      });
      expect(tokenless.status).toBe(401);

      const unlock = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ passphrase: PASSPHRASE }),
      });
      expect(unlock.status).toBe(200);
      expect((await unlock.json()).unlocked).toBe(true);
    } finally {
      stderr.mockRestore();
    }
  });

  it("reports readiness ready:'locked' while parked (no master key, no identity manager)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-ready";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/readiness`, {
      headers: { Authorization: "Bearer park-token-ready" },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ready).toBe("locked");
  });

  it("serves NO protected state while parked (audit-log route hits the fail-closed empty path)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-noprot";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    // Authenticated audit-log read: there is no master key, so no decrypted
    // audit entries can be served. The route must NOT 500 and must NOT leak
    // protected state; it returns the empty/closed shape.
    const res = await fetch(`http://127.0.0.1:${result.port}/api/audit-log`, {
      headers: { Authorization: "Bearer park-token-noprot" },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    const entries = Array.isArray(data) ? data : (data.entries ?? []);
    expect(entries.length).toBe(0);
  });

  it("rejects a TOKENLESS unlock POST EVEN on loopback (custody carve-out)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-tokenless";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    // No Authorization header. Loopback origin is NOT a proxy for operator
    // identity for the unlock door; a co-resident agent must not self-unlock.
    const res = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(res.status).toBe(401);
    // And the dashboard stayed parked: it did NOT unlock without a token.
    expect(dashboard.isParked()).toBe(true);
    const ready = await fetch(`http://127.0.0.1:${result.port}/api/readiness`, {
      headers: { Authorization: "Bearer park-token-tokenless" },
    });
    expect((await ready.json()).ready).toBe("locked");
  });

  it("rejects a WRONG-token unlock POST (fail-closed)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-wrongtok";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer not-the-real-token",
      },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(res.status).toBe(401);
    expect(dashboard.isParked()).toBe(true);
  });

  it("rejects a WRONG-credential unlock and stays parked (generic 401, no oracle)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-wrongcred";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer park-token-wrongcred",
      },
      body: JSON.stringify({ passphrase: "this-is-the-wrong-passphrase" }),
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    // Generic message only — no tier/rule oracle (invariant 7).
    expect(JSON.stringify(body)).not.toMatch(/tier|rule|envelope|MAC|kdf/i);
    expect(dashboard.isParked()).toBe(true);
  });

  it("after a WRONG-credential rejection, a subsequent CORRECT unlock still succeeds (retry allowed)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-retry";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;
    const base = `http://127.0.0.1:${result.port}`;
    const auth = { Authorization: "Bearer park-token-retry" };

    const wrong = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: "wrong-pass" }),
    });
    expect(wrong.status).toBe(401);
    expect(dashboard.isParked()).toBe(true);

    const right = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(right.status).toBe(200);
    expect(dashboard.isParked()).toBe(false);
  });

  it("a CORRECT-credential unlock whose dependency WIRING fails leaves the dashboard CLEANLY PARKED (atomic-wiring: no half-unlocked state)", async () => {
    // Custody fail-open regression guard. establishMaster SUCCEEDS (the
    // credential is correct), but a fault is injected into wireUnlockedDeps
    // AFTER every dep is constructed/loaded/saved and BEFORE any is attached.
    // The unlock must fail closed (401) and the dashboard must remain provably
    // fully parked: isParked() true, readiness "locked", audit-log empty, and
    // loopback auto-auth OFF (a co-resident agent cannot read protected state).
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-wirefault";

    const result = await startOnFreePort({
      host: "127.0.0.1",
      allowPark: true,
      __testFaultAfterLoads: () => {
        throw new Error("injected post-load wiring fault");
      },
    });
    dashboard = result.dashboard;
    const base = `http://127.0.0.1:${result.port}`;
    const auth = { Authorization: "Bearer park-token-wirefault" };

    // Pre-unlock: parked + locked.
    expect(dashboard.isParked()).toBe(true);
    expect((await (await fetch(`${base}/api/readiness`, { headers: auth })).json()).ready).toBe("locked");

    // Correct token + correct credential, but wiring throws after the loads.
    const unlock = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(unlock.status).toBe(401);

    // PROVE fully parked: every attach was rolled back / never happened.
    expect(dashboard.isParked()).toBe(true);

    const ready = await fetch(`${base}/api/readiness`, { headers: auth });
    expect((await ready.json()).ready).toBe("locked");

    const audit = await fetch(`${base}/api/audit-log`, { headers: auth });
    expect(audit.status).toBe(200);
    const auditData = await audit.json();
    const entries = Array.isArray(auditData) ? auditData : (auditData.entries ?? []);
    expect(entries.length).toBe(0);

    // Loopback auto-auth MUST be off: an UNAUTHENTICATED loopback request to a
    // protected route must still be rejected (if auto-auth had leaked on, the
    // co-resident agent could read protected state without the token).
    const noAuthReadiness = await fetch(`${base}/api/readiness`);
    expect(noAuthReadiness.status).toBe(401);
  });

  it("the CORRECT-token + CORRECT-credential unlock lights up the read surface (locked -> serving) WITHOUT a restart", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-unlock";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;
    const base = `http://127.0.0.1:${result.port}`;
    const auth = { Authorization: "Bearer park-token-unlock" };

    // Pre-unlock: locked.
    expect((await (await fetch(`${base}/api/readiness`, { headers: auth })).json()).ready).toBe("locked");

    // Unlock with the operator token + the correct passphrase.
    const unlock = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(unlock.status).toBe(200);
    expect((await unlock.json()).unlocked).toBe(true);

    // Post-unlock: serving — same process, no restart.
    expect(dashboard.isParked()).toBe(false);
    const ready = await fetch(`${base}/api/readiness`, { headers: auth });
    expect((await ready.json()).ready).toBe("serving");

    // And the read surface now serves the seeded identity.
    const ids = await fetch(`${base}/api/identity`, { headers: auth });
    expect(ids.status).toBe(200);
  });

  it("a second unlock after a successful unlock returns 409 (idempotent, already unlocked)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-twice";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;
    const base = `http://127.0.0.1:${result.port}`;
    const auth = { Authorization: "Bearer park-token-twice" };

    const first = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(first.status).toBe(200);

    const second = await fetch(`${base}/api/unlock`, {
      method: "POST",
      headers: { ...auth, "Content-Type": "application/json" },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(second.status).toBe(409);
  });

  it("the unlock door does not exist (404) on a dashboard booted WITH a credential (park off)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "unlocked-no-door";

    // Boot unlocked (passphrase supplied). No park, no unlock handler.
    const result = await startOnFreePort({
      host: "127.0.0.1",
      passphrase: PASSPHRASE,
    });
    dashboard = result.dashboard;
    expect(dashboard.isParked()).toBe(false);

    const res = await fetch(`http://127.0.0.1:${result.port}/api/unlock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer unlocked-no-door",
      },
      body: JSON.stringify({ passphrase: PASSPHRASE }),
    });
    expect(res.status).toBe(404);
  });

  it("crash-loop eliminated: a locked-start process STAYS UP (no exit) over a sustained window", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-token-stayup";

    const result = await startOnFreePort({ host: "127.0.0.1", allowPark: true });
    dashboard = result.dashboard;
    const base = `http://127.0.0.1:${result.port}`;

    // The locked start returned a live, listening server (it did not throw and
    // exit). Probe it repeatedly: every probe must succeed, proving the process
    // is long-lived and not in a relaunch loop.
    for (let i = 0; i < 5; i++) {
      const health = await fetch(`${base}/api/health`);
      expect(health.status).toBe(200);
      expect((await health.json()).ok).toBe(true);
    }
    // Still parked, still up, never auto-unlocked.
    expect(dashboard.isParked()).toBe(true);
  });

  it("without --allow-park, a locked start still throws loudly (interactive ergonomics preserved)", async () => {
    await seedWrappedFortress(storagePath);
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "park-off-throws";

    await expect(
      startOnFreePort({ host: "127.0.0.1" /* allowPark omitted */ }),
    ).rejects.toThrow(/cannot unlock this fortress|valid credential/i);
  });
});

describe("Slice 2: user-domain LaunchAgent plist", () => {
  const validArgs = [
    "/usr/local/bin/node",
    "/opt/sanctuary/dist/cli.js",
    "dashboard",
    "--allow-park",
    "--no-open",
  ];

  it("renders a RunAtLoad + KeepAlive LaunchAgent with the expected label", () => {
    const plist = generateDashboardLaunchAgentPlist({
      programArguments: validArgs,
    });
    expect(plist).toContain(`<string>${DASHBOARD_LAUNCHAGENT_LABEL}</string>`);
    expect(plist).toMatch(/<key>RunAtLoad<\/key>\s*<true\/>/);
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<true\/>/);
    expect(plist).toMatch(/<key>ThrottleInterval<\/key>\s*<integer>5<\/integer>/);
    expect(dashboardLaunchAgentWellFormed(plist)).toBe(true);
  });

  it("embeds SANCTUARY_STORAGE_PATH (a path, not a secret) when given a fortress path", () => {
    const plist = generateDashboardLaunchAgentPlist({
      programArguments: validArgs,
      fortressPath: "/Users/op/.sanctuary",
    });
    expect(plist).toContain("<key>SANCTUARY_STORAGE_PATH</key>");
    expect(plist).toContain("<string>/Users/op/.sanctuary</string>");
  });

  it("REFUSES to render if --allow-park is missing (would re-introduce the crash-loop)", () => {
    expect(() =>
      generateDashboardLaunchAgentPlist({
        programArguments: [
          "/usr/local/bin/node",
          "/opt/sanctuary/dist/cli.js",
          "dashboard",
          "--no-open",
        ],
      }),
    ).toThrow(/--allow-park/);
  });

  it("REFUSES to embed SANCTUARY_PASSPHRASE (forbidden, world-readable plist)", () => {
    expect(() =>
      generateDashboardLaunchAgentPlist({
        programArguments: validArgs,
        extraEnv: [["SANCTUARY_PASSPHRASE", "hunter2"]],
      }),
    ).toThrow(/Refusing to embed SANCTUARY_PASSPHRASE/);
  });

  it("REFUSES to embed SANCTUARY_RECOVERY_KEY (forbidden)", () => {
    expect(() =>
      generateDashboardLaunchAgentPlist({
        programArguments: validArgs,
        extraEnv: [["SANCTUARY_RECOVERY_KEY", "abc-def-ghi"]],
      }),
    ).toThrow(/Refusing to embed SANCTUARY_RECOVERY_KEY/);
  });

  it("REFUSES a non-absolute program path", () => {
    expect(() =>
      generateDashboardLaunchAgentPlist({
        programArguments: ["node", "dist/cli.js", "dashboard", "--allow-park"],
      }),
    ).toThrow(/must be absolute/);
  });

  it("validator rejects a plist that smuggles in a forbidden env name", () => {
    const tampered =
      generateDashboardLaunchAgentPlist({ programArguments: validArgs }).replace(
        "<key>PATH</key>",
        "<key>SANCTUARY_PASSPHRASE</key>\n\t\t<string>leak</string>\n\t\t<key>PATH</key>",
      );
    expect(dashboardLaunchAgentWellFormed(tampered)).toBe(false);
  });

  it("validator rejects a plist with the wrong label", () => {
    const wrong = generateDashboardLaunchAgentPlist({
      programArguments: validArgs,
    }).replace(DASHBOARD_LAUNCHAGENT_LABEL, "com.evil.dashboard");
    expect(dashboardLaunchAgentWellFormed(wrong)).toBe(false);
  });
});

describe("Slice 2: single-owner / EADDRINUSE clean-exit (channel level)", () => {
  it("a second start() on the same port with exitCleanOnAddrInUse RESOLVES cleanly and flags addrInUse (no throw, no churn)", async () => {
    const port = randomTestPort();
    const owner = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2,
      auto_deny: true,
    });
    const second = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2,
      auto_deny: true,
    });
    try {
      await owner.start();
      // The supervised single-owner path: second start must NOT throw; it
      // resolves and flags addrInUse so the boot path can exit 0 (KeepAlive
      // sees a successful run, never a crash -> no restart churn).
      await expect(
        second.start({ exitCleanOnAddrInUse: true }),
      ).resolves.toBeUndefined();
      expect(second.addrInUse()).toBe(true);
      // At most one listener survives: the owner.
      expect(owner.addrInUse()).toBe(false);
    } finally {
      await second.stop().catch(() => {});
      await owner.stop().catch(() => {});
    }
  });

  it("WITHOUT exitCleanOnAddrInUse, a second start() on the same port still THROWS (interactive path)", async () => {
    const port = randomTestPort();
    const owner = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2,
      auto_deny: true,
    });
    const second = new DashboardApprovalChannel({
      port,
      host: "127.0.0.1",
      timeout_seconds: 2,
      auto_deny: true,
    });
    try {
      await owner.start();
      await expect(second.start()).rejects.toThrow();
      expect(second.addrInUse()).toBe(false);
    } finally {
      await second.stop().catch(() => {});
      await owner.stop().catch(() => {});
    }
  });
});
