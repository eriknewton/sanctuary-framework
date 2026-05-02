/**
 * Sanctuary MCP Server — Standalone Dashboard Tests
 *
 * Tests the standalone dashboard mode that runs without the MCP server.
 */

import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { persistUserProvidedPassphrase } from "../src/cocoon/passphrase.js";
import {
  bindWithRetry,
  randomTestPort,
} from "./util/port-collision-retry.js";

/**
 * Boot startStandaloneDashboard with a freshly chosen port, retrying on
 * EADDRINUSE up to 3 times with a small jitter. See
 * server/test/util/port-collision-retry.ts for rationale.
 */
async function startDashboardOnFreePort(
  options: Omit<Parameters<typeof startStandaloneDashboard>[0], "port"> = {},
): Promise<{ dashboard: DashboardApprovalChannel; port: number }> {
  return bindWithRetry(async () => {
    const port = randomTestPort();
    const dashboard = await startStandaloneDashboard({ ...options, port });
    return { dashboard, port };
  });
}

describe("Standalone Dashboard", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-test-dashboard-"));
    // Ensure test environment flags are set (auto-open is skipped in test)
    process.env.VITEST = "true";
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
    // Clean up temp storage
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    // Clean up env vars
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
  });

  it("starts a standalone dashboard HTTP server", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-standalone";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-standalone",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Dashboard should be serving
    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    // Should show login page (we didn't provide auth)
    expect(text).toContain("Sanctuary");
  });

  it("serves audit log API in standalone mode", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-audit";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-audit",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Authenticate and get audit log
    const res = await fetch(`http://127.0.0.1:${result.port}/api/audit-log`, {
      headers: { Authorization: "Bearer test-token-audit" },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    // Audit log returns array of entries (or object with entries array)
    // For fresh installation, should be empty
    if (Array.isArray(data)) {
      expect(data.length).toBe(0);
    } else {
      // AuditLog.query may return { entries: [] } or similar
      expect(data).toBeDefined();
    }
  });

  it("serves policy status in standalone mode", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-status";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-status",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/status`, {
      headers: { Authorization: "Bearer test-token-status" },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty("pending_count");
    expect(data).toHaveProperty("connected_clients");
    expect(data.pending_count).toBe(0);
  });

  it("uses custom port from options", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-port",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Should be accessible on the custom port
    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
  });

  it("requires credentials when existing data is present", async () => {
    // First run: create data with a passphrase
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-creds";

    const first = await startDashboardOnFreePort({
      passphrase: "first-run-passphrase",
      host: "127.0.0.1",
    });
    dashboard = first.dashboard;
    await dashboard.stop();
    dashboard = null;

    // Second run: no credentials should fail. The expected failure is at the
    // credentials-resolution stage which runs before any port is bound, so
    // EADDRINUSE retry is irrelevant here. We still pick a random port for
    // forward compatibility with code paths that may bind earlier.
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;

    let dashboard2: DashboardApprovalChannel | null = null;
    try {
      dashboard2 = await startStandaloneDashboard({
        port: randomTestPort(),
        host: "127.0.0.1",
      });
      // If we get here, clean up and fail
      await dashboard2.stop();
      expect.unreachable("Should have thrown due to missing credentials");
    } catch (err: unknown) {
      expect((err as Error).message).toMatch(/credentials|passphrase/i);
    } finally {
      if (dashboard2) await dashboard2.stop();
    }
  });

  it("auto-generates auth token when set to 'auto'", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "auto";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-auto",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Should serve login page (auth is enabled with auto-generated token)
    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("Sanctuary");
  });

  // v0.10.2 regression — dashboard must auto-load the per-tenant passphrase
  // from the same persistence the wrap CLI writes (Keychain on macOS, encrypted
  // fallback file everywhere else) when no explicit passphrase is supplied.
  // The pre-fix behaviour was to demand SANCTUARY_PASSPHRASE and report
  // `Identities loaded: 0` when the env var was missing, which is broken on a
  // multi-tenant host where one env-var passphrase cannot unlock N tenants.
  it("v0.10.2: auto-loads the stored passphrase for the tenant when no env var is set", async () => {
    const passphrase = "persisted-tenant-passphrase-0.10.2";

    // Pre-seed the tenant's passphrase exactly the way `sanctuary wrap` does.
    // Forcing `platformOverride: "linux"` plus an injected exec that always
    // returns code 1 ensures the persistence writes to the encrypted fallback
    // file rather than the real macOS Keychain or a live Linux Secret Service
    // on a developer host with gnome-keyring active.
    await persistUserProvidedPassphrase(passphrase, {
      storagePath: tempDir,
      platformOverride: "linux",
      exec: async () => ({ stdout: "", stderr: "", code: 1 }),
    });

    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    delete process.env.SANCTUARY_PASSPHRASE;

    // Boot with NO explicit passphrase — the dashboard must find the
    // persisted fallback-file entry by storage path and boot successfully.
    const result = await startDashboardOnFreePort({
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
  });

  // v0.10.2 regression — after the supplied passphrase decrypts at least one
  // identity, loopback callers skip the dashboard login prompt. The operator
  // has already proved principalship on the command line; re-prompting in the
  // auto-opened browser just trains users to paste secrets into web forms.
  it("v0.10.2: loopback callers skip the login prompt once identities decrypt", async () => {
    // Seed one identity encrypted under passphrase A so the second boot's
    // `loadResult.loaded > 0` gate flips.
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "autoauth-seed-token";
    const seed = await startDashboardOnFreePort({
      passphrase: "autoauth-tenant-passphrase",
      host: "127.0.0.1",
    });

    const { IdentityManager } = await import("../src/l1-cognitive/tools.js");
    const { FilesystemStorage } = await import("../src/storage/filesystem.js");
    const { deriveMasterKey, derivePurposeKey } = await import(
      "../src/core/key-derivation.js"
    );
    const { createIdentity } = await import("../src/core/identity.js");
    const { bytesToString } = await import("../src/core/encoding.js");
    const storage = new FilesystemStorage(`${tempDir}/state`);
    const rawParams = await storage.read("_meta", "key-params");
    const params = rawParams ? JSON.parse(bytesToString(rawParams)) : undefined;
    const { key: mk } = await deriveMasterKey("autoauth-tenant-passphrase", params);
    const idEncKey = derivePurposeKey(mk, "identity-encryption");
    const idMgr = new IdentityManager(storage, mk);
    await idMgr.load();
    const { storedIdentity } = createIdentity(
      "autoauth-test-identity",
      idEncKey,
      "passphrase"
    );
    await idMgr.save(storedIdentity);
    await seed.dashboard.stop();

    // Real boot — auth token is set, but loopback callers should bypass it.
    const result = await startDashboardOnFreePort({
      passphrase: "autoauth-tenant-passphrase",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // GET / from loopback with no Authorization header must serve the
    // dashboard HTML (not the login page). Pre-fix behaviour served the
    // login page here because auth_token was truthy.
    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
    const body = await res.text();
    // Login page contains "Auth Token" / "Session tokens expire" copy; the
    // real dashboard does not. Assert we got the real dashboard.
    expect(body).not.toMatch(/Auth Token/);
    expect(body).not.toMatch(/Session tokens expire/);

    // API endpoints must also work without a bearer token on loopback.
    const statusRes = await fetch(`http://127.0.0.1:${result.port}/api/status`);
    expect(statusRes.status).toBe(200);
    const statusJson = await statusRes.json();
    expect(statusJson).toHaveProperty("pending_count");
  });

  it("v0.10.2: the `identities none loaded` warning names the tenant's Keychain service", async () => {
    const logs: string[] = [];
    const origError = console.error;
    console.error = (...args: unknown[]) => {
      logs.push(args.map(String).join(" "));
    };
    try {
      // First boot establishes encrypted state under passphrase A.
      process.env.SANCTUARY_STORAGE_PATH = tempDir;
      process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-warn-a";

      const first = await startDashboardOnFreePort({
        passphrase: "tenant-passphrase-A",
        host: "127.0.0.1",
      });

      // Create an identity so there is an encrypted `_identities/*.enc` file
      // on disk. Without this the warning banner never fires (total === 0).
      const { IdentityManager } = await import("../src/l1-cognitive/tools.js");
      const { FilesystemStorage } = await import("../src/storage/filesystem.js");
      const { deriveMasterKey, derivePurposeKey } = await import(
        "../src/core/key-derivation.js"
      );
      const { createIdentity } = await import("../src/core/identity.js");
      const storage = new FilesystemStorage(`${tempDir}/state`);
      const { bytesToString } = await import("../src/core/encoding.js");
      const rawParams = await storage.read("_meta", "key-params");
      const params = rawParams ? JSON.parse(bytesToString(rawParams)) : undefined;
      const { key: mkA } = await deriveMasterKey("tenant-passphrase-A", params);
      const idEncKey = derivePurposeKey(mkA, "identity-encryption");
      const idMgr = new IdentityManager(storage, mkA);
      await idMgr.load();
      const { storedIdentity } = createIdentity(
        "test-identity",
        idEncKey,
        "passphrase"
      );
      await idMgr.save(storedIdentity);

      await first.dashboard.stop();

      // Second boot supplies a WRONG passphrase — encrypted identities exist
      // on disk, but the master key derived here cannot decrypt any of them.
      const second = await startDashboardOnFreePort({
        passphrase: "tenant-passphrase-B-WRONG",
        host: "127.0.0.1",
      });
      dashboard = second.dashboard;

      const banner = logs.join("\n");
      expect(banner).toMatch(/Encrypted identities found but NONE loaded/);
      // v0.10.4: banner names this tenant's per-tenant Keychain service so
      // operators can run `security find-generic-password -s <service> -w`.
      expect(banner).toMatch(/sanctuary-passphrase-[0-9a-f]{12}/);
      // v0.10.4: banner points at the canonical schema doc (which contains
      // every diagnostic recipe) rather than inlining a remediation
      // command that may go stale.
      expect(banner).toMatch(/server\/docs\/keychain-schema\.md/);
      // v0.10.4: the misleading `SANCTUARY_PASSPHRASE=<your-passphrase>`
      // hint that v0.10.1–v0.10.3 printed must not return.
      expect(banner).not.toMatch(/SANCTUARY_PASSPHRASE=<your-passphrase>/);
    } finally {
      console.error = origError;
    }
  });
});
