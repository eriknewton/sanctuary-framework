/**
 * Sanctuary MCP Server — Standalone Dashboard Tests
 *
 * Tests the standalone dashboard mode that runs without the MCP server.
 */

import { describe, it, expect, afterEach, beforeEach } from "vitest";
import { startStandaloneDashboard } from "../src/dashboard-standalone.js";
import type { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { persistUserProvidedPassphrase } from "../src/wrap/passphrase.js";
import {
  bindWithRetry,
  randomTestPort,
} from "./util/port-collision-retry.js";

type StandaloneDashboardStartOptions = Omit<
  Parameters<typeof startStandaloneDashboard>[0],
  "port"
>;

let isolatedDiscoveryOptions:
  | StandaloneDashboardStartOptions["discoveryOptions"]
  | undefined;

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
    const dashboard = await startStandaloneDashboard({
      // Durable-fix: a first-run mint now requires confirmed off-host capture.
      // In CI there is no tty, so default to noConfirm + an off-host escrow
      // target (SANCTUARY_RECOVERY_OUT, set per-test) so the gate is satisfied
      // deterministically. Individual tests may still override noConfirm.
      noConfirm: true,
      // Ephemeral distress port so parallel dashboards never contend on 8741.
      distressPort: 0,
      ...options,
      discoveryOptions: options.discoveryOptions ?? isolatedDiscoveryOptions,
      port,
    });
    return { dashboard, port };
  });
}

describe("Standalone Dashboard", () => {
  let dashboard: DashboardApprovalChannel | null = null;
  let tempDir: string;
  let escrowDir: string;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-test-dashboard-"));
    escrowDir = await mkdtemp(join(tmpdir(), "sanctuary-test-dash-escrow-"));
    const discoveryRoot = join(tempDir, "discovery-root");
    const discoveryHome = join(tempDir, "discovery-home");
    await mkdir(discoveryRoot, { recursive: true, mode: 0o700 });
    await mkdir(discoveryHome, { recursive: true, mode: 0o700 });
    isolatedDiscoveryOptions = {
      root: discoveryRoot,
      home: discoveryHome,
      env: {},
    };
    // Ensure test environment flags are set (auto-open is skipped in test)
    process.env.VITEST = "true";
    // Durable-fix: off-host recovery escrow target for first-run mints, so the
    // provisioning gate is satisfied non-interactively (no tty in CI). In a
    // SEPARATE temp dir so it is always outside the fortress storage path.
    process.env.SANCTUARY_RECOVERY_OUT = join(escrowDir, "recovery.txt");
  });

  afterEach(async () => {
    if (dashboard) {
      await dashboard.stop();
      dashboard = null;
    }
    // Clean up temp storage
    await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    await rm(escrowDir, { recursive: true, force: true }).catch(() => {});
    // Clean up env vars
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
    delete process.env.SANCTUARY_DASHBOARD_PORT;
    delete process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE;
    delete process.env.SANCTUARY_RECOVERY_OUT;
    isolatedDiscoveryOptions = undefined;
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

  it("threads allowPlaintextRemote into the approval channel config", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-remote-plaintext";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-remote-plaintext",
      host: "0.0.0.0",
      allowPlaintextRemote: true,
    });
    dashboard = result.dashboard;

    const channel = dashboard as unknown as {
      config: { allow_plaintext_remote?: boolean };
    };
    expect(channel.config.allow_plaintext_remote).toBe(true);
  });

  it("refuses standalone non-loopback plaintext when allowPlaintextRemote is unset", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-remote-refuse";

    await expect(
      startStandaloneDashboard({
        passphrase: "test-passphrase-remote-refuse",
        host: "0.0.0.0",
        port: randomTestPort(),
        distressPort: 0,
        noConfirm: true,
        discoveryOptions: isolatedDiscoveryOptions,
      })
    ).rejects.toThrow(/refusing to start on non-loopback interface/i);
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

  it("serves /api/snapshot in standalone mode (F-1.3.2-N-002)", async () => {
    // v1.3.2 Mini1 drill finding: /api/snapshot returned 404 in standalone
    // mode because the route only existed in the co-located server
    // (dashboard/api.ts); the standalone legacy route table never
    // registered it. This pins the fix: the standalone dashboard serves
    // the same ProtectionSnapshot document the co-located server does.
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-snapshot";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-snapshot",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/snapshot`, {
      headers: { Authorization: "Bearer test-token-snapshot" },
    });
    expect(res.status).toBe(200);
    const snapshot = await res.json();
    expect(snapshot.mode).toBe("standalone");
    expect(snapshot).toHaveProperty("overall");
    expect(snapshot).toHaveProperty("agent");
    expect(snapshot).toHaveProperty("layers");
    expect(snapshot.layers).toHaveProperty("l1");
    expect(snapshot.layers).toHaveProperty("l4");
    expect(snapshot).toHaveProperty("pending_approvals");
    expect(snapshot).toHaveProperty("generated_at");
    expect(snapshot).toHaveProperty("server_version");
  });

  it("rejects unauthenticated /api/snapshot requests in standalone mode", async () => {
    // The fix must not weaken the auth posture: /api/snapshot sits behind
    // the same bearer-token gate as every other legacy /api/* route. The
    // helper also pins tenant discovery to an empty test root, so this fresh
    // fortress cannot auto-discover a parallel tenant and engage loopback
    // auto-auth.
    const authToken = "test-token-snapshot-auth";
    delete process.env.SANCTUARY_STORAGE_PATH;
    delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-snapshot-auth",
      host: "127.0.0.1",
      storagePath: tempDir,
      authToken,
      recoveryOut: join(escrowDir, "recovery.txt"),
    });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/api/snapshot`);
    expect(res.status).toBe(401);
    const authed = await fetch(`http://127.0.0.1:${result.port}/api/snapshot`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });
    expect(authed.status).toBe(200);
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
        distressPort: 0,
        discoveryOptions: isolatedDiscoveryOptions,
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

    const { IdentityManager } = await import("../src/cognitive/tools.js");
    const { FilesystemStorage } = await import("../src/storage/filesystem.js");
    const { derivePurposeKey } = await import("../src/core/key-derivation.js");
    const { createIdentity } = await import("../src/core/identity.js");
    // Sovereign-custody build: unlock through the unified path — a local
    // Argon2id re-derivation from key-params would produce a DIFFERENT
    // master than the envelope holds (the exact divergence class the
    // custody envelope ended; its MAC check catches the attempt).
    const { establishMaster } = await import("../src/core/master-custody.js");
    const storage = new FilesystemStorage(`${tempDir}/state`);
    const { masterKey: mk } = await establishMaster({
      storage,
      passphrase: "autoauth-tenant-passphrase",
    });
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

  it("v0.10.2/custody: a wrong passphrase fails closed and names the tenant's Keychain service", async () => {
    // First boot establishes encrypted state under passphrase A.
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-warn-a";

    const first = await startDashboardOnFreePort({
      passphrase: "tenant-passphrase-A",
      host: "127.0.0.1",
    });
    await first.dashboard.stop();

    // Second boot supplies a WRONG passphrase. Sovereign-custody build:
    // the boot FAILS CLOSED (booting with a wrong master would split state,
    // not recover it). The error carries the v0.10.4 diagnostics that used
    // to live in the warning banner.
    let threw: Error | null = null;
    try {
      const second = await startDashboardOnFreePort({
        passphrase: "tenant-passphrase-B-WRONG",
        host: "127.0.0.1",
      });
      dashboard = second.dashboard;
    } catch (err) {
      threw = err as Error;
    }

    expect(threw).not.toBeNull();
    expect(threw!.message).toMatch(/Encrypted identities found but NONE loaded/);
    // v0.10.4: names this tenant's per-tenant Keychain service so operators
    // can run `security find-generic-password -s <service> -w`.
    expect(threw!.message).toMatch(/sanctuary-passphrase-[0-9a-f]{16}/);
    // v0.10.4: points at the canonical schema doc (which contains every
    // diagnostic recipe) rather than inlining a remediation command.
    expect(threw!.message).toMatch(/server\/docs\/keychain-schema\.md/);
    // v0.10.4: the misleading `SANCTUARY_PASSPHRASE=<your-passphrase>`
    // hint that v0.10.1–v0.10.3 printed must not return.
    expect(threw!.message).not.toMatch(/SANCTUARY_PASSPHRASE=<your-passphrase>/);
  });

  // v1.3 cycle 2: standalone dashboard must wire TaskService so
  // `sanctuary task create/list/show/update` CLI commands work.
  // Pre-fix, these hit /api/hub/tasks/* and got task_service_not_configured.
  // The standalone boot path now creates a fortress-local identity if none
  // exists, so this works on a fresh fortress (matching the drill flow).
  it("v1.3: task API endpoints work in standalone mode", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-task";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-task",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const base = `http://127.0.0.1:${result.port}`;
    const headers = {
      Authorization: "Bearer test-token-task",
      "Content-Type": "application/json",
    };

    // POST /api/hub/tasks - create a task
    const createRes = await fetch(`${base}/api/hub/tasks`, {
      method: "POST",
      headers,
      body: JSON.stringify({
        title: "Standalone TaskService test",
        creator: "drill-test",
      }),
    });
    // Must not return task_service_not_configured (which would be 500 or 400).
    // Accept 200/201 as success.
    const createBody = await createRes.json();
    if (createRes.status >= 300) {
      throw new Error(`task create returned ${createRes.status}: ${JSON.stringify(createBody)}`);
    }
    const taskId =
      createBody.data?.task?.id ?? createBody.id ?? createBody.task_id;
    expect(taskId).toBeTruthy();

    // GET /api/hub/tasks/:id - retrieve the created task
    const showRes = await fetch(`${base}/api/hub/tasks/${taskId}`, { headers });
    expect(showRes.status).toBe(200);
    const showBody = await showRes.json();
    const fetchedTask = showBody.data?.task ?? showBody;
    expect(fetchedTask.title).toBe("Standalone TaskService test");

    // Full approval flow: in_progress -> ready_for_review -> approve
    const ipRes = await fetch(`${base}/api/hub/tasks/${taskId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ status: "in_progress", actor: "test" }),
    });
    expect(ipRes.status).toBe(200);

    const rfrRes = await fetch(`${base}/api/hub/tasks/${taskId}`, {
      method: "PATCH",
      headers,
      body: JSON.stringify({ status: "ready_for_review", actor: "test" }),
    });
    expect(rfrRes.status).toBe(200);
    const rfrBody = await rfrRes.json();
    const approvalRequestId =
      rfrBody.data?.task?.approval_request_id ?? rfrBody.approval_request_id;
    expect(approvalRequestId).toBeTruthy();

    // List inbox - should contain the approval
    const inboxRes = await fetch(`${base}/api/hub/inbox`, { headers });
    expect(inboxRes.status).toBe(200);
    const inboxBody = await inboxRes.json();
    const items = inboxBody.data?.items ?? [];
    const matchingItem = items.find(
      (i: any) => i.item_id === approvalRequestId,
    );
    expect(matchingItem).toBeTruthy();

    // Approve the item
    const approveRes = await fetch(
      `${base}/api/hub/inbox/${encodeURIComponent(approvalRequestId)}/approve`,
      { method: "POST", headers, body: JSON.stringify({}) },
    );
    if (approveRes.status >= 400) {
      const errBody = await approveRes.json();
      throw new Error(
        `approve returned ${approveRes.status}: ${JSON.stringify(errBody)}`,
      );
    }
    expect(approveRes.status).toBe(200);
  });

  // ── Remote operator console drill regressions (PR #375) ────────────────
  // Three defects an Erik-present browser drill caught that server-side curl
  // could not see. Each test pins the fix.

  it("FIX 1: GET /api/health sends Access-Control-Allow-Origin so a cross-host fleet probe can read it", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-health-cors";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-health-cors",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Simulate the switcher's cross-host browser probe: a different Origin
    // than the host it connected to.
    const crossOrigin = "https://100.64.0.5:3501";
    const res = await fetch(`http://127.0.0.1:${result.port}/api/health`, {
      headers: { Origin: crossOrigin },
    });
    expect(res.status).toBe(200);
    // The browser would block the response body without this header; the fix
    // reflects the request Origin so the cross-host probe can read `ok`.
    expect(res.headers.get("access-control-allow-origin")).toBe(crossOrigin);
    // SECURITY: never the reflected-origin + credentials account-takeover combo.
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
    const body = await res.json();
    expect(body.ok).toBe(true);
    // The probe stays liveness-only: no secrets, no posture, no auth state.
    expect(body).not.toHaveProperty("supervisor");
    expect(body).not.toHaveProperty("arm_state");
  });

  it("FIX 1 (security): a protected route does NOT reflect a cross-origin Origin", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-protected-cors";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-protected-cors",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // A protected JSON route with a foreign Origin must NOT get an ACAO header
    // reflecting that origin (the permissive header is scoped to /api/health).
    const crossOrigin = "https://evil.example:3501";
    const res = await fetch(`http://127.0.0.1:${result.port}/api/status`, {
      headers: { Origin: crossOrigin },
    });
    expect(res.headers.get("access-control-allow-origin")).not.toBe(
      crossOrigin,
    );
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it("FIX 3: unauthenticated remote GET / serves the login page when an auth token is required", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-remote-login";

    // Remote (non-loopback) bind: loopback auto-auth is OFF, so an
    // unauthenticated browser at the root URL must get the login box, not a
    // data-less shell.
    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-remote-login",
      host: "0.0.0.0",
      allowPlaintextRemote: true,
    });
    dashboard = result.dashboard;

    const base = `http://127.0.0.1:${result.port}`;

    // No bearer => login page (offers a token box), NOT the empty concierge
    // shell. Default-flip preserves the remote-login affordance for `/`.
    const noAuth = await fetch(`${base}/`);
    expect(noAuth.status).toBe(200);
    const noAuthBody = await noAuth.text();
    expect(noAuthBody).toMatch(/Auth Token/);
    expect(noAuthBody).toMatch(/Session tokens expire/);
    // S2 (2026-07-18): the posture page identity is "Security Posture" (copy
    // rule; renamed off the retired term). The login page is not that shell.
    expect(noAuthBody).not.toContain("Security Posture");

    // The v1.1 SPA aliases get the same login affordance.
    const aliasNoAuth = await fetch(`${base}/dashboard`);
    expect(aliasNoAuth.status).toBe(200);
    expect(await aliasNoAuth.text()).toMatch(/Auth Token/);

    // With a valid bearer token, the SAME root path serves the v1.1 concierge
    // (the single default surface) - auth is not weakened, the login box is
    // just the unauthenticated entry point. Default-flip: `/` is the concierge,
    // NOT the separate posture shell (which is preserved at /posture).
    const authed = await fetch(`${base}/`, {
      headers: { Authorization: "Bearer test-token-remote-login" },
    });
    expect(authed.status).toBe(200);
    const authedBody = await authed.text();
    expect(authedBody).toContain('id="main"');
    // S2: the v1.1 concierge surface is not the posture shell.
    expect(authedBody).not.toContain("Security Posture");
    expect(authedBody).not.toMatch(/Session tokens expire/);

    // SECURITY: the data routes still require the token regardless of the
    // login affordance - an unauthenticated posture read is 401, not data.
    const dataNoAuth = await fetch(`${base}/api/posture/home`);
    expect(dataNoAuth.status).toBe(401);
  });

  it("FIX 3 (loopback): an auto-auth loopback GET / serves the v1.1 concierge (default surface), not the login page", async () => {
    // Seed an identity so standalone enables loopback auto-auth.
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-loopback-shell";

    const seed = await startDashboardOnFreePort({
      passphrase: "loopback-shell-passphrase",
      host: "127.0.0.1",
    });

    const { IdentityManager } = await import("../src/cognitive/tools.js");
    const { FilesystemStorage } = await import("../src/storage/filesystem.js");
    const { derivePurposeKey } = await import("../src/core/key-derivation.js");
    const { createIdentity } = await import("../src/core/identity.js");
    const { establishMaster } = await import("../src/core/master-custody.js");
    const storage = new FilesystemStorage(`${tempDir}/state`);
    const { masterKey: mk } = await establishMaster({
      storage,
      passphrase: "loopback-shell-passphrase",
    });
    const idEncKey = derivePurposeKey(mk, "identity-encryption");
    const idMgr = new IdentityManager(storage, mk);
    await idMgr.load();
    const { storedIdentity } = createIdentity(
      "loopback-shell-identity",
      idEncKey,
      "passphrase",
    );
    await idMgr.save(storedIdentity);
    await seed.dashboard.stop();

    const result = await startDashboardOnFreePort({
      passphrase: "loopback-shell-passphrase",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    // Loopback auto-auth => the v1.1 concierge (default surface), never the
    // login page. Default-flip: `/` serves the concierge, NOT the posture shell
    // (the posture board is preserved at /posture and folded into the concierge).
    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('id="main"');
    // S2: the v1.1 concierge surface is not the posture shell.
    expect(body).not.toContain("Security Posture");
    expect(body).not.toMatch(/Auth Token/);
    expect(body).not.toMatch(/Session tokens expire/);

    // The posture board is preserved at /posture (frozen surface).
    const postureRes = await fetch(`http://127.0.0.1:${result.port}/posture`);
    expect(postureRes.status).toBe(200);
    // S2: the posture page identity is "Security Posture" (renamed off the
    // retired term, which must never appear on screen).
    expect(await postureRes.text()).toContain("Security Posture");
  });
});
