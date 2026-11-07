/**
 * Sanctuary MCP Server - Standalone Dashboard Tests
 *
 * Tests the standalone dashboard mode that runs without the MCP server.
 */
import { describe, it, expect, afterEach, beforeEach, vi } from "vitest";
import { startStandaloneDashboard, handleStandaloneShutdownSignal, __resetStandaloneShutdownStateForTest } from "../src/dashboard-standalone.js";
import * as escrowModule from "../src/wrap/boot-recovery-escrow.js";
import { DashboardApprovalChannel } from "../src/principal-policy/dashboard.js";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { persistUserProvidedPassphrase } from "../src/wrap/passphrase.js";
import {
  withExclusiveMasterRotationBarrier,
  kernelBackedCrossProcessLockPlatformSupported,
} from "../src/storage/cross-process-lock.js";

type StandaloneDashboardStartOptions = Omit<
  Parameters<typeof startStandaloneDashboard>[0],
  "port"
>;

let isolatedDiscoveryOptions:
  | StandaloneDashboardStartOptions["discoveryOptions"]
  | undefined;

/**
 * Ephemeral ports keep independent dashboard fixtures from contending.
 * The helper retains the channel until its bound address is available,
 * so address read-back failure can still close the listener.
 */
async function startDashboardOnFreePort(
  options: Omit<Parameters<typeof startStandaloneDashboard>[0], "port"> = {},
): Promise<{ dashboard: DashboardApprovalChannel; port: number }> {
  return (async () => {
    const port = EPHEMERAL_PORT;
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
    return standaloneBoundAddress(dashboard);
  })();
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
    captureStandaloneResources();
    process.env.VITEST = "true";
    // Durable-fix: off-host recovery escrow target for first-run mints, so the
    // provisioning gate is satisfied non-interactively (no tty in CI). In a
    // SEPARATE temp dir so it is always outside the fortress storage path.
    process.env.SANCTUARY_RECOVERY_OUT = join(escrowDir, "recovery.txt");
  });

  afterEach(async () => {
    try {
      await stopStandaloneResources(dashboard);
    } finally {
      dashboard = null;
      await Promise.all([tempDir, escrowDir].map(
        (path) => rm(path, { recursive: true, force: true })));
      // Restore this test's environment even when resource teardown fails.
      delete process.env.SANCTUARY_STORAGE_PATH;
      delete process.env.SANCTUARY_DASHBOARD_ENABLED;
      delete process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN;
      delete process.env.SANCTUARY_DASHBOARD_PORT;
      delete process.env.SANCTUARY_DASHBOARD_ALLOW_PLAINTEXT_REMOTE;
      delete process.env.SANCTUARY_RECOVERY_OUT;
      isolatedDiscoveryOptions = undefined;
    }
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
        port: EPHEMERAL_PORT,
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
    // this allocation cannot reach the dashboard listener. If this path ever
    // binds, move the allocation and startup into the retry helper.
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;

    let dashboard2: DashboardApprovalChannel | null = null;
    try {
      dashboard2 = await startStandaloneDashboard({
        port: EPHEMERAL_PORT,
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

  // v0.10.2 regression - dashboard must auto-load the per-tenant passphrase
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

    // Boot with NO explicit passphrase - the dashboard must find the
    // persisted fallback-file entry by storage path and boot successfully.
    const result = await startDashboardOnFreePort({
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const res = await fetch(`http://127.0.0.1:${result.port}/`);
    expect(res.status).toBe(200);
  });

  // v0.10.2 regression - after the supplied passphrase decrypts at least one
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
    // Sovereign-custody build: unlock through the unified path - a local
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

    // Real boot - auth token is set, but loopback callers should bypass it.
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

  it("answers optional v1.1 panel reads with a typed standalone-mode signal, while other misses stay 404", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-optional-panels";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-optional-panels",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const headers = { Authorization: "Bearer test-token-optional-panels" };

    for (const path of STANDALONE_OPTIONAL_PANEL_PATHS) {
      const res = await fetch(`http://127.0.0.1:${result.port}${path}`, {
        headers,
      });
      expect(res.status, path).toBe(503);
      expect(await res.json()).toEqual(dashboardModeNotServedBody("standalone"));
    }

    const missing = await fetch(
      `http://127.0.0.1:${result.port}/api/not-a-real-panel`,
      { headers },
    );
    expect(missing.status).toBe(404);
  });

  it("keeps standalone optional panel reads behind the same unauthenticated response as other protected API reads", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-optional-panels-auth";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-optional-panels-auth",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;
    dashboard.setAutoAuthLocalhost(false);

    const control = await fetch(`http://127.0.0.1:${result.port}/api/status`);
    const controlText = await control.text();
    expect(control.status).toBe(401);

    for (const path of STANDALONE_OPTIONAL_PANEL_PATHS) {
      const res = await fetch(`http://127.0.0.1:${result.port}${path}`);
      expect(res.status, path).toBe(control.status);
      expect(await res.text(), path).toBe(controlText);
      expect(res.status, path).not.toBe(503);
    }
  });

  it("does not apply the standalone optional-panel signal to mutations or exact-path subroutes", async () => {
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-optional-panels-scope";

    const result = await startDashboardOnFreePort({
      passphrase: "test-passphrase-optional-panels-scope",
      host: "127.0.0.1",
    });
    dashboard = result.dashboard;

    const headers = { Authorization: "Bearer test-token-optional-panels-scope" };
    const probes: Array<[string, RequestInit]> = [
      ["/api/honeypot/tool-traps", { method: "POST", headers }],
      ["/api/auto-trigger/rules/example", { method: "PATCH", headers }],
      ["/api/auto-trigger/rules/example", { method: "GET", headers }],
    ];

    for (const [path, init] of probes) {
      const res = await fetch(`http://127.0.0.1:${result.port}${path}`, init);
      expect(res.status, `${init.method ?? "GET"} ${path}`).not.toBe(503);
    }
  });

  it("serves optional panel routes normally when hosted route runtimes are mounted", async () => {
    const hosted = await startHostedOptionalPanelDashboard();
    dashboard = hosted.dashboard;

    const headers = { Authorization: `Bearer ${hosted.authToken}` };
    for (const path of STANDALONE_OPTIONAL_PANEL_PATHS) {
      const res = await fetch(`${hosted.baseUrl}${path}`, { headers });
      expect(res.status, path).not.toBe(503);
      expect(res.status, path).not.toBe(404);
      expect(res.status, path).toBe(200);
    }
  });
});

import { AuditLog } from "../src/operational/audit-log.js";
import { generateRandomKey } from "../src/core/random.js";
import { MemoryStorage } from "../src/storage/memory.js";
import {
  ActionDispatcher,
  NotifyOperatorAction,
} from "../src/auto-trigger/action-dispatcher.js";
import { CalibrationSuggester } from "../src/auto-trigger/calibration-suggester.js";
import { ThresholdConfigStore } from "../src/auto-trigger/threshold-config-store.js";
import { TrapRegistry } from "../src/honeypot/trap-registry.js";
import { ToolCallTrapRuntime } from "../src/honeypot/tool-call-trap-runtime.js";
import { CredentialTrapRuntime } from "../src/honeypot/credential-trap-runtime.js";
import { SentinelFindingStore } from "../src/sentinel/sentinel-finding-store.js";
import { UnifiedInboxBridge } from "../src/principal-policy/unified-inbox-bridge.js";
import { UnifiedInboxStore } from "../src/principal-policy/unified-inbox-store.js";
import { UnifiedInboxPrefsStore } from "../src/principal-policy/unified-inbox-prefs-store.js";
import {
  STANDALONE_OPTIONAL_PANEL_PATHS,
  dashboardModeNotServedBody,
} from "../src/dashboard/standalone-mode-signal.js";

async function startHostedOptionalPanelDashboard(): Promise<{
  dashboard: DashboardApprovalChannel;
  authToken: string;
  baseUrl: string;
}> {
  const authToken = "hosted-optional-panel-token";
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const fortressId = "hosted_optional_panel_fortress";
  const identityId = "hosted_optional_panel_operator";
  const port = EPHEMERAL_PORT;
  const dashboard = new DashboardApprovalChannel({
    port,
    host: "127.0.0.1",
    timeout_seconds: 30,
    auth_token: authToken,
    auto_open: false,
  });

  const autoTriggerStore = new ThresholdConfigStore({
    storage,
    masterKey,
    fortressId,
  });
  const autoTriggerDispatcher = new ActionDispatcher({
    store: autoTriggerStore,
    action: new NotifyOperatorAction(auditLog, identityId, fortressId),
    auditLog,
    fortressId,
    identityId,
  });
  const autoTriggerSuggester = new CalibrationSuggester({
    store: autoTriggerStore,
    dispatcher: autoTriggerDispatcher,
    auditLog,
    fortressId,
    identityId,
    tickIntervalMs: 0,
  });
  dashboard.setAutoTrigger({
    store: autoTriggerStore,
    dispatcher: autoTriggerDispatcher,
    suggester: autoTriggerSuggester,
  });

  const inboxStore = new UnifiedInboxStore({
    storage,
    masterKey,
    fortressId,
  });
  dashboard.setUnifiedInbox({
    bridge: new UnifiedInboxBridge({
      auditLog,
      identityId,
      fortressId,
      store: inboxStore,
    }),
    prefsStore: new UnifiedInboxPrefsStore({
      storage,
      masterKey,
      fortressId,
      operatorId: identityId,
    }),
    fortressId,
    identityId,
  });

  const findingStore = new SentinelFindingStore({
    storage,
    masterKey,
    fortressId,
  });
  const trapRegistry = new TrapRegistry();
  dashboard.setHoneypotRegistry({
    registry: trapRegistry,
    findingStore,
    auditLog,
    operatorId: identityId,
    fortressId,
    toolCallRuntime: new ToolCallTrapRuntime({
      registry: trapRegistry,
      findingStore,
      auditLog,
      operatorId: identityId,
      fortressId,
    }),
    credentialRuntime: new CredentialTrapRuntime({
      registry: trapRegistry,
      findingStore,
      auditLog,
      operatorId: identityId,
      fortressId,
    }),
  });

  await dashboard.start();
  return {
    dashboard,
    authToken,
    baseUrl: `http://127.0.0.1:${((dashboard as unknown as { httpServer: import("node:net").Server }).httpServer.address() as import("node:net").AddressInfo).port}`,
  };
}

// Keep resource ownership in the test: refused starts never return a channel.
// Helpers live here to preserve the existing diagnostic baseline's line anchors.
import { DistressListener } from "../src/distress/listener.js";

let capturedChannels: DashboardApprovalChannel[] = [];
let distressListeners: DistressListener[] = [];

function captureStandaloneResources(): void {
  capturedChannels = [];
  distressListeners = [];
  const startChannel = DashboardApprovalChannel.prototype.start;
  vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(function (this: DashboardApprovalChannel, ...args) {
    capturedChannels.push(this);
    return startChannel.apply(this, args);
  });
  const startDistress = DistressListener.prototype.start;
  vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener, ...args) {
    distressListeners.push(this);
    return startDistress.apply(this, args);
  });
}

async function stopStandaloneResources(dashboard: DashboardApprovalChannel | null): Promise<void> {
  const failures: unknown[] = [];
  const channels = new Set(capturedChannels);
  if (dashboard) channels.add(dashboard);
  try {
    for (const cleanup of [
      // stop clears the constructor interval even when the HTTP bind refused.
      ...Array.from(channels, (channel) => () => channel.stop()),
      ...distressListeners.map((listener) => async () => {
        await listener.stop();
        expect(listener.address()).toBeNull();
      }),
    ]) {
      try { await cleanup(); } catch (error) { failures.push(error); }
    }
    if (capturedChannels.length || distressListeners.length) {
      // Await runtime removal and custody release without exiting Vitest.
      const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
      try {
        await handleStandaloneShutdownSignal("SIGTERM");
      } catch (error) {
        failures.push(error);
      } finally {
        exit.mockRestore();
        __resetStandaloneShutdownStateForTest();
      }
    }
  } finally {
    vi.restoreAllMocks();
  }
  if (failures.length) throw new AggregateError(failures, "Standalone teardown failed");
}
function deferred<T = void>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

describe.skipIf(!kernelBackedCrossProcessLockPlatformSupported(process.platform))("Standalone session lifetime", () => {
  let root: string;
  let dashboard: DashboardApprovalChannel | undefined;
  let sessions: custodyModule.EstablishMasterResult[];
  let savedEnv: NodeJS.ProcessEnv;
  let channels: DashboardApprovalChannel[];
  let listeners: DistressListener[];
  const passphrase = "standalone-session-test-passphrase";
  const startup = (options: Parameters<typeof startStandaloneDashboard>[0] = {}) => startStandaloneDashboard({
    passphrase, host: "127.0.0.1", port: EPHEMERAL_PORT, distressPort: EPHEMERAL_PORT,
    ...options,
  });
  const exclusive = () => withExclusiveMasterRotationBarrier(
    new FilesystemStorage(join(root, "state")), custodyModule.CUSTODY_WRITE_LOCK_NAMESPACE,
    custodyModule.MASTER_ROTATION_BARRIER_NAME, async () => "entered", { timeoutMs: 0 },
  );
  const assertReleased = async () => {
    expect(sessions.length).toBe(1);
    expect(sessions[0]!.masterWriteBarrier!.signal.aborted).toBe(true);
    await expect(exclusive()).resolves.toBe("entered");
  };

  const holdRelease = () => {
    const entered = deferred();
    const finish = deferred();
    const establish = vi.mocked(custodyModule.establishMaster).getMockImplementation()!;
    vi.spyOn(custodyModule, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options);
      const lease = session.masterWriteBarrier!;
      const release = lease.release.bind(lease);
      vi.spyOn(lease, "release").mockImplementation(async () => {
        entered.resolve();
        await finish.promise;
        await release();
      });
      return session;
    });
    return { entered, finish };
  };

  beforeEach(async () => {
    root = await mkdtemp(join(tmpdir(), "standalone-session-"));
    savedEnv = { ...process.env };
    process.env.HOME = root;
    process.env.SANCTUARY_STORAGE_PATH = root;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "standalone-session-token";
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    const seed = await custodyModule.establishMaster({
      storage: new FilesystemStorage(join(root, "state")), passphrase,
      firstRun: { installMode: "headless", mintRecoveryKey: false }, storagePathHint: root,
    });
    await seed.masterWriteBarrier?.release();
    seed.masterKey.fill(0);
    sessions = [];
    channels = [];
    listeners = [];
    const markStandalone = vi.mocked(DashboardApprovalChannel.prototype.setStandaloneMode).getMockImplementation()!;
    vi.spyOn(DashboardApprovalChannel.prototype, "setStandaloneMode").mockImplementation(function (this: DashboardApprovalChannel, ...args) {
      channels.push(this);
      return markStandalone.apply(this, args);
    });
    const listen = vi.mocked(DistressListener.prototype.start).getMockImplementation()!;
    vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener) {
      listeners.push(this);
      return listen.call(this);
    });
    const establish = vi.mocked(custodyModule.establishMaster).getMockImplementation()!;
    vi.spyOn(custodyModule, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options);
      sessions.push(session);
      return session;
    });
  });

  afterEach(async () => {
    try {
      await dashboard?.stop().catch(() => undefined);
    } finally {
      dashboard = undefined;
      vi.restoreAllMocks();
      for (const channel of channels) await channel.stop().catch(() => undefined);
      for (const listener of listeners) {
        try { await listener.stop(); } catch { /* Lease rescue must run after a listener failure. */ }
      }
      for (const session of sessions) {
        await session.masterWriteBarrier?.release();
        session.masterKey.fill(0);
      }
      process.env = savedEnv;
      await rm(root, { recursive: true, force: true });
    }
  });

  it.each([false, true])("hosted stop unregisters after finalization with cleanup failure=%s", async (fails) => {
    __resetStandaloneShutdownStateForTest();
    const beforeExit = new Set(process.listeners("exit"));
    const cleanups = new Set<() => Promise<void>>();
    const unregister = vi.fn();
    const { entered, finish } = holdRelease();
    try {
      dashboard = await startup({ processLifecycle: {
        registerCleanup: (cleanup) => {
          cleanups.add(cleanup);
          return () => { cleanups.delete(cleanup); unregister(); };
        },
      } });
      expect(cleanups.size).toBe(1);
      expect(process.listeners("SIGINT")).not.toContain(handleStandaloneShutdownSignal);
      expect(process.listeners("SIGTERM")).not.toContain(handleStandaloneShutdownSignal);
      expect(process.listeners("exit").filter((listener) => !beforeExit.has(listener))).toHaveLength(1);
      if (fails) {
        const flush = AuditLog.prototype.flush;
        vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async function (this: AuditLog) {
          await flush.call(this);
          throw new Error("hosted flush sentinel");
        });
      }
      const stopped = [...cleanups][0]!();
      await entered.promise;
      expect(unregister).not.toHaveBeenCalled();
      expect(cleanups.size).toBe(1);
      finish.resolve();
      await stopped; // The existing signal cleanup reports and swallows stop's rejection.
      await assertReleased();
      expect(unregister).toHaveBeenCalledOnce();
      expect(cleanups.size).toBe(0);
      expect(process.listeners("exit").filter((listener) => !beforeExit.has(listener))).toEqual([]);
    } finally {
      finish.resolve();
      await dashboard?.stop().catch(() => undefined);
      __resetStandaloneShutdownStateForTest();
    }
  });

  it("stop releases the standalone session after final persistence", async () => {
    dashboard = await startup();
    const lease = sessions[0]!.masterWriteBarrier!;
    const release = vi.spyOn(lease, "release");
    expect(lease.signal.aborted).toBe(false);
    await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    const saving = deferred();
    const save = deferred();
    const originalSave = BaselineTracker.prototype.save;
    vi.spyOn(BaselineTracker.prototype, "save").mockImplementation(async function (this: BaselineTracker) {
      saving.resolve();
      await save.promise;
      await originalSave.call(this);
    });
    const first = dashboard.stop();
    const concurrent = dashboard.stop();
    try {
      await saving.promise;
      expect(release).not.toHaveBeenCalled();
      expect(lease.signal.aborted).toBe(false);
    } finally {
      save.resolve();
      await first;
    }
    await assertReleased();
    expect(concurrent).toBe(first);
    expect(dashboard.stop()).toBe(first);
    expect(release).toHaveBeenCalledTimes(1);
  });

  it.each(["policy", "constructor", "bind"] as const)("startup releases its session after %s failure", async (phase) => {
    const error = new Error("startup sentinel");
    if (phase === "policy") vi.spyOn(policyModule, "loadPrincipalPolicy").mockRejectedValue(error);
    if (phase === "constructor") vi.spyOn(channelModule, "DashboardApprovalChannel").mockImplementation(function () { throw error; });
    if (phase === "bind") vi.spyOn(DashboardApprovalChannel.prototype, "start").mockRejectedValue(error);
    const { entered, finish } = holdRelease();
    let settled = false;
    const pending = startup().catch((failure: unknown) => failure).finally(() => { settled = true; });
    try {
      await entered.promise;
      expect(settled).toBe(false);
      expect(sessions[0]!.masterWriteBarrier!.signal.aborted).toBe(false);
    } finally {
      finish.resolve();
      await pending;
    }
    await assertReleased();
    expect(await pending).toBe(error);
  });

  it("malformed policy releases custody before exit", async () => {
    const error = new policyModule.MalformedPrincipalPolicyError(root, "policy sentinel");
    vi.spyOn(policyModule, "loadPrincipalPolicy").mockRejectedValue(error);
    const exit = vi.spyOn(process, "exit").mockImplementation(() => { throw error; });
    const { entered, finish } = holdRelease();
    const pending = startup().catch(() => undefined);
    try {
      await entered.promise;
      expect(exit).not.toHaveBeenCalled();
    } finally {
      finish.resolve();
      await pending;
    }
    await assertReleased();
    expect(exit).toHaveBeenCalledWith(1);
  });

  it("address-in-use stand-down releases the session and preserves runtime bookkeeping", async () => {
    const listener = createServer();
    // A literal 0 lets the OS assign the port, so the port-discipline gate needs no retry wrapper here.
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    try {
      const address = listener.address() as import("node:net").AddressInfo;
      const runtime = await import("../src/cli/agents/runtime.js");
      const clear = vi.spyOn(runtime, "clearTenantRuntime");
      dashboard = await startup({ allowPark: true, port: address.port });
      expect(dashboard.addrInUse()).toBe(true);
      await assertReleased();
      expect(clear).not.toHaveBeenCalled();
    } finally {
      await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("a stop during an address-in-use stand-down bind preserves the port owner's runtime record", async () => {
    const listener = createServer();
    // A literal 0 lets the OS assign the port, so the port-discipline gate needs no retry wrapper here.
    await new Promise<void>((resolve) => listener.listen(0, "127.0.0.1", resolve));
    const entered = deferred();
    const finish = deferred();
    const start = DashboardApprovalChannel.prototype.start;
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(async function (this: DashboardApprovalChannel, options) {
      entered.resolve();
      await finish.promise;
      await start.call(this, options);
    });
    let pending: Promise<{ succeeded: boolean }> | undefined;
    let stopped: Promise<void> | undefined;
    try {
      const address = listener.address() as import("node:net").AddressInfo;
      const runtime = await import("../src/cli/agents/runtime.js");
      const clear = vi.spyOn(runtime, "clearTenantRuntime");
      pending = startup({ allowPark: true, port: address.port })
        .then(() => ({ succeeded: true }), () => ({ succeeded: false }));
      await entered.promise;
      stopped = channels[0]!.stop();
      finish.resolve();
      await stopped;
      expect((await pending).succeeded).toBe(false);
      expect(channels[0]!.addrInUse()).toBe(true);
      expect(clear).not.toHaveBeenCalled();
      await assertReleased();
    } finally {
      finish.resolve();
      await pending;
      await stopped?.catch(() => undefined);
      await new Promise<void>((resolve, reject) => listener.close((error) => error ? reject(error) : resolve()));
    }
  });

  it("stop retains custody until a pending flush completes", async () => {
    dashboard = await startup();
    const entered = deferred();
    const finish = deferred();
    vi.spyOn(AuditLog.prototype, "flush").mockImplementation(async () => {
      entered.resolve();
      await finish.promise;
    });
    const stopped = dashboard.stop();
    try {
      await Promise.race([entered.promise, stopped]);
      await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    } finally {
      finish.resolve();
      await stopped;
    }
    await assertReleased();
  });

  it.each(["flush", "release", "both", "undefined", "channel"] as const)("stop preserves %s failure and attempts release once", async (phase) => {
    const operation = phase === "undefined" ? undefined : new Error("operation sentinel");
    const releaseError = new Error("release sentinel");
    if (phase === "channel") {
      const original = DashboardApprovalChannel.prototype.stop;
      vi.spyOn(DashboardApprovalChannel.prototype, "stop").mockImplementation(async function (this: DashboardApprovalChannel) {
        await original.call(this);
        throw operation;
      });
    }
    dashboard = await startup();
    const lease = sessions[0]!.masterWriteBarrier!;
    const realRelease = lease.release.bind(lease);
    const release = vi.spyOn(lease, "release").mockImplementation(async () => {
      await realRelease();
      if (phase === "release" || phase === "both") throw releaseError;
    });
    if (phase === "flush" || phase === "both" || phase === "undefined") {
      vi.spyOn(AuditLog.prototype, "flush").mockRejectedValue(operation);
    }
    const first = dashboard.stop();
    const concurrent = dashboard.stop();
    const outcome = await first.then(() => ({ ok: true as const }), (error: unknown) => ({ ok: false as const, error }));
    await concurrent.catch(() => undefined);
    await assertReleased();
    expect(concurrent).toBe(first);
    expect(dashboard.stop()).toBe(first);
    expect(release).toHaveBeenCalledTimes(1);
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      if (phase === "both") expect((outcome.error as AggregateError).errors).toEqual([operation, releaseError]);
      else expect(outcome.error).toBe(phase === "release" ? releaseError : operation);
    }
  });

  it("partial wiring flushes audit without saving an incomplete baseline", async () => {
    const save = vi.spyOn(BaselineTracker.prototype, "save");
    const flush = vi.spyOn(AuditLog.prototype, "flush");
    await startup({ __testFaultAfterLoads: () => { throw undefined; } }).catch(() => undefined);
    expect(save).not.toHaveBeenCalled();
    expect(flush).toHaveBeenCalled();
  });

  it("optional distress startup failure retains custody until stop", async () => {
    vi.spyOn(DistressListener.prototype, "start").mockRejectedValue(new Error("distress sentinel"));
    dashboard = await startup();
    expect(sessions[0]!.masterWriteBarrier!.signal.aborted).toBe(false);
    await expect(exclusive()).rejects.toMatchObject({ kind: "contention" });
    await dashboard.stop();
    await assertReleased();
  });

  it("startup rejects when stop joins initial wiring", async () => {
    const entered = deferred();
    const finish = deferred();
    const attach = vi.spyOn(DashboardApprovalChannel.prototype, "setDependencies");
    const bind = vi.spyOn(DashboardApprovalChannel.prototype, "start");
    const pending = startup({ __testFaultAfterLoads: async () => {
      entered.resolve();
      await finish.promise;
    } }).then(() => ({ succeeded: true }), (error: unknown) => ({ succeeded: false, error }));
    let stopped: Promise<void> | undefined;
    try {
      await entered.promise;
      stopped = channels[0]!.stop();
      finish.resolve();
      await stopped;
      expect((await pending).succeeded).toBe(false);
      expect(attach).not.toHaveBeenCalled();
      expect(bind).not.toHaveBeenCalled();
      await assertReleased();
    } finally {
      finish.resolve();
      await pending;
      await stopped;
    }
  });

  it.each([false, true])("stop joins a pending bind before finalization with parked=%s", async (parked) => {
    const entered = deferred();
    const finish = deferred();
    const start = DashboardApprovalChannel.prototype.start;
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockImplementation(async function (this: DashboardApprovalChannel, options) {
      entered.resolve();
      await finish.promise;
      await start.call(this, options);
    });
    const pending = startup(parked ? { passphrase: undefined, allowPark: true } : {})
      .then(() => ({ succeeded: true }), () => ({ succeeded: false }));
    let stopped: Promise<void> | undefined;
    let settled = false;
    try {
      await entered.promise;
      stopped = channels[0]!.stop();
      void stopped.then(() => { settled = true; });
      // With bind gated, this event-loop checkpoint observes all runnable stop work.
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(settled).toBe(false);
      if (!parked) expect(sessions[0]!.masterWriteBarrier!.signal.aborted).toBe(false);
      finish.resolve();
      await stopped;
      expect((await pending).succeeded).toBe(false);
      expect((channels[0] as unknown as { httpServer: unknown }).httpServer).toBeNull();
      if (!parked) await assertReleased();
    } finally {
      finish.resolve();
      await pending;
      await stopped;
      // Also reap a late listener if the ownership implementation under test failed.
      if (channels[0]) await DashboardApprovalChannel.prototype.stop.call(channels[0]);
    }
  });

  it("a signal joins an ordinary stop already awaiting release", async () => {
    __resetStandaloneShutdownStateForTest();
    const { entered, finish } = holdRelease();
    dashboard = await startup();
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const stopped = dashboard.stop();
    let signal: Promise<void> | undefined;
    try {
      await entered.promise;
      signal = handleStandaloneShutdownSignal("SIGTERM");
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(exit).not.toHaveBeenCalled();
      finish.resolve();
      await signal;
      await assertReleased();
      expect(exit).toHaveBeenCalledWith(128 + 15); // Shell signal status plus SIGTERM.
    } finally {
      finish.resolve();
      await stopped;
      await signal;
      __resetStandaloneShutdownStateForTest();
    }
  });

  it("stand-down preserves a single cleanup failure without relabeling it as wiring", async () => {
    const error = new Error("release sentinel");
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockResolvedValue();
    vi.spyOn(DashboardApprovalChannel.prototype, "addrInUse").mockReturnValue(true);
    const pending = startup({ allowPark: true, __testFaultAfterLoads: () => {
      const lease = sessions[0]!.masterWriteBarrier!;
      const release = lease.release.bind(lease);
      vi.spyOn(lease, "release").mockImplementation(async () => { await release(); throw error; });
    } }).catch((failure: unknown) => failure);
    expect(await pending).toBe(error);
    await assertReleased();
  });

  it("bind and release failures describe cleanup and retain each cause once", async () => {
    const operation = new Error("bind sentinel");
    const cleanup = new Error("release sentinel");
    vi.spyOn(DashboardApprovalChannel.prototype, "start").mockRejectedValue(operation);
    const outcome = await startup({ __testFaultAfterLoads: () => {
      const lease = sessions[0]!.masterWriteBarrier!;
      const release = lease.release.bind(lease);
      vi.spyOn(lease, "release").mockImplementation(async () => { await release(); throw cleanup; });
    } }).catch((error: unknown) => error);
    expect(outcome).toBeInstanceOf(AggregateError);
    expect((outcome as AggregateError).errors).toEqual([operation, cleanup]);
    expect((outcome as Error).message).toBe("Sanctuary Dashboard: cleanup failed.");
    await assertReleased();
  });

  it("the first Ctrl+C at recovery confirmation awaits release and exits", async () => {
    __resetStandaloneShutdownStateForTest();
    const { entered: releasing, finish: release } = holdRelease();
    const prompted = deferred();
    const answer = deferred();
    const establish = vi.mocked(custodyModule.establishMaster).getMockImplementation()!;
    vi.spyOn(custodyModule, "establishMaster").mockImplementation(async (options) => {
      const session = await establish(options);
      session.mintedRecoveryKey = "test-only-recovery-key";
      return session;
    });
    vi.spyOn(escrowModule, "escrowBootRecoveryKey").mockImplementation(async () => {
      prompted.resolve();
      await answer.promise;
      return { disclosedOnTty: true, confirmed: true };
    });
    const attach = vi.spyOn(DashboardApprovalChannel.prototype, "setDependencies");
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    const pending = startup().catch((error: unknown) => error);
    let signal: Promise<void> | undefined;
    try {
      await prompted.promise;
      signal = handleStandaloneShutdownSignal("SIGINT");
      // Escrow is the only outstanding operation; stop can now reach the gated release.
      await new Promise<void>((resolve) => setImmediate(resolve));
      expect(sessions[0]!.masterWriteBarrier!.release).toHaveBeenCalledOnce();
      await releasing.promise;
      expect(exit).not.toHaveBeenCalled();
      release.resolve();
      await signal;
      expect(exit).toHaveBeenCalledWith(128 + 2); // Shell signal status plus SIGINT.
      await assertReleased();
      answer.resolve();
      // Startup never settles under a signal, so the CLI's start-failure handler cannot print or exit 1.
      const outcome = await Promise.race([pending.then(() => "settled"),
        new Promise<string>((resolve) => setTimeout(() => resolve("unsettled"), 50))]); // 50 ms spans many event-loop turns; the unfixed rejection settles within a few microtasks.
      expect(outcome).toBe("unsettled");
      expect(attach).not.toHaveBeenCalled();
    } finally {
      answer.resolve();
      release.resolve();
      await signal;
      __resetStandaloneShutdownStateForTest();
    }
  });

  it("signal cleanup reports rejection and shares the stop outcome", async () => {
    __resetStandaloneShutdownStateForTest();
    dashboard = await startup();
    const error = new Error("flush sentinel");
    vi.spyOn(AuditLog.prototype, "flush").mockRejectedValue(error);
    const stderr = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const exit = vi.spyOn(process, "exit").mockImplementation(() => undefined as never);
    try {
      await handleStandaloneShutdownSignal("SIGTERM");
      expect(stderr).toHaveBeenCalledWith("Sanctuary Dashboard: cleanup failed.");
      expect(exit).toHaveBeenCalledWith(128 + 15); // Shell signal status plus SIGTERM.
      await expect(dashboard.stop()).rejects.toBe(error);
    } finally {
      __resetStandaloneShutdownStateForTest();
    }
  });

});

const EPHEMERAL_PORT = 0;
import * as custodyModule from "../src/core/master-custody.js";
import * as policyModule from "../src/principal-policy/loader.js";
import * as channelModule from "../src/principal-policy/dashboard.js";
import { FilesystemStorage } from "../src/storage/filesystem.js";
import { BaselineTracker } from "../src/principal-policy/baseline.js";
import { createServer } from "node:net";

async function standaloneBoundAddress(dashboard: DashboardApprovalChannel) {
  try {
    const address = (dashboard as unknown as { httpServer: import("node:net").Server }).httpServer.address();
    if (!address || typeof address === "string") throw new Error("expected TCP address");
    return { dashboard, port: address.port };
  } catch (error) {
    await dashboard.stop();
    throw error;
  }
}

let rescueHome: string;
let previousHome: string | undefined;
let rescueSessions: custodyModule.EstablishMasterResult[] = [];
let rescueChannels: DashboardApprovalChannel[] = [];
let rescueListeners: DistressListener[] = [];

beforeEach(async () => {
  previousHome = process.env.HOME;
  rescueHome = await mkdtemp(join(tmpdir(), "standalone-home-"));
  process.env.HOME = rescueHome;
  rescueSessions = [];
  rescueChannels = [];
  rescueListeners = [];
  const establish = custodyModule.establishMaster;
  vi.spyOn(custodyModule, "establishMaster").mockImplementation(async (options) => {
    const session = await establish(options);
    rescueSessions.push(session);
    return session;
  });
  const markStandalone = DashboardApprovalChannel.prototype.setStandaloneMode;
  vi.spyOn(DashboardApprovalChannel.prototype, "setStandaloneMode").mockImplementation(function (this: DashboardApprovalChannel, ...args) {
    rescueChannels.push(this);
    return markStandalone.apply(this, args);
  });
  const listen = DistressListener.prototype.start;
  vi.spyOn(DistressListener.prototype, "start").mockImplementation(function (this: DistressListener) {
    rescueListeners.push(this);
    return listen.call(this);
  });
});

afterEach(async () => {
  // Rescue runs after assertions so it cannot satisfy an ownership witness for the owner.
  vi.restoreAllMocks();
  for (const channel of rescueChannels) await channel.stop().catch(() => undefined);
  for (const listener of rescueListeners) await listener.stop().catch(() => undefined);
  for (const session of rescueSessions) {
    await session.masterWriteBarrier?.release();
    session.masterKey.fill(0);
  }
  if (previousHome === undefined) delete process.env.HOME;
  else process.env.HOME = previousHome;
  await rm(rescueHome, { recursive: true, force: true });
});
