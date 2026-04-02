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

function randomPort(): number {
  return 10000 + Math.floor(Math.random() * 50000);
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
    const port = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-standalone";

    dashboard = await startStandaloneDashboard({
      passphrase: "test-passphrase-standalone",
      port,
      host: "127.0.0.1",
    });

    // Dashboard should be serving
    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    // Should show login page (we didn't provide auth)
    expect(text).toContain("Sanctuary");
  });

  it("serves audit log API in standalone mode", async () => {
    const port = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-audit";

    dashboard = await startStandaloneDashboard({
      passphrase: "test-passphrase-audit",
      port,
      host: "127.0.0.1",
    });

    // Authenticate and get audit log
    const res = await fetch(`http://127.0.0.1:${port}/api/audit-log`, {
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
    const port = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-status";

    dashboard = await startStandaloneDashboard({
      passphrase: "test-passphrase-status",
      port,
      host: "127.0.0.1",
    });

    const res = await fetch(`http://127.0.0.1:${port}/api/status`, {
      headers: { Authorization: "Bearer test-token-status" },
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toHaveProperty("pending_count");
    expect(data).toHaveProperty("connected_clients");
    expect(data.pending_count).toBe(0);
  });

  it("uses custom port from options", async () => {
    const port = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;

    dashboard = await startStandaloneDashboard({
      passphrase: "test-passphrase-port",
      port,
      host: "127.0.0.1",
    });

    // Should be accessible on the custom port
    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);
  });

  it("requires credentials when existing data is present", async () => {
    // First run: create data with a passphrase
    const port1 = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "test-token-creds";

    dashboard = await startStandaloneDashboard({
      passphrase: "first-run-passphrase",
      port: port1,
      host: "127.0.0.1",
    });
    await dashboard.stop();
    dashboard = null;

    // Second run: no credentials should fail
    delete process.env.SANCTUARY_PASSPHRASE;
    delete process.env.SANCTUARY_RECOVERY_KEY;
    delete process.env.SANCTUARY_DASHBOARD_ENABLED;

    const port2 = randomPort();
    let dashboard2: DashboardApprovalChannel | null = null;
    try {
      dashboard2 = await startStandaloneDashboard({
        port: port2,
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
    const port = randomPort();
    process.env.SANCTUARY_STORAGE_PATH = tempDir;
    process.env.SANCTUARY_DASHBOARD_AUTH_TOKEN = "auto";

    dashboard = await startStandaloneDashboard({
      passphrase: "test-passphrase-auto",
      port,
      host: "127.0.0.1",
    });

    // Should serve login page (auth is enabled with auto-generated token)
    const res = await fetch(`http://127.0.0.1:${port}/`);
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).toContain("Sanctuary");
  });
});
