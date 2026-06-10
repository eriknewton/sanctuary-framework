/**
 * Integration tests for the tenant dashboard health probe.
 *
 * Spins up ephemeral HTTP servers to validate each branch of the probe's
 * decision tree without touching real Sanctuary infrastructure.
 */

import { describe, it, expect, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { probeTenantDashboard } from "../../../src/cli/agents/health.js";
import type { TenantDescriptor } from "../../../src/cli/agents/discovery.js";

function baseTenant(
  overrides: Partial<TenantDescriptor> = {}
): TenantDescriptor {
  return {
    name: "test",
    storage_path: "/tmp/unused",
    exists: true,
    initialized: true,
    has_profile: false,
    keychain_service: "sanctuary-passphrase-aaaaaaaaaaaaaaaa",
    passphrase_status: "keychain",
    last_activity: null,
    runtime: null,
    ...overrides,
  };
}

describe("cli/agents/health probeTenantDashboard", () => {
  let server: Server | null = null;

  afterEach(async () => {
    if (server) {
      await new Promise<void>((resolve) => server!.close(() => resolve()));
      server = null;
    }
  });

  async function startServer(
    handler: (_req: unknown, res: import("node:http").ServerResponse) => void
  ): Promise<number> {
    server = createServer(handler);
    await new Promise<void>((resolve, reject) => {
      server!.once("error", reject);
      server!.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server!.address();
    if (!addr || typeof addr !== "object") throw new Error("no address");
    return addr.port;
  }

  it("reports not-running when runtime is null", async () => {
    const result = await probeTenantDashboard(baseTenant({ runtime: null }));
    expect(result.running).toBe(false);
    expect(result.reason).toContain("no runtime.json");
  });

  it("reports running on a 200 response", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end("{}");
    });
    const result = await probeTenantDashboard(
      baseTenant({
        runtime: {
          version: "x",
          pid: 1,
          started_at: "2026-04-17T00:00:00.000Z",
          dashboard_host: "127.0.0.1",
          dashboard_port: port,
          mode: "wrap",
        },
      })
    );
    expect(result.running).toBe(true);
    expect(result.status).toBe(200);
  });

  it("reports running on a 401 (token-protected dashboard)", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(401);
      res.end();
    });
    const result = await probeTenantDashboard(
      baseTenant({
        runtime: {
          version: "x",
          pid: 1,
          started_at: "2026-04-17T00:00:00.000Z",
          dashboard_host: "127.0.0.1",
          dashboard_port: port,
          mode: "wrap",
        },
      })
    );
    expect(result.running).toBe(true);
    expect(result.status).toBe(401);
  });

  it("reports not-running on 500", async () => {
    const port = await startServer((_req, res) => {
      res.writeHead(500);
      res.end();
    });
    const result = await probeTenantDashboard(
      baseTenant({
        runtime: {
          version: "x",
          pid: 1,
          started_at: "2026-04-17T00:00:00.000Z",
          dashboard_host: "127.0.0.1",
          dashboard_port: port,
          mode: "wrap",
        },
      })
    );
    expect(result.running).toBe(false);
    expect(result.status).toBe(500);
  });

  it("reports not-running on ECONNREFUSED (nothing listening)", async () => {
    // Port 1 is almost always refused without a listener.
    const result = await probeTenantDashboard(
      baseTenant({
        runtime: {
          version: "x",
          pid: 1,
          started_at: "2026-04-17T00:00:00.000Z",
          dashboard_host: "127.0.0.1",
          dashboard_port: 1,
          mode: "wrap",
        },
      }),
      { timeoutMs: 500 }
    );
    expect(result.running).toBe(false);
    expect(result.reason).toBeTruthy();
  });
});
