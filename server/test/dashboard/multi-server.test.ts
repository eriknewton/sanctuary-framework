/**
 * Integration tests for the multi-tenant dashboard HTTP server.
 *
 * Exercises auth, HTML vs JSON routes, health endpoint, and proper 404
 * behaviour. Stubs the per-tenant probe via discovery root (tenants have no
 * listening server so `running` is false everywhere — that's fine, we just
 * verify the route plumbing).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { startMultiDashboardServer } from "../../src/dashboard/multi-server.js";
import type { MultiDashboardHandle } from "../../src/dashboard/multi-server.js";

function fetchText(
  url: URL,
  token?: string
): Promise<{ status: number; body: string; headers: Record<string, string | string[] | undefined> }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const req = httpRequest(
      {
        host: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: "GET",
        headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString("utf-8"),
            headers: res.headers,
          });
        });
      }
    );
    req.on("error", reject);
    req.end();
  });
}

async function makeTenant(
  root: string,
  name: string,
  withRuntime: boolean
): Promise<void> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "0.enc"), "");
  if (withRuntime) {
    const { writeTenantRuntime } = await import(
      "../../src/cli/agents/runtime.js"
    );
    await writeTenantRuntime(dir, {
      version: "0.10.0-test",
      pid: 123,
      started_at: new Date().toISOString(),
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      mode: "wrap",
    });
  }
}

describe("multi-server", () => {
  let home: string;
  let root: string;
  let handle: MultiDashboardHandle | null = null;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-multi-server-"));
    root = join(home, ".sanctuary");
    await mkdir(root, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    if (handle) await handle.stop();
    handle = null;
    await rm(home, { recursive: true, force: true });
  });

  async function start(authToken?: string): Promise<MultiDashboardHandle> {
    const options: Parameters<typeof startMultiDashboardServer>[0] = {
      port: 0,
      host: "127.0.0.1",
      home,
    };
    if (authToken) options.authToken = authToken;
    handle = await startMultiDashboardServer(options);
    return handle;
  }

  it("serves the /agents HTML page on GET /", async () => {
    await makeTenant(root, "nsa", false);
    const h = await start();
    const res = await fetchText(new URL(h.url + "/"));
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/text\/html/);
    expect(res.body).toContain("Multi-Agent Overview");
    expect(res.body).toContain(">nsa<");
  });

  it("/agents also serves the HTML page", async () => {
    await makeTenant(root, "alpha", false);
    const h = await start();
    const res = await fetchText(new URL(h.url + "/agents"));
    expect(res.status).toBe(200);
    expect(res.body).toContain("Multi-Agent Overview");
  });

  it("/api/agents returns machine-readable JSON", async () => {
    await makeTenant(root, "alpha", false);
    await makeTenant(root, "beta", true);
    const h = await start();
    const res = await fetchText(new URL(h.url + "/api/agents"));
    expect(res.status).toBe(200);
    expect(res.headers["content-type"]).toMatch(/application\/json/);
    const parsed = JSON.parse(res.body);
    expect(parsed.version).toBe(1);
    expect(parsed.tenant_count).toBe(2);
    expect(parsed.tenants.map((t: { name: string }) => t.name).sort()).toEqual(
      ["alpha", "beta"]
    );
  });

  it("/api/health is available without a token", async () => {
    const h = await start();
    const res = await fetchText(new URL(h.url + "/api/health"));
    expect(res.status).toBe(200);
    const parsed = JSON.parse(res.body);
    expect(parsed.ok).toBe(true);
    expect(parsed.mode).toBe("multi");
  });

  it("returns 401 on missing/invalid bearer token when auth enabled", async () => {
    const h = await start("secret-token");
    const no = await fetchText(new URL(h.url + "/"));
    expect(no.status).toBe(401);
    const wrong = await fetchText(new URL(h.url + "/"), "wrong-token");
    expect(wrong.status).toBe(401);
    const ok = await fetchText(new URL(h.url + "/"), "secret-token");
    expect(ok.status).toBe(200);
  });

  it("returns 404 on unknown routes", async () => {
    const h = await start();
    const res = await fetchText(new URL(h.url + "/does-not-exist"));
    expect(res.status).toBe(404);
    const parsed = JSON.parse(res.body);
    expect(parsed.error).toBe("not_found");
  });
});
