/**
 * End-to-end test: `sanctuary agents list` discovers two mock tenants.
 *
 * The spawn prompt for Thread G requires an end-to-end test that spins up
 * two tenants and confirms enumeration. This test provisions two real
 * storage paths with real `runtime.json` files and real listening HTTP
 * servers (the `/api/health` probe hits them), then walks the full CLI
 * output through list/show/status without any fakes on the probe.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { createServer, type Server } from "node:http";
import { runAgentsCommand } from "../../../src/cli/agents/cli.js";
import { writeTenantRuntime } from "../../../src/cli/agents/runtime.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(chunk: Buffer | string, _enc: BufferEncoding, cb: (err?: Error) => void) {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

async function buildMockTenant(
  root: string,
  name: string,
  port: number
): Promise<{ dir: string; server: Server }> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "0.enc"), "");
  await writeFile(join(dir, "cocoon-profile.json"), JSON.stringify({ version: 1 }));
  const server = createServer((req, res) => {
    if (req.url === "/api/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, tenant: name }));
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr !== "object") throw new Error("no address");
  await writeTenantRuntime(dir, {
    version: "0.10.0-test",
    pid: process.pid,
    started_at: new Date().toISOString(),
    dashboard_host: "127.0.0.1",
    dashboard_port: addr.port,
    webhook_callback_port: addr.port + 100,
    mode: "wrap",
  });
  return { dir, server };
}

describe("sanctuary agents — two-tenant end-to-end", () => {
  let home: string;
  let root: string;
  let serverA: Server | null = null;
  let serverB: Server | null = null;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-agents-e2e-"));
    root = join(home, ".sanctuary");
    await mkdir(root, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    if (serverA) await new Promise<void>((r) => serverA!.close(() => r()));
    if (serverB) await new Promise<void>((r) => serverB!.close(() => r()));
    serverA = null;
    serverB = null;
    await rm(home, { recursive: true, force: true });
  });

  it("list + show + status all see two running tenants end-to-end", async () => {
    const a = await buildMockTenant(root, "nsa", 0);
    const b = await buildMockTenant(root, "standards", 0);
    serverA = a.server;
    serverB = b.server;

    // list
    const listOut = new StringWritable();
    const listErr = new StringWritable();
    const listCode = await runAgentsCommand({
      argv: ["list", "--json"],
      out: listOut,
      err: listErr,
      home,
      env: {},
    });
    expect(listCode).toBe(0);
    const listJson = JSON.parse(listOut.text);
    expect(listJson.length).toBe(2);
    const names = listJson.map((r: { name: string }) => r.name).sort();
    expect(names).toEqual(["nsa", "standards"]);
    // Both should probe as running (real servers answering /api/health):
    const runningFlags = listJson.map((r: { running: boolean }) => r.running);
    expect(runningFlags).toEqual([true, true]);

    // status
    const statusOut = new StringWritable();
    const statusErr = new StringWritable();
    const statusCode = await runAgentsCommand({
      argv: ["status", "--json"],
      out: statusOut,
      err: statusErr,
      home,
      env: {},
    });
    expect(statusCode).toBe(0);
    const statusJson = JSON.parse(statusOut.text);
    expect(statusJson.length).toBe(2);
    for (const row of statusJson) {
      expect(row.running).toBe(true);
      expect(typeof row.dashboard_port).toBe("number");
    }

    // show nsa
    const showOut = new StringWritable();
    const showErr = new StringWritable();
    const showCode = await runAgentsCommand({
      argv: ["show", "nsa", "--json"],
      out: showOut,
      err: showErr,
      home,
      env: {},
    });
    expect(showCode).toBe(0);
    const showJson = JSON.parse(showOut.text);
    expect(showJson.name).toBe("nsa");
    expect(showJson.probe.running).toBe(true);
    expect(typeof showJson.runtime.dashboard_port).toBe("number");
  });

  it("reports running=false when tenant has runtime but no live server", async () => {
    const a = await buildMockTenant(root, "active", 0);
    serverA = a.server;
    // Build a second tenant with a runtime pointing at a dead port:
    const dir = join(root, "dead");
    await mkdir(join(dir, "state", "_identities"), { recursive: true });
    await writeTenantRuntime(dir, {
      version: "0.10.0-test",
      pid: 999999,
      started_at: new Date().toISOString(),
      dashboard_host: "127.0.0.1",
      dashboard_port: 1, // should be refused
      mode: "wrap",
    });

    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["list", "--json"],
      out,
      err,
      home,
      env: {},
    });
    expect(code).toBe(0);
    const rows = JSON.parse(out.text);
    const active = rows.find((r: { name: string }) => r.name === "active");
    const dead = rows.find((r: { name: string }) => r.name === "dead");
    expect(active.running).toBe(true);
    expect(dead.running).toBe(false);
  });
});
