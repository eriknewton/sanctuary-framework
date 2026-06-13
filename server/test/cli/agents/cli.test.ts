/**
 * End-to-end tests for the `sanctuary agents` CLI.
 *
 * Uses a fake HOME + two mock tenant directories so we exercise discovery
 * + formatting across list / show / status without binding ports or
 * unlocking Keychain. The HTTP probe is stubbed — we never open sockets.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runAgentsCommand } from "../../../src/cli/agents/cli.js";
import type { HealthProbeResult } from "../../../src/cli/agents/health.js";
import type { TenantDescriptor } from "../../../src/cli/agents/discovery.js";
import { writeTenantRuntime } from "../../../src/cli/agents/runtime.js";
import { registerHostTenant } from "../../../src/cli/agents/tenant-registry.js";

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

async function makeTenant(
  root: string,
  name: string,
  { withRuntime = false }: { withRuntime?: boolean } = {}
): Promise<string> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "00.enc"), "");
  await writeFile(join(dir, "wrap-profile.json"), JSON.stringify({ version: 1 }));
  if (withRuntime) {
    await writeTenantRuntime(dir, {
      version: "0.10.0-test",
      pid: 99000,
      started_at: new Date().toISOString(),
      dashboard_host: "127.0.0.1",
      dashboard_port: 3501,
      webhook_callback_port: 3511,
      mode: "wrap",
    });
  }
  return dir;
}

function fakeProbe(running: boolean) {
  return async (_t: TenantDescriptor): Promise<HealthProbeResult> =>
    running
      ? { running: true, status: 200, reason: null }
      : { running: false, status: null, reason: "ECONNREFUSED" };
}

describe("sanctuary agents CLI", () => {
  let home: string;
  let root: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-agents-cli-"));
    root = join(home, ".sanctuary");
    await mkdir(root, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("prints usage when called with no subcommand", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: [],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(false),
    });
    expect(code).toBe(0);
    expect(out.text).toContain("Usage: sanctuary agents");
    expect(out.text).toContain("list");
    expect(out.text).toContain("show");
    expect(out.text).toContain("status");
  });

  it("list reports empty on a bare host", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["list"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(false),
    });
    expect(code).toBe(0);
    expect(out.text).toMatch(/no Sanctuary tenants found/i);
    expect(err.text).toBe("");
  });

  it("list shows both tenants with correct statuses (table mode)", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    await makeTenant(root, "standards", { withRuntime: false });
    const out = new StringWritable();
    const err = new StringWritable();
    // nsa has runtime.json + probe says running; standards has no runtime.
    const code = await runAgentsCommand({
      argv: ["list"],
      out,
      err,
      home,
      env: {},
      probe: async (t) =>
        t.name === "nsa"
          ? { running: true, status: 200, reason: null }
          : { running: false, status: null, reason: "no runtime.json" },
    });
    expect(code).toBe(0);
    const text = out.text;
    expect(text).toContain("NAME");
    expect(text).toContain("STATUS");
    expect(text).toMatch(/nsa\s+running/);
    expect(text).toMatch(/standards\s+stopped/);
    // dashboard port from runtime.json surfaces for nsa:
    expect(text).toContain("3501");
    expect(err.text).toBe("");
  });

  it("list --json emits structured rows", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    await makeTenant(root, "bravo", { withRuntime: false });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["list", "--json"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(true),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text);
    expect(Array.isArray(parsed)).toBe(true);
    expect(parsed.length).toBe(2);
    const nsa = parsed.find((p: { name: string }) => p.name === "nsa");
    expect(nsa).toBeTruthy();
    expect(nsa.dashboard_port).toBe(3501);
    expect(nsa.pid).toBe(99000);
    expect(nsa.running).toBe(true);
    const bravo = parsed.find((p: { name: string }) => p.name === "bravo");
    expect(bravo.dashboard_port).toBeNull();
    expect(err.text).toBe("");
  });

  // F4 (drill 2026-06-13): `agents list` must read the tenant registry from
  // the SAME root that `wrap` wrote it under. When SANCTUARY_STORAGE_PATH
  // points at an isolated fortress, the read side honors it (so a wrap +
  // list under the same env agree), and a default (env-unset) list does NOT
  // see the isolated registry — proving the operator fortress stays clean.
  it("list honors SANCTUARY_STORAGE_PATH for the registry root (read/write agree)", async () => {
    const isoRoot = await mkdtemp(join(tmpdir(), "sanctuary-agents-iso-"));
    try {
      const fortress = await makeTenant(isoRoot, "iso-fortress");
      // Write side: registry under the isolated root, mirroring wrap with
      // SANCTUARY_STORAGE_PATH=isoRoot (registry root === resolved storage root).
      await registerHostTenant(fortress, { root: isoRoot });

      // Read side WITH the env var set: list discovers the registered fortress.
      const out = new StringWritable();
      const err = new StringWritable();
      const code = await runAgentsCommand({
        argv: ["list", "--json"],
        out,
        err,
        home,
        env: { SANCTUARY_STORAGE_PATH: isoRoot },
        probe: fakeProbe(false),
      });
      expect(code).toBe(0);
      const parsed = JSON.parse(out.text) as Array<{ name: string; storage_path: string }>;
      expect(parsed.some((p) => p.storage_path === fortress)).toBe(true);

      // Read side WITHOUT the env var: the default-root list does not pick up
      // the isolated registry (the operator's ~/.sanctuary view is unpolluted).
      const out2 = new StringWritable();
      const code2 = await runAgentsCommand({
        argv: ["list", "--json"],
        out: out2,
        err: new StringWritable(),
        home,
        env: {},
        probe: fakeProbe(false),
      });
      expect(code2).toBe(0);
      const parsed2 = JSON.parse(out2.text) as Array<{ storage_path: string }>;
      expect(parsed2.some((p) => p.storage_path === fortress)).toBe(false);
    } finally {
      await rm(isoRoot, { recursive: true, force: true });
    }
  });

  it("show prints detailed info for a named tenant", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "nsa"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(true),
    });
    expect(code).toBe(0);
    const text = out.text;
    expect(text).toContain("tenant:");
    expect(text).toContain("storage_path:");
    expect(text).toContain("keychain_service:");
    expect(text).toContain("passphrase:");
    expect(text).toContain("runtime:");
    expect(text).toContain("dashboard:");
    expect(text).toMatch(/probe:\s+running/);
    expect(err.text).toBe("");
  });

  it("show --json returns a full descriptor", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "nsa", "--json"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(true),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text);
    expect(parsed.name).toBe("nsa");
    expect(parsed.runtime.dashboard_port).toBe(3501);
    expect(parsed.probe.running).toBe(true);
    expect(err.text).toBe("");
  });

  it("show exits 1 on unknown tenant", async () => {
    await makeTenant(root, "nsa");
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show", "unknown-tenant"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(false),
    });
    expect(code).toBe(1);
    expect(err.text).toContain("unknown tenant");
  });

  it("show exits 2 when no tenant name given", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["show"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(false),
    });
    expect(code).toBe(2);
    expect(err.text).toContain("Missing tenant");
  });

  it("status prints one line per tenant", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    await makeTenant(root, "bravo", { withRuntime: false });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["status"],
      out,
      err,
      home,
      env: {},
      probe: async (t) =>
        t.name === "nsa"
          ? { running: true, status: 200, reason: null }
          : { running: false, status: null, reason: "ECONNREFUSED" },
    });
    expect(code).toBe(0);
    const lines = out.text.trim().split("\n");
    expect(lines.length).toBe(2);
    // Alphabetical sort (default-first rule doesn't apply — no default tenant).
    expect(lines[0]).toMatch(/bravo\s+stopped/);
    expect(lines[1]).toMatch(/nsa\s+running.*:3501/);
  });

  it("status --json returns per-tenant rows", async () => {
    await makeTenant(root, "nsa", { withRuntime: true });
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["status", "--json"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(true),
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(out.text);
    expect(parsed).toEqual([
      expect.objectContaining({
        name: "nsa",
        running: true,
        dashboard_port: 3501,
      }),
    ]);
  });

  it("unknown subcommand exits 2 and prints usage", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["teleport"],
      out,
      err,
      home,
      env: {},
      probe: fakeProbe(false),
    });
    expect(code).toBe(2);
    expect(err.text).toContain("Unknown subcommand");
    expect(err.text).toContain("Usage: sanctuary agents");
  });
});
