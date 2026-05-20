/**
 * `sanctuary agents list --fortress` scoping tests.
 *
 * Verifies drill friction item 3: when --fortress is passed, discovery
 * scans only that path instead of defaulting to ~/.sanctuary.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";
import { runAgentsCommand } from "../../src/cli/agents/cli.js";
import type { HealthProbeResult } from "../../src/cli/agents/health.js";
import type { TenantDescriptor } from "../../src/cli/agents/discovery.js";
import { writeLockdownStatus } from "../../src/lockdown/status.js";

class StringWritable extends Writable {
  chunks: string[] = [];
  _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ) {
    this.chunks.push(
      typeof chunk === "string" ? chunk : chunk.toString("utf8")
    );
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

const offlineProbe = async (
  _t: TenantDescriptor
): Promise<HealthProbeResult> => ({
  running: false,
  status: null,
  reason: "ECONNREFUSED",
});

async function makeTenant(root: string, name: string): Promise<string> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "00.enc"), "");
  await writeFile(
    join(dir, "cocoon-profile.json"),
    JSON.stringify({ version: 1 })
  );
  return dir;
}

describe("sanctuary agents list --fortress", () => {
  let home: string;
  let defaultRoot: string;
  let isolatedRoot: string;
  let isolatedTenant: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-agents-fortress-"));
    defaultRoot = join(home, ".sanctuary");
    await mkdir(defaultRoot, { recursive: true, mode: 0o700 });
    // Two tenants under the default root.
    await makeTenant(defaultRoot, "tenant-a");
    await makeTenant(defaultRoot, "tenant-b");

    // One isolated tenant at a different path.
    isolatedRoot = await mkdtemp(join(tmpdir(), "sanctuary-isolated-"));
    await mkdir(isolatedRoot, { recursive: true, mode: 0o700 });
    isolatedTenant = await makeTenant(isolatedRoot, "isolated-tenant");
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
    await rm(isolatedRoot, { recursive: true, force: true });
  });

  it("without --fortress, lists tenants under the default root", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["list", "--json"],
      out,
      err,
      home,
      probe: offlineProbe,
    });
    expect(code).toBe(0);
    const rows = JSON.parse(out.text) as Array<{ name: string }>;
    const names = rows.map((r) => r.name);
    expect(names).toContain("tenant-a");
    expect(names).toContain("tenant-b");
    expect(names).not.toContain("isolated-tenant");
  });

  it("with --fortress, lists only the scoped tenant", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["list", "--fortress", isolatedRoot, "--json"],
      out,
      err,
      home,
      probe: offlineProbe,
    });
    expect(code).toBe(0);
    const rows = JSON.parse(out.text) as Array<{ name: string }>;
    const names = rows.map((r) => r.name);
    expect(names).toContain("isolated-tenant");
    expect(names).not.toContain("tenant-a");
    expect(names).not.toContain("tenant-b");
  });

  it("shows LOCKED status and JSON lockdown_status when the tenant is locked", async () => {
    await writeLockdownStatus(isolatedTenant, {
      active: true,
      activated_at: "2026-05-19T12:00:00.000Z",
      reason: "operator_lockdown",
    });

    const humanOut = new StringWritable();
    const humanErr = new StringWritable();
    const humanCode = await runAgentsCommand({
      argv: ["list", "--fortress", isolatedRoot],
      out: humanOut,
      err: humanErr,
      home,
      probe: async () => ({ running: true, status: 200, reason: null }),
    });
    expect(humanCode).toBe(0);
    expect(humanOut.text).toContain("LOCKED");
    expect(humanOut.text).not.toContain("running");

    const jsonOut = new StringWritable();
    const jsonErr = new StringWritable();
    const jsonCode = await runAgentsCommand({
      argv: ["list", "--fortress", isolatedRoot, "--json"],
      out: jsonOut,
      err: jsonErr,
      home,
      probe: async () => ({ running: true, status: 200, reason: null }),
    });
    expect(jsonCode).toBe(0);
    const rows = JSON.parse(jsonOut.text) as Array<{
      status: string;
      lockdown_status: { active: boolean };
    }>;
    expect(rows[0]).toMatchObject({
      status: "LOCKED",
      lockdown_status: { active: true },
    });
  });

  it("help text documents --fortress", async () => {
    const out = new StringWritable();
    const err = new StringWritable();
    const code = await runAgentsCommand({
      argv: ["--help"],
      out,
      err,
      home,
      probe: offlineProbe,
    });
    expect(code).toBe(0);
    expect(out.text).toContain("--fortress");
  });
});
