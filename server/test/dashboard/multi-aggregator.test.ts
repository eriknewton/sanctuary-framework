/**
 * Unit tests for the multi-tenant aggregator.
 *
 * Provisions two fake tenants on disk, stubs the HTTP probe, and validates
 * the JSON shape + branch logic (running / stopped / empty tenants, plus
 * the dashboard deep-link construction from runtime.json).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getMultiTenantSnapshot } from "../../src/dashboard/multi-aggregator.js";
import { writeTenantRuntime } from "../../src/cli/agents/runtime.js";

async function makeTenant(
  root: string,
  name: string,
  { withRuntime = false, port = 3501 }: { withRuntime?: boolean; port?: number } = {}
): Promise<string> {
  const dir = join(root, name);
  await mkdir(join(dir, "state", "_identities"), { recursive: true });
  await mkdir(join(dir, "state", "_audit"), { recursive: true });
  await writeFile(join(dir, "state", "_audit", "0.enc"), "");
  if (withRuntime) {
    await writeTenantRuntime(dir, {
      version: "0.10.0-test",
      pid: 99001,
      started_at: "2026-04-17T12:00:00.000Z",
      dashboard_host: "127.0.0.1",
      dashboard_port: port,
      webhook_callback_port: port + 10,
      mode: "wrap",
    });
  }
  return dir;
}

describe("dashboard/multi-aggregator", () => {
  let home: string;
  let root: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-multi-agg-"));
    root = join(home, ".sanctuary");
    await mkdir(root, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("returns empty rows when no tenants on host", async () => {
    const snap = await getMultiTenantSnapshot({
      discovery: { home, env: {} },
      probe: async () => ({ running: false, status: null, reason: "stub" }),
    });
    expect(snap.tenant_count).toBe(0);
    expect(snap.running_count).toBe(0);
    expect(snap.tenants).toEqual([]);
  });

  it("builds rows with dashboard_url derived from runtime", async () => {
    await makeTenant(root, "nsa", { withRuntime: true, port: 3501 });
    await makeTenant(root, "bravo", { withRuntime: false });
    const snap = await getMultiTenantSnapshot({
      discovery: { home, env: {} },
      probe: async (t) =>
        t.name === "nsa"
          ? { running: true, status: 200, reason: null }
          : { running: false, status: null, reason: "no runtime.json" },
    });
    expect(snap.tenant_count).toBe(2);
    expect(snap.running_count).toBe(1);
    const nsa = snap.tenants.find((r) => r.name === "nsa")!;
    expect(nsa.dashboard_url).toBe("http://127.0.0.1:3501");
    expect(nsa.dashboard_port).toBe(3501);
    expect(nsa.webhook_callback_port).toBe(3511);
    expect(nsa.pid).toBe(99001);
    expect(nsa.running).toBe(true);
    const bravo = snap.tenants.find((r) => r.name === "bravo")!;
    expect(bravo.dashboard_url).toBeNull();
    expect(bravo.running).toBe(false);
  });

  it("counts running tenants correctly (mixed state)", async () => {
    await makeTenant(root, "a", { withRuntime: true, port: 3501 });
    await makeTenant(root, "b", { withRuntime: true, port: 3502 });
    await makeTenant(root, "c", { withRuntime: false });
    const snap = await getMultiTenantSnapshot({
      discovery: { home, env: {} },
      probe: async (t) =>
        t.name === "a"
          ? { running: true, status: 200, reason: null }
          : { running: false, status: null, reason: "no" },
    });
    expect(snap.tenant_count).toBe(3);
    expect(snap.running_count).toBe(1);
  });

  it("preserves discovery sort (default first, others alphabetical)", async () => {
    await makeTenant(root, ".", { withRuntime: false });
    await makeTenant(root, "zeta", { withRuntime: false });
    await makeTenant(root, "alpha", { withRuntime: false });
    const snap = await getMultiTenantSnapshot({
      discovery: { home, env: {} },
      probe: async () => ({ running: false, status: null, reason: "stub" }),
    });
    expect(snap.tenants.map((t) => t.name)).toEqual([
      "default",
      "alpha",
      "zeta",
    ]);
  });

  it("surfaces last_activity in each row", async () => {
    await makeTenant(root, "nsa", { withRuntime: false });
    const snap = await getMultiTenantSnapshot({
      discovery: { home, env: {} },
      probe: async () => ({ running: false, status: null, reason: "stub" }),
    });
    expect(snap.tenants[0]!.last_activity).toBeTruthy();
  });
});
