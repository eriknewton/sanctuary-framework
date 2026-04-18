/**
 * Unit tests for tenant discovery.
 *
 * Cross-platform (no real Keychain, no real HTTP). A disposable temp dir
 * stands in for `~/.sanctuary`. The fake layout exercises every branch of
 * the scanner.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  discoverTenants,
  findTenant,
} from "../../../src/cli/agents/discovery.js";
import { writeTenantRuntime } from "../../../src/cli/agents/runtime.js";

async function makeTenantLayout(
  root: string,
  name: string,
  opts: {
    withState?: boolean;
    withCocoonProfile?: boolean;
    withFallback?: boolean;
    auditFiles?: string[];
  } = {}
): Promise<string> {
  const dir = name === "." ? root : join(root, name);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if (opts.withState) {
    await mkdir(join(dir, "state"), { recursive: true });
    await mkdir(join(dir, "state", "_identities"), { recursive: true });
  }
  if (opts.withCocoonProfile) {
    await writeFile(
      join(dir, "cocoon-profile.json"),
      JSON.stringify({ version: 1 })
    );
  }
  if (opts.withFallback) {
    await writeFile(join(dir, "passphrase.enc"), Buffer.alloc(40, 0xaa));
  }
  if (opts.auditFiles && opts.auditFiles.length > 0) {
    await mkdir(join(dir, "state", "_audit"), { recursive: true });
    for (const fname of opts.auditFiles) {
      await writeFile(join(dir, "state", "_audit", fname), "");
    }
  }
  return dir;
}

describe("cli/agents/discovery", () => {
  let tmpRoot: string;
  let home: string;

  beforeEach(async () => {
    home = await mkdtemp(join(tmpdir(), "sanctuary-agents-home-"));
    tmpRoot = join(home, ".sanctuary");
    await mkdir(tmpRoot, { recursive: true, mode: 0o700 });
  });

  afterEach(async () => {
    await rm(home, { recursive: true, force: true });
  });

  it("returns empty list when storage root has no tenants", async () => {
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants).toEqual([]);
  });

  it("detects default root as a tenant when it has a state dir", async () => {
    await makeTenantLayout(tmpRoot, ".", { withState: true });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants.map((t) => t.name)).toEqual(["default"]);
    expect(tenants[0]!.initialized).toBe(true);
    expect(tenants[0]!.storage_path).toBe(tmpRoot);
  });

  it("detects named sub-directory tenants", async () => {
    await makeTenantLayout(tmpRoot, "nsa", { withState: true, withCocoonProfile: true });
    await makeTenantLayout(tmpRoot, "standards", { withState: true });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants.map((t) => t.name).sort()).toEqual(["nsa", "standards"]);
  });

  it("sorts with default first, others alphabetical", async () => {
    await makeTenantLayout(tmpRoot, ".", { withState: true });
    await makeTenantLayout(tmpRoot, "zulu", { withState: true });
    await makeTenantLayout(tmpRoot, "alpha", { withState: true });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants.map((t) => t.name)).toEqual(["default", "alpha", "zulu"]);
  });

  it("skips dot directories and the default tenant's own state/backup dirs", async () => {
    // Default tenant at root:
    await makeTenantLayout(tmpRoot, ".", { withState: true });
    // These belong to the default tenant's own path — should not become
    // their own tenants:
    await mkdir(join(tmpRoot, ".git"), { recursive: true });
    await mkdir(join(tmpRoot, "backup"), { recursive: true });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants.map((t) => t.name)).toEqual(["default"]);
  });

  it("marks passphrase status keychain when only cocoon-profile exists", async () => {
    await makeTenantLayout(tmpRoot, "ck", {
      withState: true,
      withCocoonProfile: true,
    });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants[0]!.passphrase_status).toBe("keychain");
  });

  it("marks passphrase status fallback-file when passphrase.enc exists", async () => {
    await makeTenantLayout(tmpRoot, "fb", {
      withState: true,
      withFallback: true,
    });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants[0]!.passphrase_status).toBe("fallback-file");
  });

  it("computes last_activity from the newest audit file mtime", async () => {
    await makeTenantLayout(tmpRoot, "audit-tenant", {
      withState: true,
      auditFiles: ["a.enc", "b.enc"],
    });
    const tenants = await discoverTenants({ home, env: {} });
    const t = tenants.find((x) => x.name === "audit-tenant")!;
    expect(t.last_activity).toBeTruthy();
    expect(new Date(t.last_activity!).getTime()).toBeGreaterThan(0);
  });

  it("reports null last_activity when no audit dir", async () => {
    await makeTenantLayout(tmpRoot, "no-audit", { withState: true });
    const tenants = await discoverTenants({ home, env: {} });
    expect(tenants[0]!.last_activity).toBeNull();
  });

  it("includes extras from SANCTUARY_AGENTS_EXTRA_PATHS", async () => {
    // Default tenant so we have something in the root layout too.
    await makeTenantLayout(tmpRoot, "nsa", { withState: true });
    const extraHome = await mkdtemp(join(tmpdir(), "sanctuary-extra-"));
    const extraPath = join(extraHome, "custom-agent");
    await makeTenantLayout(extraHome, "custom-agent", { withState: true });
    try {
      const tenants = await discoverTenants({
        home,
        env: { SANCTUARY_AGENTS_EXTRA_PATHS: extraPath },
      });
      expect(tenants.map((t) => t.name)).toContain("custom-agent");
      expect(
        tenants.find((t) => t.name === "custom-agent")!.storage_path
      ).toBe(extraPath);
    } finally {
      await rm(extraHome, { recursive: true, force: true });
    }
  });

  it("includes extras from agents-extra.json", async () => {
    const extraHome = await mkdtemp(join(tmpdir(), "sanctuary-extra-"));
    const extraPath = join(extraHome, "file-agent");
    await makeTenantLayout(extraHome, "file-agent", { withState: true });
    await writeFile(
      join(tmpRoot, "agents-extra.json"),
      JSON.stringify([extraPath])
    );
    try {
      const tenants = await discoverTenants({ home, env: {} });
      expect(tenants.map((t) => t.name)).toContain("file-agent");
    } finally {
      await rm(extraHome, { recursive: true, force: true });
    }
  });

  it("de-duplicates extras that overlap with the default scan", async () => {
    await makeTenantLayout(tmpRoot, "dup", { withState: true });
    const dupPath = join(tmpRoot, "dup");
    const tenants = await discoverTenants({
      home,
      env: { SANCTUARY_AGENTS_EXTRA_PATHS: dupPath },
    });
    const count = tenants.filter((t) => t.name === "dup").length;
    expect(count).toBe(1);
  });

  it("surfaces runtime.json when present", async () => {
    const dir = await makeTenantLayout(tmpRoot, "live", { withState: true });
    await writeTenantRuntime(dir, {
      version: "0.10.0-test",
      pid: 99999,
      started_at: new Date().toISOString(),
      dashboard_host: "127.0.0.1",
      dashboard_port: 3524,
      webhook_callback_port: 3525,
      mode: "wrap",
    });
    const tenants = await discoverTenants({ home, env: {} });
    const t = tenants.find((x) => x.name === "live")!;
    expect(t.runtime?.dashboard_port).toBe(3524);
    expect(t.runtime?.webhook_callback_port).toBe(3525);
    expect(t.runtime?.mode).toBe("wrap");
  });

  it("tolerates missing / malformed runtime.json", async () => {
    const dir = await makeTenantLayout(tmpRoot, "bad-rt", { withState: true });
    await writeFile(join(dir, "runtime.json"), "{ this is not: json");
    const tenants = await discoverTenants({ home, env: {} });
    const t = tenants.find((x) => x.name === "bad-rt")!;
    expect(t.runtime).toBeNull();
  });

  it("findTenant returns null when unknown", async () => {
    await makeTenantLayout(tmpRoot, "alpha", { withState: true });
    const t = await findTenant("omega", { home, env: {} });
    expect(t).toBeNull();
  });

  it("findTenant returns a matching tenant by name", async () => {
    await makeTenantLayout(tmpRoot, "alpha", { withState: true });
    const t = await findTenant("alpha", { home, env: {} });
    expect(t).not.toBeNull();
    expect(t!.name).toBe("alpha");
  });

  it("keychain service hashes per-tenant but stays `sanctuary-passphrase` for default", async () => {
    await makeTenantLayout(tmpRoot, ".", { withState: true });
    await makeTenantLayout(tmpRoot, "custom", { withState: true });
    const tenants = await discoverTenants({ home, env: {} });
    const defaultT = tenants.find((t) => t.name === "default")!;
    const customT = tenants.find((t) => t.name === "custom")!;
    expect(defaultT.keychain_service).toBe("sanctuary-passphrase");
    expect(customT.keychain_service).toMatch(/^sanctuary-passphrase-[0-9a-f]{12}$/);
    expect(customT.keychain_service).not.toBe(defaultT.keychain_service);
  });
});
