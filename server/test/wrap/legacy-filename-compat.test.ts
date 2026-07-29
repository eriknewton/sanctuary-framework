/**
 * Legacy on-disk filename compatibility — read-both, write-new migration.
 *
 * Earlier releases wrote the wrap profile and unwrap-meta pointer under
 * legacy filenames carrying the retired vocabulary term. The migration
 * contract is:
 *
 *   - WRITE-NEW: every fresh wrap writes `wrap-profile.json` and
 *     `backup/wrap-meta.json`, never the legacy names.
 *   - READ-BOTH: tenant discovery recognizes a tenant marked only by the
 *     legacy profile filename, and unwrap restores from a legacy-named
 *     meta pointer, so installs wrapped by earlier releases keep working.
 *
 * This file is one of the few permitted carriers of the legacy literals
 * (allowlisted per-file in test/vocabulary/no-retired-vocabulary.test.ts);
 * everything else in the repo must use the wrap-* names.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, mkdir, writeFile, readFile, rm, access } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runWrap,
  type DashboardStarter,
} from "../../src/wrap/cli.js";
import {
  findLatestBackup,
  removeWrapMeta,
  saveWrapMeta,
} from "../../src/wrap/config-reader.js";
import { discoverTenants } from "../../src/cli/agents/discovery.js";

const LEGACY_PROFILE = "cocoon-profile.json";
const LEGACY_META = "cocoon-meta.json";

function capturingDashboardStarter(): DashboardStarter {
  return async (opts) => ({
    url: `http://127.0.0.1:${opts.port}`,
    port: opts.port,
    host: "127.0.0.1",
    stop: async () => {},
    publish: () => {},
    publishActivity: () => {},
    publishApproval: () => {},
  });
}

describe("legacy filename compatibility (read-both, write-new)", () => {
  let tempHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let configPath: string;

  beforeEach(async () => {
    tempHome = await mkdtemp(join(tmpdir(), "sanctuary-legacy-compat-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tempHome;
    configPath = join(tempHome, "openclaw.json");
    await writeFile(
      configPath,
      JSON.stringify({
        mcp: {
          servers: {
            demo: { command: "node", args: ["demo-server.js"] },
          },
        },
      }),
      "utf-8"
    );
  });

  afterEach(async () => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined)
      delete process.env.SANCTUARY_STORAGE_PATH;
    else process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    await rm(tempHome, { recursive: true, force: true });
  });

  it("fresh wrap writes wrap-profile.json and wrap-meta.json, never the legacy names", async () => {
    const tenantDir = join(tempHome, "tenant-fresh");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;

    await runWrap(
      { wrap: configPath, noOpen: true },
      {
        startDashboard: capturingDashboardStarter(),
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "gen",
          location: "macOS Keychain",
          source: "generated",
        }),
        // Write a real sanctuary entry so wrap's post-rewrite verification passes.
        rewriteConfig: vi.fn(async (_agentConfig, command: string, args: string[]) => {
          await writeFile(
            configPath,
            JSON.stringify({
              mcp: { servers: { sanctuary: { command, args } } },
            }),
            "utf-8"
          );
          return configPath;
        }),
      }
    );

    const profile = JSON.parse(
      await readFile(join(tenantDir, "wrap-profile.json"), "utf-8")
    );
    expect(profile.version).toBe(1);
    const meta = JSON.parse(
      await readFile(join(tenantDir, "backup", "wrap-meta.json"), "utf-8")
    );
    expect(meta.originalPath).toBe(configPath);

    await expect(access(join(tenantDir, LEGACY_PROFILE))).rejects.toThrow();
    await expect(
      access(join(tenantDir, "backup", LEGACY_META))
    ).rejects.toThrow();
  });

  it("discovers a tenant marked only by the legacy profile filename", async () => {
    const root = join(tempHome, ".sanctuary");
    const legacyDir = join(root, "legacy-agent");
    await mkdir(legacyDir, { recursive: true });
    await writeFile(
      join(legacyDir, LEGACY_PROFILE),
      JSON.stringify({ version: 1 })
    );

    const tenants = await discoverTenants({ home: tempHome, root });
    const legacy = tenants.find((t) => t.name === "legacy-agent");
    expect(legacy).toBeDefined();
    expect(legacy!.has_profile).toBe(true);
  });

  it("findLatestBackup falls back to a legacy-named meta pointer", async () => {
    const tenantDir = join(tempHome, "tenant-legacy-meta");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const backupDir = join(tenantDir, "backup");
    await mkdir(backupDir, { recursive: true });
    const backupPath = join(backupDir, "config-backup-legacy.json");
    await writeFile(backupPath, "{}");
    await writeFile(
      join(backupDir, LEGACY_META),
      JSON.stringify({ backupPath, originalPath: configPath })
    );

    const meta = await findLatestBackup();
    expect(meta).toEqual({ backupPath, originalPath: configPath });
  });

  it("prefers wrap-meta.json over the legacy pointer when both exist", async () => {
    const tenantDir = join(tempHome, "tenant-both-meta");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const backupDir = join(tenantDir, "backup");
    await mkdir(backupDir, { recursive: true });
    const staleBackup = join(backupDir, "config-backup-stale.json");
    await writeFile(staleBackup, "{}");
    await writeFile(
      join(backupDir, LEGACY_META),
      JSON.stringify({ backupPath: staleBackup, originalPath: "/stale/path" })
    );
    const freshBackup = join(backupDir, "config-backup-fresh.json");
    await writeFile(freshBackup, "{}");
    await saveWrapMeta({
      backupPath: freshBackup,
      originalPath: configPath,
      platform: "openclaw",
      wrappedAt: new Date().toISOString(),
    });

    const meta = await findLatestBackup();
    expect(meta).toEqual({ backupPath: freshBackup, originalPath: configPath });
  });

  it("removeWrapMeta scoped to the restored surface leaves a legacy meta naming a DIFFERENT surface", async () => {
    const tenantDir = join(tempHome, "tenant-mixed-meta");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const backupDir = join(tenantDir, "backup");
    await mkdir(backupDir, { recursive: true });

    // Legacy meta from a pre-sweep release, pointing at a DIFFERENT wrapped
    // surface that unwrap did not touch. It is the only pointer to that
    // surface's pristine backup.
    const legacyBackup = join(backupDir, "config-backup-legacy.json");
    await writeFile(legacyBackup, "{}");
    const otherSurface = join(tempHome, "other-agent-config.json");
    await writeFile(
      join(backupDir, LEGACY_META),
      JSON.stringify({ backupPath: legacyBackup, originalPath: otherSurface })
    );

    // Canonical meta from a newer wrap of THIS surface.
    const freshBackup = join(backupDir, "config-backup-fresh.json");
    await writeFile(freshBackup, "{}");
    await saveWrapMeta({
      backupPath: freshBackup,
      originalPath: configPath,
      platform: "openclaw",
      wrappedAt: new Date().toISOString(),
    });

    // Unwrap of this surface retires ONLY its pointer; the legacy pointer
    // to the other surface's pristine backup survives.
    expect(await removeWrapMeta(configPath)).toEqual([]);
    await expect(access(join(backupDir, "wrap-meta.json"))).rejects.toThrow();
    const remaining = JSON.parse(
      await readFile(join(backupDir, LEGACY_META), "utf-8")
    );
    expect(remaining.originalPath).toBe(otherSurface);
  });

  it("F6 re-wrap preservation consults the LEGACY pointer when the canonical meta names a DIFFERENT surface", async () => {
    const tenantDir = join(tempHome, "tenant-mixed-rewrap");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const backupDir = join(tenantDir, "backup");
    await mkdir(backupDir, { recursive: true });

    // Legacy meta from a pre-sweep release: the ONLY pointer at surface X's
    // pristine pre-wrap backup.
    const pristineBackup = join(backupDir, "config-backup-2020-01-01-x.json");
    await writeFile(pristineBackup, '{"pristine":true}');
    await writeFile(
      join(backupDir, LEGACY_META),
      JSON.stringify({ backupPath: pristineBackup, originalPath: configPath })
    );

    // Canonical meta from a newer wrap of a DIFFERENT surface Y.
    const otherSurface = join(tempHome, "other-agent-config.json");
    const otherBackup = join(backupDir, "config-backup-2025-01-01-y.json");
    await writeFile(otherBackup, "{}");
    await saveWrapMeta({
      backupPath: otherBackup,
      originalPath: otherSurface,
      platform: "openclaw",
      wrappedAt: new Date().toISOString(),
    });

    // Re-wrap of X: the fresh backup captures the ALREADY-WRAPPED content.
    // The preservation scan must find X's legacy pointer across BOTH meta
    // files; the first-parseable-file reader compared against Y's canonical
    // meta, failed the same-surface check, and pointed the meta at the
    // fresh (wrapped) backup — orphaning X's pristine one.
    const freshWrappedBackup = join(
      backupDir,
      "config-backup-2026-01-01-x.json"
    );
    await writeFile(freshWrappedBackup, '{"wrapped":true}');
    await saveWrapMeta({
      backupPath: freshWrappedBackup,
      originalPath: configPath,
      platform: "openclaw",
      wrappedAt: new Date().toISOString(),
    });

    const canonical = JSON.parse(
      await readFile(join(backupDir, "wrap-meta.json"), "utf-8")
    );
    expect(canonical.originalPath).toBe(configPath);
    expect(canonical.backupPath).toBe(pristineBackup);
  });

  it("unwraps an install that has only the legacy-named meta pointer", async () => {
    const tenantDir = join(tempHome, "tenant-legacy-unwrap");
    process.env.SANCTUARY_STORAGE_PATH = tenantDir;
    const backupDir = join(tenantDir, "backup");
    await mkdir(backupDir, { recursive: true });

    const originalConfig = JSON.stringify({
      mcp: { servers: { demo: { command: "node", args: ["demo-server.js"] } } },
    });
    const backupPath = join(backupDir, "config-backup-legacy.json");
    await writeFile(backupPath, originalConfig);
    await writeFile(
      join(backupDir, LEGACY_META),
      JSON.stringify({ backupPath, originalPath: configPath })
    );
    // Simulate the wrapped (rewritten) config that unwrap must restore from backup.
    await writeFile(
      configPath,
      JSON.stringify({ mcp: { servers: { sanctuary: { command: "npx" } } } })
    );

    const stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await runWrap({ unwrap: true });
    } finally {
      stderrSpy.mockRestore();
    }

    expect(await readFile(configPath, "utf-8")).toBe(originalConfig);
  });
});
