/**
 * 2026-07-02 install-path hardening, Group B: surface-scoped wrap-meta and
 * backup discrimination, non-destructive meta removal, the orphan-wrap
 * guard on every rollback path, the deduplicated banner honesty predicate,
 * the wrap-time pinned-version resolvability probe, and the unwrap
 * recovery breadcrumb for wrap-created files.
 *
 * Findings pinned here (Review/Sanctuary/Hardening_Wave_Revise_List_2026-07-02.md):
 *   1. hasExistingWrapMeta / findNewerBackup discriminate by SURFACE
 *      (resolve()d originalPath), not tenant-globally / by extension alone.
 *   2. removeWrapMeta never unlinks the pointer on a transient READ error;
 *      only genuinely-absent (ENOENT) or affirmatively-unparseable content
 *      is removable.
 *   3. The MED-1 orphan-wrap guard fires on ALL rollback paths, not just
 *      the meta-write-failure one.
 *   4. The MED-2 crash-window warning fires for surface X even when a
 *      DIFFERENT surface Y's wrap-meta exists (regression for the
 *      tenant-global suppression).
 *   5. castleWallProtectionConfirmed is THE banner honesty gate (truth
 *      table pinned; refactor-only, never weaken).
 *   6. checkPinnedVersionResolvable outcomes + the honest wrap-output
 *      downgrade on unpublished/unreachable pins (never blocks the wrap).
 *   7. Unwrap of a wrap-created file preserves its final contents as a
 *      timestamped backup breadcrumb before removal.
 *
 * Isolation: temp HOME + SANCTUARY_STORAGE_PATH (never the real
 * ~/.sanctuary), per the existing wrap-test idiom.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  writeFile,
  readFile,
  mkdir,
  mkdtemp,
  rm,
  chmod,
  access,
  readdir,
} from "node:fs/promises";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";

import {
  runWrap,
  castleWallProtectionConfirmed,
  checkPinnedVersionResolvable,
} from "../../src/wrap/cli.js";
import {
  backupConfig,
  findLatestBackup,
  findNewerBackup,
  hasExistingWrapMeta,
  removeWrapMeta,
  saveWrapMeta,
} from "../../src/wrap/config-reader.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

const CRASH_WINDOW_MARKER = "already contains a Sanctuary entry";

describe("surface-scoped wrap-meta + backups, orphan guard, banner gate, pin probe", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let errSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-surface-scope-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    errSpy.mockRestore();
    vi.restoreAllMocks();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps(overrides: Record<string, unknown> = {}) {
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {},
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated" as const,
      }),
      ...overrides,
    };
  }

  function stderrOutput(): string {
    return errSpy.mock.calls.map((c) => c.map(String).join(" ")).join("\n");
  }

  function backupDirPath(): string {
    return join(tmpHome, ".sanctuary", "backup");
  }

  async function seedMetaFor(originalPath: string): Promise<void> {
    await writeFile(originalPath, "{}");
    const backup = await backupConfig(originalPath);
    await saveWrapMeta({
      backupPath: backup,
      originalPath,
      platform: "claude-code",
      wrappedAt: new Date().toISOString(),
    });
  }

  // ── Finding 1: per-surface wrap-meta + backup discrimination ────────

  it("hasExistingWrapMeta is scoped to the surface's resolve()d originalPath", async () => {
    const surfaceY = join(tmpHome, "surface-y.json");
    await seedMetaFor(surfaceY);

    const surfaceX = join(tmpHome, "surface-x.json");
    expect(await hasExistingWrapMeta(surfaceY)).toBe(true);
    expect(await hasExistingWrapMeta(surfaceX)).toBe(false);
  });

  it("hasExistingWrapMeta reads false when no meta exists at all", async () => {
    expect(await hasExistingWrapMeta(join(tmpHome, "anything.json"))).toBe(
      false,
    );
  });

  it("findNewerBackup never points at a DIFFERENT surface's backup of the same extension", async () => {
    const surfaceA = join(tmpHome, "a-config.json");
    const surfaceB = join(tmpHome, "b-config.json");
    await writeFile(surfaceA, '{"a":1}');
    await writeFile(surfaceB, '{"b":1}');

    const backupA1 = await backupConfig(surfaceA);
    // Millisecond-resolution filenames: keep the timestamps distinct.
    await new Promise((resolve) => setTimeout(resolve, 5));
    await backupConfig(surfaceB); // newer, same .json extension, OTHER surface

    // Pre-fix this returned surface B's backup (prefix+extension matched).
    expect(await findNewerBackup(backupA1, surfaceA)).toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 5));
    const backupA2 = await backupConfig(surfaceA);
    expect(await findNewerBackup(backupA1, surfaceA)).toBe(backupA2);
    // The newest backup of a chain has nothing newer.
    expect(await findNewerBackup(backupA2, surfaceA)).toBeNull();
  });

  // ── Finding 2: removeWrapMeta is non-destructive on a read error ────

  it.skipIf(process.getuid?.() === 0)(
    "removeWrapMeta leaves the pointer in place and reports a failure on a transient read error",
    async () => {
      const configPath = join(tmpHome, "unreadable-meta-config.json");
      await seedMetaFor(configPath);
      const metaPath = join(backupDirPath(), "wrap-meta.json");

      await chmod(metaPath, 0o000);
      try {
        const failures = await removeWrapMeta(configPath);
        expect(failures).toContain(metaPath);
      } finally {
        await chmod(metaPath, 0o600);
      }
      // The pointer survived the error path: unwrap remains re-runnable.
      expect(await findLatestBackup()).not.toBeNull();

      // Once readable again, removal completes normally.
      expect(await removeWrapMeta(configPath)).toEqual([]);
      expect(await findLatestBackup()).toBeNull();
    },
  );

  it("removeWrapMeta still removes an affirmatively unparseable pointer file", async () => {
    const metaPath = join(backupDirPath(), "wrap-meta.json");
    await mkdir(backupDirPath(), { recursive: true, mode: 0o700 });
    await writeFile(metaPath, "not json {{{");

    expect(await removeWrapMeta(join(tmpHome, "whatever.json"))).toEqual([]);
    await expect(access(metaPath)).rejects.toThrow();
  });

  // ── Findings 3 + 4: orphan guard on all rollbacks, crash-window scope ──

  it.skipIf(process.getuid?.() === 0)(
    "a failed rollback on the REWRITE failure path writes the fallback meta (orphan-wrap guard beyond the meta-write site)",
    async () => {
      const settingsDir = join(tmpHome, ".claude");
      await mkdir(settingsDir, { recursive: true });
      const settingsPath = join(settingsDir, "settings.json");
      const pristine = JSON.stringify({ mcpServers: {} }, null, 2);
      await writeFile(settingsPath, pristine);

      const exitSpy = vi
        .spyOn(process, "exit")
        .mockImplementation((code?: string | number | null) => {
          throw new Error(`process.exit:${code}`);
        });
      try {
        await expect(
          runWrap(
            { claudeCode: true, noOpen: true },
            makeDeps({
              rewriteConfig: async () => {
                // Corrupt the live config, make the rollback restore fail
                // (read-only target), then die: the exact shape that used
                // to end wrapped/corrupt with NO meta on disk.
                await writeFile(settingsPath, "corrupted {{{");
                await chmod(settingsPath, 0o400);
                throw new Error("EIO: simulated mid-write failure");
              },
            }),
          ),
        ).rejects.toThrow("process.exit:1");
      } finally {
        exitSpy.mockRestore();
      }

      // The guard wrote the fallback meta so --unwrap can find the wrap.
      const meta = await findLatestBackup();
      expect(meta?.originalPath).toBe(settingsPath);
      expect(await readFile(meta!.backupPath, "utf-8")).toBe(pristine);
      expect(stderrOutput()).toContain(
        "Wrap metadata was written after the failed restore",
      );
    },
  );

  it("crash-window warning fires for surface X even when surface Y's wrap-meta exists (MED-2 residual)", async () => {
    // Surface Y: some other config with a live wrap-meta.
    await seedMetaFor(join(tmpHome, "surface-y.json"));

    // Surface X: crash-window state — the config already carries the
    // sanctuary entry but no meta points at X.
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(
      settingsPath,
      JSON.stringify(
        { mcpServers: { sanctuary: { command: "npx", args: ["-y"] } } },
        null,
        2,
      ),
    );

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    // Pre-fix, the tenant-global hasExistingWrapMeta saw Y's meta and
    // suppressed this warning.
    expect(stderrOutput()).toContain(CRASH_WINDOW_MARKER);
  });

  it("crash-window warning does NOT fire on a normal re-wrap (this surface's own meta exists)", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    errSpy.mockClear();
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    expect(stderrOutput()).not.toContain(CRASH_WINDOW_MARKER);
  });

  // ── Finding 5: THE banner honesty gate (refactor-only; never weaken) ──

  it("castleWallProtectionConfirmed truth table: ONLY armed && observed is confirmed", () => {
    expect(castleWallProtectionConfirmed(true, true)).toBe(true);
    // Every other combination — false, undefined, absent signal — reads
    // NOT confirmed. Weakening any row here is a security defect.
    const notConfirmed: Array<[boolean | undefined, boolean | undefined]> = [
      [true, false],
      [true, undefined],
      [false, true],
      [false, false],
      [false, undefined],
      [undefined, true],
      [undefined, false],
      [undefined, undefined],
    ];
    for (const [armed, observed] of notConfirmed) {
      expect(castleWallProtectionConfirmed(armed, observed)).toBe(false);
    }
  });

  // ── Finding 6: wrap-time pinned-version resolvability ───────────────

  describe("checkPinnedVersionResolvable", () => {
    let server: Server | undefined;
    let savedKnob: string | undefined;

    beforeEach(() => {
      // The suite-wide vitest env sets the zero-outbound knob; these tests
      // exercise the probe itself against a loopback server.
      savedKnob = process.env.SANCTUARY_NO_UPDATE_CHECK;
      delete process.env.SANCTUARY_NO_UPDATE_CHECK;
    });

    afterEach(async () => {
      if (savedKnob !== undefined)
        process.env.SANCTUARY_NO_UPDATE_CHECK = savedKnob;
      else delete process.env.SANCTUARY_NO_UPDATE_CHECK;
      if (server) {
        await new Promise<void>((resolve) => server!.close(() => resolve()));
        server = undefined;
      }
    });

    async function startRegistryStub(statusCode: number): Promise<string> {
      server = createServer((_req, res) => {
        res.statusCode = statusCode;
        res.end(statusCode === 200 ? '{"version":"9.9.9"}' : "{}");
      });
      await new Promise<void>((resolve) =>
        server!.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = server!.address() as AddressInfo;
      return `http://127.0.0.1:${port}`;
    }

    it("a registry that serves the version reads resolvable", async () => {
      const base = await startRegistryStub(200);
      expect(
        await checkPinnedVersionResolvable("9.9.9", { registryBaseUrl: base }),
      ).toBe("resolvable");
    });

    it("an affirmative registry 404 reads unpublished", async () => {
      const base = await startRegistryStub(404);
      expect(
        await checkPinnedVersionResolvable("9.9.9", { registryBaseUrl: base }),
      ).toBe("unpublished");
    });

    it("a connection failure reads unreachable (honest-unknown), never resolvable", async () => {
      // Bind a port, then close it so nothing listens there.
      const probe = createServer();
      await new Promise<void>((resolve) =>
        probe.listen(0, "127.0.0.1", () => resolve()),
      );
      const { port } = probe.address() as AddressInfo;
      await new Promise<void>((resolve) => probe.close(() => resolve()));
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: `http://127.0.0.1:${port}`,
          timeoutMs: 500,
        }),
      ).toBe("unreachable");
    });

    it("SANCTUARY_NO_UPDATE_CHECK=1 skips the probe entirely (zero outbound)", async () => {
      process.env.SANCTUARY_NO_UPDATE_CHECK = "1";
      expect(
        await checkPinnedVersionResolvable("9.9.9", {
          registryBaseUrl: "http://127.0.0.1:1",
        }),
      ).toBe("skipped");
    });
  });

  it("an unpublished pin downgrades the wrap output with an honest WARNING and does not block the wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "unpublished" }),
    );

    const out = stderrOutput();
    expect(out).toContain("does not have that version");
    expect(out).toContain("--dev-dist");
    // Availability: the wrap still completed.
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(wrapped.mcpServers.sanctuary).toBeDefined();
  });

  it("an unreachable registry prints the honest could-not-verify note and does not block the wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "unreachable" }),
    );

    expect(stderrOutput()).toContain(
      "could not reach the npm registry to confirm the pinned version",
    );
    const wrapped = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(wrapped.mcpServers.sanctuary).toBeDefined();
  });

  it("a resolvable pin adds no warning noise", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap(
      { claudeCode: true, noOpen: true },
      makeDeps({ checkPinResolvability: async () => "resolvable" }),
    );

    const out = stderrOutput();
    expect(out).not.toContain("does not have that version");
    expect(out).not.toContain("could not reach the npm registry");
  });

  // ── Finding 7: recovery breadcrumb for wrap-created files on unwrap ──

  it("unwrap of a wrap-created Hermes config.yaml preserves its final contents as a backup breadcrumb", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    await writeFile(jsonPath, "{}");
    // No config.yaml: wrap creates it fresh (backupPath: null).

    await runWrap({ hermes: true, noOpen: true }, makeDeps());

    // The operator adds their own MCP entry AFTER the wrap.
    const wrappedYaml = await readFile(yamlPath, "utf-8");
    const operatorLine = '  operator-added-server:\n    command: "my-tool"\n';
    await writeFile(yamlPath, wrappedYaml + operatorLine);

    errSpy.mockClear();
    await runWrap({ unwrap: true }, makeDeps());

    // Restore semantics unchanged: the wrap-created file is removed.
    await expect(access(yamlPath)).rejects.toThrow();
    // ...but its final contents survive in a timestamped backup, and the
    // operator was told where.
    expect(stderrOutput()).toContain("Its final contents were preserved at:");
    const backups = await readdir(backupDirPath());
    const yamlBackups = backups.filter((name) => name.endsWith(".yaml"));
    let preserved = false;
    for (const name of yamlBackups) {
      const content = await readFile(join(backupDirPath(), name), "utf-8");
      if (content.includes("operator-added-server")) preserved = true;
    }
    expect(preserved).toBe(true);
  });
});
