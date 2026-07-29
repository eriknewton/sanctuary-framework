/**
 * Wrap-meta write failure paths (fix-round MED-4a/MED-4b for PR #843).
 *
 * The wrap flow defers the wrap-meta write until every wrapped surface is
 * verified-committed. That makes the meta write the LAST failure point, and
 * its handling carries two invariants pinned here:
 *
 *   1. (MED-4a) When saveWrapMeta throws, EVERY wrapped surface (the primary
 *      JSON config and, for Hermes, the authoritative config.yaml) is rolled
 *      back to its pre-wrap bytes and the process exits non-zero, with no
 *      wrap-meta left on disk.
 *   2. (MED-4b / MED-1 orphan-wrap guard) When saveWrapMeta throws AND a
 *      surface restore itself fails (disk full, unwritable file), the config
 *      is still wrapped while nothing points at the backup; --unwrap would
 *      report "No Sanctuary wrap found" while traffic keeps routing through
 *      Sanctuary. The wrap must retry the meta write (a meta pointing at the
 *      good backup beats the orphan state) and, if that also fails, print an
 *      explicit CRITICAL message with the exact manual restore commands.
 *
 * Isolation: temp HOME + SANCTUARY_STORAGE_PATH (never the real
 * ~/.sanctuary), per the existing wrap-test idiom.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  writeFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  chmod,
  access,
} from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { runWrap } from "../../src/wrap/cli.js";
import { saveWrapMeta } from "../../src/wrap/config-reader.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import {
  agreeingHermesParity,
  installHermesParityHook,
  clearHermesParityHook,
} from "../helpers/hermes-parity.js";

describe("wrap-meta write failure: rollback + orphan-wrap guard", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let errSpy: ReturnType<typeof vi.spyOn>;
  let exitSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    // mkdtemp: atomic fresh 0o700 dir (CodeQL js/insecure-temporary-file).
    tmpHome = await mkdtemp(join(tmpdir(), "sanctuary-meta-fail-"));
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: string | number | null) => {
        throw new Error(`process.exit:${code}`);
      });
  });

  afterEach(async () => {
    clearHermesParityHook();
    errSpy.mockRestore();
    exitSpy.mockRestore();
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
    // Agree with the scanner via the test-only sidecar hook so these Hermes
    // rollback/meta mechanics tests do not depend on the CI host carrying
    // PyYAML (the parse-parity guard is proven separately in
    // hermes-yaml-parse-parity.test.ts). The sidecar seam is NOT a public
    // runWrap dep (DI-bypass closed 2026-07-03), so it is installed here
    // rather than passed through deps/overrides.
    installHermesParityHook(agreeingHermesParity);
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

  function metaPath(): string {
    return join(tmpHome, ".sanctuary", "backup", "wrap-meta.json");
  }

  it("saveWrapMeta throw rolls BOTH Hermes surfaces back to pre-wrap bytes and exits non-zero (MED-4a)", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const originalJson = JSON.stringify(
      { mcp_servers: { weather: { command: "uvx", args: ["mcp-weather"] } } },
      null,
      2,
    );
    await writeFile(jsonPath, originalJson);
    const yamlPath = join(hermesDir, "config.yaml");
    const originalYaml = 'mcp_servers:\n  weather:\n    command: "uvx"\n';
    await writeFile(yamlPath, originalYaml);

    await expect(
      runWrap(
        { hermes: true, noOpen: true },
        makeDeps({
          saveWrapMeta: async () => {
            throw new Error("ENOSPC: no space left on device");
          },
        }),
      ),
    ).rejects.toThrow("process.exit:1");

    // Both surfaces are byte-identical to the pre-wrap originals.
    expect(await readFile(jsonPath, "utf-8")).toBe(originalJson);
    expect(await readFile(yamlPath, "utf-8")).toBe(originalYaml);
    // No wrap-meta was left behind for a wrap that did not stick.
    await expect(access(metaPath())).rejects.toThrow();
    expect(stderrOutput()).toContain("Wrap metadata write FAILED");
  });

  it("saveWrapMeta throw + failed restore writes the fallback meta so --unwrap can still find the wrap (MED-1)", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristine = JSON.stringify(
      { mcpServers: { demo: { command: "node", args: ["demo.js"] } } },
      null,
      2,
    );
    await writeFile(settingsPath, pristine);

    // First call: sabotage the restore target (read-only live config makes
    // restoreConfig's write fail), then throw. Second call: delegate to the
    // real saveWrapMeta, pinning that the fallback write actually happens.
    let calls = 0;
    const failingThenReal: typeof saveWrapMeta = async (meta, options) => {
      calls += 1;
      if (calls === 1) {
        await chmod(settingsPath, 0o400);
        throw new Error("EIO: simulated meta write failure");
      }
      return saveWrapMeta(meta, options);
    };

    await expect(
      runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps({ saveWrapMeta: failingThenReal }),
      ),
    ).rejects.toThrow("process.exit:1");

    // The restore failed, so the live config is still wrapped...
    const live = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(live.mcpServers.sanctuary).toBeDefined();
    // ...but the fallback meta write happened: --unwrap has a pointer at
    // the pristine backup instead of reporting "No Sanctuary wrap found".
    expect(calls).toBe(2);
    const meta = JSON.parse(await readFile(metaPath(), "utf-8"));
    expect(meta.originalPath).toBe(settingsPath);
    expect(await readFile(meta.backupPath, "utf-8")).toBe(pristine);
    expect(stderrOutput()).toContain(
      "Wrap metadata was written after the failed restore",
    );
  });

  it("double failure (meta write + restore + fallback meta write) prints the explicit CRITICAL orphan message (MED-1)", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    const pristine = JSON.stringify(
      { mcpServers: { demo: { command: "node", args: ["demo.js"] } } },
      null,
      2,
    );
    await writeFile(settingsPath, pristine);

    let sabotaged = false;
    const alwaysFailing: typeof saveWrapMeta = async () => {
      if (!sabotaged) {
        sabotaged = true;
        await chmod(settingsPath, 0o400);
      }
      throw new Error("ENOSPC: no space left on device");
    };

    await expect(
      runWrap(
        { claudeCode: true, noOpen: true },
        makeDeps({ saveWrapMeta: alwaysFailing }),
      ),
    ).rejects.toThrow("process.exit:1");

    // Still wrapped, no meta anywhere: the one state the wrap must never
    // end in silently.
    const live = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(live.mcpServers.sanctuary).toBeDefined();
    await expect(access(metaPath())).rejects.toThrow();
    const out = stderrOutput();
    expect(out).toContain("CRITICAL: the config is STILL WRAPPED");
    expect(out).toContain("--unwrap will NOT find this wrap");
    // The exact manual restore command, quoting both paths.
    expect(out).toContain(`cp "`);
    expect(out).toContain(`" "${settingsPath}"`);
  });
});
