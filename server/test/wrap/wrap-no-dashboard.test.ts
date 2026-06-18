/**
 * v1.1.5 (Finding AA) — `sanctuary wrap --no-dashboard` skips the
 * per-call dashboard server spawn while preserving the rest of the
 * wrap pipeline (config rewrite, passphrase persistence, agent record).
 *
 * Default behavior is preserved when the flag is absent: dashboard
 * spawns, port binds, URL prints, browser auto-opens.
 *
 * Together with the v1.1.5(z) agent-record persistence write, this
 * unblocks the canonical operator-clean flow:
 *
 *   sanctuary dashboard &                                # once
 *   sanctuary wrap --claude-code --no-dashboard          # per harness
 *   sanctuary wrap --openclaw    --no-dashboard
 *
 * `sanctuary dashboard` rehydrates the registry from the same hub-
 * layer file each `wrap --no-dashboard` writes, so the persistent
 * dashboard sees both harnesses without sprawl.
 */

import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { cp, mkdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  formatWrapSuccessNoDashboard,
  parseWrapArgs,
  runWrap,
  type DashboardStarter,
  type RunWrapDeps,
  type WrapOptions,
} from "../../src/wrap/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";
import { readPersistedLocalAgents } from "../../src/hub/agent-registry-persistence.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

describe("parseWrapArgs --no-dashboard capture", () => {
  it("captures --no-dashboard into WrapOptions", () => {
    const opts = parseWrapArgs(["--claude-code", "--no-dashboard"]);
    expect(opts.noDashboard).toBe(true);
    expect(opts.claudeCode).toBe(true);
  });

  it("returns undefined when --no-dashboard is not passed", () => {
    const opts = parseWrapArgs(["--claude-code"]);
    expect(opts.noDashboard).toBeUndefined();
  });

  it("--no-dashboard composes with other flags (--no-open, --port)", () => {
    const opts = parseWrapArgs([
      "--claude-code",
      "--no-dashboard",
      "--no-open",
      "--port",
      "3777",
    ]);
    expect(opts.noDashboard).toBe(true);
    expect(opts.noOpen).toBe(true);
    expect(opts.port).toBe(3777);
  });
});

describe("formatWrapSuccessNoDashboard", () => {
  it("includes the wrapped tool + version line", () => {
    const out = formatWrapSuccessNoDashboard({
      toolName: "Claude Code",
      version: "1.1.5",
      toolCount: 0,
      serverCount: 0,
      passphraseLocation: "fixture-keychain",
      passphraseSource: "generated",
    });
    expect(out).toContain("Wrapped");
    expect(out).toContain("Claude Code");
    expect(out).toContain("1.1.5");
  });

  it("replaces the dashboard URL line with the persistent-dashboard note", () => {
    const out = formatWrapSuccessNoDashboard({
      toolName: "OpenClaw",
      version: "1.1.5",
      toolCount: 3,
      serverCount: 1,
      passphraseLocation: "fixture-keychain",
      passphraseSource: "generated",
    });
    expect(out).toContain("Dashboard spawn skipped per --no-dashboard");
    expect(out).toContain("Run `sanctuary dashboard` separately");
    // Sanity: the dashboard URL line from the default formatter is gone.
    expect(out).not.toContain("Sovereignty Dashboard running at");
  });

  it("preserves the protected-status footer when Castle Wall armed", () => {
    const out = formatWrapSuccessNoDashboard({
      toolName: "Claude Code",
      version: "1.1.5",
      toolCount: 0,
      serverCount: 0,
      passphraseLocation: "fixture-keychain",
      passphraseSource: "generated",
      // Honesty (audit seam #1): the protected/Full footer is reserved for an
      // observed daemon arm.
      castleWallArmed: true,
    });
    expect(out).toContain("Your agent is protected");
    expect(out).toContain("Castle Wall Full");
    // L1-L4 numbering was MANDATORY-retired 2026-05-24.
    expect(out).not.toMatch(/\bL[1-4]\b/);
  });

  // Honesty (audit seam #1): a failed arm must not print protected/Full.
  it("downgrades the footer when Castle Wall did not arm", () => {
    const out = formatWrapSuccessNoDashboard({
      toolName: "Claude Code",
      version: "1.1.5",
      toolCount: 0,
      serverCount: 0,
      passphraseLocation: "fixture-keychain",
      passphraseSource: "generated",
      castleWallArmed: false,
    });
    expect(out).not.toContain("Your agent is protected");
    expect(out).not.toContain("Castle Wall Full");
    expect(out).toContain("Castle Wall NOT ARMED");
  });

  it("pluralizes 'server' correctly", () => {
    const single = formatWrapSuccessNoDashboard({
      toolName: "Claude Code",
      version: "1.1.5",
      toolCount: 0,
      serverCount: 1,
      passphraseLocation: "kc",
      passphraseSource: "generated",
    });
    expect(single).toContain("1 upstream server");
    expect(single).not.toContain("1 upstream servers");

    const multi = formatWrapSuccessNoDashboard({
      toolName: "Claude Code",
      version: "1.1.5",
      toolCount: 0,
      serverCount: 3,
      passphraseLocation: "kc",
      passphraseSource: "generated",
    });
    expect(multi).toContain("3 upstream servers");
  });
});

describe("runWrap --no-dashboard end-to-end", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let originalPassphrase: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-aa-runwrap-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    originalPassphrase = process.env.SANCTUARY_PASSPHRASE;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    process.env.SANCTUARY_PASSPHRASE = "fixture-passphrase-aa";
    stderrSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    if (originalStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    }
    if (originalPassphrase === undefined) {
      delete process.env.SANCTUARY_PASSPHRASE;
    } else {
      process.env.SANCTUARY_PASSPHRASE = originalPassphrase;
    }
    vi.restoreAllMocks();
    await rm(tmpHome, { recursive: true, force: true });
  });

  function deps(): {
    runWrapDeps: RunWrapDeps;
    dashboardSpawnCount: { value: number };
  } {
    const dashboardSpawnCount = { value: 0 };
    const startDashboard: DashboardStarter = async (startOpts) => {
      dashboardSpawnCount.value += 1;
      return {
        url: `http://127.0.0.1:${startOpts.port}`,
        port: startOpts.port,
        host: "127.0.0.1",
        mode: "co-located",
        stop: async () => {},
        setV11Bindings: () => {},
        setV11LoopbackAutoAuth: () => {},
      } as unknown as DashboardHandle;
    };
    return {
      runWrapDeps: {
        startDashboard,
        openBrowser: async () => {},
        resolvePassphrase: async () => ({
          value: "fixture-passphrase-aa",
          location: "fixture-keychain",
          source: "generated" as const,
        }),
      },
      dashboardSpawnCount,
    };
  }

  async function installFixture(
    relPath: string,
    fixtureName: string,
  ): Promise<string> {
    const target = join(tmpHome, relPath);
    await mkdir(dirname(target), { recursive: true });
    await cp(join(fixturesDir, fixtureName), target);
    return target;
  }

  function storagePath(): string {
    return process.env.SANCTUARY_STORAGE_PATH!;
  }

  function options(extra: WrapOptions = {}): WrapOptions {
    return { claudeCode: true, ...extra };
  }

  function stderrText(): string {
    return (
      console.error as unknown as { mock: { calls: unknown[][] } }
    ).mock.calls
      .map((call) => call.join(" "))
      .join("\n");
  }

  it("--no-dashboard does not spawn a dashboard server", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    const { runWrapDeps, dashboardSpawnCount } = deps();
    await runWrap(options({ noDashboard: true }), runWrapDeps);
    expect(dashboardSpawnCount.value).toBe(0);
  });

  it("--no-dashboard does not print a dashboard URL line", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ noDashboard: true }), deps().runWrapDeps);
    const stderr = stderrText();
    expect(stderr).not.toContain("Sovereignty Dashboard running at");
    expect(stderr).not.toMatch(/http:\/\/127\.0\.0\.1:35\d\d\?token=/);
  });

  it("--no-dashboard prints the persistent-dashboard skip note", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ noDashboard: true }), deps().runWrapDeps);
    const stderr = stderrText();
    expect(stderr).toContain("Dashboard spawn skipped per --no-dashboard");
    expect(stderr).toContain("Run `sanctuary dashboard` separately");
  });

  it("--no-dashboard still persists the agent record (Z fix preserved)", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ noDashboard: true }), deps().runWrapDeps);
    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted).toHaveLength(1);
    expect(persisted[0]!.harness).toBe("claude_code");
  });

  it("--no-dashboard still rewrites the harness config", async () => {
    const configPath = await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(options({ noDashboard: true }), deps().runWrapDeps);
    const raw = await readFile(configPath, "utf-8");
    const parsed = JSON.parse(raw) as {
      mcpServers?: Record<string, unknown>;
    };
    expect(parsed.mcpServers?.sanctuary).toBeDefined();
  });

  it("default (no flag) DOES spawn the dashboard (no regression)", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    const { runWrapDeps, dashboardSpawnCount } = deps();
    await runWrap(options({ noOpen: true }), runWrapDeps);
    expect(dashboardSpawnCount.value).toBe(1);
    expect(stderrText()).toContain("Sovereignty Dashboard running at");
  });

  it("two --no-dashboard wraps against the same fortress register two harnesses (multi-harness flow)", async () => {
    await installFixture(".claude.json", "flat-mcp.json");
    await runWrap(
      options({ claudeCode: true, noDashboard: true }),
      deps().runWrapDeps,
    );
    await installFixture(".cursor/mcp.json", "flat-mcp.json");
    await runWrap(
      options({ claudeCode: false, cursor: true, noDashboard: true }),
      deps().runWrapDeps,
    );
    const persisted = readPersistedLocalAgents(storagePath());
    expect(persisted.map((r) => r.harness).sort()).toEqual([
      "claude_code",
      "cursor",
    ]);
  });
});
