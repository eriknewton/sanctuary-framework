/**
 * Wrap CLI flag plumbing — `--install-hooks` / `--no-install-hooks`
 * (v1.2.0 F10).
 *
 * Asserts the runtime branch off WrapOptions.installHooks + the
 * detected platform:
 *
 *   undefined + claude-code  → install (default-on)
 *   undefined + cline        → no install, no warning
 *   true      + claude-code  → install (explicit on)
 *   true      + cline        → no install, prints not-supported note
 *   false     + claude-code  → no install, prints opt-out note
 *
 * Tests use the `installClaudeCodeStopHook` dependency injection on
 * runWrap to assert the call shape without touching the developer's
 * real ~/.claude/settings.json. parseWrapArgs round-trip is asserted
 * directly on the flag.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  parseWrapArgs,
  runWrap,
} from "../../src/cocoon/cli.js";
import type {
  InstallClaudeCodeHookOptions,
  InstallClaudeCodeHookResult,
} from "../../src/cocoon/claude-code-hooks.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

describe("Wrap CLI install-hooks plumbing (v1.2.0 F10)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;
  let stderrSpy: ReturnType<typeof vi.spyOn>;
  let stderrCaptured: string;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-wrap-F10-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
    stderrCaptured = "";
    stderrSpy = vi
      .spyOn(console, "error")
      .mockImplementation((...args: unknown[]) => {
        stderrCaptured += args.map((a) => String(a)).join(" ") + "\n";
      });
  });

  afterEach(async () => {
    stderrSpy.mockRestore();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  function makeDeps(opts: {
    onInstall?: (
      o: InstallClaudeCodeHookOptions,
    ) => Promise<InstallClaudeCodeHookResult>;
  } = {}) {
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
        source: "generated",
      }),
      installClaudeCodeStopHook:
        opts.onInstall ??
        (async () =>
          ({
            installedAt: join(tmpHome, ".claude", "settings.json"),
            alreadyPresent: false,
            envUpdated: false,
          }) satisfies InstallClaudeCodeHookResult),
    };
  }

  async function seedClaudeCodeConfig() {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));
    return settingsPath;
  }

  async function seedClineConfig() {
    // Cline VS Code globalStorage path on macOS.
    const settingsDir = join(
      tmpHome,
      "Library",
      "Application Support",
      "Code",
      "User",
      "globalStorage",
      "saoudrizwan.claude-dev",
      "settings",
    );
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "cline_mcp_settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));
    return settingsPath;
  }

  describe("parseWrapArgs", () => {
    it("--install-hooks sets installHooks=true", () => {
      const opts = parseWrapArgs(["--claude-code", "--install-hooks"]);
      expect(opts.installHooks).toBe(true);
    });

    it("--no-install-hooks sets installHooks=false", () => {
      const opts = parseWrapArgs(["--claude-code", "--no-install-hooks"]);
      expect(opts.installHooks).toBe(false);
    });

    it("absent flag leaves installHooks undefined (default applies later)", () => {
      const opts = parseWrapArgs(["--claude-code"]);
      expect(opts.installHooks).toBeUndefined();
    });
  });

  describe("runWrap branch on installHooks + platform", () => {
    it("undefined + claude-code: installs hook (default-on)", async () => {
      await seedClaudeCodeConfig();
      const installCalls: InstallClaudeCodeHookOptions[] = [];
      await runWrap(
        { claudeCode: true, noOpen: true, noDashboard: true },
        makeDeps({
          onInstall: async (o) => {
            installCalls.push(o);
            return {
              installedAt: "/tmp/settings.json",
              alreadyPresent: false,
              envUpdated: false,
            };
          },
        }),
      );
      expect(installCalls).toHaveLength(1);
      expect(installCalls[0]!.agentId).toMatch(/^agent:claude_code:/);
      expect(installCalls[0]!.identityId).toBe("sanctuary-chat");
    });

    it("--no-install-hooks + claude-code: skips install, prints opt-out note", async () => {
      await seedClaudeCodeConfig();
      const installCalls: InstallClaudeCodeHookOptions[] = [];
      await runWrap(
        {
          claudeCode: true,
          installHooks: false,
          noOpen: true,
          noDashboard: true,
        },
        makeDeps({
          onInstall: async (o) => {
            installCalls.push(o);
            return {
              installedAt: "/tmp/settings.json",
              alreadyPresent: false,
              envUpdated: false,
            };
          },
        }),
      );
      expect(installCalls).toHaveLength(0);
      expect(stderrCaptured).toMatch(/Stop hook NOT installed/);
    });

    it("--install-hooks + cline: skips install, prints not-supported note", async () => {
      await seedClineConfig();
      const installCalls: InstallClaudeCodeHookOptions[] = [];
      await runWrap(
        {
          cline: true,
          installHooks: true,
          noOpen: true,
          noDashboard: true,
        },
        makeDeps({
          onInstall: async (o) => {
            installCalls.push(o);
            return {
              installedAt: "/tmp/settings.json",
              alreadyPresent: false,
              envUpdated: false,
            };
          },
        }),
      );
      expect(installCalls).toHaveLength(0);
      expect(stderrCaptured).toMatch(/--install-hooks is only supported for --claude-code/);
    });

    it("undefined + cline: no install, no warning (default-off for non-claude-code)", async () => {
      await seedClineConfig();
      const installCalls: InstallClaudeCodeHookOptions[] = [];
      await runWrap(
        { cline: true, noOpen: true, noDashboard: true },
        makeDeps({
          onInstall: async (o) => {
            installCalls.push(o);
            return {
              installedAt: "/tmp/settings.json",
              alreadyPresent: false,
              envUpdated: false,
            };
          },
        }),
      );
      expect(installCalls).toHaveLength(0);
      expect(stderrCaptured).not.toMatch(/--install-hooks is only supported/);
      expect(stderrCaptured).not.toMatch(/Stop hook NOT installed/);
    });

    it("alreadyPresent=true envUpdated=false prints idempotent note", async () => {
      await seedClaudeCodeConfig();
      await runWrap(
        { claudeCode: true, noOpen: true, noDashboard: true },
        makeDeps({
          onInstall: async () => ({
            installedAt: "/tmp/settings.json",
            alreadyPresent: true,
            envUpdated: false,
          }),
        }),
      );
      expect(stderrCaptured).toMatch(/Stop hook already present/);
    });

    it("alreadyPresent=true envUpdated=true prints refresh note", async () => {
      await seedClaudeCodeConfig();
      await runWrap(
        { claudeCode: true, noOpen: true, noDashboard: true },
        makeDeps({
          onInstall: async () => ({
            installedAt: "/tmp/settings.json",
            alreadyPresent: true,
            envUpdated: true,
          }),
        }),
      );
      expect(stderrCaptured).toMatch(/Stop hook refreshed/);
    });

    it("install failure: stderr warning, wrap continues (no throw)", async () => {
      await seedClaudeCodeConfig();
      await expect(
        runWrap(
          { claudeCode: true, noOpen: true, noDashboard: true },
          makeDeps({
            onInstall: async () => {
              throw new Error("settings.json is not valid JSON");
            },
          }),
        ),
      ).resolves.not.toThrow();
      expect(stderrCaptured).toMatch(/Stop hook install failed/);
      expect(stderrCaptured).toMatch(/settings\.json is not valid JSON/);
    });
  });
});
