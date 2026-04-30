/**
 * Claude Code config path probing — v1.0 rc.1 finding C
 *
 * Pre-v1.0 wrap only probed ~/.claude/settings.json and the XDG sibling
 * ~/.config/claude-code/settings.json for Claude Code's MCP config.
 * Modern Claude Code writes its MCP config to ~/.claude.json (this is
 * the file `claude mcp add` updates), and the two tools were silently
 * disagreeing about where the user's config lived: any operator who
 * had run `claude mcp add` had their config invisible to wrap.
 *
 * The fix adds ~/.claude.json as the FIRST entry in the platform path
 * list. Probe order = preference order: detection returns the first
 * path that exists; bootstrap (Finding A) creates one at the canonical
 * path when neither legacy nor modern config is present.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, readFile, rm, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  detectAgentConfigWithDiagnostics,
  getPlatformPaths,
} from "../../src/cocoon/config-reader.js";
import { runWrap } from "../../src/cocoon/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

describe("Claude Code config path probing (finding C)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    tmpHome = join(tmpdir(), `sanctuary-wrap-C-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
  });

  afterEach(async () => {
    if (originalHome !== undefined) process.env.HOME = originalHome;
    else delete process.env.HOME;
    if (originalStoragePath !== undefined)
      process.env.SANCTUARY_STORAGE_PATH = originalStoragePath;
    else delete process.env.SANCTUARY_STORAGE_PATH;
    try {
      await rm(tmpHome, { recursive: true, force: true });
    } catch {}
  });

  function makeDeps() {
    const fakeHandle = {
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
    };
  }

  it("lists ~/.claude.json as the first claude-code path", () => {
    // Pin the probe-order contract so the bootstrap path is stable too:
    // when no config exists, cli.ts creates one at paths[0].
    const paths = getPlatformPaths()["claude-code"];
    expect(paths[0]).toBe(join(tmpHome, ".claude.json"));
    expect(paths).toContain(join(tmpHome, ".claude", "settings.json"));
  });

  it("detects an existing ~/.claude.json", async () => {
    const claudeJsonPath = join(tmpHome, ".claude.json");
    await writeFile(
      claudeJsonPath,
      JSON.stringify({
        mcpServers: {
          filesystem: { command: "node", args: ["fs.js"] },
        },
      })
    );

    const result = await detectAgentConfigWithDiagnostics("claude-code");
    expect(result.config).not.toBeNull();
    expect(result.config!.configPath).toBe(claudeJsonPath);
    expect(result.config!.servers.map((s) => s.name)).toEqual(["filesystem"]);
  });

  it("prefers ~/.claude.json over ~/.claude/settings.json when both exist", async () => {
    const claudeJsonPath = join(tmpHome, ".claude.json");
    const legacyPath = join(tmpHome, ".claude", "settings.json");
    await mkdir(join(tmpHome, ".claude"), { recursive: true });
    await writeFile(
      claudeJsonPath,
      JSON.stringify({
        mcpServers: {
          modern: { command: "node", args: ["modern.js"] },
        },
      })
    );
    await writeFile(
      legacyPath,
      JSON.stringify({
        mcpServers: {
          legacy: { command: "node", args: ["legacy.js"] },
        },
      })
    );

    const result = await detectAgentConfigWithDiagnostics("claude-code");
    expect(result.config).not.toBeNull();
    expect(result.config!.configPath).toBe(claudeJsonPath);
    expect(result.config!.servers.map((s) => s.name)).toEqual(["modern"]);
    // Legacy file is untouched, just not the source of truth.
    const legacyRaw = JSON.parse(await readFile(legacyPath, "utf-8"));
    expect(legacyRaw.mcpServers.legacy).toBeDefined();
  });

  it("falls back to ~/.claude/settings.json when ~/.claude.json is absent", async () => {
    const legacyPath = join(tmpHome, ".claude", "settings.json");
    await mkdir(join(tmpHome, ".claude"), { recursive: true });
    await writeFile(
      legacyPath,
      JSON.stringify({
        mcpServers: {
          legacy: { command: "node", args: ["legacy.js"] },
        },
      })
    );

    const result = await detectAgentConfigWithDiagnostics("claude-code");
    expect(result.config).not.toBeNull();
    expect(result.config!.configPath).toBe(legacyPath);
    expect(result.config!.servers.map((s) => s.name)).toEqual(["legacy"]);
  });

  it("wrap end-to-end: writes Sanctuary into ~/.claude.json when it exists", async () => {
    const claudeJsonPath = join(tmpHome, ".claude.json");
    await writeFile(
      claudeJsonPath,
      JSON.stringify(
        {
          mcpServers: {
            filesystem: { command: "node", args: ["fs.js"] },
          },
          someOtherClaudeCodeKey: "preserved",
        },
        null,
        2
      )
    );

    const deps = makeDeps();
    await runWrap({ claudeCode: true, noOpen: true }, deps);

    const written = JSON.parse(await readFile(claudeJsonPath, "utf-8"));
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(written.mcpServers.sanctuary.command).toBe("npx");
    expect(written.mcpServers.filesystem).toBeDefined();
    // Top-level non-MCP fields the operator (or `claude` itself) wrote
    // must survive the rewrite.
    expect(written.someOtherClaudeCodeKey).toBe("preserved");
  });

  it("wrap end-to-end: bootstraps ~/.claude.json (canonical path) when neither config exists", async () => {
    const claudeJsonPath = join(tmpHome, ".claude.json");
    const legacyPath = join(tmpHome, ".claude", "settings.json");
    await expect(access(claudeJsonPath)).rejects.toThrow();
    await expect(access(legacyPath)).rejects.toThrow();

    const deps = makeDeps();
    // v1.2.0 F10: skip the Stop-hook install so this test stays scoped to
    // MCP-config path probing. The hook installer would otherwise create
    // ~/.claude/settings.json on the legacy path because that's where
    // Claude Code's hooks live (independent surface from .claude.json).
    // Hook-install behaviour gets dedicated coverage in
    // wrap-claude-code-hook-flag.test.ts and claude-code-hook-install.test.ts.
    await runWrap(
      { claudeCode: true, noOpen: true, installHooks: false },
      deps,
    );

    // Bootstrap creates the canonical (first-listed) path: ~/.claude.json.
    // Legacy path remains absent (hook-install path is exercised separately).
    const written = JSON.parse(await readFile(claudeJsonPath, "utf-8"));
    expect(written.mcpServers.sanctuary).toBeDefined();
    await expect(access(legacyPath)).rejects.toThrow();
  });
});
