/**
 * Wrap on empty Claude Code config — v1.0 rc.1 finding A
 *
 * Pre-v1.0 wrap exited non-zero on `~/.claude/settings.json` with no
 * `mcpServers` key, forcing first-time operators to seed an unrelated
 * placeholder before wrap would proceed. The fix:
 *
 *   1. Bootstrap an empty config when none exists for an explicitly-hinted
 *      platform (`--claude-code`, `--cursor`, `--cline`, `--openclaw`,
 *      `--hermes`). Wrap proceeds to install Sanctuary as the only entry.
 *
 *   2. An empty servers list no longer aborts wrap. Sanctuary is installed
 *      as the sole entry; `mcpServers` is created if absent.
 *
 * These tests verify the rewrite shape end-to-end against real fixture
 * configs without spinning up the dashboard or the network.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, readFile, rm, access } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runWrap } from "../../src/cocoon/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

describe("Wrap — empty Claude Code config (finding A)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    tmpHome = join(tmpdir(), `sanctuary-wrap-A-${Date.now()}-${Math.random().toString(36).slice(2)}`);
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
    let stopped = false;
    const fakeHandle: DashboardHandle = {
      url: "http://127.0.0.1:0",
      port: 0,
      host: "127.0.0.1",
      mode: "co-located",
      stop: async () => {
        stopped = true;
      },
    } as unknown as DashboardHandle;
    return {
      startDashboard: async () => fakeHandle,
      openBrowser: async () => {},
      resolvePassphrase: async () => ({
        value: "test-passphrase",
        location: "test-keychain",
        source: "generated",
      }),
      _isStopped: () => stopped,
    };
  }

  it("inserts Sanctuary as sole MCP server when settings.json has no mcpServers key", async () => {
    // Pre-condition: settings.json exists but has no mcpServers key.
    // First-install Claude Code default shape.
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ theme: "dark" }, null, 2));

    const deps = makeDeps();
    await runWrap({ claudeCode: true, noOpen: true }, deps);

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers).toBeDefined();
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(written.mcpServers.sanctuary.command).toBe("npx");
    // Top-level non-MCP fields preserved.
    expect(written.theme).toBe("dark");
  });

  it("inserts Sanctuary when mcpServers exists but is empty", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    const deps = makeDeps();
    await runWrap({ claudeCode: true, noOpen: true }, deps);

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(Object.keys(written.mcpServers).length).toBe(1);
  });

  it("inserts Sanctuary alongside existing placeholder server", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(
      settingsPath,
      JSON.stringify(
        {
          mcpServers: {
            placeholder: { command: "echo", args: ["placeholder"] },
          },
        },
        null,
        2
      )
    );

    const deps = makeDeps();
    await runWrap({ claudeCode: true, noOpen: true }, deps);

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(Object.keys(written.mcpServers).sort()).toEqual([
      "placeholder",
      "sanctuary",
    ]);
    expect(written.mcpServers.sanctuary.command).toBe("npx");
    expect(written.mcpServers.placeholder.command).toBe("echo");
  });

  it("bootstraps a fresh config when none exists for --claude-code", async () => {
    // Pre-condition: no Claude Code config anywhere under HOME — neither
    // the legacy ~/.claude/settings.json nor any sibling path.
    const legacyPath = join(tmpHome, ".claude", "settings.json");
    await expect(access(legacyPath)).rejects.toThrow();

    const deps = makeDeps();
    await runWrap({ claudeCode: true, noOpen: true }, deps);

    // After wrap, a Claude Code config file with Sanctuary exists at the
    // canonical (first-listed) path for the platform. The exact location
    // is the first entry in getPlatformPaths()["claude-code"]; this test
    // pins the contract that some bootstrap happened, not which path.
    const candidatePaths = [
      join(tmpHome, ".claude.json"),
      join(tmpHome, ".claude", "settings.json"),
      join(tmpHome, ".config", "claude-code", "settings.json"),
    ];
    let foundPath: string | null = null;
    for (const p of candidatePaths) {
      try {
        await access(p);
        foundPath = p;
        break;
      } catch {}
    }
    expect(foundPath).not.toBeNull();
    const written = JSON.parse(await readFile(foundPath!, "utf-8"));
    expect(written.mcpServers).toBeDefined();
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(written.mcpServers.sanctuary.command).toBe("npx");
  });
});
