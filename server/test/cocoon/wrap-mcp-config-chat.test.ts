/**
 * Wrap MCP-config integration — sanctuary-chat sibling registration (v1.2.x F9)
 *
 * Verifies the wrap CLI registers `sanctuary-chat` as a sibling MCP
 * server alongside `sanctuary` so the wrapped agent's MCP runtime can
 * deliver replies on direct-agent chat sessions.
 *
 *  - sanctuary + sanctuary-chat both appear in the harness MCP config.
 *  - sanctuary-chat command + args match `sanctuary chat-server`.
 *  - sanctuary-chat carries SANCTUARY_AGENT_ID matching the v1.1 hub
 *    agent_id shape (agent:<harness>:<fortressId>).
 *  - Re-wrap on the same config is idempotent (does not duplicate or
 *    drop entries).
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { runWrap } from "../../src/cocoon/cli.js";
import type { DashboardHandle } from "../../src/dashboard/index.js";

describe("Wrap — sanctuary-chat sibling MCP entry (v1.2.x F9)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-wrap-F9-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
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
    };
  }

  it("registers sanctuary-chat alongside sanctuary on a fresh wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(written.mcpServers["sanctuary-chat"]).toBeDefined();
    expect(written.mcpServers["sanctuary-chat"].command).toBe("npx");
    expect(written.mcpServers["sanctuary-chat"].args).toEqual([
      "@sanctuary-framework/mcp-server",
      "chat-server",
    ]);
  });

  it("sanctuary-chat env carries SANCTUARY_AGENT_ID in the hub-registry shape", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    const env = written.mcpServers["sanctuary-chat"].env;
    expect(env).toBeDefined();
    expect(env.SANCTUARY_AGENT_ID).toBeDefined();
    // Shape matches buildLocalAgentRecord in cocoon/cli.ts:
    // `agent:<harness>:<fortressId>`. The fortress id is a hash of the
    // storage path, so we just assert the prefix + non-empty suffix.
    expect(env.SANCTUARY_AGENT_ID).toMatch(/^agent:claude_code:.+/);
  });

  it("preserves an existing user-named sibling on re-wrap", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(
      settingsPath,
      JSON.stringify(
        {
          mcpServers: {
            "user-tool": { command: "node", args: ["my-tool.js"] },
          },
        },
        null,
        2,
      ),
    );

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers["user-tool"]).toBeDefined();
    expect(written.mcpServers["user-tool"].command).toBe("node");
    expect(written.mcpServers.sanctuary).toBeDefined();
    expect(written.mcpServers["sanctuary-chat"]).toBeDefined();
  });

  it("re-wrap is idempotent: sanctuary + sanctuary-chat stay exactly once", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());
    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    const keys = Object.keys(written.mcpServers).sort();
    expect(keys).toEqual(["sanctuary", "sanctuary-chat"]);
  });

  it("--dev-dist points both entries at the local build", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    const distPath = "/path/to/local/dist/cli.js";
    await runWrap(
      { claudeCode: true, noOpen: true, devDist: distPath },
      makeDeps(),
    );

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers.sanctuary.command).toBe("node");
    expect(written.mcpServers.sanctuary.args).toEqual([distPath]);
    expect(written.mcpServers["sanctuary-chat"].command).toBe("node");
    expect(written.mcpServers["sanctuary-chat"].args).toEqual([
      distPath,
      "chat-server",
    ]);
  });

  it("default (no --dev-dist) keeps npx command", async () => {
    const settingsDir = join(tmpHome, ".claude");
    await mkdir(settingsDir, { recursive: true });
    const settingsPath = join(settingsDir, "settings.json");
    await writeFile(settingsPath, JSON.stringify({ mcpServers: {} }, null, 2));

    await runWrap({ claudeCode: true, noOpen: true }, makeDeps());

    const written = JSON.parse(await readFile(settingsPath, "utf-8"));
    expect(written.mcpServers.sanctuary.command).toBe("npx");
    expect(written.mcpServers.sanctuary.args).toEqual([
      "@sanctuary-framework/mcp-server",
    ]);
    expect(written.mcpServers["sanctuary-chat"].command).toBe("npx");
    expect(written.mcpServers["sanctuary-chat"].args).toEqual([
      "@sanctuary-framework/mcp-server",
      "chat-server",
    ]);
  });
});
