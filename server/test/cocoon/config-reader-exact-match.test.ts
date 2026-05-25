/**
 * Sanctuary-name filter — exact match (v1.0 rc.1 finding B)
 *
 * Pre-v1.0 extractServers used a case-insensitive substring match on
 * "sanctuary" to skip the canonical Sanctuary entry from the upstream
 * count. That filter swallowed legitimate operator-installed servers
 * whose names happened to contain the substring (e.g. `sanctuary-helper`,
 * `my-sanctuary-fork`). It also ate the sole entry on a re-wrap, which
 * combined with the empty-servers exit gate (Finding A) to make every
 * re-wrap exit non-zero with "no MCP servers configured".
 *
 * The fix tightens the filter to an exact lowercase match. These tests
 * pin both the negative shape (canonical entry still skipped) and the
 * positive shape (siblings preserved) across all platforms that share
 * the filter: claude-code, cursor, hermes, cline.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { detectAgentConfig } from "../../src/wrap/config-reader.js";

describe("extractServers — exact-match Sanctuary filter (finding B)", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = join(tmpdir(), `sanctuary-test-B-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    await mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    try {
      await rm(tmpDir, { recursive: true, force: true });
    } catch {}
  });

  // ─── Negative shape: canonical "sanctuary" entry still skipped ───

  it("still skips the canonical 'sanctuary' entry on claude-code", async () => {
    const configPath = join(tmpDir, "settings.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
        filesystem: { command: "node", args: ["fs.js"] },
      },
    }));
    const result = await detectAgentConfig("claude-code", configPath);
    expect(result).not.toBeNull();
    const names = result!.servers.map((s) => s.name);
    expect(names).not.toContain("sanctuary");
    expect(names).toContain("filesystem");
  });

  it("still skips 'Sanctuary' (case-insensitive) on cursor", async () => {
    const configPath = join(tmpDir, "mcp.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        Sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
        github: { command: "npx", args: ["-y", "@github/mcp-server"] },
      },
    }));
    const result = await detectAgentConfig("cursor", configPath);
    expect(result).not.toBeNull();
    const names = result!.servers.map((s) => s.name);
    expect(names).not.toContain("Sanctuary");
    expect(names).toContain("github");
  });

  // ─── Positive shape: operator-named siblings now preserved ───

  it("preserves 'sanctuary-helper' on claude-code (substring no longer matches)", async () => {
    const configPath = join(tmpDir, "settings.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
        "sanctuary-helper": { command: "node", args: ["helper.js"] },
        filesystem: { command: "node", args: ["fs.js"] },
      },
    }));
    const result = await detectAgentConfig("claude-code", configPath);
    expect(result).not.toBeNull();
    const names = result!.servers.map((s) => s.name);
    expect(names).not.toContain("sanctuary");
    expect(names).toContain("sanctuary-helper");
    expect(names).toContain("filesystem");
  });

  it("preserves 'my-sanctuary-fork' on cline", async () => {
    const configPath = join(tmpDir, "cline_mcp_settings.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        "my-sanctuary-fork": { command: "node", args: ["fork.js"] },
        filesystem: { command: "node", args: ["fs.js"] },
      },
    }));
    const result = await detectAgentConfig("cline", configPath);
    expect(result).not.toBeNull();
    const names = result!.servers.map((s) => s.name);
    expect(names).toContain("my-sanctuary-fork");
    expect(names).toContain("filesystem");
  });

  it("preserves 'unsanctuary' on hermes (suffix collision)", async () => {
    const configPath = join(tmpDir, "cli-config.json");
    await writeFile(configPath, JSON.stringify({
      mcp_servers: {
        sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
        unsanctuary: { command: "node", args: ["something.js"] },
      },
    }));
    const result = await detectAgentConfig("hermes", configPath);
    expect(result).not.toBeNull();
    const names = result!.servers.map((s) => s.name);
    expect(names).not.toContain("sanctuary");
    expect(names).toContain("unsanctuary");
  });

  // ─── Re-wrap shape: only-sanctuary config now reads as empty (and is
  //     allowed by Finding A's gate-removal). ───

  it("returns an empty server list when the only entry is canonical sanctuary", async () => {
    const configPath = join(tmpDir, "settings.json");
    await writeFile(configPath, JSON.stringify({
      mcpServers: {
        sanctuary: { command: "npx", args: ["@sanctuary-framework/mcp-server"] },
      },
    }));
    const result = await detectAgentConfig("claude-code", configPath);
    expect(result).not.toBeNull();
    expect(result!.servers).toHaveLength(0);
    // Raw config retains the entry — re-wrap detection (handled in cli.ts)
    // inspects rawConfig, not the filtered servers list.
    const raw = result!.rawConfig as { mcpServers: Record<string, unknown> };
    expect(raw.mcpServers.sanctuary).toBeDefined();
  });
});
