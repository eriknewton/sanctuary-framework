/**
 * Wrap --dry-run is write-free — D4 Hermes drill staging, Bug 1
 *
 * Pre-fix, the bootstrap-empty-config write in runWrap ran BEFORE the
 * dry-run gate, so `sanctuary protect --hermes --dry-run` on a host with
 * no ~/.hermes/cli-config.json still created the file. The fix hoists a
 * dry-run early-return above the bootstrap, keeping the gate above ALL
 * write paths (config bootstrap, fortress state, agent-record
 * persistence, passphrase resolution).
 *
 * These tests pin the contract with a filesystem snapshot: a dry run
 * against a temp HOME must leave the tree byte-for-byte identical, and
 * must never reach the passphrase resolver or dashboard starter.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { writeFile, mkdir, readFile, readdir, stat, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createHash } from "node:crypto";
import { runWrap, type RunWrapDeps } from "../../src/wrap/cli.js";

/** Recursive content+mtime snapshot of every file under root. */
async function snapshotTree(root: string): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  let entries: string[];
  try {
    entries = (await readdir(root, { recursive: true })) as string[];
  } catch {
    return out;
  }
  for (const rel of entries) {
    const p = join(root, rel);
    const s = await stat(p);
    if (!s.isFile()) continue;
    const digest = createHash("sha256").update(await readFile(p)).digest("hex");
    out.set(rel, `${digest}:${s.mtimeMs}`);
  }
  return out;
}

describe("Wrap — --dry-run guarantees zero filesystem writes (D4 Bug 1)", () => {
  let tmpHome: string;
  let originalHome: string | undefined;
  let originalStoragePath: string | undefined;

  beforeEach(async () => {
    tmpHome = join(
      tmpdir(),
      `sanctuary-dryrun-${Date.now()}-${Math.random().toString(36).slice(2)}`
    );
    await mkdir(tmpHome, { recursive: true });
    originalHome = process.env.HOME;
    originalStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    process.env.HOME = tmpHome;
    process.env.SANCTUARY_STORAGE_PATH = join(tmpHome, ".sanctuary");
  });

  afterEach(async () => {
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

  /**
   * Deps that fail the test if the dry run reaches any post-gate stage:
   * the gate sits above passphrase resolution and dashboard startup, so
   * neither hook may fire.
   */
  function tripwireDeps(): RunWrapDeps {
    return {
      startDashboard: async () => {
        throw new Error("dry-run must not start the dashboard");
      },
      openBrowser: async () => {
        throw new Error("dry-run must not open a browser");
      },
      resolvePassphrase: async () => {
        throw new Error("dry-run must not resolve or generate a passphrase");
      },
    };
  }

  it("creates NOTHING when --hermes --dry-run runs with no hermes config (the D4 regression)", async () => {
    const before = await snapshotTree(tmpHome);
    expect(before.size).toBe(0);

    await runWrap({ hermes: true, dryRun: true, noOpen: true }, tripwireDeps());

    const after = await snapshotTree(tmpHome);
    expect([...after.keys()]).toEqual([]);
    // The specific pre-fix artifact: the bootstrapped cli-config.json.
    await expect(
      stat(join(tmpHome, ".hermes", "cli-config.json"))
    ).rejects.toThrow();
  });

  it("modifies NOTHING when --hermes --dry-run runs against existing JSON + YAML configs", async () => {
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await writeFile(
      join(hermesDir, "cli-config.json"),
      JSON.stringify(
        { mcp_servers: { weather: { command: "uvx", args: ["mcp-weather"] } } },
        null,
        2
      )
    );
    await writeFile(
      join(hermesDir, "config.yaml"),
      "mcp_servers:\n  weather:\n    command: \"uvx\"\n"
    );

    const before = await snapshotTree(tmpHome);
    await runWrap({ hermes: true, dryRun: true, noOpen: true }, tripwireDeps());
    const after = await snapshotTree(tmpHome);

    expect(after).toEqual(before);
  });

  it("reports the config.yaml plan on --hermes --dry-run without writing it", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    await runWrap({ hermes: true, dryRun: true, noOpen: true }, tripwireDeps());

    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Hermes MCP routing: would");
    expect(output).toContain("config.yaml");
    expect(output).toContain("Dry run. No changes made.");
    await expect(stat(join(tmpHome, ".hermes"))).rejects.toThrow();
  });

  it("creates NOTHING when --claude-code --dry-run hits the bootstrap path (fix covers all platforms)", async () => {
    await runWrap(
      { claudeCode: true, dryRun: true, noOpen: true },
      tripwireDeps()
    );

    const after = await snapshotTree(tmpHome);
    expect([...after.keys()]).toEqual([]);
  });
});
