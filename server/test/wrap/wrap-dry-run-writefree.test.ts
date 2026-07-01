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

  it("does NOT claim 'no config found' when config.yaml already exists but the JSON surface is absent (honesty fix)", async () => {
    // The exact install target: a host with a populated ~/.hermes/config.yaml
    // (a `venice` MCP entry) but NO cli-config.json. Pre-fix, the bootstrap
    // path fired on the absent JSON and printed "No existing hermes config
    // found." + "0 MCP servers", which is false on this host — Hermes routes
    // MCP traffic through config.yaml (hermes-yaml.ts:4-10).
    const hermesDir = join(tmpHome, ".hermes");
    await mkdir(hermesDir, { recursive: true });
    await writeFile(
      join(hermesDir, "config.yaml"),
      'mcp_servers:\n  venice:\n    command: "uvx"\n    args:\n      - "mcp-venice"\n'
    );

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await runWrap({ hermes: true, dryRun: true, noOpen: true }, tripwireDeps());
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");

    // Honest: names config.yaml, promises preservation, does NOT lie.
    expect(output).not.toContain("No existing hermes config found");
    expect(output).toContain("Found your Hermes MCP config");
    expect(output).toContain("config.yaml");
    expect(output).toContain("preserved");
    // The routing line still reports the venice entry it would preserve.
    expect(output).toContain("Hermes MCP routing: would");
    expect(output).toContain("1 existing entry preserved");

    // Still write-free: no JSON bootstrapped, config.yaml untouched.
    await expect(
      stat(join(hermesDir, "cli-config.json"))
    ).rejects.toThrow();
  });

  it("still says 'No existing hermes config found' when NEITHER surface exists (fresh install unchanged)", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await runWrap({ hermes: true, dryRun: true, noOpen: true }, tripwireDeps());
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("No existing hermes config found");
    expect(output).not.toContain("Found your Hermes MCP config");
  });

  it("creates NOTHING when --claude-code --dry-run hits the bootstrap path (fix covers all platforms)", async () => {
    await runWrap(
      { claudeCode: true, dryRun: true, noOpen: true },
      tripwireDeps()
    );

    const after = await snapshotTree(tmpHome);
    expect([...after.keys()]).toEqual([]);
  });

  /**
   * Fabricate a wrapped Hermes state by hand: a wrapped JSON + YAML pair,
   * their backups, and the wrap-meta.json pointing at them. Unwrap reads
   * only these, so this exercises the real restore path without running a
   * full wrap first.
   */
  async function fabricateWrappedHermesState(opts: { yamlCreatedFresh: boolean }) {
    const hermesDir = join(tmpHome, ".hermes");
    const backupDir = join(tmpHome, ".sanctuary", "backup");
    await mkdir(hermesDir, { recursive: true });
    await mkdir(backupDir, { recursive: true });
    const jsonPath = join(hermesDir, "cli-config.json");
    const yamlPath = join(hermesDir, "config.yaml");
    const jsonBackup = join(backupDir, "config-backup-2026-01-01T00-00-00-000Z.json");
    const yamlBackup = join(backupDir, "config-backup-2026-01-01T00-00-00-001Z.yaml");
    await writeFile(
      jsonPath,
      JSON.stringify({ mcp_servers: { sanctuary: { command: "npx" } } }, null, 2)
    );
    await writeFile(yamlPath, 'mcp_servers:\n  sanctuary:\n    command: "npx"\n');
    await writeFile(jsonBackup, JSON.stringify({ mcp_servers: {} }, null, 2));
    if (!opts.yamlCreatedFresh) {
      await writeFile(yamlBackup, "mcp_servers: {}\n");
    }
    await writeFile(
      join(backupDir, "wrap-meta.json"),
      JSON.stringify(
        {
          backupPath: jsonBackup,
          originalPath: jsonPath,
          platform: "hermes",
          wrappedAt: "2026-01-01T00:00:00.000Z",
          auxiliary: [
            {
              originalPath: yamlPath,
              backupPath: opts.yamlCreatedFresh ? null : yamlBackup,
            },
          ],
        },
        null,
        2
      )
    );
    return { jsonPath, yamlPath, jsonBackup, yamlBackup };
  }

  it("restores NOTHING when --unwrap --dry-run runs against a wrapped agent (D4 P2-2)", async () => {
    const { jsonPath, yamlPath, jsonBackup } = await fabricateWrappedHermesState({
      yamlCreatedFresh: false,
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const before = await snapshotTree(tmpHome);
    await runWrap({ unwrap: true, dryRun: true }, tripwireDeps());
    const after = await snapshotTree(tmpHome);

    // Byte-for-byte identical tree: nothing restored, nothing removed.
    expect(after).toEqual(before);
    const wrapped = JSON.parse(await readFile(jsonPath, "utf-8"));
    expect(wrapped.mcp_servers.sanctuary).toBeDefined();

    // And the dry run REPORTED the restore it would perform.
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain("Unwrap (dry run)");
    expect(output).toContain(`Would restore ${jsonPath} from ${jsonBackup}`);
    expect(output).toContain(`Would restore ${yamlPath} from`);
    expect(output).toContain("Dry run. No changes made.");
  });

  it("removes NOTHING on --unwrap --dry-run when wrap created config.yaml fresh (D4 P2-2)", async () => {
    const { yamlPath } = await fabricateWrappedHermesState({
      yamlCreatedFresh: true,
    });
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const before = await snapshotTree(tmpHome);
    await runWrap({ unwrap: true, dryRun: true }, tripwireDeps());
    const after = await snapshotTree(tmpHome);

    expect(after).toEqual(before);
    await expect(stat(yamlPath)).resolves.toBeDefined();
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain(`Would remove ${yamlPath}`);
    expect(output).toContain("Dry run. No changes made.");
  });
});
