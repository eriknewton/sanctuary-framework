/**
 * Top-level `--fortress` flag tests (drill finding F-1.3.2-N-001,
 * v1.3.2 Mini1 drill 2026-05-23).
 *
 * Pre-fix, `sanctuary --fortress <path> <subcommand>` silently ignored
 * BOTH the flag and the subcommand: dispatch matched on args[0], so a
 * leading flag fell through every subcommand check and booted the MCP
 * server against ~/.sanctuary. These tests pin the fix:
 *
 * 1. The extractor pulls a leading --fortress out of argv and hands the
 *    subcommand dispatch an argv identical to one typed without the flag.
 * 2. A malformed flag (missing value) produces an error, never a silent
 *    fall-through ("never silently degrade").
 * 3. Subcommand-owned --fortress occurrences (after the subcommand word)
 *    are left untouched.
 * 4. End-to-end through the same mechanism cli.ts uses: promoting the
 *    extracted path to SANCTUARY_STORAGE_PATH redirects state I/O
 *    (config resolution + filesystem storage) to the given path.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { extractTopLevelFortressFlag } from "../../src/cli/top-level-fortress.js";
import { loadConfig } from "../../src/config.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

describe("extractTopLevelFortressFlag", () => {
  it("extracts a leading --fortress and preserves the subcommand argv (drill repro shape)", () => {
    // Exact drill repro: sanctuary --fortress /tmp/drill-fortress agents list
    const result = extractTopLevelFortressFlag([
      "--fortress",
      "/tmp/drill-fortress",
      "agents",
      "list",
    ]);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBe("/tmp/drill-fortress");
    expect(result.args).toEqual(["agents", "list"]);
  });

  it("supports the --fortress=<path> form", () => {
    const result = extractTopLevelFortressFlag([
      "--fortress=/tmp/drill-fortress",
      "identity",
      "show",
    ]);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBe("/tmp/drill-fortress");
    expect(result.args).toEqual(["identity", "show"]);
  });

  it("fails loud when --fortress has no value", () => {
    const result = extractTopLevelFortressFlag(["--fortress"]);
    expect(result.error).toContain("--fortress requires a path argument");
    expect(result.fortressPath).toBeUndefined();
  });

  it("fails loud when --fortress is followed by another flag", () => {
    const result = extractTopLevelFortressFlag([
      "--fortress",
      "--dashboard",
    ]);
    expect(result.error).toContain("--fortress requires a path argument");
    expect(result.fortressPath).toBeUndefined();
  });

  it("fails loud on an empty --fortress= value", () => {
    const result = extractTopLevelFortressFlag(["--fortress=", "agents"]);
    expect(result.error).toContain("--fortress requires a path argument");
  });

  it("leaves subcommand-owned --fortress occurrences untouched", () => {
    // `init`, `protect`/`wrap`, `reset-passphrase`, and `audit-chain
    // export` parse their own --fortress after the subcommand word.
    const argv = ["init", "--fortress", "/tmp/other", "--force"];
    const result = extractTopLevelFortressFlag(argv);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBeUndefined();
    expect(result.args).toEqual(argv);
  });

  it("extracts --fortress among other leading flags", () => {
    const result = extractTopLevelFortressFlag([
      "--dashboard",
      "--fortress",
      "/tmp/drill-fortress",
    ]);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBe("/tmp/drill-fortress");
    expect(result.args).toEqual(["--dashboard"]);
  });

  it("does not mistake a --passphrase value for the subcommand boundary", () => {
    const result = extractTopLevelFortressFlag([
      "--passphrase",
      "hunter2",
      "--fortress",
      "/tmp/drill-fortress",
    ]);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBe("/tmp/drill-fortress");
    expect(result.args).toEqual(["--passphrase", "hunter2"]);
  });

  it("returns argv unchanged when no --fortress is present", () => {
    const argv = ["agents", "list"];
    const result = extractTopLevelFortressFlag(argv);
    expect(result.error).toBeUndefined();
    expect(result.fortressPath).toBeUndefined();
    expect(result.args).toEqual(argv);
  });
});

describe("top-level --fortress redirects state I/O (F-1.3.2-N-001)", () => {
  let tempDir: string;
  let savedStoragePath: string | undefined;
  let savedFortressPath: string | undefined;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "sanctuary-top-level-fortress-"));
    savedStoragePath = process.env.SANCTUARY_STORAGE_PATH;
    savedFortressPath = process.env.SANCTUARY_FORTRESS_PATH;
  });

  afterEach(() => {
    if (savedStoragePath === undefined) {
      delete process.env.SANCTUARY_STORAGE_PATH;
    } else {
      process.env.SANCTUARY_STORAGE_PATH = savedStoragePath;
    }
    if (savedFortressPath === undefined) {
      delete process.env.SANCTUARY_FORTRESS_PATH;
    } else {
      process.env.SANCTUARY_FORTRESS_PATH = savedFortressPath;
    }
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("flag path wins over both env vars and drives config storage_path", async () => {
    // Simulate the cli.ts wiring: env vars point elsewhere, the operator
    // typed --fortress. The flag must win over both.
    process.env.SANCTUARY_STORAGE_PATH = "/tmp/somewhere-else";
    process.env.SANCTUARY_FORTRESS_PATH = "/tmp/somewhere-else-again";

    const extraction = extractTopLevelFortressFlag([
      "--fortress",
      tempDir,
      "agents",
      "list",
    ]);
    expect(extraction.fortressPath).toBe(tempDir);

    // This is exactly what cli.ts main() does with the extraction result.
    process.env.SANCTUARY_STORAGE_PATH = extraction.fortressPath!;
    process.env.SANCTUARY_FORTRESS_PATH = extraction.fortressPath!;

    const config = await loadConfig();
    expect(config.storage_path).toBe(tempDir);
  });

  it("state writes land under the flag-named fortress, not the default", async () => {
    const extraction = extractTopLevelFortressFlag([
      "--fortress",
      tempDir,
      "agents",
      "list",
    ]);
    process.env.SANCTUARY_STORAGE_PATH = extraction.fortressPath!;
    process.env.SANCTUARY_FORTRESS_PATH = extraction.fortressPath!;

    const config = await loadConfig();
    const storage = new FilesystemStorage(`${config.storage_path}/state`);
    await storage.write(
      "_test_namespace",
      "drill-key",
      new TextEncoder().encode("drill-value")
    );

    // The write must be observable under the flag path on disk.
    expect(existsSync(join(tempDir, "state"))).toBe(true);
    const readBack = await storage.read("_test_namespace", "drill-key");
    expect(readBack).not.toBeNull();
    expect(new TextDecoder().decode(readBack!)).toBe("drill-value");
  });
});
