/**
 * `sanctuary intelligence diagnose --fortress` flag test (CCCCC)
 *
 * Verifies the --fortress flag is honored by diagnose, and that the
 * default (no flag) still works.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import { mkdtemp, rm, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runIntelligenceCommand } from "../../src/cli/intelligence.js";

describe("sanctuary intelligence diagnose --fortress (CCCCC)", () => {
  let tempDir: string;
  const origEnv: Record<string, string | undefined> = {};

  afterEach(async () => {
    vi.restoreAllMocks();
    if (tempDir) await rm(tempDir, { recursive: true, force: true }).catch(() => {});
    for (const key of Object.keys(origEnv)) {
      if (origEnv[key] === undefined) delete process.env[key];
      else process.env[key] = origEnv[key];
    }
  });

  it("diagnose --fortress uses the specified path", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-intel-test-"));
    const intelligenceDir = join(tempDir, "state", "_intelligence");
    await mkdir(intelligenceDir, { recursive: true });

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const code = await runIntelligenceCommand({
      argv: ["diagnose", "--fortress", tempDir],
    });
    expect(code).toBe(0);
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain(`Fortress: ${tempDir}`);
  });

  it("diagnose without --fortress defaults to env var", async () => {
    tempDir = await mkdtemp(join(tmpdir(), "sanctuary-intel-default-"));
    origEnv.SANCTUARY_STORAGE_PATH = process.env.SANCTUARY_STORAGE_PATH;
    process.env.SANCTUARY_STORAGE_PATH = tempDir;

    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});

    const code = await runIntelligenceCommand({ argv: ["diagnose"] });
    const output = errSpy.mock.calls.map((c) => c.join(" ")).join("\n");
    expect(output).toContain(`Fortress: ${tempDir}`);
  });
});
