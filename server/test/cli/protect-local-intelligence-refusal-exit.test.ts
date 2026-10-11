/**
 * CLI refusal surface for explicit local-intelligence setup.
 *
 * This spawns the built CLI so the assertion covers the real subcommand
 * dispatcher, output channels, and exit code.
 */

import { chmod, cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  runCliRaw,
} from "./helpers/run-cli.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

async function writeFixtureCli(binDir: string): Promise<void> {
  await mkdir(binDir, { recursive: true });
  const cli = join(binDir, "sanctuary");
  await writeFile(cli, "#!/bin/sh\nexit 0\n");
  await chmod(cli, 0o755);
}

describe("protect CLI local-intelligence refusal exit", () => {
  // defect.explicit-local-intelligence-provisioning-refusal-exits-zero
  it("returns non-zero when an explicit local-intelligence request is refused after wrap", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-protect-li-refusal-"));
    try {
      const home = join(tmp, "home");
      const bin = join(tmp, "bin");
      const fortress = join(tmp, "fortress");
      const manifest = join(tmp, "model-manifest.json");
      await mkdir(home, { recursive: true });
      await writeFixtureCli(bin);
      await cp(join(fixturesDir, "flat-mcp.json"), join(home, ".claude.json"));
      await writeFile(manifest, "{}\n", { mode: 0o600 });

      const result = await runCliRaw(
        [
          "protect",
          "--claude-code",
          "--no-open",
          "--no-dashboard",
          "--passphrase",
          "test-passphrase",
          "--provision-local-intelligence",
          "--model-manifest",
          manifest,
        ],
        {
          attemptTimeoutMs: 30_000,
          env: {
            HOME: home,
            USERPROFILE: home,
            PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
            SANCTUARY_STORAGE_PATH: fortress,
          },
        },
      );

      expect(result.code).toBe(1);
      expect(result.stderr).toContain("Local intelligence remains DEGRADED");
      expect(result.stderr).toContain("explicitly requested");
      expect(result.stderr).not.toContain("Sanctuary MCP Server failed to start");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
