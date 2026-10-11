/**
 * CLI refusal surface for unauthenticated recovery staging.
 *
 * This spawns the built CLI so the assertion covers the real subcommand
 * dispatcher, output channels, and exit code.
 */

import { chmod, cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import {
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
  runCliRaw,
} from "./helpers/run-cli.js";
import { agentGuidedRecoveryOutputPath } from "../../src/wrap/custody-flow.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const fixturesDir = join(__dirname, "..", "harness", "fixtures");

async function writeFixtureCli(binDir: string): Promise<void> {
  await mkdir(binDir, { recursive: true });
  const cli = join(binDir, "sanctuary");
  await writeFile(cli, "#!/bin/sh\nexit 0\n");
  await chmod(cli, 0o755);
}

describe("protect CLI recovery-staging refusal", () => {
  // defect.protect-stale-staged-recovery-file-surfaces-as-raw-stack-trace
  it("returns an actionable refusal for an unauthenticated staged recovery file", async () => {
    const tmp = await mkdtemp(join(tmpdir(), "sanctuary-protect-staged-refusal-"));
    try {
      const home = join(tmp, "home");
      const bin = join(tmp, "bin");
      const fortress = join(tmp, "fortress");
      const recoveryPath = agentGuidedRecoveryOutputPath(fortress);
      await mkdir(home, { recursive: true });
      await mkdir(dirname(recoveryPath), { recursive: true, mode: 0o700 });
      await writeFixtureCli(bin);
      await cp(join(fixturesDir, "flat-mcp.json"), join(home, ".claude.json"));
      await writeFile(
        recoveryPath,
        "Recovery key:\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\nRecovery staging receipt:\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n",
        { mode: 0o600 },
      );

      const result = await runCliRaw(
        [
          "protect",
          "--claude-code",
          "--no-open",
          "--no-dashboard",
          "--passphrase",
          "test-passphrase",
          "--no-provision-local-intelligence",
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
      expect(result.stderr).toContain("recovery staging file");
      expect(result.stderr).toContain(recoveryPath);
      expect(result.stderr).toContain("Move the file aside");
      expect(result.stderr).not.toContain("Sanctuary MCP Server failed to start");
      expect(result.stderr).not.toContain(" at ");
      expect(await readFile(recoveryPath, "utf8")).toContain("Recovery staging receipt:");
    } finally {
      await rm(tmp, { recursive: true, force: true });
    }
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
