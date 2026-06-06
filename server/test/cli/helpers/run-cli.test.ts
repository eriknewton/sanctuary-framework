/**
 * Regression tests for the shared CLI-subprocess helper's contention
 * resilience. These pin the behavior that fixes the "expected 1 to be 0"
 * flake: a transient signal-kill must be retried, a genuine non-zero exit
 * must NOT be retried or masked, and a persistently-failing spawn must throw a
 * descriptive error rather than returning a coerced exit-code 1.
 *
 * They drive `runCliRaw` with a fake `command` so the retry logic is exercised
 * deterministically, independent of the real dist/cli.js or machine load.
 */
import { describe, it, expect } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  runCli,
  runCliRaw,
  CLI_SUBPROCESS_TEST_TIMEOUT_MS,
} from "./run-cli";

describe("runCliRaw resilience (CLI-subprocess flake fix)", () => {
  it("returns a genuine non-zero exit immediately and does not retry", async () => {
    let backoffCalls = 0;
    const result = await runCliRaw([], {
      command: process.execPath,
      prefixArgs: ["-e", "process.exit(3)"],
      attemptTimeoutMs: 10_000, // generous so a slow boot is never killed
      maxAttempts: 3,
      backoffMs: () => {
        backoffCalls++;
        return 0;
      },
    });

    // The numeric exit code is surfaced verbatim, never coerced.
    expect(result.code).toBe(3);
    // backoffMs only runs before a retry; a genuine exit must not retry.
    expect(backoffCalls).toBe(0);
  }, 30_000);

  it("retries a transient timeout-kill and recovers", async () => {
    const dir = await mkdtemp(join(tmpdir(), "run-cli-retry-"));
    const flag = join(dir, "flag");
    try {
      // First run: flag absent -> create it, then hang until the per-attempt
      // timeout SIGTERM-kills us (a transient failure -> code null).
      // A later run: flag present -> exit 0.
      const script =
        "const fs=require('fs');const f=process.env.FLAG_FILE;" +
        "if(fs.existsSync(f)){process.exit(0)}" +
        "fs.writeFileSync(f,'1');setInterval(()=>{},1000);";

      const result = await runCliRaw([], {
        command: process.execPath,
        prefixArgs: ["-e", script],
        env: { FLAG_FILE: flag },
        attemptTimeoutMs: 5_000,
        maxAttempts: 3,
        backoffMs: () => 50,
      });

      expect(result.code).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it("throws a descriptive error after exhausting retries on a persistent transient failure", async () => {
    await expect(
      runCliRaw([], {
        command: process.execPath,
        prefixArgs: ["-e", "setInterval(()=>{},1000)"], // hangs forever
        attemptTimeoutMs: 800,
        maxAttempts: 2,
        backoffMs: () => 20,
      }),
    ).rejects.toThrow(/failed after 2 attempt/);
  }, 30_000);

  it("runs the real CLI through the default path (smoke)", async () => {
    const { code, stdout } = await runCli("--help");
    expect(code).toBe(0);
    expect(stdout).toContain("Usage:");
  }, CLI_SUBPROCESS_TEST_TIMEOUT_MS);
});
