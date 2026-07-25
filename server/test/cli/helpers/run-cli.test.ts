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
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, userInfo } from "node:os";
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
      await rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
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

// ── Child fortress isolation ─────────────────────────────────────────
//
// A spawned CLI is a fresh process, so none of the in-process isolation a test
// does reaches it. Left alone the child resolves the operator's own
// `~/.sanctuary`, reads real custody, and writes into it. These pin that the
// helper hands every child its own fortress, and that a caller who names one
// still wins.

describe("runCliRaw child fortress isolation", () => {
  /** Print the fortress the child would resolve, without importing src. */
  const PRINT_RESOLVED = [
    "-e",
    "const os=require('node:os');const p=require('node:path');" +
      "console.log(process.env.SANCTUARY_STORAGE_PATH||p.join(os.homedir(),'.sanctuary'))",
  ];

  it("gives the child a fortress that is not the operator's own", async () => {
    const { code, stdout } = await runCliRaw([], {
      command: process.execPath,
      prefixArgs: PRINT_RESOLVED,
    });
    expect(code).toBe(0);
    const resolved = stdout.trim();
    // The account record, not $HOME: the operator's real fortress is the one
    // path the child must never resolve, however this process moved HOME.
    expect(resolved).not.toBe(join(userInfo().homedir, ".sanctuary"));
    expect(resolved).toContain("sanctuary-run-cli-home-");
  }, 30_000);

  it("removes the child's temporary home afterwards", async () => {
    const { stdout } = await runCliRaw([], {
      command: process.execPath,
      prefixArgs: ["-e", "console.log(process.env.HOME)"],
    });
    const childHome = stdout.trim();
    expect(childHome).toContain("sanctuary-run-cli-home-");
    // Isolation that leaks a directory per spawn just moves the pollution.
    expect(existsSync(childHome)).toBe(false);
  }, 30_000);

  it("lets a caller-supplied fortress win over the default isolation", async () => {
    const { stdout } = await runCliRaw([], {
      command: process.execPath,
      prefixArgs: PRINT_RESOLVED,
      env: { SANCTUARY_STORAGE_PATH: "/tmp/caller-chosen-fortress" },
    });
    expect(stdout.trim()).toBe("/tmp/caller-chosen-fortress");
  }, 30_000);

  it("lets a caller-supplied HOME win over the default isolation", async () => {
    const { stdout } = await runCliRaw([], {
      command: process.execPath,
      prefixArgs: ["-e", "console.log(process.env.HOME)"],
      env: { HOME: "/tmp/caller-chosen-home" },
    });
    expect(stdout.trim()).toBe("/tmp/caller-chosen-home");
  }, 30_000);
});
