/**
 * Executes the CI baseline guard's Gate 2c run block (extracted verbatim from
 * .github/workflows/test-baseline-guard.yml) against throwaway git fixtures.
 *
 * Capability under test: on pull_request the guard reads its count helper
 * (parser and compare_counts) from the pull request's BASE commit, so a head
 * that edits scripts/parse-vitest-summary.sh cannot grade itself; it fails
 * closed when the base has no helper or a helper without compare_counts; and
 * on push it uses the pushed commit's own copy.
 *
 * The block runs under the same shell flags GitHub uses for `run:` on Linux
 * (`bash --noprofile --norc -eo pipefail`), with the step's `env:` values
 * supplied directly, in a fixture repo (never the developer's own repo).
 */

import { afterEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const WORKFLOW_PATH = path.join(REPO_ROOT, ".github", "workflows", "test-baseline-guard.yml");
const REAL_HELPER_PATH = path.join(REPO_ROOT, "scripts", "parse-vitest-summary.sh");

// Ten spaces: the indentation of a step's `run: |` body in this workflow
// (two for `jobs:` children, four for the job's keys, six for a step list
// item, eight for step keys, ten for the block scalar's content).
const RUN_BODY_INDENT = 10;

/** Extract the Gate 2c `run: |` body exactly as Actions would hand it to bash. */
function extractGate2cRunBlock(): string {
  const lines = fs.readFileSync(WORKFLOW_PATH, "utf8").split("\n");
  const stepIdx = lines.findIndex((l) => /^\s*- name: Gate 2c\b/.test(l));
  if (stepIdx === -1) throw new Error("Gate 2c step not found in the workflow");
  const runIdx = lines.findIndex((l, i) => i > stepIdx && /^ {8}run: \|\s*$/.test(l));
  if (runIdx === -1) throw new Error("Gate 2c run block not found in the workflow");
  const body: string[] = [];
  for (const line of lines.slice(runIdx + 1)) {
    if (line.trim() !== "" && line.length - line.trimStart().length < RUN_BODY_INDENT) break;
    body.push(line.slice(RUN_BODY_INDENT));
  }
  return body.join("\n") + "\n";
}

function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  env.VITEST = process.env.VITEST ?? "true";
  for (const key of Object.keys(env)) {
    if (key.startsWith("GIT_") || key.startsWith("GITHUB_") || key === "RUNNER_TEMP") {
      delete env[key];
    }
  }
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  return env;
}

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: {
      ...gitEnv(),
      VITEST: process.env.VITEST ?? "true",
    },
  }).trim();
}

/** A head-side helper that grades every count as equal to the floor. */
const SELF_GRADING_HELPER = `#!/usr/bin/env bash
emit_error() { printf '%s\\n' "$1" >&2; }
is_canonical_count() { return 0; }
compare_counts() { printf 'eq\\n'; }
count_difference() { printf '0\\n'; }
if [[ "\${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi
printf '17345\\n'
`;

/** A helper shaped like the one before compare_counts existed. */
const PRE_COMPARE_HELPER = `#!/usr/bin/env bash
set -euo pipefail
emit_error() { printf '%s\\n' "$1" >&2; }
if [[ "\${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi
grep -oE 'Tests[[:space:]]+[0-9]+ passed' "$1" | grep -oE '[0-9]+'
`;

let cleanupDirs: string[] = [];

function buildFixture(opts: { baseHelper: string | null; headHelper: string | null }): {
  repoDir: string;
  runnerTemp: string;
  baseSha: string;
} {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sanctuary-gate2c-fixture-"));
  cleanupDirs.push(tmpRoot);
  const repoDir = path.join(tmpRoot, "repo");
  const runnerTemp = path.join(tmpRoot, "runner-temp");
  fs.mkdirSync(path.join(repoDir, "scripts"), { recursive: true });
  fs.mkdirSync(runnerTemp);
  git(["init", "--quiet", "-b", "main"], repoDir);
  git(["config", "--local", "user.email", "test@example.com"], repoDir);
  git(["config", "--local", "user.name", "Test"], repoDir);

  const helperPath = path.join(repoDir, "scripts", "parse-vitest-summary.sh");
  fs.writeFileSync(path.join(repoDir, "f.txt"), "base\n", "utf8");
  if (opts.baseHelper !== null) fs.writeFileSync(helperPath, opts.baseHelper, "utf8");
  git(["add", "-A"], repoDir);
  git(["commit", "--quiet", "--no-verify", "-m", "base"], repoDir);
  const baseSha = git(["rev-parse", "HEAD"], repoDir);

  fs.writeFileSync(path.join(repoDir, "f.txt"), "head\n", "utf8");
  if (opts.headHelper === null) {
    fs.rmSync(helperPath, { force: true });
  } else {
    fs.writeFileSync(helperPath, opts.headHelper, "utf8");
  }
  git(["add", "-A"], repoDir);
  git(["commit", "--quiet", "--no-verify", "-m", "head"], repoDir);
  return { repoDir, runnerTemp, baseSha };
}

function runGate2c(
  fixture: { repoDir: string; runnerTemp: string; baseSha: string },
  opts: { event: string; baseSha?: string; baseline: string; passing: string },
): { status: number | null; output: string } {
  // The raw floor bytes, exactly as Gate 2c reads them from the checkout.
  fs.writeFileSync(path.join(fixture.repoDir, ".test-baseline"), opts.baseline, "utf8");
  const logPath = path.join(fixture.runnerTemp, "vitest-output.log");
  fs.writeFileSync(
    logPath,
    `Test Files  3 passed (3)\n      Tests  ${opts.passing} passed (${opts.passing})\n`,
    "utf8",
  );
  const scriptPath = path.join(fixture.runnerTemp, "gate2c.sh");
  fs.writeFileSync(scriptPath, extractGate2cRunBlock(), "utf8");
  const result = spawnSync("bash", ["--noprofile", "--norc", "-eo", "pipefail", scriptPath], {
    cwd: fixture.repoDir,
    encoding: "utf8",
    env: {
      ...gitEnv(),
      GITHUB_ACTIONS: "true",
      RUNNER_TEMP: fixture.runnerTemp,
      EVENT_NAME: opts.event,
      BASE_SHA: opts.baseSha ?? (opts.event === "pull_request" ? fixture.baseSha : ""),
      BASELINE_FILE: ".test-baseline",
      VITEST_LOG: logPath,
    },
  });
  return { status: result.status, output: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

const REAL_HELPER = fs.readFileSync(REAL_HELPER_PATH, "utf8");

describe("CI baseline guard Gate 2c: count helper trust boundary", () => {
  afterEach(() => {
    for (const dir of cleanupDirs) fs.rmSync(dir, { recursive: true, force: true });
    cleanupDirs = [];
  });

  it("on pull_request uses the base commit's helper, so a self-grading head helper cannot pass a regression", () => {
    const fixture = buildFixture({ baseHelper: REAL_HELPER, headHelper: SELF_GRADING_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: "17345\n",
      passing: "4",
    });

    expect(output).toContain(`Count helper source: base commit ${fixture.baseSha}`);
    expect(output).toContain("Test baseline regression");
    expect(output).not.toContain("Baseline guard passed");
    expect(status).not.toBe(0);
  });

  it("on pull_request passes an exact 7-digit match through the base helper", () => {
    const fixture = buildFixture({ baseHelper: REAL_HELPER, headHelper: REAL_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: "1234567\n",
      passing: "1234567",
    });

    expect(output).toContain("Baseline guard passed");
    expect(status).toBe(0);
  });

  it("on pull_request fails closed when the base commit has no helper", () => {
    const fixture = buildFixture({ baseHelper: null, headHelper: SELF_GRADING_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: "17345\n",
      passing: "17345",
    });

    expect(output).toContain("has no scripts/parse-vitest-summary.sh");
    expect(output).not.toContain("Baseline guard passed");
    expect(status).not.toBe(0);
  });

  it("on pull_request fails closed when the base helper predates compare_counts", () => {
    const fixture = buildFixture({ baseHelper: PRE_COMPARE_HELPER, headHelper: REAL_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: "17345\n",
      passing: "17345",
    });

    expect(output).toContain("does not define");
    expect(output).not.toContain("Baseline guard passed");
    expect(status).not.toBe(0);
  });

  it("on pull_request refuses a missing or malformed base SHA", () => {
    const fixture = buildFixture({ baseHelper: REAL_HELPER, headHelper: REAL_HELPER });

    for (const baseSha of ["", "not-a-sha", fixture.baseSha.slice(0, 12)]) {
      const { status, output } = runGate2c(fixture, {
        event: "pull_request",
        baseSha,
        baseline: "17345\n",
        passing: "17345",
      });

      expect(output).toContain("base SHA is missing or malformed");
      expect(status).not.toBe(0);
    }
  });

  it.each([
    ["an embedded space", "123 4567\n"],
    ["an embedded newline", "123\n4567\n"],
    ["CRLF", "1234567\r\n"],
  ])("refuses a floor file with %s instead of normalizing it", (_label, rawFloor) => {
    const fixture = buildFixture({ baseHelper: REAL_HELPER, headHelper: REAL_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: rawFloor,
      passing: "1234567",
    });

    expect(output).toContain("at most one trailing newline");
    expect(output).not.toContain("Baseline guard passed");
    expect(status).not.toBe(0);
  });

  it("accepts a floor file with no trailing newline", () => {
    const fixture = buildFixture({ baseHelper: REAL_HELPER, headHelper: REAL_HELPER });

    const { status, output } = runGate2c(fixture, {
      event: "pull_request",
      baseline: "1234567",
      passing: "1234567",
    });

    expect(output).toContain("Baseline guard passed");
    expect(status).toBe(0);
  });

  it("on push uses the pushed commit's own helper and compares a 20-digit count exactly", () => {
    const fixture = buildFixture({ baseHelper: null, headHelper: REAL_HELPER });

    // 2^64 + 17345 wraps to 17345 in signed 64-bit bash arithmetic.
    const { status, output } = runGate2c(fixture, {
      event: "push",
      baseline: "17345\n",
      passing: "18446744073709568961",
    });

    expect(output).toContain("Count helper source: pushed commit");
    expect(output).toContain("Test baseline drifted above the floor");
    expect(output).not.toContain("Baseline guard passed");
    expect(status).not.toBe(0);
  });
});
