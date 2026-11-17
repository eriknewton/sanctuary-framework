/**
 * Capability: no test process inherits a git variable that redirects which
 * repository, config file, or object graph git acts on (a git hook exports
 * GIT_DIR pointing at the real repository; a shell can add GIT_CONFIG and
 * runtime config pairs). Witness for the setupFiles entry
 * test/setup/git-env-scrub.ts: a child vitest run, seeded with every variable
 * the guard must clear, runs a probe that reports what it inherited and writes
 * `core.bare=true` from its own fixture repo while GIT_DIR and GIT_CONFIG aim
 * at a throwaway "victim" repo. With the setup file nothing seeded reaches the
 * probe and the fixture repo is written (positive control); with the setup
 * file removed from the child's setupFiles every seeded variable reaches it
 * and the victim is written instead (fail-before). The last two tests pin the
 * two bash copies of the list to scripts/git-redirect-env-keys.json.
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import config, { leaseGuardHookTimeoutMs } from "../../vitest.config.js";
import {
  GIT_REDIRECT_ENV_KEYS,
  GIT_REDIRECT_NUMBERED_KEY_RE,
  isGitRedirectEnvKey,
  scrubGitRedirectEnv,
} from "../setup/git-env-scrub.js";

const serverDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = path.resolve(serverDir, "..");
const SETUP_ENTRY = "./test/setup/git-env-scrub.ts";
const PROBE_GLOB = "test/fixtures/git-env-scrub/*.probe.ts";
const childStartupHeadroomMs = 30_000; // Allow module loading on a loaded runner.
const childExitHeadroomMs = 10_000; // Allow reporting and worker shutdown after the probe.
const parentHeadroomMs = 30_000; // Allow the fixture git inits and report reads outside the child budget.
// One probe test: startup, the config's per-test budget, one hook budget for setup/teardown, then exit.
const childTimeoutMs = childStartupHeadroomMs + (config.test?.testTimeout ?? childStartupHeadroomMs) + leaseGuardHookTimeoutMs + childExitHeadroomMs;
const probeTestTimeoutMs = childTimeoutMs + parentHeadroomMs;
const cleanup: string[] = [];

/**
 * Independent oracle: the names the guard MUST clear, stated here on purpose
 * rather than read from scripts/git-redirect-env-keys.json, so shrinking the
 * shared list makes the positive control fail. Includes numbered config pairs
 * inside and beyond GIT_CONFIG_COUNT, since the scrub is pattern-based.
 */
const MUST_SCRUB = [
  "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
  "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX", "GIT_CONFIG",
  "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
  "GIT_SHALLOW_FILE", "GIT_GRAFT_FILE",
  "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_KEY_7", "GIT_CONFIG_VALUE_7",
] as const;
/** Names the guard must leave alone: discovery restriction, and a non-numbered lookalike. */
const MUST_KEEP = ["GIT_CEILING_DIRECTORIES", "GIT_CONFIG_KEY_X"] as const;

/** Values that keep a leaked redirect aimed at `victim`, so fail-before writes land there. */
function seeds(tmp: string, victim: string): Record<(typeof MUST_SCRUB)[number] | (typeof MUST_KEEP)[number], string> {
  const dotGit = path.join(victim, ".git");
  return {
    GIT_DIR: dotGit,
    GIT_COMMON_DIR: dotGit,
    GIT_WORK_TREE: victim,
    GIT_INDEX_FILE: path.join(dotGit, "index"),
    GIT_OBJECT_DIRECTORY: path.join(dotGit, "objects"),
    GIT_ALTERNATE_OBJECT_DIRECTORIES: path.join(dotGit, "objects"),
    GIT_NAMESPACE: "probe",
    GIT_PREFIX: "probe/",
    GIT_CONFIG: path.join(dotGit, "config"),
    GIT_CONFIG_PARAMETERS: "'sanctuary.probeparameters=leaked'",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "sanctuary.probenumbered",
    GIT_CONFIG_VALUE_0: "leaked",
    GIT_CONFIG_KEY_7: "sanctuary.probebeyondcount",
    GIT_CONFIG_VALUE_7: "leaked",
    // Also the child's own isolation when the scrub is absent: no user or system config.
    GIT_CONFIG_GLOBAL: "/dev/null",
    GIT_CONFIG_SYSTEM: "/dev/null",
    GIT_SHALLOW_FILE: path.join(tmp, "absent-shallow"),
    GIT_GRAFT_FILE: path.join(tmp, "absent-grafts"),
    GIT_CEILING_DIRECTORIES: tmp,
    GIT_CONFIG_KEY_X: "not-a-numbered-pair",
  };
}

/** The parent environment (VITEST included) minus git's redirect variables, with no user or system git config. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  scrubGitRedirectEnv(env);
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  return env;
}
/** Reads core.bare from the repo's own config file, independent of discovery. */
function bare(repo: string): string {
  const r = spawnSync("git", ["config", "--file", path.join(repo, ".git", "config"), "--get", "core.bare"], { encoding: "utf8", env: cleanEnv() });
  return r.stdout.trim();
}

interface ProbeRun { victim: string; fixture: string; seen: string[]; status: number | null; signal: NodeJS.Signals | null; error?: Error; out: string }

/** Runs the probe as a child vitest seeded with every MUST_SCRUB and MUST_KEEP name. */
function runProbe(withScrub: boolean): ProbeRun {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "git-env-scrub-")));
  cleanup.push(tmp);
  const victim = path.join(tmp, "victim");
  const fixture = path.join(tmp, "fixture");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home);
  for (const d of [victim, fixture]) {
    fs.mkdirSync(d);
    execFileSync("git", ["init", "--quiet"], { cwd: d, env: cleanEnv() });
  }
  // The child's setupFiles come from the REAL config; only the fail-before
  // case removes the scrub entry, and only from this child's copy.
  const realSetup = [...((config.test?.setupFiles ?? []) as string[])];
  expect(realSetup[0]).toBe(SETUP_ENTRY); // invariant: the scrub runs first
  const setupFiles = withScrub ? realSetup : realSetup.filter((e) => e !== SETUP_ENTRY);
  const cfg = path.join(tmp, "probe.config.mjs");
  // One thread worker confines probe execution to the child process that spawnSync reaps.
  fs.writeFileSync(cfg, `
import config from ${JSON.stringify(path.join(serverDir, "vitest.config.ts"))};
export default { ...config, cacheDir: ${JSON.stringify(path.join(tmp, "vite-cache"))}, test: { ...config.test, include: [${JSON.stringify(PROBE_GLOB)}], pool: "threads", maxWorkers: 1, setupFiles: ${JSON.stringify(setupFiles)} } };
`);
  const report = path.join(tmp, "seen.json");
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...seeds(tmp, victim),
    HOME: home,
    PROBE_REPO: fixture,
    PROBE_REPORT: report,
    // The keychain chokepoint refuses inside any child that inherits VITEST.
    VITEST: "true",
  };
  // Thread workers die with the synchronous child, which is reaped even when its timeout fires.
  const r = spawnSync(process.execPath, [path.join(serverDir, "node_modules/vitest/vitest.mjs"), "run", "--config", cfg], {
    cwd: serverDir, encoding: "utf8", env, timeout: childTimeoutMs, killSignal: "SIGKILL",
  });
  const seen = fs.existsSync(report) ? (JSON.parse(fs.readFileSync(report, "utf8")) as string[]) : [];
  return { victim, fixture, seen, status: r.status, signal: r.signal, error: r.error, out: `${r.stdout}${r.stderr}` };
}

function expectChildCompleted(r: ProbeRun): void {
  expect(r.error, r.out).toBeUndefined();
  expect(r.signal, r.out).toBeNull();
  expect(r.status, r.out).toBe(0);
}

/** Non-comment lines of a shipped bash file; comments are never evidence. */
function codeLines(rel: string): string[] {
  return fs.readFileSync(path.join(repoRoot, rel), "utf8").split("\n").filter((l) => !l.trimStart().startsWith("#"));
}

/**
 * Pins one bash copy to the shared list: the fixed array and the numbered
 * pattern must equal it exactly, and the shipped function, extracted verbatim
 * and run under `set -euo pipefail`, must clear every MUST_SCRUB name and keep
 * every MUST_KEEP name.
 */
function expectBashCopyMatches(rel: string): string[] {
  const lines = codeLines(rel);
  // String operations only (prefix, suffix, slice, split on spaces): no
  // quantified pattern runs over the hook text, so parsing cannot backtrack.
  const arrayPrefix = "GIT_REDIRECT_ENV_KEYS=(";
  const arrays = lines.filter((l) => l.startsWith(arrayPrefix));
  expect(arrays, rel).toHaveLength(1);
  expect(arrays[0].endsWith(")"), rel).toBe(true);
  const keys = arrays[0].slice(arrayPrefix.length, -1).split(" ").filter(Boolean);
  expect(keys).toEqual([...GIT_REDIRECT_ENV_KEYS]);
  const patterns = lines.filter((l) => l.startsWith("GIT_REDIRECT_NUMBERED_KEY_RE="));
  expect(patterns, rel).toHaveLength(1);
  expect(patterns[0]).toBe(`GIT_REDIRECT_NUMBERED_KEY_RE='${GIT_REDIRECT_NUMBERED_KEY_RE.source}'`);
  const start = lines.indexOf("scrub_git_redirect_env() {");
  expect(start, rel).toBeGreaterThanOrEqual(0);
  const end = lines.findIndex((l, i) => i > start && l === "}");
  expect(end, rel).toBeGreaterThan(start);
  const harness = ["set -euo pipefail", arrays[0], patterns[0], ...lines.slice(start, end + 1), "scrub_git_redirect_env", "compgen -e"].join("\n");
  const tmp = os.tmpdir();
  const out = execFileSync("bash", ["-c", harness], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, VITEST: "true", ...seeds(tmp, path.join(tmp, "victim")) },
  });
  const left = out.split("\n").filter(Boolean);
  expect(MUST_SCRUB.filter((k) => left.includes(k))).toEqual([]);
  expect(MUST_KEEP.filter((k) => !left.includes(k))).toEqual([]);
  return lines;
}

afterAll(() => {
  for (const d of cleanup) fs.rmSync(d, { recursive: true, force: true });
});

describe("test git-env scrub", () => {
  it("with the setup file, no seeded git redirect reaches a test and its git writes stay in its own repo", () => {
    const r = runProbe(true);
    expectChildCompleted(r);
    expect(MUST_SCRUB.filter((k) => r.seen.includes(k))).toEqual([]);
    expect(MUST_KEEP.filter((k) => !r.seen.includes(k))).toEqual([]);
    expect(MUST_KEEP.filter((k) => isGitRedirectEnvKey(k))).toEqual([]);
    expect(bare(r.fixture)).toBe("true"); // positive control: fixture repo was written
    expect(bare(r.victim)).toBe("false"); // throwaway "real" repo unchanged
  }, probeTestTimeoutMs);

  it("fail-before: without the setup file every seeded redirect reaches the probe and the victim repo is written", () => {
    const r = runProbe(false);
    expectChildCompleted(r);
    expect(MUST_SCRUB.filter((k) => !r.seen.includes(k))).toEqual([]);
    expect(bare(r.victim)).toBe("true");
    expect(bare(r.fixture)).toBe("false");
  }, probeTestTimeoutMs);

  it("the pre-commit hook clears the same set inside its one vitest call", () => {
    const lines = expectBashCopyMatches(".githooks/pre-commit");
    // A `log "..."` progress message names the command without running it.
    const vitestCalls = lines.filter((l) => l.includes("npx vitest") && !l.trimStart().startsWith("log "));
    expect(vitestCalls).toHaveLength(1);
    // The scrub runs inside the command-substitution subshell, so the hook's own git calls keep their env.
    expect(vitestCalls[0].startsWith("related_output=$(cd server && scrub_git_redirect_env && npx vitest related ")).toBe(true);
  });

  it("the verify-fail-before self-test clears the same set in both of its git subshells", () => {
    const lines = expectBashCopyMatches("scripts/verify-fail-before-self-test.sh");
    // clean_git and run_verify each call it once; no hand-written unset loop remains.
    expect(lines.filter((l) => l.trim() === "scrub_git_redirect_env")).toHaveLength(2);
    expect(lines.filter((l) => l.includes('unset "$key"'))).toEqual([]);
  });
});
