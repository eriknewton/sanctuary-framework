/**
 * Capability: no test process inherits a git variable that redirects which
 * repository, config file, or object graph git acts on (a git hook exports
 * GIT_DIR pointing at the real repository; a shell can add GIT_CONFIG and
 * runtime config pairs). Witness for test/setup/git-env-scrub.ts, the first
 * entry of both globalSetup and setupFiles: a child vitest run, seeded with
 * every variable the guard must clear, runs a globalSetup probe that reports
 * what the MAIN process still holds and a test probe that reports what a
 * WORKER inherited and writes `core.bare=true` from its own fixture repo while
 * GIT_DIR and GIT_CONFIG aim at a throwaway "victim" repo. With the scrub
 * entries nothing seeded reaches either probe and the fixture repo is written
 * (positive control); with both entries removed from the child's lists every
 * seeded variable reaches them and the victim is written instead
 * (fail-before). The bash copies of the list are pinned to
 * scripts/git-redirect-env-keys.json statically and by running them, the
 * pre-commit hook end to end with stub vitest launchers.
 *
 * Coverage bound: the end-to-end hook run exercises the branch a commit with
 * a staged .ts file takes. A launch on a branch that run never reaches, in a
 * spelling the static `mayLaunchVitest` heuristic does not list (for example
 * `exec vitest` or `$(npm bin)/vitest`), is not caught by either check.
 *
 * Every child here runs in its own process group and the whole group is
 * SIGKILLed on every exit path (timeout, failure, normal exit, afterAll), so
 * no worker, subshell, git or node descendant outlives the test.
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
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
import { removeTestRunMarker, TEST_RUN_TOKEN_ID_ENV } from "../setup/test-run-marker.js";

const serverDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = path.resolve(serverDir, "..");
const SETUP_ENTRY = "./test/setup/git-env-scrub.ts";
const PROBE_GLOB = "test/fixtures/git-env-scrub/*.probe.ts";
const MAIN_PROBE = "./test/fixtures/git-env-scrub/main-process.probe-global.ts";
const childStartupHeadroomMs = 30_000; // Allow module loading on a loaded runner.
const childExitHeadroomMs = 10_000; // Allow reporting and worker shutdown after the probe.
const parentHeadroomMs = 30_000; // Allow the fixture git inits and report reads outside the child budget.
// One probe test: startup, the config's per-test budget, one hook budget for setup/teardown, then exit.
const childTimeoutMs = childStartupHeadroomMs + (config.test?.testTimeout ?? childStartupHeadroomMs) + leaseGuardHookTimeoutMs + childExitHeadroomMs;
const probeTestTimeoutMs = childTimeoutMs + parentHeadroomMs;
// The hook run does git plumbing and calls stubs only; the same startup and exit headroom bound it.
const hookTimeoutMs = childStartupHeadroomMs + childExitHeadroomMs;
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

/** Values that keep a leaked redirect aimed at `target`, so fail-before writes land there. */
function seeds(tmp: string, target: string): Record<(typeof MUST_SCRUB)[number] | (typeof MUST_KEEP)[number], string> {
  const dotGit = path.join(target, ".git");
  return {
    GIT_DIR: dotGit,
    GIT_COMMON_DIR: dotGit,
    GIT_WORK_TREE: target,
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
function cleanEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  scrubGitRedirectEnv(env);
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  return env;
}
/** Reads core.bare from the repo's own config file, independent of discovery. */
function bare(repo: string): string {
  const r = spawnSync("git", ["config", "--file", path.join(repo, ".git", "config"), "--get", "core.bare"], { encoding: "utf8", env: cleanEnv(process.env) });
  return r.stdout.trim();
}
function scratch(): string {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "git-env-scrub-")));
  cleanup.push(tmp);
  return tmp;
}
function readNames(report: string): string[] {
  return fs.existsSync(report) ? (JSON.parse(fs.readFileSync(report, "utf8")) as string[]) : [];
}

/**
 * Process groups this file started and has not yet reaped. A detached child
 * leads a new group whose id is its pid, so `kill(-pid)` reaches every
 * descendant (vitest workers, hook subshells, git, the node redactor) even
 * after the leader has exited.
 */
const liveGroups = new Set<number>();
function killGroup(pgid: number): void {
  try {
    process.kill(-pgid, "SIGKILL");
  } catch (err) {
    // ESRCH: the whole group is already gone, which is the goal.
    if ((err as NodeJS.ErrnoException).code !== "ESRCH") throw err;
  }
  liveGroups.delete(pgid);
}

interface GroupRun { status: number | null; signal: NodeJS.Signals | null; error?: Error; timedOut: boolean; out: string }

/**
 * Runs `command` as the leader of its own process group, SIGKILLs the whole
 * group if it outlives `timeoutMs`, and SIGKILLs the group again once the
 * leader has closed, so a backgrounded descendant cannot survive a clean exit
 * either. Failure mode this prevents: a timed-out hook or vitest child whose
 * descendants keep running after the suite, holding files and CPU and
 * reading as unrelated flakes in later runs.
 */
function runInOwnGroup(command: string, args: string[], opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number }): Promise<GroupRun> {
  return new Promise((resolve) => {
    let out = "";
    let timedOut = false;
    let settled = false;
    const child = spawn(command, args, {
      cwd: opts.cwd,
      env: { ...opts.env, VITEST: "true" }, // the keychain chokepoint refuses inside any child carrying VITEST
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const pgid = child.pid;
    if (pgid !== undefined) liveGroups.add(pgid);
    const timer = setTimeout(() => {
      timedOut = true;
      if (pgid !== undefined) killGroup(pgid);
    }, opts.timeoutMs);
    const finish = (result: Omit<GroupRun, "timedOut" | "out">) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (pgid !== undefined) killGroup(pgid);
      resolve({ ...result, timedOut, out });
    };
    child.stdout.on("data", (d: Buffer) => { out += d.toString("utf8"); });
    child.stderr.on("data", (d: Buffer) => { out += d.toString("utf8"); });
    child.on("error", (error) => finish({ status: null, signal: null, error }));
    child.on("close", (status, signal) => finish({ status, signal }));
  });
}

interface ProbeRun extends GroupRun { victim: string; fixture: string; workerSeen: string[]; mainSeen: string[] }

/** Runs the probes as a child vitest seeded with every MUST_SCRUB and MUST_KEEP name. */
async function runProbe(withScrub: boolean): Promise<ProbeRun> {
  const tmp = scratch();
  const victim = path.join(tmp, "victim");
  const fixture = path.join(tmp, "fixture");
  const home = path.join(tmp, "home");
  fs.mkdirSync(home);
  for (const d of [victim, fixture]) {
    fs.mkdirSync(d);
    execFileSync("git", ["init", "--quiet"], { cwd: d, env: cleanEnv(process.env) });
  }
  // The child's lists come from the REAL config; only the fail-before case
  // removes the scrub entry, and only from this child's copies.
  const realSetup = [...((config.test?.setupFiles ?? []) as string[])];
  const realGlobal = [...((config.test?.globalSetup ?? []) as string[])];
  expect(realSetup[0]).toBe(SETUP_ENTRY); // invariant: the worker scrub runs first
  expect(realGlobal[0]).toBe(SETUP_ENTRY); // invariant: the main-process scrub runs first
  const keep = (e: string) => withScrub || e !== SETUP_ENTRY;
  const setupFiles = realSetup.filter(keep);
  const globalSetup = [...realGlobal.filter(keep), MAIN_PROBE];
  const cfg = path.join(tmp, "probe.config.mjs");
  // One thread worker keeps probe execution inside the child's own process group.
  fs.writeFileSync(cfg, `
import config from ${JSON.stringify(path.join(serverDir, "vitest.config.ts"))};
export default { ...config, cacheDir: ${JSON.stringify(path.join(tmp, "vite-cache"))}, test: { ...config.test, include: [${JSON.stringify(PROBE_GLOB)}], pool: "threads", maxWorkers: 1, setupFiles: ${JSON.stringify(setupFiles)}, globalSetup: ${JSON.stringify(globalSetup)} } };
`);
  const workerReport = path.join(tmp, "worker-seen.json");
  const mainReport = path.join(tmp, "main-seen.json");
  // The child's globalSetup (test-run-marker.ts, via the spread real config)
  // names its marker token with this id, so the parent can delete exactly that
  // token after the child exits. Must match TEST_RUN_TOKEN_ID_ENV in
  // test/setup/test-run-marker.ts. Failure mode this prevents: a SIGKILLed
  // child skips its teardown, its token survives the outer run, and the
  // checkout keeps reading as "under test" (the CLI refuses keychain work)
  // until a later run prunes it after the staleness ceiling. Matching by pid
  // instead would be unsafe: runs in other pid namespaces sharing this
  // checkout can carry the same pid.
  const childTokenId = randomUUID();
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ...seeds(tmp, victim),
    HOME: home,
    PROBE_REPO: fixture,
    PROBE_REPORT: workerReport,
    PROBE_MAIN_REPORT: mainReport,
    [TEST_RUN_TOKEN_ID_ENV]: childTokenId,
  };
  try {
    const r = await runInOwnGroup(process.execPath, [path.join(serverDir, "node_modules/vitest/vitest.mjs"), "run", "--config", cfg], {
      cwd: serverDir, env, timeoutMs: childTimeoutMs,
    });
    return { ...r, victim, fixture, workerSeen: readNames(workerReport), mainSeen: readNames(mainReport) };
  } finally {
    // Every exit path: the group is already killed here, so its exact token can go.
    // removeTestRunMarker tolerates a token or directory that is already gone (ENOENT).
    removeTestRunMarker(serverDir, childTokenId);
  }
}

function expectChildCompleted(r: GroupRun): void {
  expect(r.timedOut, `child timed out and its process group was killed:\n${r.out}`).toBe(false);
  expect(r.error, r.out).toBeUndefined();
  expect(r.signal, r.out).toBeNull();
  expect(r.status, r.out).toBe(0);
}

/** Non-comment lines of a shipped bash file; comments are never evidence. */
function codeLines(rel: string): string[] {
  return fs.readFileSync(path.join(repoRoot, rel), "utf8").split("\n").filter((l) => !l.trimStart().startsWith("#"));
}

const KEYS_DEF = `GIT_REDIRECT_ENV_KEYS=(${GIT_REDIRECT_ENV_KEYS.join(" ")})`;
const RE_DEF = `GIT_REDIRECT_NUMBERED_KEY_RE='${GIT_REDIRECT_NUMBERED_KEY_RE.source}'`;
const FN_DEF = "scrub_git_redirect_env() {";
const KEYS_USE = '  for name in "${GIT_REDIRECT_ENV_KEYS[@]}"; do';
const RE_USE = '    if [[ "$name" =~ $GIT_REDIRECT_NUMBERED_KEY_RE ]]; then';
const COMPGEN_USE = "  for name in $(compgen -e); do";

/**
 * Pins one bash copy to the shared list, using string operations only (exact
 * line equality, includes, slice), so no quantified pattern runs over the
 * shipped text and parsing cannot backtrack. Every non-comment line that
 * names the array, the pattern, the function, or compgen must be one of the
 * exact expected lines, so an indented or `declare -a` reassignment, a `+=`
 * append, a second or `function`-keyword definition, or an extra call site
 * fails. The function, extracted verbatim and run under `set -euo pipefail`,
 * must clear every MUST_SCRUB name and keep every MUST_KEEP name.
 */
function expectBashCopyMatches(rel: string, callLines: string[]): string[] {
  const lines = codeLines(rel);
  const start = lines.indexOf(FN_DEF);
  expect(start, `${rel}: no line equal to "${FN_DEF}"; the scrub function must be defined at column 0 in exactly that form`).toBeGreaterThanOrEqual(0);
  const end = lines.findIndex((l, i) => i > start && l === "}");
  expect(end, `${rel}: scrub_git_redirect_env has no closing "}" at column 0`).toBeGreaterThan(start);
  const body = lines.slice(start, end + 1);
  for (const use of [KEYS_USE, RE_USE, COMPGEN_USE]) expect(body, `${rel}: the scrub function must contain the line ${JSON.stringify(use)}`).toContain(use);
  const expectations: [string, string[]][] = [
    ["GIT_REDIRECT_ENV_KEYS", [KEYS_DEF, KEYS_USE]],
    ["GIT_REDIRECT_NUMBERED_KEY_RE", [RE_DEF, RE_USE]],
    ["scrub_git_redirect_env", [FN_DEF, ...callLines]],
    ["compgen", [COMPGEN_USE]],
  ];
  for (const [token, expected] of expectations) {
    expect(lines.filter((l) => l.includes(token)), `${rel}: every non-comment line naming ${token} must be one of these exact lines (a reassignment, append, second definition or extra call is refused); if the list changed, update scripts/git-redirect-env-keys.json and both bash copies together`).toEqual(expected);
  }
  // Definitions precede the function, which precedes every call.
  expect(lines.indexOf(KEYS_DEF), `${rel}: the array must be defined before the scrub function`).toBeLessThan(start);
  expect(lines.indexOf(RE_DEF), `${rel}: the pattern must be defined before the scrub function`).toBeLessThan(start);
  for (const call of callLines) expect(lines.indexOf(call), `${rel}: the call ${JSON.stringify(call)} must come after the scrub function`).toBeGreaterThan(end);
  const harness = ["set -euo pipefail", KEYS_DEF, RE_DEF, ...body, "scrub_git_redirect_env", "compgen -e"].join("\n");
  const tmp = os.tmpdir();
  const out = execFileSync("bash", ["-c", harness], {
    encoding: "utf8",
    env: { PATH: process.env.PATH, VITEST: "true", ...seeds(tmp, path.join(tmp, "victim")) },
  });
  const left = out.split("\n").filter(Boolean);
  expect(MUST_SCRUB.filter((k) => left.includes(k)), `${rel}: names the extracted scrub function left set`).toEqual([]);
  expect(MUST_KEEP.filter((k) => !left.includes(k)), `${rel}: names the extracted scrub function wrongly cleared`).toEqual([]);
  return lines;
}

const HOOK = ".githooks/pre-commit";
const HOOK_CALL = 'related_output=$(cd server && scrub_git_redirect_env && npx vitest related --run "${abs_staged_files[@]}" 2>&1 \\';
const HOOK_CALL_NEXT = "  | node ../scripts/redact-test-output.mjs)";
const HOOK_LOG = 'log "Gate 2/2: npx vitest related --run (${#staged_ts_files[@]} staged file(s)) + transform-error scan"';

/** True for a line that could launch vitest in any common spelling (substring checks only). */
function mayLaunchVitest(l: string): boolean {
  const t = l.trimStart();
  return (l.includes("npx ") && l.includes("vitest"))
    || l.includes(".bin/vitest") || l.includes("vitest.mjs")
    || l.includes("npm test") || l.includes("npm run test") || l.includes("npm t ") || l.includes("npm exec")
    || l.includes("pnpm") || l.includes("yarn")
    || t.startsWith("vitest ") || l.includes("| vitest") || l.includes("&& vitest") || l.includes("; vitest") || l.includes("$(vitest");
}

/**
 * One launcher stub: records its name, args and every GIT_* name it inherited.
 * When PROBE_FAIL_TYPECHECK is set, the typecheck launch prints a planted
 * diagnostic and fails, to prove the hook still shows its log tail.
 */
const DUMP_STUB = `#!/usr/bin/env bash
{
  printf 'CALL %s' "\${0##*/}"; printf ' %s' "$@"; printf '\\n'
  compgen -e | grep '^GIT_' || true
  printf 'END\\n'
} >> "$PROBE_DUMP"
if [[ -n "\${PROBE_FAIL_TYPECHECK:-}" && "$*" == "run typecheck --silent" ]]; then
  echo "planted-typecheck-diagnostic"
  exit 1
fi
exit 0
`;

interface HookFixture { repo: string; dump: string; tmpdir: string; env: NodeJS.ProcessEnv }

/** A throwaway repo holding the real hook, one staged .ts file, and dumping stubs for every launcher spelling. */
function hookFixture(): HookFixture {
  const tmp = scratch();
  const repo = path.join(tmp, "repo");
  const bin = path.join(tmp, "bin");
  const home = path.join(tmp, "home");
  // The hook's mktemp lands here, never in the shared system temp dir.
  const tmpdir = path.join(tmp, "tmpdir");
  for (const d of [repo, bin, home, tmpdir, path.join(repo, "server/node_modules/.bin"), path.join(repo, ".githooks"), path.join(repo, "scripts")]) {
    fs.mkdirSync(d, { recursive: true });
  }
  execFileSync("git", ["init", "--quiet"], { cwd: repo, env: cleanEnv(process.env) });
  fs.copyFileSync(path.join(repoRoot, HOOK), path.join(repo, HOOK));
  fs.copyFileSync(path.join(repoRoot, "scripts/redact-test-output.mjs"), path.join(repo, "scripts/redact-test-output.mjs"));
  fs.writeFileSync(path.join(repo, "server/staged.ts"), "export const staged = 1;\n");
  execFileSync("git", ["add", "server/staged.ts"], { cwd: repo, env: cleanEnv(process.env) });
  // Every launcher spelling routes to the dumping stub, so an unscrubbed extra launch is seen too.
  for (const stub of [path.join(bin, "npx"), path.join(bin, "npm"), path.join(bin, "vitest"), path.join(bin, "pnpm"), path.join(bin, "yarn"), path.join(repo, "server/node_modules/.bin/vitest")]) {
    fs.writeFileSync(stub, DUMP_STUB, { mode: 0o755 });
  }
  const dump = path.join(tmp, "dump.log");
  // Seeds aim at the hook's own repo, as git's real hook env does, so the hook's git calls work.
  const env: NodeJS.ProcessEnv = { ...seeds(tmp, repo), PATH: `${bin}:${process.env.PATH ?? ""}`, HOME: home, TMPDIR: tmpdir, PROBE_DUMP: dump };
  return { repo, dump, tmpdir, env };
}

function dumpedCalls(dump: string): { header: string; names: string[] }[] {
  return fs.readFileSync(dump, "utf8").split("END\n").filter(Boolean).map((block) => {
    const [header, ...names] = block.split("\n").filter(Boolean);
    return { header, names };
  });
}

afterAll(() => {
  // Reap any group a failed or interrupted test left, before deleting its files.
  for (const pgid of [...liveGroups]) killGroup(pgid);
  for (const d of cleanup) fs.rmSync(d, { recursive: true, force: true });
});

describe("test git-env scrub", () => {
  it("with the scrub entries, no seeded git redirect reaches the main process or a test, and git writes stay in the test's repo", async () => {
    const r = await runProbe(true);
    expectChildCompleted(r);
    expect(MUST_SCRUB.filter((k) => r.workerSeen.includes(k))).toEqual([]);
    expect(MUST_SCRUB.filter((k) => r.mainSeen.includes(k))).toEqual([]);
    expect(MUST_KEEP.filter((k) => !r.workerSeen.includes(k))).toEqual([]);
    expect(MUST_KEEP.filter((k) => isGitRedirectEnvKey(k))).toEqual([]);
    expect(bare(r.fixture)).toBe("true"); // positive control: fixture repo was written
    expect(bare(r.victim)).toBe("false"); // throwaway "real" repo unchanged
  }, probeTestTimeoutMs);

  it("fail-before: without the scrub entries every seeded redirect reaches both probes and the victim repo is written", async () => {
    const r = await runProbe(false);
    expectChildCompleted(r);
    expect(MUST_SCRUB.filter((k) => !r.workerSeen.includes(k))).toEqual([]);
    expect(MUST_SCRUB.filter((k) => !r.mainSeen.includes(k))).toEqual([]);
    expect(bare(r.victim)).toBe("true");
    expect(bare(r.fixture)).toBe("false");
  }, probeTestTimeoutMs);

  it("the pre-commit hook defines the scrub once and calls it inside its one vitest launch", () => {
    const lines = expectBashCopyMatches(HOOK, [HOOK_CALL]);
    expect(lines.filter(mayLaunchVitest), `${HOOK}: the only lines that may name a vitest launcher are the progress log ${JSON.stringify(HOOK_LOG)} and the one scrubbed launch; a second launch must call scrub_git_redirect_env too and be added here`).toEqual([HOOK_LOG, HOOK_CALL]);
    // Exact line equality: nothing chained after the launch, and the scrub runs
    // inside the command-substitution subshell, so the hook's own git calls keep their env.
    expect(lines[lines.indexOf(HOOK_CALL) + 1], `${HOOK}: the launch must continue with exactly ${JSON.stringify(HOOK_CALL_NEXT)}`).toBe(HOOK_CALL_NEXT);
  });

  it("the real pre-commit hook, run with git's hook env and every seeded redirect, launches vitest with none of them", async () => {
    const f = hookFixture();
    const r = await runInOwnGroup("bash", [path.join(f.repo, HOOK)], { cwd: f.repo, env: f.env, timeoutMs: hookTimeoutMs });
    expectChildCompleted(r);
    const calls = dumpedCalls(f.dump);
    // The typecheck gate runs before the scrub, in the hook's own env; every other launch must be clean.
    const launches = calls.filter((c) => c.header !== "CALL npm run typecheck --silent");
    expect(launches.map((c) => c.header), "the hook must launch vitest exactly once, as `npx vitest related --run <staged file>`").toEqual([`CALL npx vitest related --run ${path.join(f.repo, "server/staged.ts")}`]);
    expect(MUST_SCRUB.filter((k) => launches[0].names.includes(k)), "redirect variables that reached the hook's vitest launch").toEqual([]);
    expect(MUST_KEEP.filter((k) => !launches[0].names.includes(k))).toEqual([]);
    expect(fs.readdirSync(f.tmpdir), "the hook's per-invocation typecheck log must be removed on exit").toEqual([]);
  }, hookTimeoutMs + parentHeadroomMs);

  it("the real pre-commit hook still shows the typecheck log tail on failure and removes the log", async () => {
    const f = hookFixture();
    const r = await runInOwnGroup("bash", [path.join(f.repo, HOOK)], { cwd: f.repo, env: { ...f.env, PROBE_FAIL_TYPECHECK: "1" }, timeoutMs: hookTimeoutMs });
    expect(r.timedOut, r.out).toBe(false);
    expect(r.signal, r.out).toBeNull();
    expect(r.status, r.out).toBe(1);
    expect(r.out).toContain("TYPECHECK FAILED - commit blocked");
    expect(r.out).toContain("planted-typecheck-diagnostic");
    expect(dumpedCalls(f.dump).map((c) => c.header), "a failed typecheck must stop the hook before any vitest launch").toEqual(["CALL npm run typecheck --silent"]);
    expect(fs.readdirSync(f.tmpdir), "the hook's per-invocation typecheck log must be removed on exit").toEqual([]);
  }, hookTimeoutMs + parentHeadroomMs);

  it("the verify-fail-before self-test defines the scrub once and calls it in both git subshells", () => {
    const lines = expectBashCopyMatches("scripts/verify-fail-before-self-test.sh", ["  scrub_git_redirect_env", "    scrub_git_redirect_env"]);
    expect(lines.filter((l) => l.includes('unset "$key"'))).toEqual([]);
  });
});
