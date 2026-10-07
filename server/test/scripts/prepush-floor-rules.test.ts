/**
 * End-to-end fixture tests for the shipped `.githooks/pre-push` floor rules
 * (Rule (a): passing count vs. the pushed commit's own `.test-baseline`;
 * Rule (b), round 3 correction: the pushed floor vs. the PREVIOUS floor for
 * the ref being updated, read from git's own pre-push stdin remote SHA -
 * never from a local `origin/main` that may be stale), the commit-binding
 * check (including the `^{commit}` peel that lets an annotated tag pointing
 * at HEAD bind), the untracked-file check across both vitest include roots,
 * and the skip-worktree refusal.
 *
 * These invoke the REAL shipped hook file as a subprocess against a
 * throwaway git repo fixture (never the developer's own repo) with a
 * controlled pre-push stdin line and a fake `origin` remote (a
 * `git clone --bare` of the same fixture, so `git fetch origin main` works
 * fully offline). The 15-to-19-minute real `npm test` is replaced with
 * `SANCTUARY_PREPUSH_TEST_CMD`, an env var the hook honors ONLY for this
 * purpose (see the invariant comment at its call site in
 * .githooks/pre-push) - it is never read as meaningful by CI or an
 * operator's real push.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HOOK_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  ".githooks",
  "pre-push",
);

const REAL_GATE2B_PATH = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "scripts",
  "gate2b-check.sh",
);

const ZERO_SHA = "0".repeat(40);
const UNRESOLVABLE_SHA = "1234567890abcdef1234567890abcdef12345678";

// Isolation: never let git commands wander into a real repo (see
// install-hooks.test.ts's "real git worktree" test for the incident this
// mirrors) and never touch the operator's global git config.
function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env };
  // The keychain chokepoint refuses inside any child that inherits VITEST;
  // test/wrap/keychain-exec-guard.test.ts requires every spawned env to carry it.
  env.VITEST = process.env.VITEST ?? "true";
  for (const key of [
    "GIT_DIR",
    "GIT_COMMON_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
  ]) {
    delete env[key];
  }
  env.GIT_CONFIG_GLOBAL = "/dev/null";
  env.GIT_CONFIG_SYSTEM = "/dev/null";
  return env;
}

function git(args: string[], cwd: string, env = gitEnv()): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", env }).trim();
}

/**
 * Build a two-commit fixture repo: commit1 (pushed to a bare `origin` as
 * `main`, carrying `baselineMain`) and commit2 (the local HEAD, unpushed,
 * carrying `baselineHead`). Both commits carry the fixed gate2b machinery
 * (the real shipped `scripts/gate2b-check.sh` plus a trivial fixture
 * `count-vitest-test-files.mjs` stub that always reports 3 files, and a
 * `server/package.json` whose "test" script matches gate2b's supported
 * invocation) so a push that reaches the test-run step can complete
 * end-to-end without a real vitest install.
 */
function buildRepo(opts: {
  baselineMain: number;
  baselineHead: number;
}): { repoDir: string; originDir: string; mainSha: string; headSha: string } {
  const tmpRoot = fs.mkdtempSync(
    path.join(os.tmpdir(), "sanctuary-prepush-fixture-"),
  );
  const originDir = path.join(tmpRoot, "origin.git");
  const repoDir = path.join(tmpRoot, "repo");
  fs.mkdirSync(repoDir, { recursive: true });

  git(["init", "--quiet", "-b", "main"], repoDir);
  git(["config", "--local", "user.email", "test@example.com"], repoDir);
  git(["config", "--local", "user.name", "Test"], repoDir);

  fs.mkdirSync(path.join(repoDir, "scripts"), { recursive: true });
  fs.mkdirSync(path.join(repoDir, "server", "scripts"), { recursive: true });
  fs.copyFileSync(
    REAL_GATE2B_PATH,
    path.join(repoDir, "scripts", "gate2b-check.sh"),
  );
  fs.writeFileSync(
    path.join(repoDir, "server", "scripts", "count-vitest-test-files.mjs"),
    "process.stdout.write('3\\n');\n",
    "utf8",
  );
  fs.writeFileSync(
    path.join(repoDir, "server", "package.json"),
    JSON.stringify({ scripts: { test: "vitest run" } }, null, 2),
    "utf8",
  );
  fs.writeFileSync(path.join(repoDir, "f.txt"), "v1\n", "utf8");
  fs.writeFileSync(
    path.join(repoDir, ".test-baseline"),
    `${opts.baselineMain}\n`,
    "utf8",
  );
  git(["add", "-A"], repoDir);
  git(["commit", "--quiet", "--no-verify", "-m", "c1"], repoDir);
  const mainSha = git(["rev-parse", "HEAD"], repoDir);

  // Publish commit1 to a bare origin BEFORE commit2, so origin's tip is
  // exactly commit1 - the "previous tip" this file's Rule (b) tests probe.
  execFileSync("git", ["clone", "--quiet", "--bare", repoDir, originDir], {
    env: { ...gitEnv(), VITEST: process.env.VITEST ?? "true" },
  });
  git(["remote", "add", "origin", originDir], repoDir);

  fs.writeFileSync(
    path.join(repoDir, ".test-baseline"),
    `${opts.baselineHead}\n`,
    "utf8",
  );
  // Always touch a second file too, so commit2 is non-empty even when
  // baselineHead equals baselineMain (an equal-floor fixture would
  // otherwise leave nothing to commit).
  fs.writeFileSync(path.join(repoDir, "f.txt"), "v2\n", "utf8");
  git(["add", "-A"], repoDir);
  git(["commit", "--quiet", "--no-verify", "-m", "c2"], repoDir);
  const headSha = git(["rev-parse", "HEAD"], repoDir);

  return { repoDir, originDir, mainSha, headSha };
}

/** Stub `npm test` output that satisfies gate2b (3 files) and Rule (a) (50 passed). */
const ACCEPTED_TEST_STUB =
  "printf 'Test Files  3 passed (3)\\nTests  50 passed (50)\\n'";

function runHook(
  repoDir: string,
  stdinLine: string,
  extraEnv: NodeJS.ProcessEnv = {},
): { status: number | null; stdout: string; stderr: string } {
  // git invokes the hook as `pre-push <remote-name> <remote-url>`; the hook reads $1.
  const result = spawnSync("bash", [HOOK_PATH, "origin", "origin"], {
    cwd: repoDir,
    input: stdinLine,
    encoding: "utf8",
    env: {
      ...gitEnv(),
      VITEST: process.env.VITEST ?? "true",
      SANCTUARY_PREPUSH_TEST_CMD: ACCEPTED_TEST_STUB,
      ...extraEnv,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe(".githooks/pre-push floor rules (end-to-end fixture)", () => {
  let cleanupDirs: string[] = [];

  beforeEach(() => {
    cleanupDirs = [];
  });

  afterEach(() => {
    for (const dir of cleanupDirs) {
      fs.rmSync(path.dirname(dir), { recursive: true, force: true });
    }
  });

  function track(repoDir: string) {
    cleanupDirs.push(repoDir);
  }

  it("(i) refuses a pushed floor lower than the live remote tip's floor, naming both numbers", () => {
    const { repoDir, headSha, mainSha } = buildRepo({
      baselineMain: 10,
      baselineHead: 5,
    });
    track(repoDir);

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${mainSha}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("BELOW THE PREVIOUS FLOOR");
    expect(stderr).toContain("10");
    expect(stderr).toContain("5");
  });

  it("(ii) accepts a pushed floor equal to the live remote tip's floor", () => {
    const { repoDir, headSha, mainSha } = buildRepo({
      baselineMain: 10,
      baselineHead: 10,
    });
    track(repoDir);

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${mainSha}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).toBe(0);
    expect(stderr).toContain("All baseline-guard checks passed");
  });

  it("(iii) refuses when the remote SHA does not resolve locally, with the fetch message", () => {
    const { repoDir, headSha } = buildRepo({ baselineMain: 10, baselineHead: 10 });
    track(repoDir);

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${UNRESOLVABLE_SHA}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("is not available locally");
    expect(stderr).toContain(UNRESOLVABLE_SHA);
    expect(stderr).toContain("git fetch origin main");
  });

  it("(iv) refuses a new ref with a lowered floor versus freshly fetched origin/main", () => {
    const { repoDir, headSha } = buildRepo({ baselineMain: 10, baselineHead: 5 });
    track(repoDir);

    const stdin = `refs/heads/feature ${headSha} refs/heads/feature ${ZERO_SHA}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("BELOW THE PREVIOUS FLOOR");
    expect(stderr).toContain("freshly fetched main of remote 'origin'");
    expect(stderr).toContain("10");
    expect(stderr).toContain("5");
  });

  it("(v) refuses an untracked test file under server/, naming it", () => {
    const { repoDir, headSha, mainSha } = buildRepo({
      baselineMain: 10,
      baselineHead: 10,
    });
    track(repoDir);
    fs.mkdirSync(path.join(repoDir, "server", "test"), { recursive: true });
    fs.writeFileSync(
      path.join(repoDir, "server", "test", "zz.test.ts"),
      "// untracked\n",
      "utf8",
    );

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${mainSha}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("UNCOMMITTED OR UNTRACKED CHANGES");
    expect(stderr).toContain("server/test/zz.test.ts");
  });

  it("(vi) refuses a skip-worktree entry under server/", () => {
    const { repoDir, headSha, mainSha } = buildRepo({
      baselineMain: 10,
      baselineHead: 10,
    });
    track(repoDir);
    git(["update-index", "--skip-worktree", "server/package.json"], repoDir);

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${mainSha}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("skip-worktree OR assume-unchanged");
    expect(stderr).toContain("server/package.json");
  });

  it("(vii) accepts an annotated tag whose commit is HEAD, through the ^{commit} peel", () => {
    const { repoDir, headSha } = buildRepo({ baselineMain: 10, baselineHead: 10 });
    track(repoDir);
    git(
      ["tag", "-a", "v1.0.0", "-m", "release", headSha],
      repoDir,
    );
    const tagSha = git(["rev-parse", "v1.0.0"], repoDir);
    // The tag object's own SHA must differ from the commit SHA it points at
    // for this test to actually exercise the peel (a raw string compare
    // would otherwise pass by accident).
    expect(tagSha).not.toBe(headSha);

    const stdin = `refs/tags/v1.0.0 ${tagSha} refs/tags/v1.0.0 ${ZERO_SHA}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).toBe(0);
    expect(stderr).toContain("All baseline-guard checks passed");
  });

  it("(ix) refuses when the suite passes fewer tests than the pushed commit's own floor (rule a)", () => {
    const { repoDir, headSha, mainSha } = buildRepo({
      baselineMain: 10,
      baselineHead: 10,
    });
    track(repoDir);

    const stdin = `refs/heads/main ${headSha} refs/heads/main ${mainSha}\n`;
    const { status, stderr } = runHook(repoDir, stdin, {
      SANCTUARY_PREPUSH_TEST_CMD: ACCEPTED_TEST_STUB.replace("Tests  50 passed (50)", "Tests  4 passed (4)"),
    });

    expect(status).not.toBe(0);
    expect(stderr).toContain("TEST BASELINE REGRESSION");
  });

  it("(viii) refuses a local SHA that is not HEAD's commit", () => {
    const { repoDir, mainSha } = buildRepo({ baselineMain: 10, baselineHead: 10 });
    track(repoDir);

    // mainSha is commit1, HEAD is commit2 - a straightforward non-HEAD push.
    const stdin = `refs/heads/main ${mainSha} refs/heads/main ${ZERO_SHA}\n`;
    const { status, stderr } = runHook(repoDir, stdin);

    expect(status).not.toBe(0);
    expect(stderr).toContain("PUSHED REF DOES NOT MATCH THE CHECKED-OUT COMMIT");
  });
});
