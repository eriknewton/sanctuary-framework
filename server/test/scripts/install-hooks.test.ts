import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { resolveHooksDir } from "../../scripts/install-hooks.js";

describe("install-hooks resolveHooksDir", () => {
  let tmpRoot: string;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sanctuary-install-hooks-"));
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("resolves to <root>/.git/hooks when .git is a directory (main repo checkout)", () => {
    const dotGit = path.join(tmpRoot, ".git");
    fs.mkdirSync(dotGit);
    const result = resolveHooksDir(tmpRoot);
    expect(result).toBe(path.join(dotGit, "hooks"));
  });

  // REGRESSION (2026-07-18): a worktree must resolve to the COMMON hooks dir,
  // never the per-worktree one. Git executes hooks from the common git dir, so
  // installing into `<main>/.git/worktrees/<name>/hooks` writes a file that is
  // never run — install-hooks reported success while leaving the worktree
  // unguarded. The previous version of this test asserted the per-worktree path
  // and so pinned the bug in place.
  it("follows commondir to the shared hooks dir when .git is a file (worktree checkout)", () => {
    const mainGitDir = path.join(tmpRoot, "fake-main-repo", ".git");
    const worktreeGitDir = path.join(mainGitDir, "worktrees", "foo");
    fs.mkdirSync(worktreeGitDir, { recursive: true });
    // git writes this pointer back to the shared git dir in every worktree.
    fs.writeFileSync(path.join(worktreeGitDir, "commondir"), "../..\n", "utf8");
    fs.writeFileSync(
      path.join(tmpRoot, ".git"),
      `gitdir: ${worktreeGitDir}\n`,
      "utf8"
    );
    const result = resolveHooksDir(tmpRoot);
    expect(result).toBe(path.join(mainGitDir, "hooks"));
    expect(result).not.toBe(path.join(worktreeGitDir, "hooks"));
  });

  it("falls back to the worktree git dir when no commondir pointer exists", () => {
    const worktreeGitDir = path.join(tmpRoot, "detached", "gitdir");
    fs.mkdirSync(worktreeGitDir, { recursive: true });
    fs.writeFileSync(
      path.join(tmpRoot, ".git"),
      `gitdir: ${worktreeGitDir}\n`,
      "utf8"
    );
    expect(resolveHooksDir(tmpRoot)).toBe(path.join(worktreeGitDir, "hooks"));
  });

  // The end-to-end case, against a REAL git worktree rather than a fixture:
  // this is the shape our build dispatches actually use, and it is what the
  // fixture tests above are only a proxy for.
  it("resolves a real git worktree to the main checkout's hooks dir", () => {
    const mainRepo = path.join(tmpRoot, "main");
    fs.mkdirSync(mainRepo);
    // This test shells out to real git, so it is the one test in the suite that
    // can damage the developer's own repository. It already did once, on
    // 2026-07-18: run inside the pre-commit hook, the inherited GIT_DIR pointed
    // at the Sanctuary repo, so `git init` marked THAT repo bare and
    // `git config user.*` overwrote its identity. Every later git command in the
    // checkout failed with "must be run in a work tree" until the config was
    // repaired by hand.
    //
    // So the isolation here is layered and asserted, not assumed:
    //   1. scrub every repo-scoping GIT_* var, so nothing aims git at an
    //      inherited repository;
    //   2. point GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM at /dev/null, so the
    //      config writes below cannot reach the developer's real config even if
    //      step 1 were somehow defeated;
    //   3. assert, before any mutating command runs, that git agrees the temp
    //      directory is its own top level. If that assertion ever fails, the
    //      test aborts instead of mutating whatever repo it actually found.
    const env: NodeJS.ProcessEnv = { ...process.env };
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
    const git = (args: string[], cwd: string) =>
      execFileSync("git", args, { cwd, stdio: "ignore", env });
    const gitOut = (args: string[], cwd: string) =>
      execFileSync("git", args, { cwd, encoding: "utf8", env }).trim();
    git(["init", "--quiet"], mainRepo);

    // Containment assertion (see the comment above): git must agree that the
    // repo it is operating on IS the temp repo. If isolation ever breaks, this
    // fails here, before any config write or commit touches a real repository.
    expect(fs.realpathSync(gitOut(["rev-parse", "--show-toplevel"], mainRepo)))
      .toBe(fs.realpathSync(mainRepo));

    git(["config", "--local", "user.email", "test@example.com"], mainRepo);
    git(["config", "--local", "user.name", "Test"], mainRepo);
    fs.writeFileSync(path.join(mainRepo, "f.txt"), "x\n", "utf8");
    git(["add", "f.txt"], mainRepo);
    git(["commit", "--quiet", "-m", "init", "--no-verify"], mainRepo);

    const wt = path.join(tmpRoot, "wt");
    git(["worktree", "add", "--quiet", wt, "-b", "wt-branch"], mainRepo);

    // realpath both sides: on macOS os.tmpdir() is /var/... which is a symlink
    // to /private/var/..., and git returns the resolved form.
    const result = fs.realpathSync(path.dirname(resolveHooksDir(wt)));
    expect(result).toBe(fs.realpathSync(path.join(mainRepo, ".git")));
  });

  it("throws when the root has no .git entry", () => {
    expect(() => resolveHooksDir(tmpRoot)).toThrow(/Not a git repository/);
  });
});
