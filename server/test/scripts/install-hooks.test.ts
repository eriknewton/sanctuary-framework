import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  resolveHooksDir,
  installHooksInto,
  backupExistingForeignHook,
  MARKER_LINE,
} from "../../scripts/install-hooks.js";
import { scrubGitRedirectEnv } from "../setup/git-env-scrub.js";

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
    // One list: scripts/git-redirect-env-keys.json via test/setup/git-env-scrub.ts.
    scrubGitRedirectEnv(env);
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

  // Wired consumer of scripts/git-redirect-env-keys.json in install-hooks.js.
  // The installer clears repository variables and the one-command `git -c`
  // scope (GIT_CONFIG_PARAMETERS), but KEEPS a developer's deliberate config
  // (GIT_CONFIG_GLOBAL, a numbered GIT_CONFIG_KEY_<n> pair), because later
  // ordinary git commands in the checkout use it to pick the hooks directory.
  // The global test setup already cleared all of these from process.env, so
  // each case re-seeds them to reach resolveHooksDir itself.
  function initRepo(): { repo: string; initEnv: NodeJS.ProcessEnv } {
    const repo = path.join(tmpRoot, "repo");
    fs.mkdirSync(repo);
    const initEnv: NodeJS.ProcessEnv = { ...process.env };
    scrubGitRedirectEnv(initEnv);
    initEnv.GIT_CONFIG_GLOBAL = "/dev/null";
    initEnv.GIT_CONFIG_SYSTEM = "/dev/null";
    execFileSync("git", ["init", "--quiet"], { cwd: repo, stdio: "ignore", env: initEnv });
    return { repo, initEnv };
  }
  /** What git itself answers for the hooks path under `env`: the directory it would run. */
  function gitHooksPath(repo: string, env: NodeJS.ProcessEnv): string {
    return execFileSync("git", ["rev-parse", "--git-path", "hooks"], { cwd: repo, encoding: "utf8", env }).trim();
  }
  function withProcessEnv<T>(seeded: Record<string, string>, fn: () => T): T {
    const saved = Object.fromEntries(Object.keys(seeded).map((k) => [k, process.env[k]]));
    Object.assign(process.env, seeded);
    try {
      return fn();
    } finally {
      for (const [k, v] of Object.entries(saved)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  }

  it("ignores an inherited one-command `git -c core.hooksPath` (GIT_CONFIG_PARAMETERS)", () => {
    const { repo, initEnv } = initRepo();
    const injected = path.join(tmpRoot, "injected-by-parameters");
    const seeded = { GIT_CONFIG_PARAMETERS: `'core.hookspath=${injected}'` };
    // Precondition: git really honors the seeded scope, so a pass below is the scrub's doing.
    expect(gitHooksPath(repo, { ...initEnv, ...seeded })).toBe(injected);
    expect(withProcessEnv(seeded, () => resolveHooksDir(repo))).not.toBe(injected);
  });

  it("follows a deliberate numbered-pair core.hooksPath to the directory git runs", () => {
    const { repo, initEnv } = initRepo();
    const deliberate = path.join(tmpRoot, "deliberate-numbered-pair");
    const seeded = { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.hooksPath", GIT_CONFIG_VALUE_0: deliberate };
    expect(gitHooksPath(repo, { ...initEnv, ...seeded })).toBe(deliberate);
    expect(withProcessEnv(seeded, () => resolveHooksDir(repo))).toBe(deliberate);
  });

  it("follows a deliberate GIT_CONFIG_GLOBAL core.hooksPath to the directory git runs", () => {
    const { repo, initEnv } = initRepo();
    const deliberate = path.join(tmpRoot, "deliberate-global");
    const globalConfig = path.join(tmpRoot, "global.gitconfig");
    fs.writeFileSync(globalConfig, `[core]\n\thooksPath = ${deliberate}\n`, "utf8");
    const seeded = { GIT_CONFIG_GLOBAL: globalConfig };
    expect(gitHooksPath(repo, { ...initEnv, ...seeded })).toBe(deliberate);
    expect(withProcessEnv(seeded, () => resolveHooksDir(repo))).toBe(deliberate);
  });

  it("throws when the root has no .git entry", () => {
    expect(() => resolveHooksDir(tmpRoot)).toThrow(/Not a git repository/);
  });
});

// REGRESSION (2026-09-26): pre-push (the full test-baseline guard) must be
// installed BEFORE pre-commit (the fast tier). If the second copy in the
// loop fails, installing pre-commit first would leave a repo with the fast
// tier in place and no full-suite gate at all - a partial install that
// looks complete for every commit made afterward. These tests exercise the
// real `installHooksInto`/`backupExistingForeignHook`/`MARKER_LINE` exports,
// not a re-implementation, and use temp directories throughout (never the
// developer's own hooks directory) per this suite's isolation discipline.
describe("install-hooks installHooksInto ordering + foreign-hook backup", () => {
  let tmpRoot: string;
  let fakeRoot: string;
  let hooksDir: string;

  beforeEach(() => {
    tmpRoot = fs.mkdtempSync(
      path.join(os.tmpdir(), "sanctuary-install-hooks-order-"),
    );
    fakeRoot = path.join(tmpRoot, "fake-repo-root");
    hooksDir = path.join(tmpRoot, "hooks-dir");
    fs.mkdirSync(path.join(fakeRoot, ".githooks"), { recursive: true });
    fs.mkdirSync(hooksDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  });

  it("installs pre-push before pre-commit, so a failing second copy still leaves the full-suite gate in place", () => {
    // Only the pre-push source exists - pre-commit's source is deliberately
    // absent, simulating the second copy in HOOK_NAMES failing (a missing
    // file behaves the same as any other mid-loop failure for this
    // purpose: the loop throws after the first hook is already on disk).
    fs.writeFileSync(
      path.join(fakeRoot, ".githooks", "pre-push"),
      `#!/usr/bin/env bash\n${MARKER_LINE}\necho pre-push\n`,
      "utf8",
    );

    expect(() => installHooksInto(fakeRoot, hooksDir)).toThrow(
      /pre-commit not found/,
    );

    // pre-push (the expensive, harder-to-bypass gate) must have made it to
    // disk before the failure on pre-commit.
    expect(fs.existsSync(path.join(hooksDir, "pre-push"))).toBe(true);
    // pre-commit's source never existed, so nothing should have been
    // written for it.
    expect(fs.existsSync(path.join(hooksDir, "pre-commit"))).toBe(false);
  });

  it("backs up an existing foreign hook (no MARKER_LINE) before overwriting it, for both hook names", () => {
    const foreignPrePush = "#!/bin/sh\necho some other tool's pre-push\n";
    const foreignPreCommit = "#!/bin/sh\necho some other tool's pre-commit\n";
    fs.writeFileSync(path.join(hooksDir, "pre-push"), foreignPrePush, "utf8");
    fs.writeFileSync(
      path.join(hooksDir, "pre-commit"),
      foreignPreCommit,
      "utf8",
    );

    const sanctuaryPrePush = `#!/usr/bin/env bash\n${MARKER_LINE}\necho sanctuary pre-push\n`;
    const sanctuaryPreCommit = `#!/usr/bin/env bash\n${MARKER_LINE}\necho sanctuary pre-commit\n`;
    fs.writeFileSync(
      path.join(fakeRoot, ".githooks", "pre-push"),
      sanctuaryPrePush,
      "utf8",
    );
    fs.writeFileSync(
      path.join(fakeRoot, ".githooks", "pre-commit"),
      sanctuaryPreCommit,
      "utf8",
    );

    installHooksInto(fakeRoot, hooksDir);

    const prePushBackup = path.join(hooksDir, "pre-push.pre-sanctuary.bak");
    const preCommitBackup = path.join(
      hooksDir,
      "pre-commit.pre-sanctuary.bak",
    );
    expect(fs.readFileSync(prePushBackup, "utf8")).toBe(foreignPrePush);
    expect(fs.readFileSync(preCommitBackup, "utf8")).toBe(foreignPreCommit);
    expect(fs.readFileSync(path.join(hooksDir, "pre-push"), "utf8")).toBe(
      sanctuaryPrePush,
    );
    expect(fs.readFileSync(path.join(hooksDir, "pre-commit"), "utf8")).toBe(
      sanctuaryPreCommit,
    );
  });

  it("does not back up an existing hook that already carries MARKER_LINE (a prior Sanctuary install)", () => {
    const priorSanctuaryPrePush = `#!/usr/bin/env bash\n${MARKER_LINE}\necho old sanctuary pre-push\n`;
    fs.writeFileSync(
      path.join(hooksDir, "pre-push"),
      priorSanctuaryPrePush,
      "utf8",
    );

    expect(backupExistingForeignHook(path.join(hooksDir, "pre-push"))).toBe(
      null,
    );
    expect(
      fs.existsSync(path.join(hooksDir, "pre-push.pre-sanctuary.bak")),
    ).toBe(false);
  });

  it("returns null from backupExistingForeignHook when there is nothing at dst yet", () => {
    expect(
      backupExistingForeignHook(path.join(hooksDir, "nonexistent-hook")),
    ).toBe(null);
  });

  // REGRESSION (2026-09-26): MARKER_LINE used to be the generic
  // "# Copyright 2026 Erik Newton" line, which any unrelated file (or a
  // foreign hook whose author happened to copyright-stamp it the same way)
  // could carry, silently defeating the foreign-hook backup below. A
  // distinctive token cannot collide with an ordinary copyright header.
  it("MARKER_LINE is a distinctive token, not a generic copyright line", () => {
    expect(MARKER_LINE).not.toBe("# Copyright 2026 Erik Newton");
    expect(MARKER_LINE.toLowerCase()).toContain("sanctuary-managed-hook");
    // A plausible foreign hook that just happens to carry Erik's copyright
    // boilerplate (e.g. copied from another file in this repo) must NOT be
    // mistaken for a prior Sanctuary install.
    const lookalike = "#!/bin/sh\n# Copyright 2026 Erik Newton\necho hi\n";
    expect(lookalike.includes(MARKER_LINE)).toBe(false);
  });

  // REGRESSION (2026-09-26): a fixed `<name>.pre-sanctuary.bak` path meant a
  // SECOND foreign hook backed up at some later run would silently
  // overwrite the FIRST foreign hook's backup - destroying exactly the kind
  // of file this function exists to preserve, one layer down. A UTC
  // timestamp suffix is used instead once a backup already exists.
  it("never clobbers an existing backup - suffixes a UTC timestamp instead", () => {
    const dst = path.join(hooksDir, "pre-push");
    const firstForeign = "#!/bin/sh\necho first foreign hook\n";
    fs.writeFileSync(dst, firstForeign, "utf8");

    const firstBackup = backupExistingForeignHook(dst);
    expect(firstBackup).toBe(`${dst}.pre-sanctuary.bak`);
    expect(fs.readFileSync(firstBackup!, "utf8")).toBe(firstForeign);

    // Simulate a second foreign hook later occupying the same path (e.g. the
    // Sanctuary hook was installed, then removed, then a different foreign
    // tool's hook was placed there) - the FIRST backup must survive.
    const secondForeign = "#!/bin/sh\necho second foreign hook\n";
    fs.writeFileSync(dst, secondForeign, "utf8");

    const secondBackup = backupExistingForeignHook(dst);
    expect(secondBackup).not.toBe(null);
    expect(secondBackup).not.toBe(firstBackup);
    expect(secondBackup!.startsWith(`${dst}.pre-sanctuary.`)).toBe(true);
    expect(secondBackup!.endsWith(".bak")).toBe(true);

    // Both backups must exist, unmodified, side by side.
    expect(fs.readFileSync(firstBackup!, "utf8")).toBe(firstForeign);
    expect(fs.readFileSync(secondBackup!, "utf8")).toBe(secondForeign);
  });
});
