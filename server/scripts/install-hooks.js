#!/usr/bin/env node
// Installs .githooks/pre-commit into the correct hooks directory, whether
// this checkout is the main repo (root/.git is a directory) or a worktree
// (root/.git is a file containing "gitdir: <path-to-main-repo-worktree-dir>").

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Resolve the hooks directory git will ACTUALLY execute from.
//
// This is subtler than it looks and the original implementation got it wrong in
// the one case that matters most to us. In a worktree, `.git` is a file pointing
// at `<main>/.git/worktrees/<name>`, and the old code installed the hook into
// `<main>/.git/worktrees/<name>/hooks`. But git does NOT run per-worktree hooks:
// it resolves hooks against the COMMON git dir (`<main>/.git/hooks`), and honors
// `core.hooksPath` above both. The result was silent and bad: `npm run
// install-hooks` in a worktree reported success, wrote a file nothing would ever
// execute, and left the worktree running whatever the main checkout happened to
// have (or no hook at all on a fresh clone). Since worktree-per-build is our
// standard dispatch pattern, the local gate was effectively absent there while
// appearing installed. Found 2026-07-18.
//
// So: ask git. `git rev-parse --git-path hooks` is authoritative — it accounts
// for core.hooksPath, the commondir indirection, and any future git semantics we
// would otherwise have to re-derive by hand. The pure-path fallback below runs
// only when git cannot be invoked (and is itself commondir-aware now).
export function resolveHooksDir(root) {
  const dotGit = path.join(root, ".git");
  if (!fs.existsSync(dotGit)) {
    throw new Error(`Not a git repository: ${root}`);
  }

  try {
    // Scrub the repo-scoping GIT_* variables before asking git anything. When
    // this runs inside a git hook (or any git-invoked subprocess) those are set
    // and point at the INVOKING repository, so an inherited GIT_DIR would make
    // `rev-parse` answer for the wrong repo entirely while looking perfectly
    // healthy. We want the answer for `root` and nothing else, so the resolution
    // must be driven by cwd alone. Other GIT_* vars (GIT_EXEC_PATH, GIT_SSH) are
    // left intact: they configure how git runs, not which repository it targets.
    const env = { ...process.env };
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
    const out = execFileSync("git", ["rev-parse", "--git-path", "hooks"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      env,
    }).trim();
    if (out) {
      return path.isAbsolute(out) ? out : path.resolve(root, out);
    }
  } catch {
    // git unavailable or not a repo from git's point of view; fall through.
  }

  const stat = fs.statSync(dotGit);
  if (stat.isDirectory()) {
    return path.join(dotGit, "hooks");
  }
  if (stat.isFile()) {
    const contents = fs.readFileSync(dotGit, "utf8");
    const match = contents.match(/^gitdir:\s*(.+?)\s*$/m);
    if (!match) {
      throw new Error(
        `Worktree .git file did not contain a gitdir: pointer: ${dotGit}`
      );
    }
    const worktreeGitDir = path.isAbsolute(match[1])
      ? match[1]
      : path.resolve(root, match[1]);
    // `commondir` is git's own pointer from a worktree's git dir back to the
    // shared one. Following it is what makes this fallback land on the hooks
    // directory git would use, rather than the inert per-worktree one.
    const commonDirFile = path.join(worktreeGitDir, "commondir");
    if (fs.existsSync(commonDirFile)) {
      const rel = fs.readFileSync(commonDirFile, "utf8").trim();
      if (rel) {
        const commonDir = path.isAbsolute(rel)
          ? rel
          : path.resolve(worktreeGitDir, rel);
        return path.join(commonDir, "hooks");
      }
    }
    return path.join(worktreeGitDir, "hooks");
  }
  throw new Error(`Unexpected .git entry type at ${dotGit}`);
}

// Both hook names installed by this script, in INSTALL ORDER.
//
// ORDER IS LOAD-BEARING (2026-09-26, fixed - previously "pre-commit" was
// installed first): `pre-commit` is the fast tier (typecheck + changed-path
// tests, every commit); `pre-push` is the full test-baseline guard (the
// full suite + the floor comparison, every push) - see .githooks/pre-commit's
// header for why the guard was split this way. If the SECOND copy in the
// loop below throws (a permissions error, a full disk, a hooks directory
// that vanished mid-run), installing pre-commit first left a repo with the
// fast tier in place and NO full-suite gate at all - a partial install that
// looked complete for every commit made afterward, silently missing the one
// check with the audited SKIP_TEST_BASELINE override and the baseline
// floor. Installing pre-push first means a failure on the second copy
// (pre-commit) leaves the expensive, harder-to-bypass gate already in
// place; the fast tier is convenience on top of it, not a substitute for it.
//
// Keep this list in sync with the two files that actually exist under
// .githooks/ - a name added here with no matching source file fails loudly
// below rather than silently installing nothing for it.
const HOOK_NAMES = ["pre-push", "pre-commit"];

// A line present verbatim in both shipped hooks' headers (see the top of
// .githooks/pre-commit and .githooks/pre-push). Used to tell "a Sanctuary
// hook we can safely overwrite/redeploy" apart from "someone else's hook
// that happens to occupy this path" - a foreign pre-commit/pre-push hook
// (from another tool, or hand-written by a developer) must never be
// silently destroyed by this installer.
// MUST stay a string that only the two Sanctuary-shipped hooks carry
// verbatim in their header (see the top of .githooks/pre-commit and
// .githooks/pre-push). The previous marker was the generic
// "# Copyright 2026 Erik Newton" line, which any file in this repository
// (or any hook a developer wrote and happened to copyright-stamp the same
// way) could carry - so a foreign hook whose author reused that boilerplate
// line would read as "ours" and be silently overwritten in place with no
// backup, defeating the whole point of this check. A distinctive,
// hook-specific token cannot collide with an unrelated file's copyright
// header.
export const MARKER_LINE = "# sanctuary-managed-hook: install-hooks.js owns this file";

// If `dst` already exists and does NOT carry MARKER_LINE, it is a foreign
// hook (not one this installer put there) - back it up before it gets
// overwritten below, rather than destroying whatever was in it. Returns the
// backup path, or null when there was nothing foreign to back up (no file
// at dst, or the file at dst already carries the marker and is safe to
// replace in place).
//
// NEVER CLOBBERS AN EXISTING BACKUP (2026-09-26): the previous version
// always wrote to the same fixed `<name>.pre-sanctuary.bak` path, so a
// SECOND foreign hook backed up at some later run would silently overwrite
// the FIRST foreign hook's backup - the exact "destroy what was already
// there" failure this function exists to prevent, one layer down. When a
// backup already exists at that path, this suffixes a UTC timestamp instead
// of overwriting it.
export function backupExistingForeignHook(dst) {
  if (!fs.existsSync(dst)) {
    return null;
  }
  let existing;
  try {
    existing = fs.readFileSync(dst, "utf8");
  } catch {
    // Unreadable (e.g. a directory at that path, or a permissions error) -
    // treat as foreign rather than silently overwriting; the backup attempt
    // below will surface the real error if the path truly can't be read.
    existing = "";
  }
  if (existing.includes(MARKER_LINE)) {
    return null;
  }
  let backupPath = `${dst}.pre-sanctuary.bak`;
  if (fs.existsSync(backupPath)) {
    // Colons are not valid in Windows path segments and are needlessly
    // shell-unfriendly on POSIX; strip them from the ISO timestamp so the
    // suffix is safe to embed in a filename on every platform this repo
    // targets.
    const timestamp = new Date().toISOString().replace(/[:]/g, "");
    backupPath = `${dst}.pre-sanctuary.${timestamp}.bak`;
  }
  fs.copyFileSync(dst, backupPath);
  return backupPath;
}

// The install loop itself, separated from main()'s argv/exit handling so it
// can be exercised directly (a temp root + a temp hooksDir, no real .git
// involved) - in particular so a test can simulate the second copy in
// HOOK_NAMES failing (e.g. a missing source file) and assert what state
// the FIRST hook is left in, proving the install order in HOOK_NAMES above
// is what protects the full-suite gate. Throws on the first failure
// (missing source file, or whatever fs.copyFileSync/fs.chmodSync throws);
// does not itself catch or exit - main() owns that.
export function installHooksInto(root, hooksDir) {
  fs.mkdirSync(hooksDir, { recursive: true });
  const installed = [];
  for (const hookName of HOOK_NAMES) {
    const src = path.join(root, ".githooks", hookName);
    if (!fs.existsSync(src)) {
      throw new Error(`.githooks/${hookName} not found at ${src}`);
    }
    const dst = path.join(hooksDir, hookName);
    const backupPath = backupExistingForeignHook(dst);
    if (backupPath) {
      console.log(`Backed up existing non-Sanctuary ${hookName} hook: ${backupPath}`);
    }
    fs.copyFileSync(src, dst);
    fs.chmodSync(dst, 0o755);
    console.log(`Installed ${hookName} hook: ${dst}`);
    installed.push(dst);
  }
  return installed;
}

function main() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const root = path.resolve(__dirname, "..", "..");

  let hooksDir;
  try {
    hooksDir = resolveHooksDir(root);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }

  try {
    installHooksInto(root, hooksDir);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  main();
}
