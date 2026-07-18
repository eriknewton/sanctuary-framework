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

function main() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const root = path.resolve(__dirname, "..", "..");
  const src = path.join(root, ".githooks", "pre-commit");
  if (!fs.existsSync(src)) {
    console.error(`Error: .githooks/pre-commit not found at ${src}`);
    process.exit(1);
  }
  let hooksDir;
  try {
    hooksDir = resolveHooksDir(root);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
  fs.mkdirSync(hooksDir, { recursive: true });
  const dst = path.join(hooksDir, "pre-commit");
  fs.copyFileSync(src, dst);
  fs.chmodSync(dst, 0o755);
  console.log(`Installed pre-commit hook: ${dst}`);
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
) {
  main();
}
