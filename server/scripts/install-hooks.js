#!/usr/bin/env node
// Installs .githooks/pre-commit into the correct hooks directory, whether
// this checkout is the main repo (root/.git is a directory) or a worktree
// (root/.git is a file containing "gitdir: <path-to-main-repo-worktree-dir>").

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function resolveHooksDir(root) {
  const dotGit = path.join(root, ".git");
  if (!fs.existsSync(dotGit)) {
    throw new Error(`Not a git repository: ${root}`);
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
