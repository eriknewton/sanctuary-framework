import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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

  it("resolves via gitdir: pointer when .git is a file (worktree checkout)", () => {
    const worktreeGitDir = path.join(
      tmpRoot,
      "fake-main-repo",
      ".git",
      "worktrees",
      "foo"
    );
    fs.mkdirSync(worktreeGitDir, { recursive: true });
    fs.writeFileSync(
      path.join(tmpRoot, ".git"),
      `gitdir: ${worktreeGitDir}\n`,
      "utf8"
    );
    const result = resolveHooksDir(tmpRoot);
    expect(result).toBe(path.join(worktreeGitDir, "hooks"));
  });

  it("throws when the root has no .git entry", () => {
    expect(() => resolveHooksDir(tmpRoot)).toThrow(/Not a git repository/);
  });
});
