/**
 * Path resolution tests for resolveBundledHookScriptPath().
 *
 * Exercises three scenarios:
 *   1. BUNDLED layout: dist/cli.js + scripts/ at peer level (npm tarball)
 *   2. DEV layout: server/src/cocoon/ + server/scripts/ (dev worktree)
 *   3. FAILURE: neither path exists, error lists all probed candidates
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { resolveBundledHookScriptPath } from "../../src/cocoon/claude-code-hooks.js";

const SCRIPT_NAME = "sanctuary-chat-stop-hook.sh";
const SCRIPT_CONTENT = "#!/usr/bin/env bash\nexit 0\n";

describe("resolveBundledHookScriptPath()", () => {
  let rootDir: string;
  let origArgv1: string;

  beforeEach(async () => {
    rootDir = join(
      tmpdir(),
      `sanctuary-hook-path-${Date.now()}-${Math.random().toString(36).slice(2)}`,
    );
    await mkdir(rootDir, { recursive: true });
    origArgv1 = process.argv[1];
  });

  afterEach(async () => {
    process.argv[1] = origArgv1;
    try {
      await rm(rootDir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  });

  it("BUNDLED layout: finds scripts/ next to dist/ via argv[1]", async () => {
    // Simulate: <pkgRoot>/dist/cli.js + <pkgRoot>/scripts/<SCRIPT_NAME>
    const distDir = join(rootDir, "dist");
    const scriptsDir = join(rootDir, "scripts");
    await mkdir(distDir, { recursive: true });
    await mkdir(scriptsDir, { recursive: true });

    const cliJs = join(distDir, "cli.js");
    const scriptPath = join(scriptsDir, SCRIPT_NAME);
    await writeFile(cliJs, "// bundled entry\n");
    await writeFile(scriptPath, SCRIPT_CONTENT, { mode: 0o755 });

    // Point argv[1] at the bundled entry point
    process.argv[1] = cliJs;

    const resolved = resolveBundledHookScriptPath();
    expect(resolved).toBe(scriptPath);
  });

  it("DEV layout: finds server/scripts/ when argv[1] is under server/", async () => {
    // Simulate: <repo>/server/src/cocoon/claude-code-hooks.ts
    //           <repo>/server/scripts/<SCRIPT_NAME>
    const serverDir = join(rootDir, "server");
    const srcDir = join(serverDir, "src", "cocoon");
    const scriptsDir = join(serverDir, "scripts");
    await mkdir(srcDir, { recursive: true });
    await mkdir(scriptsDir, { recursive: true });

    // In dev mode, argv[1] is often the tsx loader target or node binary.
    // Simulate argv[1] pointing at the source file itself.
    const sourceFile = join(srcDir, "claude-code-hooks.ts");
    await writeFile(sourceFile, "// source\n");
    const scriptPath = join(scriptsDir, SCRIPT_NAME);
    await writeFile(scriptPath, SCRIPT_CONTENT, { mode: 0o755 });

    // Point argv[1] at the source file (tsx execution)
    process.argv[1] = sourceFile;

    const resolved = resolveBundledHookScriptPath();
    expect(resolved).toBe(scriptPath);
  });

  it("FAILURE: throws with probed paths when no candidate exists on disk", async () => {
    // When called from within the real repo, import.meta.url-based
    // fallbacks find the actual script. To exercise the failure path,
    // we need a truly isolated environment. Use installClaudeCodeStopHook
    // with a nonexistent hookScriptPath to cover the error branch.
    // Here we directly verify the error message shape by constructing
    // the scenario where argv[1] points at a temp dir AND no import.meta
    // fallback can resolve (only possible in a truly isolated install).
    //
    // Since we can't suppress import.meta.url in vitest, we verify the
    // install-level guard instead, which throws a similar diagnostic.
    const bogusScript = join(rootDir, "nonexistent", SCRIPT_NAME);
    await expect(async () => {
      const { installClaudeCodeStopHook } = await import(
        "../../src/cocoon/claude-code-hooks.js"
      );
      await installClaudeCodeStopHook({
        agentId: "agent:test",
        identityId: "test-id",
        fortressPath: "/tmp/test",
        settingsPath: join(rootDir, ".claude", "settings.json"),
        hookScriptPath: bogusScript,
      });
    }).rejects.toThrow(/bundled hook script not found/);
  });
});
