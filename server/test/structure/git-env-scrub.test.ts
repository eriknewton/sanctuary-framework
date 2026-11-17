/**
 * Capability: no test process inherits git variables that redirect repository
 * discovery (a git hook exports GIT_DIR pointing at the real repository).
 * Witness for the setupFiles entry test/setup/git-env-scrub.ts: a child vitest
 * run with GIT_DIR aimed at a throwaway repo runs a probe that writes
 * `core.bare=true` from its own fixture repo. With the setup file the
 * throwaway repo is untouched and the fixture repo is written (positive
 * control); with the setup file removed from a COPY of the setupFiles list the
 * throwaway repo is written instead (fail-before).
 */
import { describe, it, expect, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { GIT_REDIRECT_ENV_KEYS } from "../setup/git-env-scrub.js";

const serverDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const repoRoot = path.resolve(serverDir, "..");
const SETUP_ENTRY = "./test/setup/git-env-scrub.ts";
const cleanup: string[] = [];

/** The parent environment (VITEST included) minus git's redirect variables, with no user or system git config. */
function cleanEnv(base: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base, GIT_CONFIG_GLOBAL: "/dev/null", GIT_CONFIG_SYSTEM: "/dev/null" };
  for (const k of GIT_REDIRECT_ENV_KEYS) delete env[k];
  return env;
}
function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", env: cleanEnv(process.env) }).trim();
}
function bare(repo: string): string {
  const r = spawnSync("git", ["config", "--get", "core.bare"], { cwd: repo, encoding: "utf8", env: cleanEnv(process.env) });
  return r.stdout.trim();
}

/** Runs the probe as a child vitest with GIT_DIR aimed at `victim`. */
function runProbe(withScrub: boolean): { victim: string; fixture: string; status: number | null; out: string } {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "git-env-scrub-"));
  cleanup.push(tmp);
  const victim = path.join(tmp, "victim");
  const fixture = path.join(tmp, "fixture");
  for (const d of [victim, fixture]) {
    fs.mkdirSync(d);
    git(["init", "--quiet"], d);
  }
  // The child's setupFiles come from the REAL config, so removing the entry
  // is done on this copy only.
  const real = fs.readFileSync(path.join(serverDir, "vitest.config.ts"), "utf8");
  const m = /setupFiles:\s*\[([^\]]*)\]/u.exec(real);
  if (!m) throw new Error("vitest.config.ts setupFiles array not found");
  let entries = m[1].split(",").map((e) => e.trim().replace(/^"|"$/gu, "")).filter(Boolean);
  expect(entries[0]).toBe(SETUP_ENTRY); // invariant: the scrub runs first
  if (!withScrub) entries = entries.filter((e) => e !== SETUP_ENTRY);
  const cfg = path.join(tmp, "probe.config.mjs");
  fs.writeFileSync(cfg, `export default ${JSON.stringify({
    root: serverDir,
    test: { globals: true, environment: "node", include: ["test/fixtures/git-env-scrub/*.probe.ts"], setupFiles: entries },
  })};\n`);
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_DIR: path.join(victim, ".git"), PROBE_REPO: fixture, VITEST: "true" };
  const r = spawnSync("npx", ["vitest", "run", "--config", cfg], { cwd: serverDir, encoding: "utf8", env, timeout: 120_000 });
  return { victim, fixture, status: r.status, out: `${r.stdout}${r.stderr}` };
}

afterAll(() => {
  for (const d of cleanup) fs.rmSync(d, { recursive: true, force: true });
});

describe("test git-env scrub", () => {
  it("with the setup file, a hook-style GIT_DIR cannot redirect a test's git writes", () => {
    const r = runProbe(true);
    expect(r.status, r.out).toBe(0);
    expect(bare(r.fixture)).toBe("true"); // positive control: fixture repo was written
    expect(bare(r.victim)).toBe("false"); // throwaway "real" repo unchanged
  }, 150_000);

  it("fail-before: without the setup file the same probe writes the redirected repo", () => {
    const r = runProbe(false);
    expect(bare(r.victim)).toBe("true");
    expect(bare(r.fixture)).toBe("false");
  }, 150_000);

  it("the pre-commit hook unsets exactly the same variables", () => {
    const hook = fs.readFileSync(path.join(repoRoot, ".githooks/pre-commit"), "utf8");
    const m = /unset ((?:GIT_[A-Z_]+ ?)+)&& npx vitest related/u.exec(hook);
    expect(m).not.toBeNull();
    expect(m![1].trim().split(/\s+/u)).toEqual([...GIT_REDIRECT_ENV_KEYS]);
  });
});
