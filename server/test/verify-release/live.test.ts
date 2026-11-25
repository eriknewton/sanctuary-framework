// fail-before-exempt: this test is skipped unless SANCTUARY_VERIFY_RELEASE_LIVE=1, so on any tree without that variable, the base included, it reports skipped rather than failing; its fail-before evidence is the recorded live run.
/**
 * Live integration, gated: skipped unless SANCTUARY_VERIFY_RELEASE_LIVE=1, and
 * never run in CI. It installs 1.8.4 from npm into a temporary prefix and runs
 * the BUILT verifier from this tree, by absolute path, with `--target` against
 * it: the only complete production-trust success witness. Then it changes one
 * installed file, and points `--target` at a foreign package.
 *
 * Isolation: this test process keeps deny-all network interception; only the
 * npm and verifier subprocesses reach the network. Each gets a temporary HOME
 * and npm cache, npm's own configuration variables are removed, the temporary
 * prefix is never put on PATH, and everything is removed in `finally`.
 */
import { spawnSync } from "node:child_process";
import { appendFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { denyAllNetwork } from "./helpers.js";

denyAllNetwork();

const LIVE = process.env.SANCTUARY_VERIFY_RELEASE_LIVE === "1";
const CLI = join(__dirname, "..", "..", "dist", "cli.js");

describe.skipIf(!LIVE)("live: an npm install of 1.8.4 checked against its signed release record", () => {
  it("verifies the fresh install, refuses a changed file, and refuses a foreign package", () => {
    const work = mkdtempSync(join(tmpdir(), "vr-live-"));
    try {
      // npm's own configuration variables are unset: a child drops an env key whose value is undefined.
      const unsetNpm = Object.fromEntries(Object.keys(process.env).filter(key => /^npm_/i.test(key)).map(key => [key, undefined]));
      const prefix = join(work, "prefix");
      const npm = (spec: string) => spawnSync("npm", ["install", "--global", "--prefix", prefix, "--ignore-scripts", "--no-audit", "--no-fund", spec], {
        env: { ...process.env, ...unsetNpm, HOME: join(work, "home"), npm_config_cache: join(work, "cache"), npm_config_update_notifier: "false" },
        encoding: "utf8", timeout: 600_000,
      });
      const verify = (target: string) => {
        const child = spawnSync(process.execPath, [CLI, "verify-release", "--target", target, "--json"], {
          env: { ...process.env, ...unsetNpm, HOME: join(work, "home") }, encoding: "utf8", timeout: 600_000,
        });
        return { status: child.status, report: JSON.parse(child.stdout) as { verdict: string; reason?: string; version: string } };
      };

      const installed = npm("@sanctuary-framework/mcp-server@1.8.4");
      expect(installed.status, installed.stderr).toBe(0);
      const target = join(prefix, "lib", "node_modules", "@sanctuary-framework", "mcp-server");
      const fresh = verify(target);
      expect(fresh).toMatchObject({ status: 0, report: { verdict: "verified", version: "1.8.4" } });

      appendFileSync(join(target, "README.md"), "\n");
      expect(verify(target)).toMatchObject({ status: 3, report: { verdict: "refused", reason: "installed-file-differs:README.md" } });

      const foreign = npm("@sigstore/verify@4.1.4");
      expect(foreign.status, foreign.stderr).toBe(0);
      expect(verify(join(prefix, "lib", "node_modules", "@sigstore", "verify"))).toMatchObject({ status: 3, report: { verdict: "refused", reason: "target-package-mismatch" } });
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }, 1_200_000);
});
