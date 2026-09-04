// fail-before-exempt: exercises the castle-wall-macos stage script and the built dist artifact as a sealed layout; no server/src edge is under test here.

/**
 * Runtime smoke for the sealed Castle Wall CLI layout, without signing.
 *
 * Stages `server/dist` exactly as build-wrapped.sh does (same script, same
 * excludes) into a temp directory, then creates a fortress from that layout.
 * Fortress creation is the path that forks `dist/directory-capability-worker.js`
 * beside `dist/cli.js`, so this is the check that would have failed on a runtime
 * shipping `cli.js` alone (that runtime boots an existing fortress fine and
 * times out on worker readiness during creation).
 *
 * Dependencies: the staged layout is `--dist-only`; `node_modules` is supplied
 * by a symlink to the server's own install so the test does not copy a
 * ~30k-file closure per run. Node resolves through the link; the production
 * stage script forbids links INSIDE the runtime and that property is asserted
 * separately here on the staged tree.
 *
 * Isolation: the fortress lives under the temp dir; `--no-pin` keeps the run
 * off any keychain, and the test-run marker is mirrored into the staged root so
 * the keychain chokepoint sees this layout as under test too.
 */
import { afterEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { TEST_RUN_MARKER_FILENAME } from "../../src/wrap/keychain-exec.js";
import {
  SEALED_CLI_RUNTIME_DIST_ENTRIES,
  missingSealedCliRuntimeEntries,
} from "../../scripts/sealed-cli-runtime-entries.mjs";

const repoRoot = join(fileURLToPath(import.meta.url), "..", "..", "..", "..");
const serverRoot = join(repoRoot, "server");
const stageScript = join(repoRoot, "castle-wall-macos", "scripts", "stage-cli-runtime.sh");
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function stageLayout(): string {
  const root = mkdtempSync(join(tmpdir(), "sanctuary-sealed-cli-runtime-"));
  roots.push(root);
  const runtime = join(root, "cli-runtime");
  const staged = spawnSync("/bin/bash", [stageScript, runtime, "--dist-only"], {
    encoding: "utf8",
    env: {
      ...process.env,
      SANCTUARY_CLI_RUNTIME_DIR: join(serverRoot, "dist"),
      SANCTUARY_CLI_PACKAGE_JSON: join(serverRoot, "package.json"),
    },
  });
  expect(staged.status, `${staged.stdout}\n${staged.stderr}`).toBe(0);
  expect(staged.stdout).toContain("sealed CLI runtime complete");
  return runtime;
}

describe("sealed Castle Wall CLI runtime layout", () => {
  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "carries every entry dist/cli.js reaches at run time and none of the build-only artifacts",
    () => {
      expect(existsSync(join(serverRoot, "dist", "cli.js")), "server/dist is not built").toBe(true);
      const runtime = stageLayout();
      const dist = join(runtime, "dist");

      expect(missingSealedCliRuntimeEntries(dist)).toEqual([]);
      expect(statSync(join(dist, "directory-capability-worker.js")).isFile()).toBe(true);
      expect(readdirSync(join(dist, "templates")).length).toBeGreaterThan(0);
      expect(existsSync(join(dist, "reference-plugin", "blocklist", "governance.yaml"))).toBe(true);
      expect(existsSync(join(dist, "intelligence", "catalog-v3", "schemas", "schema-digests.json"))).toBe(true);
      expect(existsSync(join(runtime, "package.json"))).toBe(true);

      // Build-only artifacts stay out; the boot daemon is sealed elsewhere.
      const walk = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
        entry.isDirectory() ? walk(join(dir, entry.name)) : [join(dir, entry.name)],
      );
      const files = walk(dist);
      expect(files.filter((path) => /\.(map|cjs|d\.ts|d\.cts|d\.mts)$/.test(path))).toEqual([]);
      expect(existsSync(join(dist, "boot-runtime"))).toBe(false);
      expect(files.length).toBeGreaterThanOrEqual(SEALED_CLI_RUNTIME_DIST_ENTRIES.length);
      // No symlinks inside the staged runtime (the signed bundle rule). lstat,
      // not stat: stat follows the link and would report the target's type.
      for (const path of walk(runtime)) expect(lstatSync(path).isSymbolicLink(), path).toBe(false);
    },
  );

  it.runIf(process.platform === "darwin" || process.platform === "linux")(
    "creates a fortress from the staged layout (the worker fork resolves beside cli.js)",
    () => {
      expect(existsSync(join(serverRoot, "dist", "cli.js")), "server/dist is not built").toBe(true);
      const runtime = stageLayout();
      // Dependencies via the server's own install; the layout's dist/ and
      // package.json are the staged bytes.
      symlinkSync(join(serverRoot, "node_modules"), join(runtime, "node_modules"), "dir");
      // The keychain chokepoint finds its package root by walking up from
      // dist/cli.js to the nearest package.json, which in this layout is the
      // staged root, so the test-run marker must exist THERE. Always write it:
      // a child that reads "no marker" would classify itself as production.
      const marker = join(serverRoot, TEST_RUN_MARKER_FILENAME);
      if (existsSync(marker)) copyFileSync(marker, join(runtime, TEST_RUN_MARKER_FILENAME));
      else writeFileSync(join(runtime, TEST_RUN_MARKER_FILENAME), "sealed-cli-runtime-layout-smoke\n");
      expect(existsSync(join(runtime, TEST_RUN_MARKER_FILENAME))).toBe(true);

      const root = join(runtime, "..");
      const fortress = join(root, "fortress");
      const recoveryOut = join(root, "recovery-key.txt");
      // Isolation belt: --no-pin keeps the run off any keychain; a private HOME
      // means even an accidental keychain or ~/.sanctuary lookup cannot reach
      // the operator's.
      const home = join(root, "home");
      mkdirSync(home, { recursive: true });
      const env: NodeJS.ProcessEnv = { ...process.env, HOME: home };
      delete env.SANCTUARY_PASSPHRASE;
      delete env.SANCTUARY_RECOVERY_KEY;
      delete env.NODE_OPTIONS;
      delete env.NODE_PATH;
      const result = spawnSync(process.execPath, [
        join(runtime, "dist", "cli.js"),
        "init",
        "--fortress",
        fortress,
        "--no-confirm",
        "--no-pin",
        "--no-identity",
        "--no-provision-local-intelligence",
        "--recovery-out",
        recoveryOut,
      ], { encoding: "utf8", env, timeout: 120_000 });

      expect(result.status, result.stderr || result.stdout).toBe(0);
      expect(result.stderr).not.toContain("directory-capability worker readiness timed out");
      expect(existsSync(join(fortress, "state", "_meta", "custody-envelope.enc"))).toBe(true);
      expect(existsSync(recoveryOut)).toBe(true);
    },
  );
});
