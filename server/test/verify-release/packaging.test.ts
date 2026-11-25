/**
 * Packaging witnesses over the BUILT CLI and the PACKED server:
 *   - in subprocesses, help, a usage error and an unrelated command load no
 *     Sigstore or tar module and open no connection;
 *   - `npm pack` of the server carries the committed trusted root at the path
 *     the verifier loads, and none of npm's install-time transforms can apply
 *     (no `.gitignore` entry, no CRLF shebang in any bin target), so installed
 *     bytes equal packed bytes.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { RUN_DEADLINE_MS } from "../../src/verify-release/constants.js";
import { Deadline } from "../../src/verify-release/deadline.js";
import { state_ARCHIVE } from "../../src/verify-release/archive.js";
import { TRUSTED_ROOT_RELATIVE_PATH } from "../../src/verify-release/trust-root.js";
import { ManualClock, denyAllNetwork, sha256Hex, trustedRootBytes } from "./helpers.js";

denyAllNetwork();

const SERVER = join(__dirname, "..", "..");
const CLI = join(SERVER, "dist", "cli.js");

/** npm's own configuration variables, unset: a child drops an env key whose value is undefined. */
function unsetNpmConfig(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.keys(process.env).filter(key => /^npm_/i.test(key)).map(key => [key, undefined]));
}

describe("lazy loading, built CLI, subprocess", () => {
  it.each([
    [["--help"], 0],
    [["verify-release", "--help"], 0],
    [["verify-release", "--bogus"], 2],
    [["check-updates", "--help"], 0],
  ])("sanctuary %j loads no Sigstore or tar module and opens no connection", (argv, status) => {
    const home = mkdtempSync(join(tmpdir(), "vr-lazy-"));
    try {
      const out = join(home, "record.json");
      const child = spawnSync(process.execPath, ["--import", join(__dirname, "module-load-recorder.mjs"), CLI, ...argv], {
        env: { ...process.env, ...unsetNpmConfig(), HOME: home, VR_RECORDER_OUT: out }, encoding: "utf8", timeout: 120_000,
      });
      expect(child.status).toBe(status);
      const record = JSON.parse(readFileSync(out, "utf8")) as { modules: string[]; network: string[] };
      expect(record.modules.length).toBeGreaterThan(0);
      expect(record.modules.filter(url => /\/node_modules\/(@sigstore\/|tar\/)/.test(url))).toEqual([]);
      expect(record.network).toEqual([]);
      if (argv[0] === "verify-release" && argv[1] === "--help") expect(child.stdout).toContain("What it does not detect:");
    } finally {
      rmSync(home, { recursive: true, force: true });
    }
  }, 180_000);
});

describe("packed artifact", () => {
  it("npm pack carries the trusted root at the loaded path, no .gitignore, and LF-only bin shebangs", async () => {
    const work = mkdtempSync(join(tmpdir(), "vr-pack-"));
    try {
      const child = spawnSync("npm", ["pack", "--ignore-scripts", "--pack-destination", work, "--json"], {
        cwd: SERVER,
        env: { ...process.env, ...unsetNpmConfig(), HOME: work, npm_config_cache: join(work, "cache"), npm_config_update_notifier: "false", npm_config_audit: "false", npm_config_fund: "false" },
        encoding: "utf8",
        timeout: 900_000,
        maxBuffer: 256 * 1024 * 1024,
      });
      expect(child.status, child.stderr).toBe(0);
      const packed = readdirSync(work).filter(name => name.endsWith(".tgz"));
      expect(packed).toHaveLength(1);
      const deadline = new Deadline(new ManualClock(), RUN_DEADLINE_MS);
      // The verifier's own parser reads the packed tarball, under its production caps.
      const parsed = await state_ARCHIVE(readFileSync(join(work, packed[0]!)), deadline);
      deadline.dispose();
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) throw new Error(parsed.reason);
      const files = parsed.evidence.files;
      expect(files.get(`dist/${TRUSTED_ROOT_RELATIVE_PATH}`)?.sha256).toBe(sha256Hex(trustedRootBytes()));
      expect([...files.keys()].filter(key => key.split("/").pop() === ".gitignore")).toEqual([]);
      const manifest = JSON.parse(readFileSync(join(SERVER, "package.json"), "utf8")) as { bin: Record<string, string> };
      for (const target of new Set(Object.values(manifest.bin))) {
        const key = target.replace(/^\.\//, "");
        expect(files.has(key), key).toBe(true);
        const bytes = readFileSync(join(SERVER, key));
        // The packed bytes are the bytes read here, so the shebang checked is the shipped one.
        expect(files.get(key)!.sha256, key).toBe(sha256Hex(bytes));
        const firstLine = bytes.subarray(0, 256).toString("latin1").split("\n")[0]!;
        expect(firstLine.startsWith("#!"), key).toBe(true);
        expect(firstLine.includes("\r"), key).toBe(false);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }, 900_000);
});
