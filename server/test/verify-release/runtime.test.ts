/**
 * state_RUNTIME: the engine range constant equals the pinned Sigstore
 * packages' own range, the range check on both sides of every bound, and, in
 * a subprocess running the built CLI, an unsupported runtime refusing before
 * any Sigstore or tar module loads.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { SIGSTORE_ENGINE_RANGE, parseEngineRange, satisfiesEngineRange } from "../../src/verify-release/runtime.js";
import { denyAllNetwork } from "./helpers.js";

denyAllNetwork();

const SERVER = join(__dirname, "..", "..");

describe("engine range", () => {
  it.each(["@sigstore/verify", "@sigstore/bundle", "@sigstore/core"])("matches the installed %s engines.node", name => {
    const manifest = JSON.parse(readFileSync(join(SERVER, "node_modules", ...name.split("/"), "package.json"), "utf8"));
    expect(manifest.engines.node).toBe(SIGSTORE_ENGINE_RANGE);
  });

  it.each([
    ["21.99.99", false],
    ["22.0.0", false],
    ["22.22.1", false],
    ["22.22.2", true],
    ["22.23.3", true],
    ["22.99.99", true],
    ["23.0.0", false],
    ["23.11.1", false],
    ["24.0.0", false],
    ["24.14.99", false],
    ["24.15.0", true],
    ["24.99.0", true],
    ["25.0.0", false],
    ["25.9.0", false],
    ["26.0.0", true],
    ["27.3.1", true],
  ])("node %s satisfies: %s", (version, expected) => {
    expect(satisfiesEngineRange(version)).toBe(expected);
  });

  it.each(["v22.23.3", "22.23", "22.23.3-nightly", "22.023.3", "", "x.y.z"])("a version string that is not exactly X.Y.Z (%s) does not satisfy", version => {
    expect(satisfiesEngineRange(version)).toBe(false);
  });

  it("refuses to parse a range shape it does not know", () => {
    expect(() => parseEngineRange("~22.0.0")).toThrow();
    expect(() => parseEngineRange("^22.0")).toThrow();
    expect(() => parseEngineRange("22.0.0 - 24.0.0")).toThrow();
    expect(parseEngineRange(SIGSTORE_ENGINE_RANGE)).toHaveLength(3);
  });
});

describe("unsupported runtime, built CLI, subprocess", () => {
  it("control: the recorder does see a Sigstore and a tar module when one loads", () => {
    const dir = mkdtempSync(join(tmpdir(), "vr-runtime-"));
    try {
      const out = join(dir, "record.json");
      const child = spawnSync(process.execPath, ["--import", join(__dirname, "module-load-recorder.mjs"), "--input-type=module", "-e", "await import('@sigstore/verify'); await import('tar');"], {
        cwd: SERVER, env: { ...process.env, HOME: dir, VR_RECORDER_OUT: out }, encoding: "utf8", timeout: 120_000,
      });
      expect(child.status).toBe(0);
      const record = JSON.parse(readFileSync(out, "utf8")) as { modules: string[] };
      expect(record.modules.some(url => url.includes("/node_modules/@sigstore/verify/"))).toBe(true);
      expect(record.modules.some(url => url.includes("/node_modules/@sigstore/core/"))).toBe(true);
      expect(record.modules.some(url => url.includes("/node_modules/tar/"))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);

  it("refuses runtime-unsupported with exit 3, loads no Sigstore or tar module, and makes no connection", () => {
    const dir = mkdtempSync(join(tmpdir(), "vr-runtime-"));
    try {
      const out = join(dir, "record.json");
      const child = spawnSync(process.execPath, ["--import", join(__dirname, "module-load-recorder.mjs"), join(SERVER, "dist", "cli.js"), "verify-release", "--target", dir, "--json"], {
        env: { ...process.env, HOME: dir, VR_RECORDER_OUT: out, VR_PRESENT_NODE_VERSION: "22.0.0" },
        encoding: "utf8",
        timeout: 120_000,
      });
      expect(child.status).toBe(3);
      const report = JSON.parse(child.stdout);
      expect(report).toMatchObject({ verdict: "refused", reason: "runtime-unsupported", version: null, target: null });
      expect(report.steps[0]).toEqual({ step: "runtime", result: "refused" });
      expect(report.steps.slice(1).every((s: { result: string }) => s.result === "not-run")).toBe(true);
      const record = JSON.parse(readFileSync(out, "utf8")) as { modules: string[]; network: string[] };
      expect(record.modules.length).toBeGreaterThan(0);
      expect(record.modules.filter(url => /\/node_modules\/(@sigstore\/|tar\/)/.test(url))).toEqual([]);
      expect(record.network).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
