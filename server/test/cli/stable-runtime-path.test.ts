/** Stable runtime selection over temp trees: the lexical opt alias is kept, never its Cellar realpath, and every unsafe path is refused. */
import * as fs from "node:fs";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { resolveStableRuntime, SANCTUARY_PACKAGE_NAME, STABLE_RUNTIME_REFUSAL_EXIT_CODE, type StableRuntimeOptions } from "../../src/cli/stable-runtime-path.js";
import { STABLE_RUNTIME_REFUSAL_EXIT_CODE as CONTRACT_REFUSAL_EXIT } from "../../src/castle-wall/liveness/constants.js";

const UID = process.getuid?.() ?? 0;
const NODE_VERSION = "22.11.0";
const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

/** A Homebrew-shaped temp prefix: a Cellar keg, its maintained opt alias, and the global package entry. */
function prefix(engines = ">=20") {
  const root = mkdtempSync(join(tmpdir(), "stable-rt-"));
  roots.push(root);
  const keg = join(root, "Cellar", "node", NODE_VERSION, "bin");
  mkdirSync(keg, { recursive: true, mode: 0o755 });
  writeFileSync(join(keg, "node"), "#!/bin/sh\n", { mode: 0o755 });
  mkdirSync(join(root, "opt"), { mode: 0o755 });
  symlinkSync(join("..", "Cellar", "node", NODE_VERSION), join(root, "opt", "node"));
  const pkg = join(root, "lib", "node_modules", "@sanctuary-framework", "mcp-server");
  mkdirSync(join(pkg, "dist"), { recursive: true, mode: 0o755 });
  writeFileSync(join(pkg, "dist", "cli.js"), "// fixture entry\n", { mode: 0o644 });
  writeFileSync(join(pkg, "package.json"), JSON.stringify({ name: SANCTUARY_PACKAGE_NAME, engines: { node: engines } }), { mode: 0o644 });
  const cellarNode = join(keg, "node");
  const optNode = join(root, "opt", "node", "bin", "node");
  const cli = join(pkg, "dist", "cli.js");
  const options: StableRuntimeOptions = {
    // The running interpreter reports its Cellar realpath, as a Homebrew node does.
    execPath: cellarNode, cliPath: cli, operatorUid: UID,
    nodeCandidates: [optNode], cliCandidates: [cli], tempRoots: [], runningNodeVersion: NODE_VERSION,
    versionProbe: () => `v${NODE_VERSION}`,
  };
  return { root, keg, cellarNode, optNode, cli, pkg, options };
}

describe("stable runtime selection", () => {
  it("the refusal exit is the contract's EX_CONFIG value", () => {
    expect(STABLE_RUNTIME_REFUSAL_EXIT_CODE).toBe(CONTRACT_REFUSAL_EXIT);
    expect(STABLE_RUNTIME_REFUSAL_EXIT_CODE).toBe(78);
  });

  it("a Cellar execPath with an opt alias selects and keeps the lexical alias, never the Cellar realpath", () => {
    const p = prefix();
    const result = resolveStableRuntime(p.options);
    expect(result).toEqual({ ok: true, node: p.optNode, cli: p.cli, nodeVersion: NODE_VERSION });
    if (result.ok) expect(result.node).not.toContain("Cellar");
  });

  it("with the opt alias removed no candidate resolves to the running Node and selection refuses", () => {
    const p = prefix();
    unlinkSync(join(p.root, "opt", "node"));
    expect(resolveStableRuntime(p.options)).toEqual({ ok: false, reason: "no stable Node candidate resolves to the running Node" });
  });

  it("never checks for an observer: it selects with no observer installed and touches only the runtime and package paths", () => {
    const p = prefix();
    const touched: string[] = [];
    const io = {
      realpathSync: (path: string) => { touched.push(path); return fs.realpathSync(path); },
      statSync: (path: string) => { touched.push(path); return fs.statSync(path); },
      readFileSync: (path: string, encoding: "utf8") => { touched.push(path); return fs.readFileSync(path, encoding); },
    };
    expect(resolveStableRuntime({ ...p.options, fs: io }).ok).toBe(true);
    expect(touched.length).toBeGreaterThan(0);
    expect(touched.filter(path => /observer|liveness|LaunchAgents/i.test(path))).toEqual([]);
  });

  it("refuses an explicit Cellar, version-manager, relative or temporary Node path", () => {
    const p = prefix();
    expect(resolveStableRuntime({ ...p.options, explicitNode: p.cellarNode })).toMatchObject({ ok: false, reason: expect.stringContaining("version-specific install (Cellar)") });
    expect(resolveStableRuntime({ ...p.options, explicitNode: "/Users/fixture/.nvm/versions/node/v22/bin/node" })).toMatchObject({ ok: false, reason: expect.stringContaining(".nvm") });
    expect(resolveStableRuntime({ ...p.options, explicitNode: "opt/node/bin/node" })).toMatchObject({ ok: false, reason: "explicit Node path is not absolute" });
    expect(resolveStableRuntime({ ...p.options, explicitNode: p.optNode, tempRoots: [p.root] })).toMatchObject({ ok: false, reason: "explicit Node path is under a temporary directory" });
  });

  it("accepts an explicit stable Node only when it reports a version", () => {
    const p = prefix();
    expect(resolveStableRuntime({ ...p.options, explicitNode: p.optNode })).toMatchObject({ ok: true, node: p.optNode });
    expect(resolveStableRuntime({ ...p.options, explicitNode: p.optNode, versionProbe: () => null })).toEqual({ ok: false, reason: "explicit Node did not report a version" });
  });

  it("refuses a target or an ancestor writable by group or other", () => {
    const p = prefix();
    chmodSync(p.cellarNode, 0o775);
    expect(resolveStableRuntime(p.options).ok).toBe(false);
    chmodSync(p.cellarNode, 0o755);
    chmodSync(p.keg, 0o777);
    expect(resolveStableRuntime(p.options).ok).toBe(false);
    chmodSync(p.keg, 0o755);
    expect(resolveStableRuntime(p.options).ok).toBe(true);
  });

  it("refuses a Node that is not executable", () => {
    const p = prefix();
    chmodSync(p.cellarNode, 0o644);
    expect(resolveStableRuntime(p.options).ok).toBe(false);
  });

  it("refuses a CLI whose package identity or Node range does not match", () => {
    const p = prefix();
    writeFileSync(join(p.pkg, "package.json"), JSON.stringify({ name: "other-package", engines: { node: ">=20" } }));
    expect(resolveStableRuntime(p.options)).toEqual({ ok: false, reason: "CLI package identity does not match" });
    const q = prefix(">=24");
    expect(resolveStableRuntime(q.options)).toEqual({ ok: false, reason: "Node version is outside the package's supported range" });
    const r = prefix("^20 || ^22");
    expect(resolveStableRuntime(r.options)).toEqual({ ok: false, reason: "Node version is outside the package's supported range" });
  });

  it("refuses a running CLI that no stable candidate names", () => {
    const p = prefix();
    expect(resolveStableRuntime({ ...p.options, cliCandidates: [] })).toEqual({ ok: false, reason: "no stable CLI candidate resolves to the running CLI" });
  });

  it("default temporary roots refuse a temp-tree prefix", () => {
    const p = prefix();
    expect(resolveStableRuntime({ ...p.options, tempRoots: undefined }).ok).toBe(false);
  });
});
