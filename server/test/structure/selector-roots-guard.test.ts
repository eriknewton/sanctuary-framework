// fail-before-exempt: selection roots are new; mutation and wired child/reset witnesses prove isolation.
import {expect, it, vi} from "vitest";
import fs from "node:fs";
import {join, resolve} from "node:path";
import {tmpdir} from "node:os";
import {fileURLToPath} from "node:url";
import {execFileSync, spawnSync} from "node:child_process";
import {defaultSelectorRoots, installSelectorRootsForTest} from "../../src/linux-business/profile-selection.js";
const root = resolve(fileURLToPath(import.meta.url), "../../../..");
const sourceRoot = join(root, "server/src");
const selector = join(sourceRoot, "linux-business/profile-selection.ts");
it("allows only the worker installer and the two forwarding callers", () => {
  const callers: string[] = [];
  for (const area of ["src", "test"]) for (const name of fs.readdirSync(join(root, "server", area), {recursive: true})) {
    if (typeof name !== "string" || !name.endsWith(".ts")) continue;
    const file = `${area}/${name}`, source = fs.readFileSync(join(root, "server", file), "utf8");
    if (file === "src/linux-business/profile-selection.ts" || file === "test/structure/selector-roots-guard.test.ts") continue;
    if (/\binstallSelectorRootsForTest\s*\(/.test(source)) callers.push(file);
    if (area === "src" && /\bselectorRoots\b/.test(source)) {
      expect(["src/cli/castle-wall.ts", "src/wrap/cli.ts"]).toContain(file);
      expect(source).not.toMatch(/\b(?:isolatedSelectorRoots|installSelectorRootsForTest|PRODUCTION_SELECTOR_ROOTS)\b/);
      expect(source).toMatch(/selectLinuxProfile\((?:ctx|deps)\.selectorRoots \?\? defaultSelectorRoots\(\), rawCandidates\(storagePath\)\)/);
    }
    if (area === "src") expect(source).not.toMatch(/\b(?:isolatedSelectorRoots|installSelectorRootsForTest)\s*\(/);
  }
  expect(callers).toEqual(["test/setup/selector-roots-isolation.ts"]);
});
// Selection and CLI children require the Linux procfs descriptor transport.
it.skipIf(process.platform !== "linux")("keeps worker roots through module reset and performs only anchored selection IO", async () => {
  const roots = defaultSelectorRoots(), paths: string[] = [];

  const check = (path: fs.PathLike) => { const p = String(path); paths.push(p); expect(p === roots.anchor || p.startsWith("/proc/self/fd/")).toBe(true); };
  vi.resetModules();
  const module = await import("../../src/linux-business/profile-selection.js");
  const freshFs = (await import("node:fs")).default;
  const open = freshFs.openSync, stat = freshFs.statSync, lstat = freshFs.lstatSync;
  expect(module.defaultSelectorRoots()).toBe(roots);
  vi.spyOn(freshFs, "openSync").mockImplementation(((path: fs.PathLike, ...args: any[]) => {check(path); return (open as any)(path, ...args);}) as typeof fs.openSync);
  vi.spyOn(freshFs, "statSync").mockImplementation(((path: fs.PathLike, ...args: any[]) => {check(path); return (stat as any)(path, ...args);}) as typeof fs.statSync);
  vi.spyOn(freshFs, "lstatSync").mockImplementation(((path: fs.PathLike, ...args: any[]) => {check(path); return (lstat as any)(path, ...args);}) as typeof fs.lstatSync);
  try {
    expect(module.selectLinuxProfile(module.defaultSelectorRoots(), [])).toEqual({kind: "LegacyV1", reason: "NoBusinessEvidence"});
    expect(paths.length).toBeGreaterThan(0);
  } finally {vi.restoreAllMocks();}
});
// Selection and CLI children require the Linux procfs descriptor transport.
it.skipIf(process.platform !== "linux")("a real child has production defaults but injected caller roots constrain every selection syscall", () => {
  const output = execFileSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
    import fs from "node:fs";
    import {tmpdir} from "node:os";
    import {join} from "node:path";
    import {syncBuiltinESMExports} from "node:module";
    const m = await import(${JSON.stringify(selector)});
    if (m.defaultSelectorRoots() !== m.PRODUCTION_SELECTOR_ROOTS || m.PRODUCTION_SELECTOR_ROOTS.expectedOwner !== 0) throw Error("production default");
    const root = fs.mkdtempSync(join(tmpdir(), "k1-child-proof-"));
    const roots = m.isolatedSelectorRoots(root);
    fs.mkdirSync(join(root, "var/lib/sanctuary-business-signer"), {recursive: true});
    const {runDaemon} = await import(${JSON.stringify(join(sourceRoot, "cli/castle-wall.ts"))});
    const {runWrap} = await import(${JSON.stringify(join(sourceRoot, "wrap/cli.ts"))});
    await import(${JSON.stringify(join(sourceRoot, "cli/castle-wall-full-agent-state.ts"))});
    const violations = [];
    const originals = new Map(); let calls = 0;
    for (const name of ["openSync", "lstatSync", "statSync", "opendirSync"]) {
      const original = fs[name]; originals.set(name, original);
      fs[name] = (path, ...args) => {
        if (String(path) !== root && !String(path).startsWith("/proc/self/fd/")) { violations.push(String(path)); throw Error("outside fixture: " + path); }
        calls++; return original(path, ...args);
      };
    }
    syncBuiltinESMExports();
    let output = "";
    const result = await runDaemon([], {platform: "linux", selectorRoots: roots,
      env: {SANCTUARY_STORAGE_PATH: join(root, "storage")}, err: {write: s => {output += s; return true;}}});
    const exit = process.exit, write = process.stderr.write;
    const sentinel = new Error("terminal"); let exitCode;
    process.exit = code => {exitCode = code; throw sentinel;};
    process.stderr.write = s => {output += s; return true;};
    let stopped = false;
    try { await runWrap({fortress: join(root, "storage")}, {osPlatform: () => "linux", selectorRoots: roots}); }
    catch (error) {if (error !== sentinel) throw error; stopped = true;}
    finally {process.exit = exit; process.stderr.write = write;}
    for (const [name, original] of originals) fs[name] = original;
    syncBuiltinESMExports();
    for (const p of ["var/lib/sanctuary-business-signer", "var/lib", "var", ""]) fs.rmdirSync(join(root, p));
    if (result !== 1 || !stopped || exitCode !== 2 || violations.length || !output.includes("(Business)") || calls < 1) throw Error("child selection");
    process.stdout.write("anchored child selection");
  `], {cwd: join(root, "server"), encoding: "utf8", timeout: 30_000});
  expect(output).toBe("anchored child selection");
  const source = fs.readFileSync(join(root, "server/test/wrap/protect-automation-blockers.test.ts"), "utf8");
  expect(source).toContain("selectorRoots: isolatedSelectorRoots(selectionRoot)");
  expect(fs.readFileSync(join(root, "server/test/fixtures/lock-teardown-child.ts"), "utf8")).toContain("selectorRoots: isolatedSelectorRoots(selectionRoot)");
});
it("non-Linux callers bypass inventory and preserve the credential consumer", async () => {
  const {runDaemon} = await import("../../src/cli/castle-wall.js");
  const {runWrap} = await import("../../src/wrap/cli.js");
  const anchor = fs.mkdtempSync(join(tmpdir(), "k1-nonlinux-"));
  const selectorRoots = {get anchor(): string { throw new Error("inventory consulted"); }, expectedOwner: process.geteuid!()};
  const credential = new Error("credential sentinel");
  const resolveCustodyCredential = vi.fn(async () => {throw credential;});
  vi.stubEnv("SANCTUARY_STORAGE_PATH", anchor);
  vi.stubEnv("SANCTUARY_FORTRESS_PATH", "");
  try {
    expect(await runDaemon([], {platform: "win32", selectorRoots, env: {SANCTUARY_STORAGE_PATH: anchor}, err: {write: () => true} as any})).toBe(1);
    await expect(runWrap({agentGuided: true, protectCommand: true}, {osPlatform: () => "win32", selectorRoots, resolveCustodyCredential})).rejects.toBe(credential);
    expect(resolveCustodyCredential).toHaveBeenCalledTimes(1);
  } finally {vi.unstubAllEnvs(); fs.rmdirSync(anchor);}
});
// Selection and CLI children require the Linux procfs descriptor transport.
it.skipIf(process.platform !== "linux")("the built CLI receives isolated roots through its real dispatcher", () => {
  const fixture = fs.mkdtempSync(join(tmpdir(), "k1-bundle-proof-"));
  const monitor = join(fixture, "monitor.mjs");
  fs.writeFileSync(monitor, `
    import fs from "node:fs";
    import {syncBuiltinESMExports} from "node:module";
    const open = fs.openSync; let calls = 0, escaped = false;
    fs.openSync = (path, flags, ...args) => {
      if (typeof flags === "number" && (flags & fs.constants.O_DIRECTORY) && (flags & fs.constants.O_NOFOLLOW)) {
        const p = String(path); calls++;
        if (!p.startsWith(${JSON.stringify(join(tmpdir(), "k1-cli-selector-"))}) && !p.startsWith("/proc/self/fd/")) {
          escaped = true; throw Error("selector escaped fixture");
        }
      }
      return open(path, flags, ...args);
    };
    syncBuiltinESMExports();
    process.once("exit", () => process.stdout.write(JSON.stringify({calls, escaped})));
  `);
  try {
    let error: any;
    try {
      execFileSync(process.execPath, ["--import", monitor, "--import", join(root, "server/test/fixtures/selector-cli-child.mjs"),
        join(root, "server/dist/cli.js"), "castle-wall", "daemon", "--fortress", join(fixture, "storage")],
      {encoding: "utf8", timeout: 30_000, env: {...process.env, SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED: "0", NODE_NO_WARNINGS: "1"}});
    } catch (caught) {error = caught;}
    expect(error?.status).toBe(1);
    expect(error?.stderr).toContain("macOS-only by default");
    const observed = JSON.parse(error.stdout);
    expect(observed.calls).toBeGreaterThan(0);
    expect(observed.escaped).toBe(false);
  } finally {fs.unlinkSync(monitor); fs.rmdirSync(fixture);}
});

it("guards every production selection call with the real-host helper", () => {
  const callers: string[] = [];
  for (const name of fs.readdirSync(sourceRoot, {recursive: true})) {
    if (typeof name !== "string" || !name.endsWith(".ts") || name === "linux-business/profile-selection.ts") continue;
    const source = fs.readFileSync(join(sourceRoot, name), "utf8");
    const calls = source.match(/\bselectLinuxProfile\s*\(/g) ?? [];
    if (!calls.length) continue;
    callers.push(name);
    const guarded = source.match(/if \(appliesLinuxProfileSelection\([^{}]+\)\) \{[^{}]*\bselectLinuxProfile\(/g) ?? [];
    expect(guarded.length, name).toBe(calls.length);
  }
  expect(callers.sort()).toEqual(["cli/castle-wall.ts", "wrap/cli.ts"]);
  expect(fs.readFileSync(selector, "utf8")).toContain('return platform === "linux" && process.platform === "linux";');
});

// The seam gate runs before transport and therefore needs no Linux procfs.
for (const runner of ["none", "VITEST", "NODE_ENV"]) it(`refuses selector seams outside a test runner (${runner})`, () => {
  const env = {...process.env};
  delete env.NODE_ENV;
  delete env.VITEST;
  if (runner === "VITEST") env.VITEST = ""; // Defined, even empty, matches the wrap hook policy.
  if (runner === "NODE_ENV") env.NODE_ENV = "test";
  const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
    import fs from "node:fs";
    import {tmpdir} from "node:os";
    import {join} from "node:path";
    import {syncBuiltinESMExports} from "node:module";
    const m = await import(${JSON.stringify(selector)});
    const {requireCliTestRunner} = await import(${JSON.stringify(join(sourceRoot, "cli/argv.ts"))});
    const {runDaemon} = await import(${JSON.stringify(join(sourceRoot, "cli/castle-wall.ts"))});
    const {runWrap} = await import(${JSON.stringify(join(sourceRoot, "wrap/cli.ts"))});
    const anchor = fs.mkdtempSync(join(tmpdir(), "k1-seam-gate-"));
    const roots = {anchor, expectedOwner: 0};
    const key = Symbol.for("sanctuary.test.selector-roots");
    const originals = new Map(); let reads = 0;
    for (const name of ["openSync", "lstatSync", "statSync", "opendirSync"]) {
      const original = fs[name]; originals.set(name, original);
      fs[name] = (path, ...args) => {
        if (String(path) === anchor || String(path).startsWith(anchor + "/")) {
          reads++; throw Error("fixture read");
        }
        return original(path, ...args);
      };
    }
    syncBuiltinESMExports();
    const results = [];
    const credential = new Error("credential reached");
    const calls = [
      () => m.installSelectorRootsForTest(roots, requireCliTestRunner("selectorRoots")),
      () => {globalThis[key] = {roots, assertTestRunner: requireCliTestRunner("selectorRoots")}; return m.defaultSelectorRoots();},
      () => runDaemon([], {platform: "win32", selectorRoots: roots,
        env: {SANCTUARY_STORAGE_PATH: anchor}, err: {write: () => true}}),
      async () => {
        try { await runWrap({fortress: anchor, agentGuided: true, protectCommand: true},
          {osPlatform: () => "win32", selectorRoots: roots, resolveCustodyCredential: async () => {throw credential;}}); }
        catch (error) {if (error !== credential) throw error; return "credential reached";}
      },
    ];
    try {
      for (const call of calls) {
        try {await call(); results.push("proceeded");}
        catch (error) {results.push(error.message);}
        finally {delete globalThis[key];}
      }
    } finally {
      for (const [name, original] of originals) fs[name] = original;
      syncBuiltinESMExports(); fs.rmdirSync(anchor);
    }
    process.stdout.write(JSON.stringify({results, reads}));
    process.exitCode = results.some(result => result !== "proceeded") ? 2 : 0;
  `], {cwd: join(root, "server"), encoding: "utf8", timeout: 30_000, env});
  expect(child.error).toBeUndefined();
  expect(child.status).toBe(runner === "none" ? 2 : 0);
  expect(JSON.parse(child.stdout)).toEqual({
    results: Array(4).fill(runner === "none"
      ? "selectorRoots is test-only and is disabled outside the test runner." : "proceeded"),
    reads: 0,
  });
});

it("constructs runner permits only in the shared CLI policy function", () => {
  const constructors: string[] = [];
  const consumers: string[] = [];
  for (const name of fs.readdirSync(sourceRoot, {recursive: true})) {
    if (typeof name !== "string" || !name.endsWith(".ts")) continue;
    const source = fs.readFileSync(join(sourceRoot, name), "utf8");
    if (/\b(?:const|function) assertTestRunner\b/.test(source)) constructors.push(name);
    if (/\bassertTestRunner\s*:/.test(source) && name !== "linux-business/profile-selection.ts") {
      consumers.push(name);
      expect(source).toMatch(/assertTestRunner: requireCliTestRunner\("selectorRoots"\)/);
      expect(source).not.toMatch(/assertTestRunner:\s*(?:\(|function\b)/);
    }
  }
  expect(constructors).toEqual(["cli/argv.ts"]);
  expect(consumers.sort()).toEqual(["cli/castle-wall.ts", "wrap/cli.ts"]);
  const policy = fs.readFileSync(join(sourceRoot, "cli/argv.ts"), "utf8");
  expect(policy).toMatch(/export function requireCliTestRunner\(name: string\): \(\) => void/);
  expect(policy.match(/process\.env\.(?:NODE_ENV|VITEST)/g)).toHaveLength(2);
  const wrap = fs.readFileSync(join(sourceRoot, "wrap/cli.ts"), "utf8");
  expect(wrap).toMatch(/function assertWrapCliTestHookAllowed\(name: string\): void \{\s*requireCliTestRunner\(name\);\s*\}/);
});

it("refuses missing permits at every selector seam before reading the supplied roots", () => {
  const child = spawnSync(process.execPath, ["--import", "tsx", "--input-type=module", "-e", `
    const m = await import(${JSON.stringify(selector)});
    let reads = 0;
    const roots = {get anchor() {reads++; throw Error("anchor read");}, expectedOwner: 0};
    const key = Symbol.for("sanctuary.test.selector-roots");
    const results = [];
    for (const call of [
      () => m.installSelectorRootsForTest(roots),
      () => m.defaultSelectorRoots({roots}),
      () => {globalThis[key] = {roots}; return m.defaultSelectorRoots();},
      () => m.defaultSelectorRoots({roots, assertTestRunner: () => {
        throw Error("selectorRoots is test-only and is disabled outside the test runner.");
      }}),
      () => {
        let allowed = true;
        m.installSelectorRootsForTest(roots, () => {
          if (!allowed) throw Error("selectorRoots is test-only and is disabled outside the test runner.");
        });
        allowed = false;
        return m.defaultSelectorRoots();
      },
    ]) {
      try {call(); results.push("proceeded");} catch (error) {results.push(error.message);}
      finally {delete globalThis[key];}
    }
    process.stdout.write(JSON.stringify({results, reads}));
  `], {cwd: join(root, "server"), encoding: "utf8", timeout: 30_000});
  expect(child.error).toBeUndefined();
  expect(child.status).toBe(0);
  expect(JSON.parse(child.stdout)).toEqual({
    results: Array(5).fill("selectorRoots is test-only and is disabled outside the test runner."), reads: 0,
  });
});

// Compile-time witnesses: injected roots cannot omit the callback permit.
function missingPermitTypes(): void {
  // @ts-expect-error installation requires the runner assertion
  installSelectorRootsForTest({anchor: "/unused", expectedOwner: 0});
  // @ts-expect-error injected roots require the runner assertion
  defaultSelectorRoots({roots: {anchor: "/unused", expectedOwner: 0}});
}
void missingPermitTypes;
