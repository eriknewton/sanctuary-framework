// fail-before-exempt: selection roots are new; mutation and wired child/reset witnesses prove isolation.
import {expect, it, vi} from "vitest";
import fs from "node:fs";
import {join, resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {execFileSync} from "node:child_process";
import {defaultSelectorRoots} from "../../src/linux-business/profile-selection.js";
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
it("keeps worker roots through module reset and performs only anchored selection IO", async () => {
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
it("a real child has production defaults but injected caller roots constrain every selection syscall", () => {
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
  const anchor = fs.mkdtempSync("/tmp/k1-nonlinux-");
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
it("the built CLI receives isolated roots through its real dispatcher", () => {
  const fixture = fs.mkdtempSync("/tmp/k1-bundle-proof-");
  const monitor = join(fixture, "monitor.mjs");
  fs.writeFileSync(monitor, `
    import fs from "node:fs";
    import {syncBuiltinESMExports} from "node:module";
    const open = fs.openSync; let calls = 0, escaped = false;
    fs.openSync = (path, flags, ...args) => {
      if (typeof flags === "number" && (flags & fs.constants.O_DIRECTORY) && (flags & fs.constants.O_NOFOLLOW)) {
        const p = String(path); calls++;
        if (!p.startsWith("/tmp/k1-cli-selector-") && !p.startsWith("/proc/self/fd/")) {
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
