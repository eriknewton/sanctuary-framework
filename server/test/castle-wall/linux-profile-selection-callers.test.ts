import {afterEach, expect, it, vi} from "vitest";
import {mkdtempSync, mkdirSync, readdirSync, writeFileSync, lstatSync, unlinkSync, rmdirSync} from "node:fs";
import {join} from "node:path";
import {Writable} from "node:stream";
import {tmpdir} from "node:os";
import {runDaemon} from "../../src/cli/castle-wall.js";
import {runWrap, type RunWrapDeps} from "../../src/wrap/cli.js";

const runtime = vi.hoisted(() => ({optIn: vi.fn(({env}) => env.SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED === "1"), activate: vi.fn()}));
vi.mock("../../src/castle-wall/runtime/index.js", async importOriginal => ({
  ...await importOriginal<object>(), isLinuxProducerSignedActivationRequested: runtime.optIn,
  maybeActivateLinuxProducerSignedCastleWall: runtime.activate,
}));
const fixtureRoots: string[] = [];
function clean(root: string): void {
  for (const name of readdirSync(root)) {
    const path = join(root, name);
    if (lstatSync(path).isDirectory()) clean(path); else unlinkSync(path);
  }
  rmdirSync(root);
}
afterEach(() => { for (const root of fixtureRoots.splice(0)) clean(root); vi.restoreAllMocks(); vi.unstubAllEnvs(); runtime.optIn.mockClear(); runtime.activate.mockClear(); });
const refusal = (reason: string) => `sanctuary castle-wall: Linux business profile selected or refused (${reason}); installed business signing is not enabled in this build\n`;
function fixture(business: boolean) {
  const root = mkdtempSync(join(tmpdir(), "k1-callers-"));
  fixtureRoots.push(root);
  const storage = join(root, "storage"); mkdirSync(storage);
  if (business) mkdirSync(join(root, "var/lib/sanctuary-business-signer"), {recursive: true});
  // Inline data keeps this FB witness executable against the original modules.
  const selectorRoots = {anchor: root, expectedOwner: process.geteuid!(), owners: {}, deniedLookup: [], deniedOpen: []};
  return {root, storage, selectorRoots};
}
for (const optIn of [undefined, "0", "1"]) it(`daemon refuses business before opt-in ${String(optIn)}`, async () => {
  const f = fixture(true), output: string[] = [];
  const env = {SANCTUARY_STORAGE_PATH: f.storage, SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED: optIn};
  const result = await runDaemon([], {platform: "linux", env, selectorRoots: f.selectorRoots, err: new Writable({write(text, _encoding, done) {output.push(String(text)); done();}})});
  expect(runtime.optIn).toHaveBeenCalledTimes(0);
  expect(runtime.activate).toHaveBeenCalledTimes(0);
  expect(result).toBe(1);
  expect(output.join("")).toBe(refusal("Business"));
  expect(readdirSync(f.storage)).toEqual([]);
});
it("daemon legacy continues to opt-in and the base unsupported text", async () => {
  const f = fixture(false), output: string[] = [];
  const ctx = {platform: "linux" as const, selectorRoots: f.selectorRoots, err: new Writable({write(text, _encoding, done) {output.push(String(text)); done();}})};
  await runDaemon([], {...ctx, env: {SANCTUARY_STORAGE_PATH: f.storage}});
  expect(runtime.optIn).toHaveBeenCalledTimes(1);
  expect(output.join("")).toContain("castle-wall daemon is macOS-only by default.");
  runtime.optIn.mockClear();
  await runDaemon([], {...ctx, env: {SANCTUARY_STORAGE_PATH: f.storage, SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED: "1"}});
  expect(runtime.optIn).toHaveBeenCalledTimes(1);
});
function wrapHooks(roots: ReturnType<typeof fixture>["selectorRoots"]) {
  const credential = new Error("credential sentinel");
  const hooks = {
    osPlatform: vi.fn(() => "linux" as const),
    resolvePassphrase: vi.fn(), resolveCustodyCredential: vi.fn(async () => { throw credential; }),
    persistPassphrase: vi.fn(), rewriteConfig: vi.fn(), saveWrapMeta: vi.fn(),
    checkPinResolvability: vi.fn(), runAutoProvisionForWrap: vi.fn(),
  };
  const deps: RunWrapDeps = {...hooks, selectorRoots: roots};
  return {hooks, deps, credential};
}
for (const optIn of [undefined, "0", "1"]) it(`wrap refuses business before credentials ${String(optIn)}`, async () => {
  const f = fixture(true), {hooks, deps} = wrapHooks(f.selectorRoots), output: string[] = [];
  vi.stubEnv("SANCTUARY_STORAGE_PATH", f.storage); vi.stubEnv("SANCTUARY_FORTRESS_PATH", "");
  vi.stubEnv("SANCTUARY_CASTLE_LINUX_PRODUCER_SIGNED", optIn);
  const terminal = new Error("exit sentinel");
  const exit = vi.spyOn(process, "exit").mockImplementation(() => {throw terminal;});
  vi.spyOn(process.stderr, "write").mockImplementation(text => {output.push(String(text)); return true;});
  let thrown: unknown; try { await runWrap({agentGuided: true, protectCommand: true}, deps); } catch (error) {thrown = error;}
  expect(hooks.resolveCustodyCredential).toHaveBeenCalledTimes(0);
  for (const [name, hook] of Object.entries(hooks)) expect(hook, name).toHaveBeenCalledTimes(name === "osPlatform" ? 1 : 0);
  expect(thrown).toBe(terminal);
  expect(exit).toHaveBeenCalledExactlyOnceWith(2);
  expect(output.join("")).toBe(refusal("Business"));
  expect(readdirSync(f.storage)).toEqual([]);
});
it("wrap legacy reaches the existing credential consumer", async () => {
  const f = fixture(false), {hooks, deps, credential} = wrapHooks(f.selectorRoots);
  vi.stubEnv("SANCTUARY_STORAGE_PATH", f.storage); vi.stubEnv("SANCTUARY_FORTRESS_PATH", "");
  await expect(runWrap({agentGuided: true, protectCommand: true}, deps)).rejects.toBe(credential);
  expect(hooks.resolveCustodyCredential).toHaveBeenCalledTimes(1);
});
for (const explicit of [true, false]) it(`wrap inventories the effective fortress (${explicit ? "option" : "environment"}) before promotion`, async () => {
  const f = fixture(true), {deps, hooks} = wrapHooks(f.selectorRoots), output: string[] = [];
  const effective = join(f.root, "effective"), ambient = join(f.root, "ambient");
  mkdirSync(join(effective, "policy/egress"), {recursive: true}); mkdirSync(ambient);
  writeFileSync(join(effective, "policy/egress/audit-producer.key"), "untouched");
  vi.stubEnv("SANCTUARY_STORAGE_PATH", f.storage);
  vi.stubEnv("SANCTUARY_FORTRESS_PATH", explicit ? ambient : effective);
  const terminal = new Error("exit sentinel");
  vi.spyOn(process, "exit").mockImplementation(() => {throw terminal;});
  vi.spyOn(process.stderr, "write").mockImplementation(text => {output.push(String(text)); return true;});
  await expect(runWrap({agentGuided: true, protectCommand: true, ...(explicit ? {fortress: effective} : {})}, deps)).rejects.toBe(terminal);
  expect(output.join("")).toBe(refusal("RawInventoryPresent"));
  expect(process.env.SANCTUARY_STORAGE_PATH).toBe(f.storage);
  expect(hooks.resolveCustodyCredential).toHaveBeenCalledTimes(0);
});
