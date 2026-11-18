/** Evidence export admits initialized filesystem fortresses before acquiring credentials or creating artifacts. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { lstat, mkdir, mkdtemp, readFile, readdir, readlink, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { SOURCE, exporterFixture } from "./snapshot-fixtures.js";
import * as C from "../../src/evidence-pack/snapshot-contract.js";

const TEST_TIMEOUT_MS = 60_000;
const roots: string[] = [];
let store: typeof import("../setup/keychain-memory-store.js");
beforeEach(async () => {
  vi.resetModules();
  store = await import("../setup/keychain-memory-store.js");
  store.installInMemoryKeychainStore();
  store.clearInMemoryKeychainStore();
});
afterEach(async () => {
  vi.restoreAllMocks(); vi.unstubAllEnvs(); vi.unstubAllGlobals();
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

async function inventory(path: string): Promise<unknown> {
  let info;
  try { info = await lstat(path, { bigint: true }); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return null; throw error; }
  const metadata = { mode: String(info.mode), ino: String(info.ino), size: String(info.size), mtime: String(info.mtimeNs), ctime: String(info.ctimeNs) };
  if (info.isSymbolicLink()) return { ...metadata, link: await readlink(path) };
  if (info.isDirectory()) {
    const entries: Record<string, unknown> = {};
    for (const name of (await readdir(path)).sort()) entries[name] = await inventory(join(path, name));
    return { ...metadata, entries };
  }
  return { ...metadata, bytes: (await readFile(path)).toString("hex") };
}
async function bootOutcome(boot: () => Promise<{ cleanup: () => Promise<void> }>) {
  try {
    const instance = await boot();
    await instance.cleanup();
    return { completed: true };
  } catch (error) {
    return { completed: false, error: (error as Error).message };
  }
}
async function environment() {
  const root = await realpath(await mkdtemp(join(tmpdir(), "snapshot-existing-")));
  roots.push(root);
  const fortress = join(root, "fortress");
  vi.stubEnv("HOME", root); vi.stubEnv("SANCTUARY_STORAGE_PATH", fortress); vi.stubEnv("SANCTUARY_FORTRESS_PATH", fortress);
  vi.stubEnv("SANCTUARY_PASSPHRASE", "snapshot-disposable-test-only"); vi.stubEnv("SANCTUARY_RECOVERY_KEY", "");
  vi.stubEnv("SANCTUARY_DASHBOARD_AUTO_OPEN", "false"); vi.stubGlobal("__SANCTUARY_SOURCE_SHA__", SOURCE);
  return { root, fortress };
}

describe("CLI existing fortress admission", () => {
  it.each(["missing", "empty", "unrelated", "file", "symlink"] as const)("preserves the %s path and its parent", async shape => {
    const { root, fortress } = await environment();
    if (shape === "empty" || shape === "unrelated") await mkdir(fortress);
    if (shape === "unrelated") await writeFile(join(fortress, "notes.txt"), "operator notes");
    if (shape === "file") await writeFile(fortress, "operator file");
    if (shape === "symlink") {
      const destination = join(root, "destination");
      await mkdir(join(destination, "state", "_meta"), { recursive: true });
      await writeFile(join(destination, "state", "_meta", "custody-envelope.enc"), "synthetic custody marker");
      await symlink(destination, fortress);
    }
    const entry = await import("../../src/evidence-pack/snapshot-export-cli.js");
    const boot = vi.spyOn(entry.exportDependencies, "boot");
    const exits: number[] = [], stdout: string[] = [], stderr: string[] = [];
    vi.spyOn(process, "exit").mockImplementation(((code: number) => { exits.push(code); }) as never);
    vi.spyOn(process.stdout, "write").mockImplementation(((text: string, callback?: () => void) => { stdout.push(String(text)); callback?.(); return true; }) as never);
    vi.spyOn(process.stderr, "write").mockImplementation(((text: string, callback?: () => void) => { stderr.push(String(text)); callback?.(); return true; }) as never);
    const original = process.argv;
    const before = { parent: await inventory(root), target: await inventory(fortress) };
    process.argv = [process.execPath, resolve("src/cli.ts"), "export-evidence", "--fortress", fortress, "--output", join(root, "pack"), "--receipt", join(root, "receipt.json"), "--public-key-file", join(root, "key.txt")];
    try { await (await import("../../src/cli.js")).cliEntryInvocation; }
    finally { process.argv = original; }
    expect({
      exits, stderr: stderr.join(""), stdout: stdout.join(""), bootCalls: boot.mock.calls,
      credentials: store.inMemoryKeychainCalls(), files: { parent: await inventory(root), target: await inventory(fortress) },
    }).toEqual({
      exits: [C.EXIT_FAIL], stderr: "Evidence export requires an initialized fortress. The path must be the fortress directory itself, not a symbolic link.\nEXPORT_FINDING=unsafe_path\n",
      stdout: "", bootCalls: [], credentials: [], files: before,
    });
  }, TEST_TIMEOUT_MS);
});

it.each(["missing", "empty", "symlink"] as const)("rechecks the %s root at boot admission", async shape => {
  await environment();
  const x = await exporterFixture(); roots.push(x.root);
  vi.stubEnv("SANCTUARY_STORAGE_PATH", x.options.fortress);
  const { exportSnapshot, exportDependencies } = await import("../../src/evidence-pack/snapshot-export-cli.js");
  const productionBoot = exportDependencies.boot;
  const bootCalls: string[] = [];
  x.deps.boot = path => { bootCalls.push(path); return productionBoot(path); };
  const config = await import("../../src/config.js");
  const configuration = vi.spyOn(config, "loadConfig");
  let before: unknown;
  x.deps.phase = async state => {
    if (state !== "GATHER") return;
    const parked = join(x.root, "parked");
    await rename(x.options.fortress, parked);
    if (shape === "empty") await mkdir(x.options.fortress);
    if (shape === "symlink") await symlink(parked, x.options.fortress);
    before = await inventory(x.root);
  };
  const exit = await exportSnapshot(x.options, x.deps);
  expect({ exit, bootCalls, diagnostic: x.stderr.join(""), files: await inventory(x.root), credentials: store.inMemoryKeychainCalls(), configuration: configuration.mock.calls }).toEqual({
    exit: C.EXIT_FAIL, bootCalls: [x.options.fortress], diagnostic: "Evidence export failed; any failed stage is retained.\nEXPORT_FINDING=io_error\n",
    files: before, credentials: [], configuration: [],
  });
}, TEST_TIMEOUT_MS);

it.each(["configuration", "permissions"].flatMap(boundary => ["root", "markers"].map(subject => ({ boundary, subject }))))("existing boot preserves $subject inventory after $boundary", async ({ boundary, subject }) => {
  const { root, fortress } = await environment();
  const metadata = join(fortress, "state", "_meta");
  await mkdir(metadata, { recursive: true });
  await writeFile(join(metadata, "custody-envelope.enc"), "synthetic custody marker");
  let before: unknown;
  const park = async () => {
    await rename(subject === "root" ? fortress : metadata, join(root, `parked-${subject}`));
    before = { parent: await inventory(root), target: await inventory(fortress) };
  };
  if (boundary === "configuration") {
    const config = await import("../../src/config.js"), load = config.loadConfig;
    vi.spyOn(config, "loadConfig").mockImplementation(async path => {
      const result = await load(path); await park(); return result;
    });
  } else {
    const permissions = await import("../../src/storage/permissions.js"), tighten = permissions.tightenStoragePermissions;
    vi.spyOn(permissions, "tightenStoragePermissions").mockImplementation(async path => {
      await tighten(path); await park();
    });
  }
  const { createSanctuaryServer } = await import("../../src/index.js");
  const outcome = await bootOutcome(() => createSanctuaryServer({ existingFortressPath: fortress }));
  expect({ outcome, files: { parent: await inventory(root), target: await inventory(fortress) }, credentials: store.inMemoryKeychainCalls() }).toEqual({
    outcome: { completed: false, error: "Existing fortress required." }, files: before, credentials: [],
  });
}, TEST_TIMEOUT_MS);

it("existing boot compares its required path before loading configuration", async () => {
  const { root, fortress } = await environment();
  await mkdir(join(fortress, "state", "_meta"), { recursive: true });
  await writeFile(join(fortress, "state", "_meta", "key-params.enc"), "synthetic custody marker");
  const ambient = join(root, "ambient"); await mkdir(ambient);
  await writeFile(join(ambient, "sanctuary.json"), "synthetic config text");
  vi.stubEnv("SANCTUARY_STORAGE_PATH", ambient);
  const config = await import("../../src/config.js"), configuration = vi.spyOn(config, "loadConfig");
  const { createSanctuaryServer } = await import("../../src/index.js");
  const before = { parent: await inventory(root), target: await inventory(fortress) };
  const outcome = await bootOutcome(() => createSanctuaryServer({ existingFortressPath: fortress }));
  expect({ outcome, files: { parent: await inventory(root), target: await inventory(fortress) }, configuration: configuration.mock.calls, credentials: store.inMemoryKeychainCalls() }).toEqual({
    outcome: { completed: false, error: "Existing fortress path mismatch." }, files: before, configuration: [], credentials: [],
  });
}, TEST_TIMEOUT_MS);

it("the boot credential recorder observes a host-local lookup", async () => {
  const { fortress } = await environment();
  await mkdir(join(fortress, "state", "_meta"), { recursive: true });
  await writeFile(join(fortress, "state", "_meta", "key-params.enc"), "synthetic custody marker");
  vi.stubEnv("SANCTUARY_PASSPHRASE", "");
  const { createSanctuaryServer } = await import("../../src/index.js");
  const outcome = await bootOutcome(() => createSanctuaryServer({ existingFortressPath: fortress }));
  expect({ completed: outcome.completed, observed: store.inMemoryKeychainCalls().some(([command]) => ["security", "secret-tool"].includes(command)) }).toEqual({ completed: false, observed: true });
}, TEST_TIMEOUT_MS);
