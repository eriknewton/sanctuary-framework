import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import * as nodePath from "node:path";
import * as nodeUrl from "node:url";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";
import { createRequire } from "node:module";
import { expect, it } from "vitest";
import config, { leaseGuardHookTimeoutMs } from "../../vitest.config.js";

const ts = createRequire(import.meta.url)("typescript") as typeof import("typescript");
const serverRoot = fileURLToPath(new URL("../../", import.meta.url));
const childStartupHeadroomMs = 30_000; // Allow module loading on a loaded runner.
const childExitHeadroomMs = 10_000; // Allow reporting and worker shutdown after teardown.
const parentHeadroomMs = 30_000; // Allow fixture filesystem work outside the child budgets.
const childTimeoutMs = childStartupHeadroomMs + (config.test?.testTimeout ?? childStartupHeadroomMs) + leaseGuardHookTimeoutMs + childExitHeadroomMs;
const scenarios = ["leaked", "released", "failed-teardown"] as const;
const fixtureTimeoutMs = childTimeoutMs * scenarios.length + parentHeadroomMs;

it("reaps and reports unclosed leases after file teardown while accepting released leases", async () => {
  expect(config.test?.setupFiles).toEqual([
    "./test/setup/keychain-fake.ts",
    "./test/setup/homedir-follows-env.ts",
    "./test/setup/master-write-leases.ts",
    "./test/setup/selector-roots-isolation.ts",
  ]);
  expect(config.test?.sequence).toMatchObject({ setupFiles: "list", hooks: "stack" });
  const directory = await mkdtemp(join(serverRoot, ".lease-guard-"));
  try {
    const configPath = join(directory, "vitest.config.ts");
    // One thread worker confines fixture execution to the child process that spawnSync reaps.
    await writeFile(configPath, `
import config from ${JSON.stringify(join(serverRoot, "vitest.config.ts"))};
export default { ...config, test: { ...config.test, include: [${JSON.stringify(`${directory}/*.test.ts`)}], pool: "threads", maxWorkers: 1 } };
`);
    for (const name of scenarios) {
      const release = name === "released";
      const fixturePath = join(directory, `${name}.test.ts`);
      const socketRecord = join(directory, `${name}.socket`);
      await writeFile(fixturePath, `
import { afterAll, expect, it, vi } from "vitest";
import { writeFile } from "node:fs/promises";
import { FilesystemStorage } from ${JSON.stringify(join(serverRoot, "src/storage/filesystem.ts"))};
vi.mock(${JSON.stringify(join(serverRoot, "src/storage/cross-process-lock.ts"))}, async (importOriginal) => {
  const actual = await importOriginal();
  return { ...actual, acquireMasterWriteBarrier: (...args) => actual.acquireMasterWriteBarrier(...args) };
});
let session;
afterAll(async () => {
  session?.masterKey.fill(0);
  if (${release}) await session?.masterWriteBarrier?.release();
  process.stdout.write("fixture teardown completed\\n");
  if (${name === "failed-teardown"}) {
    process.stdout.write("ORIGINAL teardown error: fixture teardown failure\\n");
    throw new Error("fixture teardown failure");
  }
});
it("holds a master session through the test body", async () => {
  vi.resetModules();
  const { establishMaster } = await vi.importActual(${JSON.stringify(join(serverRoot, "src/core/master-custody.ts"))});
  session = await establishMaster({ storage: new FilesystemStorage(${JSON.stringify(join(directory, name))}), passphrase: "lease-guard-fixture", firstRun: { installMode: "headless", mintRecoveryKey: false } });
  expect(() => session.masterWriteBarrier.assertHeld()).not.toThrow();
  await writeFile(${JSON.stringify(socketRecord)}, session.masterWriteBarrier.socketPath);
});
`);
      // Thread workers die with the synchronous child, which is reaped even when its timeout fires.
      const result = spawnSync(process.execPath, [
        join(serverRoot, "node_modules/vitest/vitest.mjs"), "run", "--config", configPath, fixturePath,
      ], { cwd: serverRoot, encoding: "utf8", timeout: childTimeoutMs, killSignal: "SIGKILL" });
      const output = result.stdout + result.stderr;
      // Expected child failures must not contaminate the outer summary parsed by the baseline guard.
      expect(result.error, output).toBeUndefined();
      expect(result.signal).toBeNull();
      expect(result.status, output).toBe(release ? 0 : 1);
      expect(output).toContain("fixture teardown completed");
      if (release) {
        expect(output).not.toContain("master-write lease(s) left open");
      } else {
        expect(output).toContain("1 master-write lease(s) left open");
        expect(output).toContain("Master-write lease acquired here");
        expect(output).toContain(`${name}.test.ts`);
      }
      if (name === "failed-teardown") {
        expect(output).toContain("fixture teardown failure");
        expect(output).toContain("ORIGINAL teardown error: fixture teardown failure");
        expect(output).toMatch(/Error: fixture teardown failure/u);
      }
      const socketPath = await readFile(socketRecord, "utf8");
      await expect(stat(socketPath)).rejects.toMatchObject({ code: "ENOENT" });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}, fixtureTimeoutMs);

it("rejects same-module acquisition calls before renaming the declaration", async () => {
  const plugin = config.plugins?.find(plugin => plugin && "name" in plugin && plugin.name === "test-master-write-lease-observer");
  if (!plugin || !("transform" in plugin) || typeof plugin.transform !== "function") throw new Error("Lease transform missing");
  const transform = plugin.transform as (source: string, id: string) => unknown;
  const modulePath = join(serverRoot, "src/storage/cross-process-lock.ts");
  const source = await readFile(modulePath, "utf8");
  expect(transform(source, modulePath)).toBeTypeOf("string");
  expect(() => transform(`${source}\nacquireMasterWriteBarrier(storage, namespace, name);`, modulePath)).toThrow("same-module call");
  expect(() => transform(`${source}\nacquireMasterWriteBarrier \n(storage, namespace, name);`, modulePath)).toThrow("same-module call");
  expect(() => transform("export const moved = true;", modulePath)).toThrow("chokepoint moved");
  expect(transform(source, `${modulePath}.unrelated`)).toBeUndefined();
});

async function guardHarness(testPath = "test/guard-regression.test.ts") {
  type Lease = { release: () => Promise<void> };
  type Observer = (acquire: () => Promise<Lease>, stack: string) => Promise<Lease>;
  let around!: (run: () => Promise<void>) => Promise<void>;
  let after!: () => Promise<void>;
  let clock = 0;
  let scheduledDelay: number | undefined;
  const setupPath = join(serverRoot, "test/setup/master-write-leases.ts");
  const source = (await readFile(setupPath, "utf8")).replaceAll("import.meta.url", JSON.stringify(nodeUrl.pathToFileURL(setupPath).href));
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const sandbox = {
    URL,
    exports: {},
    require(id: string) {
      if (id === "vitest") return {
        afterAll: (hook: typeof after) => { after = hook; },
        aroundAll: (hook: typeof around) => { around = hook; },
        expect: { getState: () => ({ testPath: join(serverRoot, testPath) }) },
      };
      if (id === "node:path") return nodePath;
      if (id === "node:url") return nodeUrl;
      if (id === "../../vitest.config.js") return { leaseGuardHookTimeoutMs };
      if (id === "node:perf_hooks") return { performance: { now: () => clock } };
      if (id === "node:timers") return {
        setTimeout: (callback: () => void, delay: number) => {
          scheduledDelay = delay;
          return setTimeout(() => { clock += delay; callback(); });
        },
        clearTimeout,
      };
      throw new Error(`Unexpected guard import: ${id}`);
    },
  };
  // Running the actual setup with captured hooks exercises rejected callbacks independently of Vitest's error serialization.
  const observer = runInNewContext(`${compiled}\nglobalThis[Symbol.for("sanctuary.test.master-write-lease-observer")];`, sandbox, { filename: setupPath }) as Observer;
  return { observer, around: (run: () => Promise<void>) => around(run), after: () => after(), delay: () => scheduledDelay };
}

it("preserves the original teardown rejection before the guard failure", async () => {
  const guard = await guardHarness();
  let released = false;
  await guard.observer(async () => ({ async release() { released = true; } }), "aggregate acquisition stack");
  const original = new Error("ORIGINAL fixture teardown rejection");
  const result = await guard.around(async () => { throw original; }).catch(error => error);
  expect(result.name).toBe("AggregateError");
  expect(result.errors).toHaveLength(2);
  expect(result.errors[0]).toBe(original);
  expect(result.errors[1].message).toContain("1 master-write lease(s) left open");
  expect(released).toBe(true);
});

it("reports pending acquisition stacks at its deadline and releases acquired leases", async () => {
  const guard = await guardHarness();
  let released = false;
  await guard.observer(async () => ({ async release() { released = true; } }), "completed acquisition stack");
  void guard.observer(() => new Promise(() => {}), "PENDING acquisition stack");
  const result = await guard.after().catch(error => error);
  expect(result.message).toContain("1 master-write acquisition(s) still pending");
  expect(result.message).toContain("PENDING acquisition stack");
  expect(result.message).toContain("completed acquisition stack");
  expect(result.message).toContain("guard-regression.test.ts");
  expect(guard.delay()).toBeGreaterThan(0);
  expect(guard.delay()).toBeLessThan(leaseGuardHookTimeoutMs);
  expect(released).toBe(true);
});

it("reports rejected releases for files without a reap exemption", async () => {
  const paths = ["test/guard-regression.test.ts", "test/cli/secrets.test.ts"];
  for (const testPath of paths) {
    const guard = await guardHarness(testPath);
    const reapError = new Error("fixture release rejection");
    let attempted = false;
    await guard.observer(async () => ({ async release() { attempted = true; throw reapError; } }), "rejecting acquisition stack");
    await expect(guard.after()).rejects.toMatchObject({
      message: expect.stringContaining(`1 master-write lease(s) left open in ${testPath}`),
      cause: { name: "AggregateError", errors: [reapError] },
    });
    expect(attempted).toBe(true);
  }
});

it("accepts rejected releases for the fixture with a reap exemption", async () => {
  const guard = await guardHarness("test/hermes-memory-bridge/process-shell.test.ts");
  let attempted = false;
  await guard.observer(async () => ({ async release() { attempted = true; throw new Error("fixture release rejection"); } }), "expected rejecting acquisition stack");
  await expect(guard.after()).resolves.toBeUndefined();
  expect(attempted).toBe(true);
});
