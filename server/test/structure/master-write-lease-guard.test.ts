import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it } from "vitest";
import config from "../../vitest.config.js";

const serverRoot = fileURLToPath(new URL("../../", import.meta.url));
// Thirty seconds bounds each fixture child so a broken guard cannot hang its parent.
const childTimeoutMs = 30_000;
const scenarios = ["leaked", "released", "failed-teardown"] as const;
const fixtureTimeoutMs = childTimeoutMs * scenarios.length;

it("reaps and reports unclosed leases after file teardown while accepting released leases", async () => {
  expect(config.test?.setupFiles).toEqual([
    "./test/setup/keychain-fake.ts",
    "./test/setup/homedir-follows-env.ts",
    "./test/setup/master-write-leases.ts",
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
  if (${name === "failed-teardown"}) throw new Error("fixture teardown failure");
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
      if (name === "failed-teardown") expect(output).toContain("fixture teardown failure");
      const socketPath = await readFile(socketRecord, "utf8");
      await expect(stat(socketPath)).rejects.toMatchObject({ code: "ENOENT" });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}, fixtureTimeoutMs);
