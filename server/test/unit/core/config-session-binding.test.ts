/** Config owners preserve the operator's binding choice across serialized writes. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import * as config from "../../../src/config.js";
import * as locks from "../../../src/storage/cross-process-lock.js";
import { createSanctuaryServer } from "../../../src/index.js";
import { MemoryStorage } from "../../../src/storage/memory.js";
import { createTempFortress, TEST_PASSPHRASE } from "../../helpers/temp-fortress.js";

let fortress: Awaited<ReturnType<typeof createTempFortress>>;
let path: string;
beforeEach(async () => {
  fortress = await createTempFortress("config-session-binding");
  await mkdir(fortress.storagePath, { recursive: true });
  path = join(fortress.storagePath, "sanctuary.json");
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  try {
    expect((await readdir(fortress.storagePath)).filter(name => name.endsWith(".lock"))).toEqual([]);
  } finally {
    await fortress.cleanup();
  }
});
const disk = async () => JSON.parse(await readFile(path, "utf8"));
const write = async (value: unknown) => writeFile(path, JSON.stringify(value));
const update = config.updateFortressConfig;
const boot = async (value: config.SanctuaryConfig) => update(path, "boot", () => value);

it("only the boolean true enables sole binding", async () => {
  for (const session_binding of [undefined, {}, { sole_identity: false }, { sole_identity: true }]) {
    await write({ session_binding });
    const loaded = await config.loadConfig(path);
    expect(loaded.session_binding?.sole_identity === true).toBe(session_binding?.sole_identity === true);
  }
});

it.each(["true", 1, null, [], false])("a wrong-typed flag fails boot without moving the file (%j)", async value => {
  await write({ session_binding: { sole_identity: value === false ? "false" : value } });
  const before = await readFile(path, "utf8");
  await expect(config.loadConfig(path)).rejects.toMatchObject({ classification: "invalid-value" });
  expect(await readFile(path, "utf8")).toBe(before);
  expect(await readdir(fortress.storagePath)).toEqual(["sanctuary.json"]);
});

it.each([null, [], true, "true"])("a non-object binding value remains in place (%j)", async session_binding => {
  await write({ session_binding });
  await expect(config.loadConfig(path)).rejects.toMatchObject({ classification: "invalid-value" });
  expect(await disk()).toEqual({ session_binding });
});

it("boot persistence never writes session_binding", async () => {
  const memory = { ...config.defaultConfig(), session_binding: { sole_identity: true } };
  await boot(memory);
  expect(await disk()).not.toHaveProperty("session_binding");
  await write({ session_binding: { sole_identity: false }, retained: "disk" });
  await boot(memory);
  expect(await disk()).toMatchObject({ session_binding: { sole_identity: false }, retained: "disk" });
});

it("enable then boot", async () => {
  await update(path, "session_binding", () => ({ session_binding: { sole_identity: true } }));
  await boot(await config.loadConfig(path));
  expect((await disk()).session_binding).toEqual({ sole_identity: true });
});

it("boot loads true, operator disables, boot persists: the file reads false", async () => {
  await write({ session_binding: { sole_identity: true } });
  const loaded = await config.loadConfig(path);
  await write({ session_binding: { sole_identity: false } });
  vi.spyOn(config, "loadConfig").mockResolvedValue(loaded);
  const server = await createSanctuaryServer({ storage: new MemoryStorage(), passphrase: TEST_PASSPHRASE });
  try {
    expect((await disk()).session_binding).toEqual({ sole_identity: false });
  } finally {
    await server.cleanup();
  }
  expect((await disk()).session_binding).toEqual({ sole_identity: false });
});

it("disable holding the lock while boot waits", async () => {
  const realLock = locks.withPathLock;
  let contended!: () => void;
  const contention = new Promise<void>(resolve => { contended = resolve; });
  vi.spyOn(locks, "withPathLock").mockImplementation((dir, name, op, options) =>
    realLock(dir, name, op, { ...options, onContended: contended }));
  let entered!: () => void;
  let release!: () => void;
  const held = new Promise<void>(resolve => { entered = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  const disabling = update(path, "session_binding", async () => {
    entered();
    await gate;
    return { session_binding: { sole_identity: false } };
  });
  let persisting: Promise<void> | undefined;
  try {
    await held;
    persisting = boot({ ...config.defaultConfig(), session_binding: { sole_identity: true } });
    await contention;
  } finally {
    release();
    await disabling;
    await persisting;
  }
  expect((await disk()).session_binding).toEqual({ sole_identity: false });
});

it("two CLI writers race: both keys survive", async () => {
  const module = new URL("../../../src/config.ts", import.meta.url).href;
  const children: ChildProcess[] = [];
  const exits: Promise<unknown>[] = [];
  let timer!: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("config writer deadline exceeded")), locks.CROSS_PROCESS_LOCK_TIMEOUT_MS);
  });
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  let acquired!: () => void;
  const acquiredPromise = new Promise<void>(resolve => { acquired = resolve; });
  const holder = locks.withPathLock(fortress.storagePath, config.FORTRESS_CONFIG_LOCK, async () => { acquired(); await held; });
  try {
    await Promise.race([acquiredPromise, holder, deadline]);
    const results = ["boot", "session_binding"].map(owner => {
      // Each writer reports contention from the helper's own lock acquisition, so both are proven to wait inside it.
      const program = `
        import { updateFortressConfig } from ${JSON.stringify(module)};
        const path = ${JSON.stringify(path)};
        await updateFortressConfig(path, ${JSON.stringify(owner)}, disk => ({ ...disk, ${owner === "boot" ? 'writer: "boot"' : 'session_binding: { sole_identity: true }'} }),
          { onContended: () => process.send?.("contended") });
      `;
      const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "--eval", program], {
        env: { ...process.env, HOME: join(fortress.home, "child-home"), SANCTUARY_STORAGE_PATH: fortress.storagePath },
        stdio: ["ignore", "pipe", "pipe", "ipc"],
      });
      let stderr = "";
      child.stderr?.on("data", chunk => { stderr += chunk; });
      children.push(child);
      const exited = once(child, "exit");
      exits.push(exited);
      const contended = Promise.race([
        once(child, "message"),
        exited.then(() => { throw new Error(`config writer exited before contention: ${stderr}`); }),
      ]);
      return { contended, exited, stderr: () => stderr };
    });
    await Promise.race([Promise.all(results.map(result => result.contended)), deadline]);
    release();
    await holder;
    await Promise.race([Promise.all(results.map(result => result.exited)), deadline]);
    for (const result of results) expect((await result.exited)[0], result.stderr()).toBe(0);
    expect(await disk()).toMatchObject({ writer: "boot", session_binding: { sole_identity: true } });
  } finally {
    clearTimeout(timer);
    release();
    try {
      await holder;
    } finally {
      for (const child of children) if (child.exitCode === null) child.kill("SIGKILL");
      await Promise.allSettled(exits);
    }
  }
});

it("no src caller of saveConfig remains", async () => {
  const root = new URL("../../../src/", import.meta.url);
  const files = await readdir(root, { recursive: true });
  const callers: string[] = [];
  for (const file of files.filter(file => file.endsWith(".ts") && file !== "config.ts")) {
    if (/\bsaveConfig\s*\(/.test(await readFile(new URL(file, root), "utf8"))) callers.push(file);
  }
  expect(callers).toEqual([]);
});

it.each(["{", "[]", '{"session_binding":null}'])("invalid locked input writes nothing (%s)", async raw => {
  await writeFile(path, raw);
  await expect(update(path, "boot", () => config.defaultConfig())).rejects.toThrow();
  expect(await readFile(path, "utf8")).toBe(raw);
});

it("config lock timeout preserves the file", async () => {
  await write({ keep: true });
  const lockPath = join(fortress.storagePath, config.FORTRESS_CONFIG_LOCK);
  await writeFile(lockPath, "holder");
  const realNow = Date.now();
  vi.spyOn(Date, "now").mockReturnValueOnce(realNow).mockReturnValue(realNow + locks.CROSS_PROCESS_LOCK_TIMEOUT_MS);
  try {
    await expect(update(path, "boot", () => ({}))).rejects.toBeInstanceOf(locks.CrossProcessLockError);
    expect(await disk()).toEqual({ keep: true });
    expect(await readFile(lockPath, "utf8")).toBe("holder");
  } finally {
    const { unlink } = await import("node:fs/promises");
    await unlink(lockPath);
  }
});

it("writes config with owner-only permissions", async () => {
  await update(path, "session_binding", () => ({ session_binding: { sole_identity: true }, ignored: true }));
  expect(await disk()).not.toHaveProperty("ignored");
  // Unix permission bits occupy the low nine bits.
  expect((await stat(path)).mode & 0o777).toBe(0o600);
});
