import { spawn, type ChildProcess } from "node:child_process";
import { createRequire } from "node:module";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, expect, it, vi } from "vitest";

const children: ChildProcess[] = [];
let root: string | undefined;
afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      const exit = once(child, "exit"); child.kill("SIGKILL"); await exit;
    }
  }
  vi.unstubAllEnvs();
  if (root) await rm(root, { recursive: true, force: true });
});

async function worker(cwd: string) {
  const identity = await stat(cwd, { bigint: true });
  const child = spawn(process.execPath, ["--import", createRequire(import.meta.url).resolve("tsx"),
    fileURLToPath(new URL("../../src/storage/directory-capability-worker.ts", import.meta.url)),
    String(identity.dev), String(identity.ino)], {
    cwd, stdio: ["ignore", "ignore", "pipe", "ipc"], env: { ...process.env, HOME: root!, SANCTUARY_STORAGE_PATH: root! },
  });
  children.push(child);
  let stderr = ""; child.stderr?.on("data", (data) => { stderr += String(data); });
  await new Promise<void>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`worker exited before ready: ${code}: ${stderr}`)));
    child.on("message", (message: any) => { if (message.ready) resolve(); });
  });
  let id = 0;
  return async (op: string, args: unknown[], boundNamespace?: true): Promise<any> => {
    const requestId = ++id;
    return new Promise((resolve, reject) => {
      const receive = (message: any) => {
        if (message.id !== requestId) return;
        child.off("message", receive);
        if (message.ok) resolve(message.value);
        else reject(Object.assign(new Error(message.error.message), message.error));
      };
      child.on("message", receive);
      child.send({ id: requestId, op, args, ...(boundNamespace ? { boundNamespace } : {}) });
    });
  };
}

it("runs list and listKeys through both Darwin worker routes with omitted, empty and explicit prefixes", async () => {
  root = await mkdtemp(join(tmpdir(), "directory-keys-")); vi.stubEnv("HOME", root);
  const namespace = "fixture";
  const dir = join(root, namespace);
  await mkdir(dir);
  for (const key of ["a", "a-2", "B"]) await writeFile(join(dir, `${key}.enc`), "fixture");
  for (const bound of [false, true]) {
    const call = await worker(bound ? dir : root);
    for (const prefixArgs of [[], [""], ["a"], ["missing"]]) {
      const args = bound ? prefixArgs : [namespace, ...prefixArgs];
      const metas = await call("list", args, bound ? true : undefined);
      const keys = await call("listKeys", args, bound ? true : undefined);
      expect(keys).toEqual(metas.map((meta: any) => meta.key).sort());
    }
    // Worker errors must cross IPC intact; no substituted empty listing.
    await writeFile(join(dir, "key-!4E2D.enc"), "invalid name");
    for (const op of ["list", "listKeys"]) {
      await expect(call(op, bound ? [] : [namespace], bound ? true : undefined))
        .rejects.toMatchObject({ code: "FILESYSTEM_STORAGE_NAME_UNADDRESSABLE" });
    }
    await rm(join(dir, "key-!4E2D.enc"));
  }
}, 30_000); // Two real worker startups include the production CLI import graph.
