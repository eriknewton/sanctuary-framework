import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  type CrossProcessLockOptions,
  withPathLock,
} from "../../src/storage/cross-process-lock.js";

const supported = process.platform === "darwin" || process.platform === "linux";
const LOCK_FILE = ".kernel-hook-await.lock";
const TEST_LOCK_TIMEOUT_MS = 1_000;
const TEST_LOCK_RETRY_MS = 10;
// 30 = three TEST_LOCK_RETRY_MS ticks, enough to observe that acquire is held.
const HOOK_HOLD_MS = TEST_LOCK_RETRY_MS * 3;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function deferred<T = void>(): {
  promise: Promise<T>;
  resolve: (value: T | PromiseLike<T>) => void;
  reject: (error: unknown) => void;
} {
  let resolve!: (value: T | PromiseLike<T>) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe.skipIf(!supported)("kernel lock test hook scheduling", () => {
  let base: string;
  let pending: Promise<unknown>[] = [];
  let releasers: Array<() => void> = [];

  beforeEach(async () => {
    base = await mkdtemp(join(tmpdir(), "kernel-hook-await-"));
    pending = [];
    releasers = [];
  });

  afterEach(async () => {
    for (const release of releasers.splice(0)) release();
    await Promise.allSettled(pending.splice(0));
    await rm(base, { recursive: true, force: true });
  });

  function track<T>(promise: Promise<T>, release?: () => void): Promise<T> {
    pending.push(promise);
    if (release) releasers.push(release);
    return promise;
  }

  it("awaits the async socket-acquired hook before entering the lock body", async () => {
    const hookEntered = deferred();
    const releaseHook = deferred();
    let operationRan = false;
    let releaseHookOnce = false;
    const release = (): void => {
      if (releaseHookOnce) return;
      releaseHookOnce = true;
      releaseHook.resolve();
    };
    const acquired = track(
      withPathLock(
        join(base, "state"),
        LOCK_FILE,
        async () => {
          operationRan = true;
          return "entered";
        },
        {
          kernelBacked: true,
          timeoutMs: TEST_LOCK_TIMEOUT_MS,
          retryMs: TEST_LOCK_RETRY_MS,
          __testAfterKernelSocketAcquired: async () => {
            hookEntered.resolve();
            await releaseHook.promise;
          },
        },
      ),
      release,
    );

    await hookEntered.promise;
    const beforeRelease = await Promise.race([
      acquired.then(() => "settled" as const),
      sleep(HOOK_HOLD_MS).then(() => "pending" as const),
    ]);
    expect(beforeRelease).toBe("pending");
    expect(operationRan).toBe(false);

    release();
    await expect(acquired).resolves.toBe("entered");
    expect(operationRan).toBe(true);
  });

  it("uses a guarded hook read so an absent hook adds no await site", async () => {
    const source = await readFile(
      fileURLToPath(new URL("../../src/storage/cross-process-lock.ts", import.meta.url)),
      "utf8",
    );
    expect(source).toContain(
      "const hook = options.__testAfterKernelSocketAcquired;\n" +
        "      if (hook !== undefined) await hook(socketPath);",
    );
    expect(source).not.toContain("await options.__testAfterKernelSocketAcquired?.(socketPath)");

    let operationRan = false;
    const options: CrossProcessLockOptions = {
      kernelBacked: true,
      timeoutMs: TEST_LOCK_TIMEOUT_MS,
      retryMs: TEST_LOCK_RETRY_MS,
    };

    await withPathLock(
      join(base, "state"),
      LOCK_FILE,
      async () => {
        operationRan = true;
      },
      options,
    );
    expect(operationRan).toBe(true);
  });
});
