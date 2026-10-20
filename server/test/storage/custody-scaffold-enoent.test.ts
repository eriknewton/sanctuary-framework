import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { constants } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { spawn, type ChildProcess } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import {
  acquireMasterWriteBarrier,
  type MasterWriteBarrierLease,
} from "../../src/storage/cross-process-lock.js";
import { classifyCustodyLockScaffold } from "../../src/storage/custody-lock-scaffold.js";

const injection = vi.hoisted(() => ({
  beforeOpen: undefined as undefined | ((path: string, flags: string | number | undefined) => Promise<void>),
  beforeLstat: undefined as undefined | ((path: string) => Promise<void>),
  handles: [] as FileHandle[],
}));

// This scoped wrapper exists only in this test module. Production has no hook.
// Real filesystem operations still produce the ENOENT at the exact pathname step.
vi.mock("node:fs/promises", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...fs,
    open: async (...args: Parameters<typeof fs.open>) => {
      const path = String(args[0]);
      await injection.beforeOpen?.(path, args[1]);
      const handle = await fs.open(...args);
      if (path.endsWith(".reaper") || path.endsWith(".reader-reaper")) {
        injection.handles.push(handle);
      }
      return handle;
    },
    lstat: async (...args: Parameters<typeof fs.lstat>) => {
      await injection.beforeLstat?.(String(args[0]));
      return fs.lstat(...args);
    },
  };
});

// Use the unwrapped API for fixture edits and assertions.
const fs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
const SHORT_PARENT = process.platform === "darwin" ? "/private/tmp" : tmpdir();
// Three = initial attempt plus recovery for each of the two pathname windows.
// Must match INERT_LOCK_SCAFFOLD_MAX_ATTEMPTS in src/storage/cross-process-lock.ts.
const SCAFFOLD_ATTEMPTS = 3;
// Two seconds = the production stale-reaper deadline reused as the age floor.
// Must match UNUSED_BARRIER_SCAFFOLD_MIN_AGE_MS in src/storage/cross-process-lock.ts.
const SCAFFOLD_MIN_AGE_MS = 2_000;
// Ten seconds gives a local tsx child time to start, sweep, release and exit.
const CHILD_DEADLINE_MS = 10_000;
const NAMESPACE = "_meta";
const BARRIER = "scaffold-enoent-test";
function stopChildGroup(child: ChildProcess) {
  if (child.pid === undefined) return;
  try {
    // The detached child owns this group, including any in-flight sweep helper.
    process.kill(-child.pid, "SIGKILL");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

const points = [
  { suffix: ".reaper", point: "open" },
  { suffix: ".reader-reaper", point: "open" },
  { suffix: ".reaper", point: "lstat" },
  { suffix: ".reader-reaper", point: "lstat" },
] as const;

describe.runIf(process.platform === "linux" || process.platform === "darwin")(
  "custody scaffold disappearance",
  () => {
    let root: string;
    let fortress: string;
    let previousRoot: string | undefined;
    let storage: FilesystemStorage;
    let leases: MasterWriteBarrierLease[];
    let children: { child: ChildProcess; done: Promise<void> }[];

    beforeEach(async () => {
      previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      leases = [];
      children = [];
      injection.handles = [];
      root = await fs.mkdtemp(join(SHORT_PARENT, "ce-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = root;
      fortress = await fs.mkdtemp(join(SHORT_PARENT, "cf-"));
      storage = new FilesystemStorage(join(fortress, "a", "state"));
    });

    afterEach(async () => {
      injection.beforeOpen = undefined;
      injection.beforeLstat = undefined;
      try {
        await Promise.all(leases.map((lease) => lease.release()));
      } finally {
        try {
          for (const { child } of children) {
            if (child.exitCode === null && child.signalCode === null) stopChildGroup(child);
          }
          await Promise.allSettled(children.map(({ done }) => done));
        } finally {
          if (previousRoot === undefined) delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
          else process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
          // Assertions above detect leaks; cleanup still closes them on failure.
          await Promise.allSettled(
            injection.handles.filter((handle) => handle.fd !== -1).map((handle) => handle.close()),
          );
          await Promise.all([
            fs.rm(root, { recursive: true, force: true }),
            fs.rm(fortress, { recursive: true, force: true }),
          ]);
        }
      }
    });

    async function acquire(degradeOnEnvironmentalLoss?: "inert" | "read-only") {
      const lease = await acquireMasterWriteBarrier(storage, NAMESPACE, BARRIER, {
        degradeOnEnvironmentalLoss,
      });
      leases.push(lease);
      return lease;
    }

    function intercept(
      suffix: string,
      point: "open" | "lstat",
      action: (path: string) => Promise<void>,
    ) {
      if (point === "open") {
        injection.beforeOpen = async (path, flags) => {
          if (path.endsWith(suffix) && flags === (constants.O_RDWR | (constants.O_NOFOLLOW ?? 0))) {
            await action(path);
          }
        };
      } else {
        injection.beforeLstat = async (path) => {
          if (path.endsWith(suffix)) await action(path);
        };
      }
    }

    async function assertNoAdmission() {
      expect(leases).toHaveLength(0);
      expect((await fs.readdir(root)).filter((name) => name.endsWith(".sock"))).toEqual([]);
      expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
    }

    for (const { suffix, point } of points) {
      for (const existing of [false, true]) {
        it(`recreates and validates ${existing ? "existing" : "new"} ${suffix} lost at ${point}`, async () => {
          if (existing) await (await acquire()).release();
          let visits = 0;
          let target = "";
          intercept(suffix, point, async (path) => {
            target = path;
            visits += 1;
            if (visits === 1) await fs.unlink(path);
          });
          const lease = await acquire();
          expect(visits).toBe(2); // One disappearance, then one validated recovery.
          expect(classifyCustodyLockScaffold(await fs.lstat(target), process.getuid!())).toBe("secure");
          expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
          expect((await fs.readdir(root)).some((name) => name.endsWith(".sock"))).toBe(true);
          await lease.release();
        });
      }

      it(`bounds repeated ${suffix} disappearance at ${point} without admission or degradation`, async () => {
        let visits = 0;
        let target = "";
        intercept(suffix, point, async (path) => {
          visits += 1;
          target = path;
          // The descriptor from the previous attempt must close before retry.
          if (point === "open") {
            expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
          } else {
            expect(injection.handles.filter((handle) => handle.fd !== -1)).toHaveLength(1);
          }
          await fs.unlink(path);
        });
        const outcome = acquire("inert");
        await expect(outcome).rejects.toThrow("kept disappearing");
        await expect(outcome).rejects.toMatchObject({
          kind: "io",
          message: expect.stringContaining(target),
        });
        expect(visits).toBe(SCAFFOLD_ATTEMPTS);
        expect(target.endsWith(suffix)).toBe(true);
        await assertNoAdmission();
      });

      it(`preserves a non-ENOENT failure at ${suffix} ${point}`, async () => {
        const failure = Object.assign(new Error("injected access refusal"), { code: "EACCES" });
        let visits = 0;
        intercept(suffix, point, async () => {
          visits += 1;
          throw failure;
        });
        await expect(acquire()).rejects.toBe(failure);
        expect(visits).toBe(1);
        await assertNoAdmission();
      });
    }

    it("uses one shared budget and can succeed on its final attempt", async () => {
      let opens = 0;
      let stats = 0;
      intercept(".reader-reaper", "open", async (path) => {
        opens += 1;
        if (opens === 1) await fs.unlink(path);
      });
      intercept(".reader-reaper", "lstat", async (path) => {
        stats += 1;
        if (stats === 1) await fs.unlink(path);
      });
      await acquire();
      expect(opens).toBe(SCAFFOLD_ATTEMPTS);
      expect(stats).toBe(SCAFFOLD_ATTEMPTS - 1);
      expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
    });

    it.each(["mode", "contents", "hardlink", "symlink", "directory", "identity"] as const)(
      "reruns validation after disappearance and refuses an unsafe %s replacement",
      async (replacement) => {
        let visits = 0;
        let target = "";
        intercept(".reader-reaper", "open", async (path) => {
          target = path;
          visits += 1;
          if (visits === 1) {
            await fs.unlink(path);
            return;
          }
          if (replacement === "mode") await fs.chmod(path, 0o666);
          if (replacement === "contents") await fs.writeFile(path, "not inert");
          if (replacement === "hardlink") await fs.link(path, join(fortress, "extra-link"));
          if (replacement === "symlink" || replacement === "directory") {
            await fs.unlink(path);
            if (replacement === "directory") await fs.mkdir(path);
            else await fs.symlink(join(fortress, "missing"), path);
          }
        });
        if (replacement === "identity") {
          intercept(".reader-reaper", "lstat", async (path) => {
            // Keep the old descriptor alive while substituting a secure new inode.
            await fs.rename(path, join(fortress, "old-inode"));
            await fs.writeFile(path, "", { flag: "wx", mode: 0o600 });
          });
        }
        await expect(acquire()).rejects.toThrow();
        expect(visits).toBe(2); // The replacement is examined on the recovery attempt.
        expect(target).not.toBe("");
        await assertNoAdmission();
      },
    );

    it("repairs a legacy scaffold again on the recovery attempt", async () => {
      let visits = 0;
      let target = "";
      intercept(".reader-reaper", "lstat", async (path) => {
        target = path;
        visits += 1;
        if (visits === 1) {
          await fs.unlink(path);
          // Plant the next attempt's legacy inode only after the real lstat fails.
          injection.beforeOpen = async (nextPath, flags) => {
            if (nextPath === path && flags === "wx") {
              await fs.writeFile(path, "", { mode: 0o644, flag: "wx" });
              await fs.chmod(path, 0o644);
              injection.beforeOpen = undefined;
            }
          };
        }
      });
      await acquire();
      expect(visits).toBe(2);
      expect(classifyCustodyLockScaffold(await fs.lstat(target), process.getuid!())).toBe("secure");
      expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
    });

    it("recovers when another process resolving a different fortress sweeps the paused admission", async () => {
      await (await acquire()).release();
      leases = [];
      const pair = (await fs.readdir(root)).filter((name) => name.endsWith("reaper"));
      expect(pair).toHaveLength(2); // One exclusive and one reader scaffold.
      // Only aging uses a timer. The race itself is ordered by the open wrapper
      // and the child's completion, with actual deletion asserted before resume.
      for (const name of pair) {
        const stat = await fs.lstat(join(root, name));
        while (Date.now() - stat.ctimeMs <= SCAFFOLD_MIN_AGE_MS) {
          // One millisecond crosses the strict floor after rounding up the remainder.
          await delay(Math.ceil(SCAFFOLD_MIN_AGE_MS - (Date.now() - stat.ctimeMs)) + 1);
        }
      }
      let visits = 0;
      intercept(".reader-reaper", "open", async (path) => {
        visits += 1;
        if (visits !== 1) return;
        const script = `
          const { FilesystemStorage } = await import(${JSON.stringify(new URL("../../src/storage/filesystem.ts", import.meta.url).href)});
          const { acquireMasterWriteBarrier } = await import(${JSON.stringify(new URL("../../src/storage/cross-process-lock.ts", import.meta.url).href)});
          const lease = await acquireMasterWriteBarrier(
            new FilesystemStorage(${JSON.stringify(join(fortress, "b", "state"))}),
            ${JSON.stringify(NAMESPACE)}, ${JSON.stringify(BARRIER)});
          try { process.stdout.write("swept"); } finally { await lease.release(); }
        `;
        const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
          env: { ...process.env },
          detached: true,
          stdio: ["ignore", "pipe", "pipe"],
        });
        let output = "";
        let errors = "";
        child.stdout.on("data", (data) => { output += String(data); });
        child.stderr.on("data", (data) => { errors += String(data); });
        const done = new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => stopChildGroup(child), CHILD_DEADLINE_MS);
          child.once("error", (error) => { clearTimeout(timer); reject(error); });
          child.once("close", (code) => {
            clearTimeout(timer);
            if (code === 0) resolve();
            else reject(new Error(`sweep child failed (${code}): ${errors}`));
          });
        });
        children.push({ child, done });
        await done;
        expect(output).toBe("swept");
        for (const name of pair) {
          await expect(fs.lstat(join(root, name))).rejects.toMatchObject({ code: "ENOENT" });
        }
        expect(path.endsWith(".reader-reaper")).toBe(true);
      });
      await acquire();
      expect(visits).toBe(2);
      const reader = (await fs.readdir(root)).find((name) => name.endsWith(".reader-reaper"));
      expect(reader).toBeDefined();
      expect(classifyCustodyLockScaffold(await fs.lstat(join(root, reader!)), process.getuid!())).toBe("secure");
      expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
    });
  },
);
