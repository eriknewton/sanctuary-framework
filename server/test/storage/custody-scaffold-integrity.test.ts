import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { constants, type Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import {
  acquireMasterWriteBarrier,
  assertStorageMasterWriteBarrierHeld,
  CrossProcessLockError,
  type MasterWriteBarrierLease,
  type MasterWriteBarrierOptions,
} from "../../src/storage/cross-process-lock.js";
import { establishMaster } from "../../src/core/master-custody.js";
import { unlockLocalFortress } from "../../src/cli/local-fortress-unlock.js";
import { withExitAdmissionLock } from "../../src/storage/exit-import-journal.js";

const injection = vi.hoisted(() => ({
  beforeOpen: undefined as undefined | ((path: string) => Promise<void>),
  beforeParentOpen: undefined as undefined | ((path: string) => Promise<void>),
  runtimePlatform: undefined as NodeJS.Platform | undefined,
  beforeLstat: undefined as undefined | ((path: string) => Promise<void>),
  afterStat: undefined as undefined | ((stats: Stats) => Stats),
  chmodFailure: false,
  handles: [] as FileHandle[],
  createServer: vi.fn(),
}));

vi.mock("node:os", async (importOriginal) => {
  const os = await importOriginal<typeof import("node:os")>();
  return { ...os, platform: () => injection.runtimePlatform ?? os.platform() };
});

vi.mock("node:net", async (importOriginal) => {
  const net = await importOriginal<typeof import("node:net")>();
  return { ...net, createServer: injection.createServer.mockImplementation(net.createServer) };
});
vi.mock("node:fs/promises", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...fs,
    open: async (...args: Parameters<typeof fs.open>) => {
      const path = String(args[0]);
      const scaffold = path.endsWith(".reaper") || path.endsWith(".reader-reaper");
      if (scaffold && args[1] === (constants.O_RDWR | (constants.O_NOFOLLOW ?? 0))) {
        await injection.beforeOpen?.(path);
      }
      const parentOpen = args[1] === (constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_DIRECTORY ?? 0));
      if (parentOpen) await injection.beforeParentOpen?.(path);
      const handle = await fs.open(...args);
      if (parentOpen) injection.handles.push(handle);
      if (!scaffold) return handle;
      injection.handles.push(handle);
      return new Proxy(handle, {
        get(target, property) {
          if (property === "stat") return async () => {
            const stats = await target.stat();
            return injection.afterStat?.(stats) ?? stats;
          };
          if (property === "chmod" && injection.chmodFailure) return async () => {
            throw Object.assign(new Error("injected repair refusal"), { code: "EPERM" });
          };
          const value = Reflect.get(target, property, target);
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    },
    lstat: async (...args: Parameters<typeof fs.lstat>) => {
      await injection.beforeLstat?.(String(args[0]));
      return fs.lstat(...args);
    },
  };
});

const fs = await vi.importActual<typeof import("node:fs/promises")>("node:fs/promises");
const PRIVATE_DIRECTORY_MODE = 0o700; // Owner rwx; no group or other access.
const PRIVATE_FILE_MODE = 0o600; // Owner rw; no group or other access.
const UNSAFE_FILE_MODE = 0o660; // Adds group rw, outside the secure and legacy shapes.
const LEGACY_FILE_MODE = 0o644; // The historical owner-rw, publicly readable scaffold.
const WORLD_WRITABLE_DIRECTORY_MODE = 0o777; // Owner, group and other rwx, without sticky.
const GROUP_WRITABLE_DIRECTORY_MODE = 0o770; // Owner and group rwx, without sticky.
const DIRECTORY_CHANGES = ["tree changed mid-check", "parent changed before binding", "parent rebound before creation", "parent rebound during creation"] as const;
const NAMESPACE = "_meta";
const BARRIER = "scaffold-integrity-test";
const SUFFIXES = [".reaper", ".reader-reaper"] as const;
const MODES = ["inert", "read-only"] as const;
const SHAPES = ["hardlink", "symlink", "wrong mode", "nonzero size", "directory", "substituted inode"] as const;

// All races are ordered by awaited filesystem interception, never by timers.
describe.runIf(process.platform === "linux" || process.platform === "darwin")(
  "custody scaffold integrity never degrades",
  () => {
    let root: string;
    let fortress: string;
    let previousRoot: string | undefined;
    let storage: FilesystemStorage;
    let leases: MasterWriteBarrierLease[];

    beforeEach(async () => {
      leases = [];
      injection.handles = [];
      injection.createServer.mockClear();
      previousRoot = process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
      const parent = process.platform === "darwin" ? "/private/tmp" : tmpdir();
      root = await fs.mkdtemp(join(parent, "si-"));
      process.env.SANCTUARY_CUSTODY_LOCK_ROOT = root;
      fortress = await fs.mkdtemp(join(parent, "sf-"));
      storage = new FilesystemStorage(join(fortress, "state"));
    });

    afterEach(async () => {
      injection.beforeParentOpen = undefined;
      injection.runtimePlatform = undefined;
      injection.beforeOpen = undefined;
      injection.beforeLstat = undefined;
      injection.afterStat = undefined;
      injection.chmodFailure = false;
      try {
        await Promise.all(leases.map((lease) => lease.release()));
      } finally {
        try {
          await Promise.allSettled(injection.handles.map((handle) => handle.close()));
        } finally {
          if (previousRoot === undefined) delete process.env.SANCTUARY_CUSTODY_LOCK_ROOT;
          else process.env.SANCTUARY_CUSTODY_LOCK_ROOT = previousRoot;
          await Promise.all([
            fs.rm(root, { recursive: true, force: true }),
            fs.rm(fortress, { recursive: true, force: true }),
          ]);
        }
      }
    });

    async function acquire(options: MasterWriteBarrierOptions = {}) {
      const lease = await acquireMasterWriteBarrier(storage, NAMESPACE, BARRIER, options);
      leases.push(lease); // Even an unexpected degraded success must be released on failure.
      return lease;
    }

    async function assertNoAdmission() {
      expect(leases).toHaveLength(0);
      expect(injection.createServer).not.toHaveBeenCalled();
      expect((await fs.readdir(root)).filter((name) => name.endsWith(".sock"))).toEqual([]);
      expect(injection.handles.every((handle) => handle.fd === -1)).toBe(true);
    }

    function plant(suffix: string, shape: typeof SHAPES[number]) {
      injection.beforeOpen = async (path) => {
        if (!path.endsWith(suffix)) return;
        if (shape === "hardlink") await fs.link(path, join(fortress, "extra-link"));
        if (shape === "wrong mode") await fs.chmod(path, UNSAFE_FILE_MODE);
        if (shape === "nonzero size") await fs.writeFile(path, "not inert");
        if (shape === "symlink" || shape === "directory") {
          await fs.unlink(path);
          if (shape === "symlink") await fs.symlink(join(fortress, "missing"), path);
          else await fs.mkdir(path, { mode: PRIVATE_DIRECTORY_MODE });
        }
      };
      if (shape === "substituted inode") injection.beforeLstat = async (path) => {
        if (!path.endsWith(suffix)) return;
        const original = join(fortress, "original-inode");
        await fs.rename(path, original);
        await fs.writeFile(path, "", { flag: "wx", mode: PRIVATE_FILE_MODE });
        expect((await fs.lstat(original)).nlink).toBe(1); // The renamed inode remains linked.
        expect((await fs.lstat(original)).ino).not.toBe((await fs.lstat(path)).ino);
      };
    }

    for (const degradeOnEnvironmentalLoss of MODES) {
      for (const change of DIRECTORY_CHANGES) {
        it(`refuses ${change} with ${degradeOnEnvironmentalLoss} intent`, async () => {
          const parent = join(root, "parent");
          const original = join(root, "original");
          await fs.mkdir(parent, { mode: PRIVATE_DIRECTORY_MODE });
          const canonicalParent = await fs.realpath(parent);
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = join(parent, "locks");
          let changed = false;
          const substitute = async (symlink = false) => {
            expect(changed).toBe(false);
            changed = true;
            await fs.rename(parent, original);
            if (symlink) await fs.symlink(original, parent);
            else await fs.mkdir(parent, { mode: PRIVATE_DIRECTORY_MODE });
          };
          if (change === "parent changed before binding") {
            injection.beforeParentOpen = async (path) => {
              if (path === canonicalParent) await substitute();
            };
          } else {
            // Exercise the canonical-path branch on either host. Filesystem locality
            // still uses the actual host through __testPlatform below; this is not a Darwin drill.
            if (change !== "tree changed mid-check") injection.runtimePlatform = "darwin";
            let parentChecks = 0;
            // Ancestry, pre-create and post-create are the three ordered parent observations.
            const targetCheck = change === "tree changed mid-check" ? 1
              : change === "parent rebound before creation" ? 2 : 3;
            injection.beforeLstat = async (path) => {
              if (path !== canonicalParent) return;
              parentChecks += 1;
              if (parentChecks === targetCheck) await substitute(change === "tree changed mid-check");
            };
          }
          const expectedMessage = {
            "tree changed mid-check": "not a non-symlink directory",
            "parent changed before binding": "changed between verification and binding",
            "parent rebound before creation": "rebound before leaf creation",
            "parent rebound during creation": "rebound during leaf creation",
          }[change];
          await expect(acquire({ degradeOnEnvironmentalLoss, __testPlatform: process.platform })).rejects.toMatchObject({
            kind: "scaffold-integrity", message: expect.stringContaining(expectedMessage),
          });
          expect(changed).toBe(true);
          await assertNoAdmission();
          // Inspect both directory identities, including any leaf, for leaked sockets.
          const entries = await fs.readdir(root, { recursive: true });
          expect(entries.filter((name) => name.endsWith(".sock"))).toEqual([]);
        });
      }

      for (const mode of [WORLD_WRITABLE_DIRECTORY_MODE, GROUP_WRITABLE_DIRECTORY_MODE]) {
        it(`keeps parent mode ${mode.toString(8)} environmental with ${degradeOnEnvironmentalLoss} intent`, async () => {
          const parent = join(root, "parent");
          await fs.mkdir(parent, { mode: PRIVATE_DIRECTORY_MODE });
          await fs.chmod(parent, mode);
          process.env.SANCTUARY_CUSTODY_LOCK_ROOT = join(parent, "locks");
          // First pin the classification without degradation, then exercise caller intent.
          await expect(acquire()).rejects.toMatchObject({ kind: "capability", message: expect.stringContaining("writable") });
          const lease = await acquire({ degradeOnEnvironmentalLoss });
          expect(lease.socketPath).toBeUndefined();
          expect(injection.createServer).not.toHaveBeenCalled();
          expect(() => lease.assertSessionHeld()).not.toThrow();
          if (degradeOnEnvironmentalLoss === "inert") expect(() => lease.assertHeld()).not.toThrow();
          else expect(() => lease.assertHeld()).toThrow(/writable/);
          expect((await fs.readdir(root, { recursive: true })).filter((name) => name.endsWith(".sock"))).toEqual([]);
        });
      }
      for (const suffix of SUFFIXES) {
        for (const shape of SHAPES) {
          it(`refuses ${suffix} ${shape} with ${degradeOnEnvironmentalLoss} intent`, async () => {
            plant(suffix, shape);
            await expect(acquire({ degradeOnEnvironmentalLoss })).rejects.toMatchObject({
              kind: "scaffold-integrity", message: expect.stringContaining("custody lock scaffold"),
            });
            await assertNoAdmission();
          });
        }
      }

      it(`refuses wrong scaffold owner with ${degradeOnEnvironmentalLoss} intent`, async () => {
        // Inject only the descriptor's owner, portable without privileged chown.
        // Adding one selects a uid distinct from the actual owner.
        injection.afterStat = (stats) => Object.assign(stats, { uid: stats.uid + 1 });
        await expect(acquire({ degradeOnEnvironmentalLoss })).rejects.toMatchObject({ kind: "scaffold-integrity" });
        await assertNoAdmission();
      });

      it(`refuses failed mode repair with ${degradeOnEnvironmentalLoss} intent`, async () => {
        injection.beforeOpen = (path) => fs.chmod(path, LEGACY_FILE_MODE);
        injection.chmodFailure = true;
        await expect(acquire({ degradeOnEnvironmentalLoss })).rejects.toMatchObject({
          kind: "scaffold-integrity", message: expect.stringContaining("mode repair failed"),
        });
        await assertNoAdmission();
      });

      it(`refuses an insecure post-repair inode with ${degradeOnEnvironmentalLoss} intent`, async () => {
        injection.beforeOpen = (path) => fs.chmod(path, LEGACY_FILE_MODE);
        injection.afterStat = (stats) => Object.assign(stats, { mode: stats.mode | LEGACY_FILE_MODE });
        await expect(acquire({ degradeOnEnvironmentalLoss })).rejects.toMatchObject({
          kind: "scaffold-integrity", message: expect.stringContaining("did not produce a secure inode"),
        });
        await assertNoAdmission();
      });

      it(`still degrades uid-unavailable capability loss with ${degradeOnEnvironmentalLoss} intent`, async () => {
        const lease = await acquire({ degradeOnEnvironmentalLoss, __testGetuid: () => undefined });
        expect(lease.socketPath).toBeUndefined();
        expect(injection.createServer).not.toHaveBeenCalled();
        expect(() => lease.assertSessionHeld()).not.toThrow();
        if (degradeOnEnvironmentalLoss === "inert") {
          expect(() => lease.assertHeld()).not.toThrow();
          expect(() => assertStorageMasterWriteBarrierHeld(storage)).not.toThrow();
        } else {
          expect(() => lease.assertHeld()).toThrow(CrossProcessLockError);
          expect(() => assertStorageMasterWriteBarrierHeld(storage)).toThrow(/owner identity/);
        }
      });

      for (const legacy of [false, true]) {
        it(`admits a ${legacy ? "repaired legacy" : "secure"} scaffold with ${degradeOnEnvironmentalLoss} intent`, async () => {
          if (legacy) injection.beforeOpen = (path) => fs.chmod(path, LEGACY_FILE_MODE);
          const lease = await acquire({ degradeOnEnvironmentalLoss });
          expect((await fs.lstat(lease.socketPath!)).isSocket()).toBe(true);
          const held = vi.spyOn(lease, "assertHeld");
          assertStorageMasterWriteBarrierHeld(storage);
          expect(held).toHaveBeenCalledOnce();
        });
      }

      it(`master custody propagates scaffold refusal with ${degradeOnEnvironmentalLoss} intent`, async () => {
        plant(".reader-reaper", "hardlink");
        await expect(establishMaster({ storage, barrierDegradeMode: degradeOnEnvironmentalLoss })).rejects.toMatchObject({
          kind: "scaffold-integrity",
        });
        await assertNoAdmission();
      });
    }

    it("refuses environmental capability loss when degradation was not requested", async () => {
      await expect(acquire({ __testGetuid: () => undefined })).rejects.toMatchObject({ kind: "capability" });
      await assertNoAdmission();
    });

    it("keeps unsupported-platform sessions read-only", async () => {
      const lease = await acquire({ __testPlatform: "win32" });
      expect(lease.socketPath).toBeUndefined();
      expect(() => lease.assertSessionHeld()).not.toThrow();
      expect(() => assertStorageMasterWriteBarrierHeld(storage)).toThrow(CrossProcessLockError);
      expect(injection.createServer).not.toHaveBeenCalled();
    });

    it("keeps non-filesystem sessions inert", async () => {
      const lease = await acquireMasterWriteBarrier(new MemoryStorage(), NAMESPACE, BARRIER);
      leases.push(lease);
      expect(lease.socketPath).toBeUndefined();
      expect(() => lease.assertHeld()).not.toThrow();
      expect(injection.createServer).not.toHaveBeenCalled();
    });

    it("local fortress write unlock returns the scaffold refusal before credential access", async () => {
      plant(".reader-reaper", "hardlink");
      const result = await unlockLocalFortress({ storage, storagePath: fortress, writeIntent: true });
      expect(result).toMatchObject({ ok: false, failure: "other", message: expect.stringContaining("custody lock scaffold") });
      await assertNoAdmission();
    });

    it("exit admission preserves the protected operation's scaffold refusal", async () => {
      const failure = new CrossProcessLockError("custody lock scaffold changed during validation", "scaffold-integrity");
      await expect(withExitAdmissionLock(new MemoryStorage(), "import", async () => {
        throw failure;
      })).rejects.toBe(failure);
      await assertNoAdmission();
    });
  },
);
