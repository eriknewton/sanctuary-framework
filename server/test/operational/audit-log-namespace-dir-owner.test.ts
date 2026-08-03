import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { generateRandomKey } from "../../src/core/random.js";
import { AuditLog, type AuditLogConfig } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

type DirChainChownCall = {
  firstCreated: string;
  leafDir: string;
  owner: { uid: number; gid: number };
};

const OWNER = { uid: 1234, gid: 5678 };

describe("AuditLog namespace directory create owner", () => {
  const dirs: string[] = [];

  afterEach(async () => {
    for (const d of dirs.splice(0)) {
      await rm(d, { recursive: true, force: true });
    }
  });

  async function makeStorage(pathSuffix: string[] = ["state"]) {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-dir-owner-"));
    dirs.push(root);
    const storagePath = join(root, ...pathSuffix);
    const storage = new FilesystemStorage(storagePath);
    return { root, storage, storagePath };
  }

  async function appendOne(log: AuditLog): Promise<void> {
    await log.append("l1", "egress_allowed", "id-1", { n: 1 });
    await log.flush();
  }

  async function pathExists(path: string): Promise<boolean> {
    try {
      await stat(path);
      return true;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw err;
    }
  }

  function isAncestorOrSelf(candidate: string, leaf: string): boolean {
    const rel = relative(resolve(candidate), resolve(leaf));
    return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
  }

  function configWithRecorder(
    calls: DirChainChownCall[],
    extra: Partial<AuditLogConfig> = {},
  ): AuditLogConfig {
    return {
      integrityMode: "lenient",
      createOwner: OWNER,
      createOwnerChown: async () => undefined,
      createOwnerChownDirChain: async (firstCreated, leafDir, owner) => {
        calls.push({ firstCreated, leafDir, owner });
      },
      // The chown seam above only RECORDS (no real chown to a foreign uid is
      // possible unprivileged), so later lock acquisitions in the same test
      // must see a healthy chain by default; ownership-drift tests override
      // this with a stateful fake.
      namespaceDirLstat: async () => healthyStats(),
      ...extra,
    };
  }

  /** Fake lstat results for the pre-existing-chain ownership check. */
  function fakeStats(
    uid: number,
    gid: number,
    opts: { symlink?: boolean; dir?: boolean } = {},
  ) {
    return {
      uid,
      gid,
      isSymbolicLink: () => opts.symlink ?? false,
      isDirectory: () => opts.dir ?? true,
    };
  }

  function healthyStats() {
    return fakeStats(OWNER.uid, OWNER.gid);
  }

  /**
   * Path-aware lstat fake for the upward ownership walk. Any path NOT listed
   * is healthy (operator-owned) so the walk terminates at a boundary rather
   * than chasing ownership to the runaway cap. `state` is mutable so a test
   * can flip the chain to healthy after the repair seam runs (models the real
   * repair actually fixing ownership across successive lock acquisitions).
   */
  function treeLstat(state: {
    rootOwned?: Set<string>;
    gidDrift?: Set<string>;
    foreign?: Set<string>;
    symlink?: Set<string>;
    onStat?: (path: string) => void;
  }) {
    return async (path: string) => {
      state.onStat?.(path);
      if (state.symlink?.has(path)) {
        return fakeStats(OWNER.uid, OWNER.gid, { symlink: true });
      }
      if (state.foreign?.has(path)) return fakeStats(4321, 4321);
      if (state.rootOwned?.has(path)) return fakeStats(0, 0);
      if (state.gidDrift?.has(path)) return fakeStats(OWNER.uid, 9999);
      return healthyStats();
    };
  }

  it("chowns the created namespace directory chain", async () => {
    const { root, storage, storagePath } = await makeStorage(["a", "b", "state"]);
    const leafDir = storage.namespacePath("_audit");
    const missingBefore = [
      join(root, "a"),
      join(root, "a", "b"),
      storagePath,
      leafDir,
    ];
    for (const path of missingBefore) {
      await expect(pathExists(path)).resolves.toBe(false);
    }

    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(storage, generateRandomKey(), configWithRecorder(calls));

    await appendOne(log);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      firstCreated: expect.any(String),
      leafDir,
      owner: OWNER,
    });
    expect(isAncestorOrSelf(calls[0]!.firstCreated, leafDir)).toBe(true);
    expect(missingBefore.map((path) => resolve(path))).toContain(
      resolve(calls[0]!.firstCreated),
    );
  });

  it("does not chown when the namespace directory already exists and is healthy", async () => {
    const { storage } = await makeStorage();
    await mkdir(storage.namespacePath("_audit"), { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        namespaceDirLstat: async () => healthyStats(),
      }),
    );

    await appendOne(log);

    expect(calls).toEqual([]);
  });

  it("does not chown a created namespace directory without createOwner", async () => {
    const { storage } = await makeStorage();
    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(storage, generateRandomKey(), {
      integrityMode: "lenient",
      createOwnerChownDirChain: async (firstCreated, leafDir, owner) => {
        calls.push({ firstCreated, leafDir, owner });
      },
    });

    await appendOne(log);

    expect(calls).toEqual([]);
  });

  it("fails closed when the created namespace directory chain chown fails", async () => {
    const { storage } = await makeStorage();
    const refused = new Error("chown refused");
    const log = new AuditLog(storage, generateRandomKey(), {
      integrityMode: "lenient",
      createOwner: OWNER,
      createOwnerChown: async () => undefined,
      createOwnerChownDirChain: async () => {
        throw refused;
      },
    });

    await expect(log.append("l1", "egress_allowed", "id-1", { n: 1 })).rejects.toBe(
      refused,
    );
  });

  it("repairs a pre-existing root-owned namespace chain instead of proceeding silently", async () => {
    // Gate F2 (PR #1084): a failed chain-chown (or a crash between mkdir and
    // chown) leaves the chain root-owned; the NEXT append's mkdir returns
    // undefined, so without the pre-existing-chain check the write proceeds
    // silently and the defect is permanently reinstated for the segment.
    const { storage } = await makeStorage();
    const leafDir = storage.namespacePath("_audit");
    await mkdir(leafDir, { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    // Two-level chain (`<base>/_audit` under `<base>`): both root-owned until
    // the repair seam runs, healthy at the storage root above them.
    const rootOwned = new Set([leafDir, dirname(leafDir)]);
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        namespaceDirLstat: treeLstat({ rootOwned }),
        createOwnerChownDirChain: async (firstCreated, leafDir2, owner) => {
          calls.push({ firstCreated, leafDir: leafDir2, owner });
          rootOwned.clear();
        },
      }),
    );

    await appendOne(log);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      firstCreated: dirname(leafDir),
      leafDir,
      owner: OWNER,
    });
  });

  it("repairs the FULL created chain depth (boot-audit/<fp>/_audit), not just the lower two", async () => {
    // Re-gate F2-deep: a deep first-ever namespace creates three levels at
    // once, so a crash mid-handback can leave the topmost (`boot-audit`)
    // root-owned while a two-level recheck would repair only the lower pair,
    // leaving the operator locked out one level up. The walk must ascend the
    // whole contiguous root-owned run to the first operator-owned ancestor.
    const { root, storage } = await makeStorage(["boot-audit", "fp"]);
    const leafDir = storage.namespacePath("_audit"); // <root>/boot-audit/fp/_audit
    await mkdir(leafDir, { recursive: true, mode: 0o700 });
    const bootAudit = join(root, "boot-audit");
    const fp = join(root, "boot-audit", "fp");
    const calls: DirChainChownCall[] = [];
    const rootOwned = new Set([leafDir, fp, bootAudit]);
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        namespaceDirLstat: treeLstat({ rootOwned }),
        createOwnerChownDirChain: async (firstCreated, leafDir2, owner) => {
          calls.push({ firstCreated, leafDir: leafDir2, owner });
          rootOwned.clear();
        },
      }),
    );

    await appendOne(log);

    expect(calls).toHaveLength(1);
    // Topmost repair target is `boot-audit` (the third level up), so
    // chownCreatedDirChain repairs boot-audit, fp, and _audit in one pass.
    expect(calls[0]).toEqual({ firstCreated: bootAudit, leafDir, owner: OWNER });
  });

  it("refuses rather than chase ownership to the filesystem root", async () => {
    // A deviating run with no healthy operator-owned ancestor before the
    // runaway cap is pathological (e.g. a root-owned fortress, repair-custody's
    // job) and must REFUSE, never seize directories up toward `/`.
    const { storage } = await makeStorage();
    const leafDir = storage.namespacePath("_audit");
    await mkdir(leafDir, { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        // EVERY ancestor reads root-owned: no healthy boundary exists.
        namespaceDirLstat: async () => fakeStats(0, 0),
      }),
    );

    await expect(
      log.append("l1", "egress_allowed", "id-1", { n: 1 }),
    ).rejects.toThrow(/filesystem root|refusing to write audit entries/);
    expect(calls).toEqual([]);
  });

  it("repairs only from the topmost drifted directory (leaf gid drift)", async () => {
    const { storage } = await makeStorage();
    const leafDir = storage.namespacePath("_audit");
    await mkdir(leafDir, { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    let repaired = false;
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        namespaceDirLstat: async (path: string) =>
          !repaired && path === leafDir
            ? fakeStats(OWNER.uid, 9999)
            : healthyStats(),
        createOwnerChownDirChain: async (firstCreated, leafDir2, owner) => {
          calls.push({ firstCreated, leafDir: leafDir2, owner });
          repaired = true;
        },
      }),
    );

    await appendOne(log);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ firstCreated: leafDir, leafDir, owner: OWNER });
  });

  it("refuses loudly when a pre-existing namespace directory has a foreign owner", async () => {
    const { storage } = await makeStorage();
    await mkdir(storage.namespacePath("_audit"), { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder(calls, {
        namespaceDirLstat: async () => fakeStats(4321, 4321),
      }),
    );

    await expect(
      log.append("l1", "egress_allowed", "id-1", { n: 1 }),
    ).rejects.toThrow(/owned by uid 4321/);
    expect(calls).toEqual([]);
  });

  it("refuses loudly when a pre-existing namespace directory is a symlink", async () => {
    const { storage } = await makeStorage();
    await mkdir(storage.namespacePath("_audit"), { recursive: true, mode: 0o700 });
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder([], {
        namespaceDirLstat: async () => fakeStats(OWNER.uid, OWNER.gid, { symlink: true }),
      }),
    );

    await expect(
      log.append("l1", "egress_allowed", "id-1", { n: 1 }),
    ).rejects.toThrow(/not a plain directory/);
  });

  it("executes the ownership check and short-circuits at the first healthy ancestor", async () => {
    // Proves the check RUNS (a check that never executes is not a check): the
    // lstat seam is consulted for the namespace dir. In the healthy case the
    // walk stops at the FIRST healthy ancestor (the leaf itself), so it does
    // exactly one lstat -- the cheap common-case path.
    const { storage } = await makeStorage();
    const leafDir = storage.namespacePath("_audit");
    await mkdir(leafDir, { recursive: true, mode: 0o700 });
    const statted: string[] = [];
    const log = new AuditLog(
      storage,
      generateRandomKey(),
      configWithRecorder([], {
        namespaceDirLstat: treeLstat({ onStat: (path) => statted.push(path) }),
      }),
    );

    await appendOne(log);

    expect(statted).toContain(leafDir);
    // Healthy leaf -> the walk breaks immediately, never ascending to the
    // parent (no wasted lstats when the tree is already clean).
    expect(statted).not.toContain(dirname(leafDir));
  });

  it("uses the default directory-chain chown wiring", async () => {
    const { storage } = await makeStorage();
    const leafDir = storage.namespacePath("_audit");
    const uid = process.getuid!();
    const gid = process.getgid!();
    const log = new AuditLog(storage, generateRandomKey(), {
      integrityMode: "lenient",
      createOwner: { uid, gid },
    });

    await appendOne(log);

    await expect(stat(leafDir).then((s) => s.isDirectory())).resolves.toBe(true);
  });
});
