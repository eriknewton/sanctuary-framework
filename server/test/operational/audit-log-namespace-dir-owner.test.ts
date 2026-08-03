import { mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
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
      ...extra,
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

  it("does not chown when the namespace directory already exists", async () => {
    const { storage } = await makeStorage();
    await mkdir(storage.namespacePath("_audit"), { recursive: true, mode: 0o700 });
    const calls: DirChainChownCall[] = [];
    const log = new AuditLog(storage, generateRandomKey(), configWithRecorder(calls));

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
