import { describe, expect, it } from "vitest";
import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import type { Stats } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Writable } from "node:stream";

import {
  REPAIR_CUSTODY_EXIT_ALREADY_CLEAN,
  REPAIR_CUSTODY_EXIT_CHANGED,
  REPAIR_CUSTODY_EXIT_FAILED,
  REPAIR_CUSTODY_EXIT_REFUSED,
  parseRepairCustodyArgs,
  runRepairCustody,
  type RepairCustodyContext,
} from "../../src/cli/castle-wall-custody.js";
import {
  CUSTODY_REPAIR_MANIFEST_KIND,
  parseCustodyRepairManifest,
  type FortressCustodyFsOps,
} from "../../src/castle-wall/provision/fortress-custody.js";

class CaptureStream extends Writable {
  chunks: string[] = [];
  override _write(chunk: unknown, _encoding: BufferEncoding, callback: (error?: Error | null) => void): void {
    this.chunks.push(String(chunk));
    callback();
  }
  text(): string {
    return this.chunks.join("");
  }
}

interface FakeNode {
  type: "dir" | "file" | "socket" | "symlink";
  uid: number;
  gid: number;
  mode: number;
  ino: number;
}

function fakeStats(node: FakeNode): Stats {
  return {
    isDirectory: () => node.type === "dir",
    isFile: () => node.type === "file",
    isSocket: () => node.type === "socket",
    isSymbolicLink: () => node.type === "symlink",
    uid: node.uid,
    gid: node.gid,
    mode: node.mode,
    dev: 1,
    ino: node.ino,
  } as unknown as Stats;
}

function enoent(): NodeJS.ErrnoException {
  const err = new Error("ENOENT") as NodeJS.ErrnoException;
  err.code = "ENOENT";
  return err;
}

function makeFakeOps(
  nodes: Record<string, FakeNode>,
  children: Record<string, string[]>,
): { ops: FortressCustodyFsOps; nodes: Map<string, FakeNode> } {
  const nodeMap = new Map(Object.entries(nodes));
  const childMap = new Map(Object.entries(children));
  return {
    nodes: nodeMap,
    ops: {
      lstat: async (path) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        return fakeStats(node);
      },
      readdir: async (path) => {
        if (!nodeMap.has(path)) throw enoent();
        return childMap.get(path) ?? [];
      },
      lchown: async (path, uid, gid) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        node.uid = uid;
        node.gid = gid;
      },
      chmod: async (path, mode) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        node.mode = mode;
      },
      open: async (path) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        return {
          stat: async () => fakeStats(node),
          chown: async (uid: number, gid: number) => {
            node.uid = uid;
            node.gid = gid;
          },
          chmod: async (mode: number) => {
            node.mode = mode;
          },
          close: async () => undefined,
        };
      },
    },
  };
}

function rootOwnedFortress(): { ops: FortressCustodyFsOps; nodes: Map<string, FakeNode> } {
  return makeFakeOps(
    {
      "/Users/mini2/.sanctuary": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 1 },
      "/Users/mini2/.sanctuary/castle.sock": { type: "socket", uid: 0, gid: 20, mode: 0o600, ino: 2 },
      "/Users/mini2/.sanctuary/state": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 3 },
      "/Users/mini2/.sanctuary/state/other.enc": { type: "file", uid: 502, gid: 20, mode: 0o600, ino: 4 },
    },
    {
      "/Users/mini2/.sanctuary": ["castle.sock", "state"],
      "/Users/mini2/.sanctuary/state": ["other.enc"],
    },
  );
}

const SUDO_ENV = { SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "mini2" };

function baseCtx(
  fake: { ops: FortressCustodyFsOps },
  manifestDir: string,
  overrides: Partial<RepairCustodyContext> = {},
): RepairCustodyContext & {
  out: CaptureStream;
  err: CaptureStream;
  auditOps: { operation: string; details: Record<string, unknown> }[];
} {
  const out = new CaptureStream();
  const err = new CaptureStream();
  const auditOps: { operation: string; details: Record<string, unknown> }[] = [];
  return {
    out,
    err,
    auditOps,
    env: { ...SUDO_ENV },
    platform: "darwin",
    getuid: () => 0,
    fsOps: fake.ops,
    manifestDir,
    lookupOperatorHome: async () => "/Users/mini2",
    appendAudit: async (operation, details) => {
      auditOps.push({ operation, details });
    },
    ...overrides,
  };
}

describe("castle-wall repair-custody", () => {
  it("refuses when not running as root", async () => {
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused", { getuid: () => 501 });
    const code = await runRepairCustody([], ctx);
    expect(code).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
    expect(ctx.err.text()).toContain("sudo sanctuary castle-wall repair-custody");
    // Refusal means untouched: still root-owned.
    expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(0);
  });

  it("refuses a root sudo shell (SUDO_UID=0; the G4 chokepoint)", async () => {
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused", {
      env: { SUDO_UID: "0", SUDO_GID: "0", SUDO_USER: "root" },
    });
    const code = await runRepairCustody([], ctx);
    expect(code).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
    expect(ctx.err.text()).toContain("refusing to repair");
    expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(0);
  });

  it("refuses on non-darwin", async () => {
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused", { platform: "linux" });
    expect(await runRepairCustody([], ctx)).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
  });

  it("repairs a root-owned fortress: manifest first, chown to operator, skip foreign uid, exit 0", async () => {
    const manifestDir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const fake = rootOwnedFortress();
      const ctx = baseCtx(fake, manifestDir);
      const code = await runRepairCustody([], ctx);
      expect(code).toBe(REPAIR_CUSTODY_EXIT_CHANGED);

      // Observe-first: the manifest exists and records the PRE-repair (root) state.
      const files = await readdir(manifestDir);
      expect(files).toHaveLength(1);
      const { readFile } = await import("node:fs/promises");
      const manifest = parseCustodyRepairManifest(
        await readFile(join(manifestDir, files[0]!), "utf8"),
      );
      expect(manifest?.kind).toBe(CUSTODY_REPAIR_MANIFEST_KIND);
      expect(manifest?.entries.find((entry) => entry.path === ".")?.uid).toBe(0);

      // Repaired: fortress + socket now operator-owned; foreign file untouched.
      expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(501);
      expect(fake.nodes.get("/Users/mini2/.sanctuary/castle.sock")!.uid).toBe(501);
      expect(fake.nodes.get("/Users/mini2/.sanctuary/state/other.enc")!.uid).toBe(502);
      expect(ctx.out.text()).toContain("skipped: state/other.enc");
      expect(ctx.out.text()).toContain("Rollback");

      // CLI-mutator audit rule: the repair writes a metadata-only audit entry.
      expect(ctx.auditOps).toHaveLength(1);
      expect(ctx.auditOps[0]!.operation).toBe("fortress_custody_repaired");
      expect(ctx.auditOps[0]!.details).toMatchObject({
        repaired: 3,
        skipped_foreign_owner: 1,
        operator_uid: 501,
      });
    } finally {
      await rm(manifestDir, { recursive: true, force: true });
    }
  });

  it("second run is a no-op that still writes a NEW manifest (idempotence + versioning)", async () => {
    const manifestDir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const fake = rootOwnedFortress();
      expect(await runRepairCustody([], baseCtx(fake, manifestDir))).toBe(
        REPAIR_CUSTODY_EXIT_CHANGED,
      );
      const ctx2 = baseCtx(fake, manifestDir);
      expect(await runRepairCustody([], ctx2)).toBe(REPAIR_CUSTODY_EXIT_ALREADY_CLEAN);
      expect(ctx2.out.text()).toContain("Already clean");
      // Two manifests side by side; nothing clobbered.
      expect(await readdir(manifestDir)).toHaveLength(2);
    } finally {
      await rm(manifestDir, { recursive: true, force: true });
    }
  });

  it("never mutates when the manifest cannot be written (observe-first is a hard precondition)", async () => {
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused", {
      writeManifest: async () => {
        throw new Error("disk full");
      },
    });
    const code = await runRepairCustody([], ctx);
    expect(code).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
    expect(ctx.err.text()).toContain("nothing was mutated");
    expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(0);
  });

  it("reports already-clean when no fortress exists", async () => {
    const fake = makeFakeOps({}, {});
    const ctx = baseCtx(fake, "/unused");
    const code = await runRepairCustody([], ctx);
    expect(code).toBe(REPAIR_CUSTODY_EXIT_ALREADY_CLEAN);
    expect(ctx.out.text()).toContain("No fortress exists");
  });

  it("notes vanished entries without failing (live daemon churn)", async () => {
    const manifestDir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const fake = rootOwnedFortress();
      // Listed but deleted before lstat: transient daemon lock file.
      const originalReaddir = fake.ops.readdir.bind(fake.ops);
      fake.ops.readdir = async (path: string) =>
        path === "/Users/mini2/.sanctuary"
          ? [...(await originalReaddir(path)), "transient.lock"]
          : originalReaddir(path);
      const ctx = baseCtx(fake, manifestDir);
      const code = await runRepairCustody([], ctx);
      expect(code).toBe(REPAIR_CUSTODY_EXIT_CHANGED);
      expect(ctx.out.text()).toContain("transient.lock vanished mid-walk");
    } finally {
      await rm(manifestDir, { recursive: true, force: true });
    }
  });

  it("rollback replays the recorded ownership exactly (round trip)", async () => {
    const manifestDir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const fake = rootOwnedFortress();
      expect(await runRepairCustody([], baseCtx(fake, manifestDir))).toBe(
        REPAIR_CUSTODY_EXIT_CHANGED,
      );
      expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(501);
      const files = await readdir(manifestDir);
      const manifestPath = join(manifestDir, files[0]!);

      const ctx = baseCtx(fake, manifestDir);
      const code = await runRepairCustody(["--rollback", manifestPath], ctx);
      expect(code).toBe(REPAIR_CUSTODY_EXIT_CHANGED);
      expect(fake.nodes.get("/Users/mini2/.sanctuary")!.uid).toBe(0);
      expect(fake.nodes.get("/Users/mini2/.sanctuary/castle.sock")!.uid).toBe(0);

      // Rolling back again: nothing to restore.
      const ctx2 = baseCtx(fake, manifestDir);
      expect(await runRepairCustody(["--rollback", manifestPath], ctx2)).toBe(
        REPAIR_CUSTODY_EXIT_ALREADY_CLEAN,
      );
    } finally {
      await rm(manifestDir, { recursive: true, force: true });
    }
  });

  it("refuses a rollback manifest recorded for a different fortress", async () => {
    const dir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const manifestPath = join(dir, "custody-x.json");
      await writeFile(
        manifestPath,
        JSON.stringify({
          version: 1,
          kind: CUSTODY_REPAIR_MANIFEST_KIND,
          generated_at: "2026-07-30T00:00:00.000Z",
          fortress_path: "/Users/somebody-else/.sanctuary",
          operator: { uid: 501, gid: 20 },
          entries: [],
          vanished: [],
        }),
      );
      const fake = rootOwnedFortress();
      const ctx = baseCtx(fake, dir);
      expect(await runRepairCustody(["--rollback", manifestPath], ctx)).toBe(
        REPAIR_CUSTODY_EXIT_REFUSED,
      );
      expect(ctx.err.text()).toContain("this run targets");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses an invalid rollback manifest", async () => {
    const dir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const manifestPath = join(dir, "bad.json");
      await writeFile(manifestPath, JSON.stringify({ nope: true }));
      const fake = rootOwnedFortress();
      const ctx = baseCtx(fake, dir);
      expect(await runRepairCustody(["--rollback", manifestPath], ctx)).toBe(
        REPAIR_CUSTODY_EXIT_REFUSED,
      );
      expect(ctx.err.text()).toContain("not a valid");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("exits failed when an entry cannot be repaired, and names the rollback path", async () => {
    const manifestDir = await mkdtemp(join(tmpdir(), "repair-manifests-"));
    try {
      const fake = rootOwnedFortress();
      const originalOpen = fake.ops.open.bind(fake.ops);
      fake.ops.open = async (path: string, flags: number) => {
        if (path.endsWith("/state")) throw new Error("EPERM: nope");
        return originalOpen(path, flags);
      };
      const ctx = baseCtx(fake, manifestDir);
      const code = await runRepairCustody([], ctx);
      expect(code).toBe(REPAIR_CUSTODY_EXIT_FAILED);
      expect(ctx.err.text()).toContain("--rollback");
    } finally {
      await rm(manifestDir, { recursive: true, force: true });
    }
  });

  it("parses its own args and rejects unknown ones", async () => {
    expect(parseRepairCustodyArgs(["--fortress", "/f"])).toEqual({ fortress: "/f" });
    expect(parseRepairCustodyArgs(["--rollback", "/m.json"])).toEqual({ rollback: "/m.json" });
    expect(parseRepairCustodyArgs(["--bogus"]).unknown).toBe("--bogus");
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused");
    expect(await runRepairCustody(["--bogus"], ctx)).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
  });

  it("requires --fortress when the operator home cannot be resolved", async () => {
    const fake = rootOwnedFortress();
    const ctx = baseCtx(fake, "/unused", {
      lookupOperatorHome: async () => undefined,
    });
    const code = await runRepairCustody([], ctx);
    expect(code).toBe(REPAIR_CUSTODY_EXIT_REFUSED);
    expect(ctx.err.text()).toContain("--fortress");
  });
});
