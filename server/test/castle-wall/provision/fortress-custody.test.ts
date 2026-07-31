import { describe, expect, it } from "vitest";
import { mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { constants as fsConstants, type Stats } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  applyCustodyRollback,
  applyFortressCustodyRepairs,
  CUSTODY_REPAIR_MANIFEST_KIND,
  isSafeManifestRelPath,
  manifestCarriesPrivilegeBits,
  normalizeFortressCustody,
  parseCustodyRepairManifest,
  planFortressCustodyRepairs,
  realFortressCustodyFsOps,
  resolveSudoIdentityDecision,
  walkFortressCustody,
  writeCustodyRepairManifest,
  type CustodyRepairManifest,
  type FortressCustodyEntry,
  type FortressCustodyFsOps,
} from "../../../src/castle-wall/provision/fortress-custody.js";

// ── Fake filesystem for uid-sensitive branches (tests cannot mint root-owned
//    files without root, so ownership states are simulated through the seam). ──

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
    mode: node.mode | (node.type === "dir" ? 0o040000 : 0),
    dev: 1,
    ino: node.ino,
  } as unknown as Stats;
}

interface FakeFs {
  ops: FortressCustodyFsOps;
  nodes: Map<string, FakeNode>;
  children: Map<string, string[]>;
  lchowns: { path: string; uid: number; gid: number }[];
  chmods: { path: string; mode: number }[];
  fchowns: { path: string; uid: number; gid: number }[];
  fchmods: { path: string; mode: number }[];
}

function enoent(): NodeJS.ErrnoException {
  const err = new Error("ENOENT") as NodeJS.ErrnoException;
  err.code = "ENOENT";
  return err;
}

function makeFakeFs(
  nodes: Record<string, FakeNode>,
  children: Record<string, string[]>,
): FakeFs {
  const nodeMap = new Map(Object.entries(nodes));
  const childMap = new Map(Object.entries(children));
  const fake: FakeFs = {
    nodes: nodeMap,
    children: childMap,
    lchowns: [],
    chmods: [],
    fchowns: [],
    fchmods: [],
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
        fake.lchowns.push({ path, uid, gid });
        node.uid = uid;
        node.gid = gid;
      },
      chmod: async (path, mode) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        fake.chmods.push({ path, mode });
        node.mode = mode;
      },
      // The fake HONORS O_NOFOLLOW / O_DIRECTORY: a mock that opened a
      // symlinked ancestor happily could not represent the very condition
      // the ancestor guard exists to catch.
      open: async (path, flags) => {
        const node = nodeMap.get(path);
        if (node === undefined) throw enoent();
        const noFollow =
          typeof fsConstants.O_NOFOLLOW === "number" &&
          (flags & fsConstants.O_NOFOLLOW) !== 0;
        const dirOnly =
          typeof fsConstants.O_DIRECTORY === "number" &&
          (flags & fsConstants.O_DIRECTORY) !== 0;
        if (noFollow && node.type === "symlink") {
          const err = new Error("ELOOP: symbolic link") as NodeJS.ErrnoException;
          err.code = "ELOOP";
          throw err;
        }
        if (dirOnly && node.type !== "dir") {
          const err = new Error("ENOTDIR: not a directory") as NodeJS.ErrnoException;
          err.code = "ENOTDIR";
          throw err;
        }
        return {
          path,
          stat: async () => fakeStats(node),
          chown: async (uid: number, gid: number) => {
            fake.fchowns.push({ path, uid, gid });
            node.uid = uid;
            node.gid = gid;
          },
          chmod: async (mode: number) => {
            fake.fchmods.push({ path, mode });
            node.mode = mode;
          },
          close: async () => undefined,
        };
      },
    },
  };
  return fake;
}

/** The Mini2 shape: root-owned fortress, root-owned socket + key file, one operator file, one foreign file. */
function mini2Fixture(): FakeFs {
  return makeFakeFs(
    {
      "/f": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 1 },
      "/f/castle.sock": { type: "socket", uid: 0, gid: 20, mode: 0o600, ino: 2 },
      "/f/castle-pinned-pubkey.bin": { type: "file", uid: 0, gid: 20, mode: 0o644, ino: 3 },
      "/f/state": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 4 },
      "/f/state/mine.enc": { type: "file", uid: 501, gid: 20, mode: 0o600, ino: 5 },
      "/f/state/foreign.enc": { type: "file", uid: 502, gid: 20, mode: 0o600, ino: 6 },
    },
    {
      "/f": ["castle.sock", "castle-pinned-pubkey.bin", "state"],
      "/f/state": ["mine.enc", "foreign.enc"],
    },
  );
}

const OPERATOR = { uid: 501, gid: 20 };

describe("fortress-custody: walk", () => {
  it("walks a real temp tree, records relative paths + modes, and never descends through symlinks", async () => {
    const outside = await mkdtemp(join(tmpdir(), "custody-outside-"));
    const root = await mkdtemp(join(tmpdir(), "custody-walk-"));
    try {
      await writeFile(join(outside, "secret.txt"), "outside", { mode: 0o600 });
      await mkdir(join(root, "sub"), { mode: 0o700 });
      await writeFile(join(root, "sub", "a.enc"), "a", { mode: 0o600 });
      await symlink(outside, join(root, "escape"));

      const walk = await walkFortressCustody(root);
      const paths = walk.entries.map((entry) => entry.path);
      expect(paths).toContain(".");
      expect(paths).toContain("sub");
      expect(paths).toContain("sub/a.enc");
      expect(paths).toContain("escape");
      // The symlinked dir is recorded as a SYMLINK and never entered: nothing
      // outside the fortress appears in the walk.
      expect(walk.entries.find((entry) => entry.path === "escape")?.type).toBe("symlink");
      expect(paths.some((path) => path.includes("secret.txt"))).toBe(false);
      expect(walk.vanished).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  });

  it("treats a mid-walk vanished entry as a note, not a failure", async () => {
    const fake = mini2Fixture();
    // Listed but gone by lstat time (live root daemon deleting a lock file).
    fake.children.get("/f")!.push("transient.lock");
    const walk = await walkFortressCustody("/f", fake.ops);
    expect(walk.vanished).toEqual(["transient.lock"]);
    expect(walk.entries).toHaveLength(6);
  });

  it("refuses a symlinked fortress root", async () => {
    const fake = makeFakeFs(
      { "/f": { type: "symlink", uid: 501, gid: 20, mode: 0o755, ino: 1 } },
      {},
    );
    await expect(walkFortressCustody("/f", fake.ops)).rejects.toThrow(
      /not a plain directory/,
    );
  });
});

describe("fortress-custody: plan", () => {
  it("plans chown for root-owned entries only, skips foreign uids, leaves operator entries alone", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);

    const actionPaths = plan.actions.map((action) => action.entry.path).sort();
    expect(actionPaths).toEqual([".", "castle-pinned-pubkey.bin", "castle.sock", "state"]);
    for (const action of plan.actions) {
      expect(action.chownTo).toEqual(OPERATOR);
    }
    expect(plan.skips).toEqual([
      { path: "state/foreign.enc", uid: 502, gid: 20, reason: "foreign_owner" },
    ]);
  });

  it("restores the fortress-dir 0700 but only REPORTS a deviant castle.sock mode (gate round 3)", () => {
    const entries: FortressCustodyEntry[] = [
      { path: ".", type: "dir", uid: 501, gid: 20, mode: 0o755, dev: 1, ino: 1 },
      { path: "castle.sock", type: "socket", uid: 501, gid: 20, mode: 0o666, dev: 1, ino: 2 },
      { path: "ok.enc", type: "file", uid: 501, gid: 20, mode: 0o644, dev: 1, ino: 3 },
    ];
    const plan = planFortressCustodyRepairs(entries, OPERATOR);
    // The fortress dir is openable, so its mode is restored through an fd.
    expect(plan.actions).toHaveLength(1);
    expect(plan.actions.find((a) => a.entry.path === ".")?.chmodTo).toBe(0o700);
    // A socket cannot be opened, so restoring its mode could only be a
    // PATHNAME chmod -- a root chmod primitive under a final-component
    // symlink swap. It is reported instead, never repaired.
    expect(plan.actions.some((a) => a.entry.path === "castle.sock")).toBe(false);
    expect(plan.socketModeDeviations).toEqual([{ path: "castle.sock", mode: 0o666 }]);
    // A non-canonical mode on an ordinary operator-owned file is NOT touched.
    expect(plan.actions.some((a) => a.entry.path === "ok.enc")).toBe(false);
  });

  it("is idempotent: a clean tree plans nothing", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    await applyFortressCustodyRepairs("/f", plan, fake.ops);

    const secondWalk = await walkFortressCustody("/f", fake.ops);
    const secondPlan = planFortressCustodyRepairs(secondWalk.entries, OPERATOR);
    expect(secondPlan.actions).toEqual([]);
    // The foreign-uid skip persists across runs (still reported, still untouched).
    expect(secondPlan.skips).toHaveLength(1);
  });
});

describe("fortress-custody: apply", () => {
  it("chowns root-owned entries to the operator and leaves the foreign file untouched", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);

    expect(applied.repaired.sort()).toEqual([
      ".",
      "castle-pinned-pubkey.bin",
      "castle.sock",
      "state",
    ]);
    expect(applied.failed).toEqual([]);
    expect(fake.nodes.get("/f")!.uid).toBe(501);
    expect(fake.nodes.get("/f/castle.sock")!.uid).toBe(501);
    expect(fake.nodes.get("/f/state")!.uid).toBe(501);
    expect(fake.nodes.get("/f/state/foreign.enc")!.uid).toBe(502);
    // Socket ownership went through the lchown (no-follow) path.
    expect(fake.lchowns.some((c) => c.path === "/f/castle.sock")).toBe(true);
    // Dirs/files went through the fd-pinned path.
    expect(fake.fchowns.some((c) => c.path === "/f/state")).toBe(true);
  });

  it("skips an entry whose identity changed between observe and apply (dev/ino pin)", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    // Swap the pinned-key file for a different inode (e.g. rewritten by the daemon).
    fake.nodes.get("/f/castle-pinned-pubkey.bin")!.ino = 999;
    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.identityChanged).toEqual(["castle-pinned-pubkey.bin"]);
    expect(fake.nodes.get("/f/castle-pinned-pubkey.bin")!.uid).toBe(0);
  });

  it("treats an entry vanished before apply as a note, not a failure", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    fake.nodes.delete("/f/castle-pinned-pubkey.bin");
    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.vanished).toEqual(["castle-pinned-pubkey.bin"]);
    expect(applied.failed).toEqual([]);
    expect(applied.repaired).toContain(".");
  });
});

describe("fortress-custody: ancestor containment (2026-07-31 gate BLOCKER-1)", () => {
  /** A nested tree so `state/` is a real ANCESTOR of the repaired entry. */
  function nestedFixture(): FakeFs {
    return makeFakeFs(
      {
        "/f": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 1 },
        "/f/state": { type: "dir", uid: 0, gid: 20, mode: 0o700, ino: 2 },
        "/f/state/a.enc": { type: "file", uid: 0, gid: 20, mode: 0o600, ino: 3 },
      },
      { "/f": ["state"], "/f/state": ["a.enc"] },
    );
  }

  it("REFUSES to chown when an ancestor became a symlink between observe and apply", async () => {
    const fake = nestedFixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);

    // The attack: swap the observed ancestor dir for a symlink pointing
    // outside the fortress. Without ancestor verification, O_NOFOLLOW on the
    // FINAL component alone would let root chown /outside/a.enc.
    fake.nodes.set("/f/state", { type: "symlink", uid: 502, gid: 20, mode: 0o777, ino: 99 });

    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.identityChanged).toContain("state/a.enc (ancestor changed)");
    expect(applied.repaired).not.toContain("state/a.enc");
    // Nothing under the swapped ancestor was touched.
    expect(fake.fchowns.some((c) => c.path === "/f/state/a.enc")).toBe(false);
    expect(fake.nodes.get("/f/state/a.enc")!.uid).toBe(0);
  });

  it("REFUSES when an ancestor is replaced by a DIFFERENT directory (inode swap)", async () => {
    const fake = nestedFixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    // Same path, same type, different inode: a rename-over attack.
    fake.nodes.get("/f/state")!.ino = 4242;

    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.identityChanged).toContain("state/a.enc (ancestor changed)");
    expect(fake.nodes.get("/f/state/a.enc")!.uid).toBe(0);
  });

  it("REFUSES when the fortress ROOT itself is swapped under us", async () => {
    const fake = nestedFixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    fake.nodes.get("/f")!.ino = 777;

    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.repaired).toEqual([]);
    expect(applied.identityChanged.length).toBeGreaterThan(0);
    expect(fake.fchowns).toEqual([]);
  });

  it("still repairs the whole nested tree when nothing is tampered with", async () => {
    const fake = nestedFixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.repaired.sort()).toEqual([".", "state", "state/a.enc"]);
    expect(applied.identityChanged).toEqual([]);
    expect(fake.nodes.get("/f/state/a.enc")!.uid).toBe(501);
  });

  it("REFUSES when the path resolves to a different inode than the descriptor (two-sided check)", async () => {
    const fake = nestedFixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    // The descriptor sees the observed inode, but a fresh path resolution
    // sees something else: the close-out check must refuse.
    const realLstat = fake.ops.lstat.bind(fake.ops);
    let seen = 0;
    fake.ops.lstat = async (path: string) => {
      if (path === "/f/state/a.enc") {
        seen += 1;
        if (seen > 0) {
          return {
            ...(await realLstat(path)),
            isDirectory: () => false,
            isFile: () => true,
            isSocket: () => false,
            isSymbolicLink: () => false,
            dev: 1,
            ino: 31337,
          } as unknown as Stats;
        }
      }
      return realLstat(path);
    };
    const applied = await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(applied.identityChanged).toContain("state/a.enc");
    expect(fake.nodes.get("/f/state/a.enc")!.uid).toBe(0);
  });
});

describe("fortress-custody: manifest", () => {
  function manifestFixture(entries: FortressCustodyEntry[]): CustodyRepairManifest {
    return {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-30T22:15:00.000Z",
      fortress_path: "/f",
      operator: OPERATOR,
      entries,
      vanished: [],
    };
  }

  it("writes a NEW manifest file per run and never clobbers an existing one", async () => {
    const dir = await mkdtemp(join(tmpdir(), "custody-manifest-"));
    try {
      const manifest = manifestFixture([
        { path: ".", type: "dir", uid: 0, gid: 20, mode: 0o700, dev: 1, ino: 1 },
      ]);
      const first = await writeCustodyRepairManifest(manifest, dir);
      const second = await writeCustodyRepairManifest(manifest, dir);
      expect(second).not.toBe(first);
      const files = await readdir(dir);
      expect(files).toHaveLength(2);
      // Both survive side by side; the first is byte-identical to what was written.
      const parsed = parseCustodyRepairManifest(await readFile(first, "utf8"));
      expect(parsed?.entries[0]?.uid).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("round-trips through parse and validates shape", () => {
    const manifest = manifestFixture([
      { path: "state/a.enc", type: "file", uid: 0, gid: 20, mode: 0o600, dev: 1, ino: 2 },
    ]);
    expect(parseCustodyRepairManifest(JSON.stringify(manifest))).not.toBeNull();
    expect(parseCustodyRepairManifest("not json")).toBeNull();
    expect(
      parseCustodyRepairManifest(JSON.stringify({ ...manifest, kind: "other" })),
    ).toBeNull();
    // Path traversal in a manifest is rejected outright.
    expect(
      parseCustodyRepairManifest(
        JSON.stringify(
          manifestFixture([
            { path: "../escape", type: "file", uid: 0, gid: 20, mode: 0o600, dev: 1, ino: 3 },
          ]),
        ),
      ),
    ).toBeNull();
  });

  it("rejects unsafe relative paths", () => {
    expect(isSafeManifestRelPath(".")).toBe(true);
    expect(isSafeManifestRelPath("state/a.enc")).toBe(true);
    expect(isSafeManifestRelPath("../x")).toBe(false);
    expect(isSafeManifestRelPath("a/../x")).toBe(false);
    expect(isSafeManifestRelPath("/abs")).toBe(false);
    expect(isSafeManifestRelPath("")).toBe(false);
    expect(isSafeManifestRelPath("a//b")).toBe(false);
  });
});

describe("fortress-custody: rollback", () => {
  it("replays recorded ownership and modes exactly (repair round-trip)", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const manifest: CustodyRepairManifest = {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-30T22:15:00.000Z",
      fortress_path: "/f",
      operator: OPERATOR,
      entries: walk.entries,
      vanished: walk.vanished,
    };
    const plan = planFortressCustodyRepairs(walk.entries, OPERATOR);
    await applyFortressCustodyRepairs("/f", plan, fake.ops);
    expect(fake.nodes.get("/f")!.uid).toBe(501);

    const rollback = await applyCustodyRollback("/f", manifest, fake.ops);
    expect(rollback.failed).toEqual([]);
    // Every repaired entry went back to the recorded (root) ownership.
    expect(fake.nodes.get("/f")!.uid).toBe(0);
    expect(fake.nodes.get("/f/castle.sock")!.uid).toBe(0);
    expect(fake.nodes.get("/f/state")!.uid).toBe(0);
    // The untouched entries were not touched by rollback either.
    expect(rollback.repaired.sort()).toEqual([
      ".",
      "castle-pinned-pubkey.bin",
      "castle.sock",
      "state",
    ]);
  });

  it("is a no-op when on-disk state already matches the manifest", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const manifest: CustodyRepairManifest = {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-30T22:15:00.000Z",
      fortress_path: "/f",
      operator: OPERATOR,
      entries: walk.entries,
      vanished: [],
    };
    const rollback = await applyCustodyRollback("/f", manifest, fake.ops);
    expect(rollback.repaired).toEqual([]);
    expect(fake.lchowns).toEqual([]);
    expect(fake.chmods).toEqual([]);
  });

  it("replays metadata onto a same-type occupant whose inode changed by tmp rename", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const manifest: CustodyRepairManifest = {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-30T22:15:00.000Z",
      fortress_path: "/f",
      operator: OPERATOR,
      entries: walk.entries,
      vanished: [],
    };
    const node = fake.nodes.get("/f/castle-pinned-pubkey.bin")!;
    node.uid = 501;
    node.mode = 0o600;
    node.ino = 31337;

    const rollback = await applyCustodyRollback("/f", manifest, fake.ops);

    expect(rollback.identityChanged).toEqual([]);
    expect(rollback.repaired).toContain("castle-pinned-pubkey.bin");
    expect(node.uid).toBe(0);
    expect(node.mode).toBe(0o644);
  });

  it("notes vanished entries and reports type changes instead of touching them", async () => {
    const fake = mini2Fixture();
    const walk = await walkFortressCustody("/f", fake.ops);
    const manifest: CustodyRepairManifest = {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-30T22:15:00.000Z",
      fortress_path: "/f",
      operator: OPERATOR,
      entries: walk.entries,
      vanished: [],
    };
    fake.nodes.delete("/f/castle.sock");
    fake.nodes.get("/f/castle-pinned-pubkey.bin")!.type = "symlink";
    fake.nodes.get("/f/castle-pinned-pubkey.bin")!.uid = 501;
    const rollback = await applyCustodyRollback("/f", manifest, fake.ops);
    expect(rollback.vanished).toEqual(["castle.sock"]);
    expect(rollback.identityChanged).toEqual(["castle-pinned-pubkey.bin"]);
  });
});

describe("fortress-custody: rollback containment (2026-07-31 gate BLOCKER-2)", () => {
  function manifestOf(
    entries: FortressCustodyEntry[],
    fortressPath = "/f",
  ): CustodyRepairManifest {
    return {
      version: 1,
      kind: CUSTODY_REPAIR_MANIFEST_KIND,
      generated_at: "2026-07-31T00:00:00.000Z",
      fortress_path: fortressPath,
      operator: OPERATOR,
      entries,
      vanished: [],
    };
  }

  it("REFUSES the codex exploit: a symlinked parent cannot carry a root chown/chmod outside the fortress", async () => {
    // Exactly the reported attack: `escape -> /Users/operator` inside the
    // fortress, plus a crafted manifest entry `escape/payload` recording
    // uid 0 / gid 0 / mode 04755. Pre-fix this chowned an attacker file to
    // root and set it setuid.
    const fake = makeFakeFs(
      {
        "/f": { type: "dir", uid: 501, gid: 20, mode: 0o700, ino: 1 },
        "/f/escape": { type: "symlink", uid: 501, gid: 20, mode: 0o777, ino: 2 },
        "/f/escape/payload": { type: "file", uid: 501, gid: 20, mode: 0o755, ino: 3 },
      },
      { "/f": ["escape"] },
    );
    const manifest = manifestOf([
      { path: ".", type: "dir", uid: 501, gid: 20, mode: 0o700, dev: 1, ino: 1 },
      // The crafted entry claims the symlink is a plain directory.
      { path: "escape", type: "dir", uid: 501, gid: 20, mode: 0o755, dev: 1, ino: 2 },
      { path: "escape/payload", type: "file", uid: 0, gid: 0, mode: 0o4755, dev: 1, ino: 3 },
    ]);

    const result = await applyCustodyRollback("/f", manifest, fake.ops);

    expect(result.identityChanged).toContain("escape/payload (ancestor changed)");
    // The attacker's file was NEVER chowned to root and NEVER made setuid.
    expect(fake.nodes.get("/f/escape/payload")!.uid).toBe(501);
    expect(fake.nodes.get("/f/escape/payload")!.mode).toBe(0o755);
    expect(fake.lchowns.some((c) => c.path === "/f/escape/payload")).toBe(false);
    expect(fake.chmods.some((c) => c.path === "/f/escape/payload")).toBe(false);
  });

  it("detects setuid/setgid/sticky in a manifest so the CLI can refuse it wholesale", () => {
    expect(
      manifestCarriesPrivilegeBits(
        manifestOf([
          { path: "x", type: "file", uid: 0, gid: 0, mode: 0o4755, dev: 1, ino: 9 },
        ]),
      ),
    ).toBe(true);
    expect(
      manifestCarriesPrivilegeBits(
        manifestOf([
          { path: "x", type: "file", uid: 0, gid: 0, mode: 0o600, dev: 1, ino: 9 },
        ]),
      ),
    ).toBe(false);
  });

  it("masks applied modes to 0o777 so no rollback path can create a setuid file", async () => {
    const fake = makeFakeFs(
      {
        "/f": { type: "dir", uid: 501, gid: 20, mode: 0o700, ino: 1 },
        "/f/bin": { type: "file", uid: 501, gid: 20, mode: 0o755, ino: 2 },
      },
      { "/f": ["bin"] },
    );
    await applyCustodyRollback(
      "/f",
      manifestOf([
        { path: ".", type: "dir", uid: 501, gid: 20, mode: 0o700, dev: 1, ino: 1 },
        { path: "bin", type: "file", uid: 501, gid: 20, mode: 0o6755, dev: 1, ino: 2 },
      ]),
      fake.ops,
    );
    expect(fake.nodes.get("/f/bin")!.mode).toBe(0o755);
    expect(fake.chmods.every((c) => (c.mode & 0o7000) === 0)).toBe(true);
  });

  it("applies file/dir rollback through an fd, never a pathname chmod (re-gate BLOCKER)", async () => {
    const fake = makeFakeFs(
      {
        "/f": { type: "dir", uid: 501, gid: 20, mode: 0o700, ino: 1 },
        "/f/a.enc": { type: "file", uid: 501, gid: 20, mode: 0o644, ino: 2 },
      },
      { "/f": ["a.enc"] },
    );
    await applyCustodyRollback(
      "/f",
      manifestOf([
        { path: ".", type: "dir", uid: 501, gid: 20, mode: 0o700, dev: 1, ino: 1 },
        { path: "a.enc", type: "file", uid: 0, gid: 20, mode: 0o600, dev: 1, ino: 2 },
      ]),
      fake.ops,
    );
    // Ownership and mode were restored...
    expect(fake.nodes.get("/f/a.enc")!.uid).toBe(0);
    expect(fake.nodes.get("/f/a.enc")!.mode).toBe(0o600);
    // ...entirely through the DESCRIPTOR: a pathname chmod after an lstat is
    // the root chmod primitive the re-gate flagged, so there must be none.
    expect(fake.chmods).toEqual([]);
    expect(fake.lchowns).toEqual([]);
    expect(fake.fchmods.some((c) => c.path === "/f/a.enc")).toBe(true);
    expect(fake.fchowns.some((c) => c.path === "/f/a.enc")).toBe(true);
  });

  it("REFUSES a symlinked fortress root (repair already did; rollback used to skip this)", async () => {
    const fake = makeFakeFs(
      { "/f": { type: "symlink", uid: 501, gid: 20, mode: 0o777, ino: 1 } },
      {},
    );
    await expect(
      applyCustodyRollback("/f", manifestOf([]), fake.ops),
    ).rejects.toThrow(/not a plain directory/);
  });
});

describe("fortress-custody: normalize chokepoint", () => {
  it("hands root-owned entries back to the operator and reports loudly", async () => {
    const fake = mini2Fixture();
    const lines: string[] = [];
    const outcome = await normalizeFortressCustody({
      fortressPath: "/f",
      operator: OPERATOR,
      log: (line) => lines.push(line),
      ops: fake.ops,
    });
    expect(outcome.status).toBe("changed");
    expect(outcome.repaired).toHaveLength(4);
    expect(fake.nodes.get("/f")!.uid).toBe(501);
    expect(lines.join("\n")).toContain("Fortress custody normalized");
    expect(lines.join("\n")).toContain("state/foreign.enc");
  });

  it("is clean + quiet on an already-operator-owned fortress", async () => {
    const fake = makeFakeFs(
      {
        "/f": { type: "dir", uid: 501, gid: 20, mode: 0o700, ino: 1 },
        "/f/a.enc": { type: "file", uid: 501, gid: 20, mode: 0o600, ino: 2 },
      },
      { "/f": ["a.enc"] },
    );
    const lines: string[] = [];
    const outcome = await normalizeFortressCustody({
      fortressPath: "/f",
      operator: OPERATOR,
      log: (line) => lines.push(line),
      ops: fake.ops,
    });
    expect(outcome.status).toBe("clean");
    expect(lines).toEqual([]);
    expect(fake.lchowns).toEqual([]);
  });

  it("refuses a root operator identity (G4) without touching anything", async () => {
    const fake = mini2Fixture();
    const lines: string[] = [];
    const outcome = await normalizeFortressCustody({
      fortressPath: "/f",
      operator: { uid: 0, gid: 0 },
      log: (line) => lines.push(line),
      ops: fake.ops,
    });
    expect(outcome.status).toBe("refused");
    expect(fake.lchowns).toEqual([]);
    expect(fake.fchowns).toEqual([]);
    expect(lines.join("\n")).toContain("repair-custody");
  });

  it("reports no_fortress when the fortress does not exist", async () => {
    const outcome = await normalizeFortressCustody({
      fortressPath: "/does/not/exist",
      operator: OPERATOR,
      log: () => undefined,
      ops: makeFakeFs({}, {}).ops,
    });
    expect(outcome.status).toBe("no_fortress");
  });

  it("never throws: an unexpected walk failure becomes a loud failed outcome naming the repair verb", async () => {
    const fake = mini2Fixture();
    fake.ops.readdir = async () => {
      throw new Error("EIO: disk exploded");
    };
    const lines: string[] = [];
    const outcome = await normalizeFortressCustody({
      fortressPath: "/f",
      operator: OPERATOR,
      log: (line) => lines.push(line),
      ops: fake.ops,
    });
    expect(outcome.status).toBe("failed");
    expect(lines.join("\n")).toContain("repair-custody");
  });
});

describe("fortress-custody: sudo identity chokepoint (moved, re-exported)", () => {
  it("resolves a normal sudo context and refuses a root shell (G4)", () => {
    expect(
      resolveSudoIdentityDecision({ SUDO_UID: "501", SUDO_GID: "20", SUDO_USER: "mini2" }),
    ).toEqual({ uid: 501, gid: 20, user: "mini2" });
    expect(
      resolveSudoIdentityDecision({ SUDO_UID: "0", SUDO_GID: "0", SUDO_USER: "root" }),
    ).toBeUndefined();
    expect(resolveSudoIdentityDecision({})).toBeUndefined();
  });

  it("stays importable from the historical auto-provision surface", async () => {
    const autoProvision = await import("../../../src/wrap/auto-provision.js");
    expect(autoProvision.resolveSudoIdentityDecision).toBe(resolveSudoIdentityDecision);
  });
});

describe("fortress-custody: real ops smoke", () => {
  it("repairs modes on a real (operator-owned) tree end to end", async () => {
    const root = await mkdtemp(join(tmpdir(), "custody-real-"));
    try {
      await mkdir(join(root, "state"), { mode: 0o700 });
      await writeFile(join(root, "state", "a.enc"), "a", { mode: 0o600 });
      // Deviant top-level mode: the plan must restore 0700 even for an
      // operator-owned fortress.
      const { chmod } = await import("node:fs/promises");
      await chmod(root, 0o755);

      const ops = realFortressCustodyFsOps();
      const walk = await walkFortressCustody(root, ops);
      const uid = process.getuid?.() ?? 0;
      const gid = process.getgid?.() ?? 0;
      const plan = planFortressCustodyRepairs(walk.entries, { uid, gid });
      expect(plan.actions).toHaveLength(1);
      expect(plan.actions[0]?.chmodTo).toBe(0o700);
      const applied = await applyFortressCustodyRepairs(root, plan, ops);
      expect(applied.failed).toEqual([]);
      const after = await walkFortressCustody(root, ops);
      expect(after.entries.find((entry) => entry.path === ".")?.mode).toBe(0o700);
      // Second run: nothing left to do.
      expect(planFortressCustodyRepairs(after.entries, { uid, gid }).actions).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
