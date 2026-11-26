/**
 * The installed comparison over real temporary directories: exact match,
 * changed, missing and extra files and directories, links and special files,
 * NFC and NFD names, collisions, the exclusions, and the deadline during
 * hashing. Collision cases that need two names differing only by case run
 * only on a case-sensitive temp volume.
 */
import { spawnSync } from "node:child_process";
import { existsSync, linkSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, truncateSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { MAX_INSTALLED_ENTRIES, RUN_DEADLINE_MS } from "../../src/verify-release/constants.js";
import { Deadline, type Clock } from "../../src/verify-release/deadline.js";
import { state_ARCHIVE } from "../../src/verify-release/archive.js";
import { state_INSTALLED, type InstalledDirent, type InstalledFs } from "../../src/verify-release/installed.js";
import type { ArchiveEvidence } from "../../src/verify-release/evidence.js";
import { ManualClock, denyAllNetwork, tgz, type TarEntrySpec } from "./helpers.js";

denyAllNetwork();

const roots: string[] = [];
afterEach(() => { for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true }); });

function tempRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "vr-installed-"));
  roots.push(root);
  return root;
}

const CASE_SENSITIVE = (() => {
  const probe = mkdtempSync(join(tmpdir(), "vr-case-"));
  writeFileSync(join(probe, "probe"), "");
  const sensitive = !existsSync(join(probe, "PROBE"));
  rmSync(probe, { recursive: true, force: true });
  return sensitive;
})();

const BASE: Record<string, string> = {
  "package.json": "{\"name\":\"@sanctuary-framework/mcp-server\"}",
  "README.md": "readme",
  "dist/cli.js": "#!/usr/bin/env node\nconsole.log(1)\n",
  "dist/chunk/a.js": "a",
};

async function archiveOf(files: Record<string, string>, extra: TarEntrySpec[] = []): Promise<ArchiveEvidence> {
  const entries: TarEntrySpec[] = [...Object.entries(files).map(([path, body]) => ({ path: `package/${path}`, body })), ...extra];
  const deadline = new Deadline(new ManualClock(), RUN_DEADLINE_MS);
  const result = await state_ARCHIVE(tgz(entries), deadline);
  deadline.dispose();
  if (!result.ok) throw new Error(`archive fixture refused: ${result.reason}`);
  return result.evidence;
}

function install(files: Record<string, string>): string {
  const root = tempRoot();
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(join(root, path, ".."), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  return root;
}

const check = (root: string, archive: ArchiveEvidence, clock: Clock = new ManualClock(), fs?: InstalledFs) => {
  const deadline = new Deadline(clock, RUN_DEADLINE_MS);
  return state_INSTALLED(root, archive, deadline, fs).finally(() => deadline.dispose());
};

describe("exact match", () => {
  it("an install with exactly the archive's files passes", async () => {
    expect(await check(install(BASE), await archiveOf(BASE))).toEqual({ ok: true, evidence: { state: "state_INSTALLED", fileCount: 4 } });
  });
});

describe("content and names", () => {
  it("a changed file refuses installed-file-differs with its path", async () => {
    expect(await check(install({ ...BASE, "dist/cli.js": "#!/usr/bin/env node\nconsole.log(2)\n" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-differs:dist/cli.js" });
  });
  it("a longer file refuses installed-file-differs without reading past the archive's size", async () => {
    expect(await check(install({ ...BASE, "README.md": `readme${"x".repeat(5_000_000)}` }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-differs:README.md" });
  });
  it("a huge sparse file is refused after at most the archive's size plus one chunk, not read to its end", async () => {
    const root = install(BASE);
    // 64 GiB of holes: reading it to the end would take minutes, so the 10 s test timeout is the witness.
    truncateSync(join(root, "README.md"), 64 * 1024 * 1024 * 1024);
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-differs:README.md" });
  }, 10_000);
  it("a shorter file refuses installed-file-differs", async () => {
    expect(await check(install({ ...BASE, "README.md": "read" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-differs:README.md" });
  });
  it("a missing file refuses installed-file-missing", async () => {
    const { "README.md": _omit, ...rest } = BASE;
    expect(await check(install(rest), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-missing:README.md" });
  });
  it("a missing explicit empty directory refuses installed-file-missing", async () => {
    expect(await check(install(BASE), await archiveOf(BASE, [{ path: "package/empty/", type: "5" }]))).toEqual({ ok: false, reason: "installed-file-missing:empty" });
  });
  it("an extra file refuses installed-file-extra", async () => {
    expect(await check(install({ ...BASE, "dist/extra.js": "x" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-extra:dist/extra.js" });
  });
  it("an extra empty directory refuses installed-dir-extra", async () => {
    const root = install(BASE);
    mkdirSync(join(root, "dist", "plugins"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-dir-extra:dist/plugins" });
  });
  it("Foo in the archive against foo installed is a missing name and an extra one, never a match", async () => {
    const archive = await archiveOf({ ...BASE, "Notes.md": "n" });
    expect(await check(install({ ...BASE, "notes.md": "n" }), archive)).toEqual({ ok: false, reason: "installed-file-extra:notes.md" });
  });
  it("an NFD installed name matches its NFC archive entry, and the reverse", async () => {
    const nfc = "café.txt";
    const nfd = "café.txt";
    expect((await check(install({ ...BASE, [nfd]: "c" }), await archiveOf({ ...BASE, [nfc]: "c" }))).ok).toBe(true);
    expect((await check(install({ ...BASE, [nfc]: "c" }), await archiveOf({ ...BASE, [nfd]: "c" }))).ok).toBe(true);
  });
  it.runIf(CASE_SENSITIVE)("NFC and NFD spellings of one name both installed refuse installed-name-collision", async () => {
    const root = install({ ...BASE, "café.txt": "c", "café.txt": "c" });
    expect((await check(root, await archiveOf({ ...BASE, "café.txt": "c" })) as { reason: string }).reason).toMatch(/^installed-name-collision:caf/);
  });
  it.runIf(CASE_SENSITIVE)("a case variant installed beside its listed name refuses as an extra name, whatever the directory order", async () => {
    const root = install({ ...BASE, "Notes.md": "n", "notes.md": "n" });
    expect(await check(root, await archiveOf({ ...BASE, "Notes.md": "n" }))).toEqual({ ok: false, reason: "installed-file-extra:notes.md" });
  });
  it.runIf(CASE_SENSITIVE)("a case variant of a listed directory component refuses as an extra directory", async () => {
    const root = install({ ...BASE, "Lib/x.js": "x", "lib/y.js": "y" });
    expect(await check(root, await archiveOf({ ...BASE, "Lib/x.js": "x" }))).toEqual({ ok: false, reason: "installed-dir-extra:lib" });
  });
  it("a name that is not UTF-8 never matches an archive name holding U+FFFD", async () => {
    const root = install(BASE);
    writeFileSync(Buffer.concat([Buffer.from(`${root}/`), Buffer.from([0x66, 0xff, 0x66])]), "x");
    expect(await check(root, await archiveOf({ ...BASE, "f\uFFFDf": "x" }))).toEqual({ ok: false, reason: "installed-name-invalid:f\\xfff" });
  });
  it("a name that is not UTF-8 refuses installed-name-invalid with its raw bytes escaped and its directory", async () => {
    const root = install(BASE);
    writeFileSync(Buffer.concat([Buffer.from(`${root}/dist/`), Buffer.from([0x66, 0xff, 0x66])]), "x");
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-name-invalid:dist/f\\xfff" });
  });
  it("dist/cli.js renamed with a leading U+FEFF, bytes kept, refuses: no code point is dropped from a name", async () => {
    const { "dist/cli.js": body, ...rest } = BASE;
    const root = install({ ...rest, "dist/\uFEFFcli.js": body! });
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-extra:dist/\\xef\\xbb\\xbfcli.js" });
  });
  it("a name holding a leading U+FEFF matches the archive entry with the same code points", async () => {
    const files = { ...BASE, "\uFEFFnotes.md": "n" };
    expect((await check(install(files), await archiveOf(files))).ok).toBe(true);
  });
  it("a control character in a path is escaped in the reason", async () => {
    expect(await check(install({ ...BASE, "dist/a\nb.js": "x" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-extra:dist/a\\x0ab.js" });
  });
});

describe("object types", () => {
  it("a symlink replacing a file, pointing at matching bytes elsewhere, refuses installed-object-type", async () => {
    const root = install(BASE);
    const outside = tempRoot();
    writeFileSync(join(outside, "readme"), BASE["README.md"]!);
    rmSync(join(root, "README.md"));
    symlinkSync(join(outside, "readme"), join(root, "README.md"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:README.md" });
  });
  it("a symlinked directory refuses installed-object-type", async () => {
    const root = install(BASE);
    const outside = install({ "a.js": "a" });
    rmSync(join(root, "dist", "chunk"), { recursive: true });
    symlinkSync(outside, join(root, "dist", "chunk"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:dist/chunk" });
  });
  it("a hardlinked file refuses installed-object-type", async () => {
    const root = install(BASE);
    const outside = tempRoot();
    linkSync(join(root, "README.md"), join(outside, "second-name"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:README.md" });
  });
  it("a fifo refuses installed-object-type without blocking", async () => {
    const root = install(BASE);
    expect(spawnSync("mkfifo", [join(root, "dist", "pipe")]).status).toBe(0);
    expect(await check(root, await archiveOf({ ...BASE, "dist/pipe": "" }))).toEqual({ ok: false, reason: "installed-object-type:dist/pipe" });
  });
  it("an unlisted .DS_Store hardlinked to an outside file refuses: its descriptor is checked before it is skipped", async () => {
    const outside = tempRoot();
    writeFileSync(join(outside, "secret"), "outside bytes");
    for (const at of [".DS_Store", "dist/.DS_Store"]) {
      const root = install(BASE);
      linkSync(join(outside, "secret"), join(root, at));
      expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: `installed-object-type:${at}` });
    }
  });
  it("a symlink named .DS_Store refuses: type is checked before the exclusion", async () => {
    const root = install(BASE);
    symlinkSync("/etc/hosts", join(root, ".DS_Store"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:.DS_Store" });
  });
});

describe("exclusions", () => {
  it(".DS_Store files are ignored at any depth", async () => {
    expect((await check(install({ ...BASE, ".DS_Store": "f", "dist/.DS_Store": "f", "dist/chunk/.DS_Store": "f" }), await archiveOf(BASE))).ok).toBe(true);
  });
  it("a .DS_Store the archive lists is required and compared", async () => {
    const archive = await archiveOf({ ...BASE, "dist/.DS_Store": "listed" });
    expect(await check(install({ ...BASE, "dist/.DS_Store": "changed" }), archive)).toEqual({ ok: false, reason: "installed-file-differs:dist/.DS_Store" });
    expect(await check(install(BASE), archive)).toEqual({ ok: false, reason: "installed-file-missing:dist/.DS_Store" });
  });
  it("a top-level node_modules directory is pruned without being read, links inside included", async () => {
    const root = install({ ...BASE, "node_modules/dep/index.js": "dep" });
    symlinkSync("/etc", join(root, "node_modules", "link"));
    expect(spawnSync("mkfifo", [join(root, "node_modules", "pipe")]).status).toBe(0);
    expect((await check(root, await archiveOf(BASE))).ok).toBe(true);
  });
  it("Node_Modules at the top level is not the exclusion: it refuses as an extra directory", async () => {
    expect(await check(install({ ...BASE, "Node_Modules/dep/index.js": "dep" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-dir-extra:Node_Modules" });
  });
  it("node_module\u017F (long s) at the top level is not the exclusion: it refuses as an extra directory", async () => {
    expect(await check(install({ ...BASE, "node_module\u017F/dep/index.js": "dep" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-dir-extra:node_module\\xc5\\xbf" });
  });
  it(".ds_store is not the exclusion: it refuses as an extra file", async () => {
    expect(await check(install({ ...BASE, "dist/.ds_store": "f" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-file-extra:dist/.ds_store" });
  });
  it("a top-level node_modules that is a file refuses installed-object-type", async () => {
    expect(await check(install({ ...BASE, node_modules: "not a folder" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:node_modules" });
  });
  it("a top-level node_modules that is a symlink refuses installed-object-type", async () => {
    const root = install(BASE);
    symlinkSync(tempRoot(), join(root, "node_modules"));
    expect(await check(root, await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:node_modules" });
  });
  it("a nested node_modules is not pruned", async () => {
    expect(await check(install({ ...BASE, "dist/node_modules/x.js": "x" }), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-dir-extra:dist/node_modules" });
  });
});

describe("deadline", () => {
  it("expiry during hashing refuses deadline-exceeded", async () => {
    const clock = new ManualClock();
    let reads = 0;
    clock.now = () => (++reads > 6 ? RUN_DEADLINE_MS : 0);
    expect(await check(install(BASE), await archiveOf(BASE), clock)).toEqual({ ok: false, reason: "deadline-exceeded" });
  });
  it("a target that is not a directory refuses installed-object-type", async () => {
    const root = tempRoot();
    writeFileSync(join(root, "file"), "x");
    expect(await check(join(root, "file"), await archiveOf(BASE))).toEqual({ ok: false, reason: "installed-object-type:." });
  });
});

describe("bounded walk over an injected directory iterator", () => {
  const FAKE_ROOT = "/vr-injected-root";
  const entry = (name: string, kind: "file" | "dir"): InstalledDirent => ({ name: Buffer.from(name), isFile: () => kind === "file", isDirectory: () => kind === "dir" });
  /** An archive map that lists every directory name, so only the walk's own bounds can stop it. */
  const everyDirectoryListed: ArchiveEvidence = { state: "state_ARCHIVE", files: new Map(), directories: { has: () => true } as unknown as ReadonlySet<string> };
  const emptyArchive: ArchiveEvidence = { state: "state_ARCHIVE", files: new Map(), directories: new Set() };

  /** A lazily generated directory, so a test never builds the entries it offers. */
  function generated(make: (index: number) => InstalledDirent, count = Number.POSITIVE_INFINITY) {
    const stats = { pulled: 0, closed: false };
    async function* entries(): AsyncGenerator<InstalledDirent> {
      try {
        for (let index = 0; index < count; index++) {
          stats.pulled += 1;
          yield make(index);
        }
      } finally {
        stats.closed = true;
      }
    }
    return { stats, entries };
  }
  const injected = (directories: (path: string) => AsyncIterable<InstalledDirent>): InstalledFs => ({
    opendir: async path => directories(path.toString("utf8")),
    lstat: async () => { throw new Error("not used"); },
    open: async () => { throw new Error("not used"); },
  });
  async function* none(): AsyncGenerator<InstalledDirent> { /* an empty directory */ }

  it("a directory offering endless listed entries refuses installed-tree-oversize one entry past MAX_INSTALLED_ENTRIES, and closes its iterator", async () => {
    const root = generated(index => entry(`d${index}`, "dir"));
    const fs = injected(path => (path === FAKE_ROOT ? root.entries() : none()));
    expect(await check(FAKE_ROOT, everyDirectoryListed, new ManualClock(), fs)).toEqual({ ok: false, reason: "installed-tree-oversize" });
    expect(root.stats.pulled).toBe(MAX_INSTALLED_ENTRIES + 1);
    expect(root.stats.closed).toBe(true);
  });

  it("the count runs across the whole walk: directories each well under the cap still refuse installed-tree-oversize together", async () => {
    const perDirectory = 100;
    const directories = Math.ceil(MAX_INSTALLED_ENTRIES / perDirectory);
    // Depth 2 is the root's own children, depth 3 their children; those are empty.
    const depth = (path: string) => path.slice(FAKE_ROOT.length).split("/").length;
    const fs = injected(path => {
      if (path === FAKE_ROOT) return generated(index => entry(`d${index}`, "dir"), directories).entries();
      return depth(path) === 2 ? generated(index => entry(`e${index}`, "dir"), perDirectory).entries() : none();
    });
    expect(await check(FAKE_ROOT, everyDirectoryListed, new ManualClock(), fs)).toEqual({ ok: false, reason: "installed-tree-oversize" });
  });

  it("an endless directory of unlisted names refuses at the first one, pulling exactly one entry", async () => {
    const root = generated(index => entry(`x${index}.js`, "file"));
    const fs = injected(path => (path === FAKE_ROOT ? root.entries() : none()));
    expect(await check(FAKE_ROOT, emptyArchive, new ManualClock(), fs)).toEqual({ ok: false, reason: "installed-file-extra:x0.js" });
    expect(root.stats.pulled).toBe(1);
    expect(root.stats.closed).toBe(true);
  });

  it("the deadline is checked per entry: expiry part way through an endless directory refuses deadline-exceeded before the cap", async () => {
    const root = generated(index => entry(`d${index}`, "dir"));
    const fs = injected(path => (path === FAKE_ROOT ? root.entries() : none()));
    const clock = new ManualClock();
    const expireAfter = 50;
    let reads = 0;
    clock.now = () => (++reads > expireAfter ? RUN_DEADLINE_MS : 0);
    expect(await check(FAKE_ROOT, everyDirectoryListed, clock, fs)).toEqual({ ok: false, reason: "deadline-exceeded" });
    expect(root.stats.pulled).toBeLessThan(MAX_INSTALLED_ENTRIES);
  });
});
