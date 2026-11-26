/**
 * state_INSTALLED: compare the target directory to the archive map.
 *
 * The contract is the content bytes and normalized names of regular files and
 * directories, excluding exactly two byte names: a top-level `node_modules`
 * directory and `.DS_Store` regular files. Links are never followed: a
 * symlink, a special file or a hardlinked file refuses, because each could
 * make the bytes read here differ from what the package's code would load.
 * The walk reads each directory incrementally, refuses at the first entry the
 * archive does not list, and reads at most MAX_INSTALLED_ENTRIES entries in
 * all. Concurrent writers are out of scope.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, type Dirent, type Stats } from "node:fs";
import { lstat, open, opendir } from "node:fs/promises";
import { join } from "node:path";
import { MAX_INSTALLED_ENTRIES } from "./constants.js";
import type { Deadline } from "./deadline.js";
import { passed, type ArchiveEvidence, type ArchiveFile, type InstalledEvidence } from "./evidence.js";
import { nfc, simpleFold } from "./names.js";
import { refuse, withPath, type RefusalReason, type StepOutcome } from "./reasons.js";

/** The two exclusions, as exact byte names: no other spelling, case or fold of them is excluded. */
const PRUNED_ROOT_DIRECTORY = Buffer.from("node_modules", "utf8");
const IGNORED_FILE = Buffer.from(".DS_Store", "utf8");
/** Read size per call when hashing an installed file. */
const READ_CHUNK_BYTES = 1024 * 1024;
const OPEN_FILE_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;

export type InstalledDirent = Pick<Dirent<Buffer>, "name" | "isFile" | "isDirectory">;
export interface InstalledFileHandle {
  stat(): Promise<Pick<Stats, "isFile" | "nlink">>;
  read(buffer: Buffer, offset: number, length: number, position: null): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}
/** The filesystem calls the walk makes; tests inject directory iterators through it. */
export interface InstalledFs {
  /** One directory's entries, yielded lazily; never the whole listing at once. */
  opendir(path: Buffer): Promise<AsyncIterable<InstalledDirent>>;
  lstat(path: Buffer): Promise<Pick<Stats, "isDirectory">>;
  open(path: Buffer, flags: number): Promise<InstalledFileHandle>;
}

export const NODE_INSTALLED_FS: InstalledFs = {
  // Buffer names keep each name's bytes exactly as stored; the Node typings do not model this encoding.
  opendir: path => opendir(path, { encoding: "buffer" as BufferEncoding }) as unknown as Promise<AsyncIterable<InstalledDirent>>,
  lstat: path => lstat(path),
  open: (path, flags) => open(path, flags),
};

class Refused extends Error {
  constructor(readonly reason: RefusalReason) {
    super(reason);
  }
}

/** Named classes of an entry, decided while its directory is read. */
type EntryKind = "listed" | "excluded-directory" | "excluded-file";
interface Accepted { readonly name: Buffer; readonly key: string; readonly path: Buffer; readonly kind: EntryKind; readonly dirent: InstalledDirent }

/**
 * Open one installed file no-follow and check the descriptor itself: the type
 * and link count checked are those of the descriptor that is then read.
 */
async function openRegularFile(fs: InstalledFs, path: Buffer, key: string): Promise<InstalledFileHandle> {
  let handle: InstalledFileHandle;
  try {
    handle = await fs.open(path, OPEN_FILE_FLAGS);
  } catch {
    // ELOOP (a link swapped in) or any open failure: the object is not a plain readable file.
    throw new Refused(withPath("installed-object-type", key));
  }
  let stat: Pick<Stats, "isFile" | "nlink">;
  try {
    stat = await handle.stat();
  } catch {
    await handle.close().catch(() => undefined);
    throw new Refused(withPath("installed-file-unreadable", key));
  }
  // A hardlink shares its bytes with a path outside this check, so a second name could change them unseen.
  if (!stat.isFile() || stat.nlink !== 1) {
    await handle.close().catch(() => undefined);
    throw new Refused(withPath("installed-object-type", key));
  }
  return handle;
}

/** Hash one installed file; reading stops as soon as the bytes exceed the archive's size for that path. */
async function hashInstalledFile(fs: InstalledFs, path: Buffer, key: string, expected: ArchiveFile, deadline: Deadline): Promise<void> {
  const handle = await openRegularFile(fs, path, key);
  try {
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(Math.min(READ_CHUNK_BYTES, expected.size + 1));
    let total = 0;
    for (;;) {
      if (deadline.expired()) throw new Refused("deadline-exceeded");
      let bytesRead: number;
      try {
        ({ bytesRead } = await handle.read(buffer, 0, buffer.length, null));
      } catch {
        // An I/O error says nothing about the bytes, so it must not read as a content difference.
        throw new Refused(withPath("installed-file-unreadable", key));
      }
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > expected.size) throw new Refused(withPath("installed-file-differs", key));
      hash.update(buffer.subarray(0, bytesRead));
    }
    // A shorter file has another sha256, so the digest comparison covers size too.
    if (!timingSafeEqual(hash.digest(), Buffer.from(expected.sha256, "hex"))) {
      throw new Refused(withPath("installed-file-differs", key));
    }
  } finally {
    await handle.close().catch(() => undefined);
  }
}

// ignoreBOM keeps a leading U+FEFF: no code point of a name is ever dropped, so names compare after NFC only.
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

export async function state_INSTALLED(
  root: string,
  archive: ArchiveEvidence,
  deadline: Deadline,
  fs: InstalledFs = NODE_INSTALLED_FS,
): Promise<StepOutcome<InstalledEvidence>> {
  const seenFolds = new Set<string>();
  const seenFiles = new Set<string>();
  const seenDirectories = new Set<string>();
  let visited = 0;

  /**
   * Read one directory lazily. Each entry is counted, deadline-checked and
   * classified as it arrives, and an entry that is neither listed nor an exact
   * exclusion refuses at once, so an unbounded directory is never held.
   */
  async function readDirectory(directory: Buffer, prefix: string): Promise<Accepted[]> {
    let entries: AsyncIterable<InstalledDirent>;
    try {
      entries = await fs.opendir(directory);
    } catch {
      throw new Refused(withPath("installed-object-type", prefix === "" ? "." : prefix));
    }
    const accepted: Accepted[] = [];
    try {
      for await (const dirent of entries) {
        visited += 1;
        // A running cap over the whole walk: no target, however large, costs more than MAX_INSTALLED_ENTRIES reads.
        if (visited > MAX_INSTALLED_ENTRIES) throw new Refused("installed-tree-oversize");
        if (deadline.expired()) throw new Refused("deadline-exceeded");
        let name: string;
        try {
          name = nfc(decoder.decode(dirent.name));
        } catch {
          // A name that is not UTF-8 has no NFC form, so it can equal no archive path.
          throw new Refused(withPath("installed-name-invalid", Buffer.concat([Buffer.from(prefix, "utf8"), dirent.name])));
        }
        const key = prefix + name;
        const path = Buffer.from(join(directory.toString("latin1"), dirent.name.toString("latin1")), "latin1");
        const kind: EntryKind | null = prefix === "" && dirent.name.equals(PRUNED_ROOT_DIRECTORY) ? "excluded-directory"
          : archive.files.has(key) || archive.directories.has(key) ? "listed"
            : dirent.name.equals(IGNORED_FILE) ? "excluded-file"
              : null;
        if (kind === null) {
          if (dirent.isDirectory()) throw new Refused(withPath("installed-dir-extra", key));
          if (dirent.isFile()) throw new Refused(withPath("installed-file-extra", key));
          throw new Refused(withPath("installed-object-type", key));
        }
        accepted.push({ name: dirent.name, key, path, kind, dirent });
      }
    } catch (error) {
      if (error instanceof Refused) throw error;
      throw new Refused(withPath("installed-object-type", prefix === "" ? "." : prefix));
    }
    // Sorted only after the cap held, so which refusal a tree reports does not depend on directory order.
    return accepted.sort((a, b) => Buffer.compare(a.name, b.name));
  }

  async function walk(directory: Buffer, prefix: string): Promise<void> {
    for (const { key, path, kind, dirent } of await readDirectory(directory, prefix)) {
      // Two names with one NFC form would be one path somewhere; the fold is taken over the NFC key.
      const folded = simpleFold(key);
      if (seenFolds.has(folded)) throw new Refused(withPath("installed-name-collision", key));
      seenFolds.add(folded);

      if (kind === "excluded-directory") {
        // Checked as a real directory, not a link, before it is pruned unread: dependencies are outside the contract.
        const stat = await fs.lstat(path).catch(() => null);
        if (stat === null || !stat.isDirectory()) throw new Refused(withPath("installed-object-type", key));
        continue;
      }
      if (kind === "excluded-file") {
        // Checked on its own descriptor before it is skipped, so no link or special file hides behind the name.
        await (await openRegularFile(fs, path, key)).close().catch(() => undefined);
        continue;
      }
      // Type first, so no listed name makes a link or a special file acceptable.
      if (!dirent.isFile() && !dirent.isDirectory()) throw new Refused(withPath("installed-object-type", key));
      if (dirent.isDirectory()) {
        if (!archive.directories.has(key)) throw new Refused(withPath("installed-dir-extra", key));
        seenDirectories.add(key);
        await walk(path, `${key}/`);
        continue;
      }
      const expected = archive.files.get(key);
      if (expected === undefined) throw new Refused(withPath("installed-file-extra", key));
      await hashInstalledFile(fs, path, key, expected, deadline);
      seenFiles.add(key);
    }
  }

  try {
    await walk(Buffer.from(root, "utf8"), "");
  } catch (error) {
    if (error instanceof Refused) return refuse(error.reason);
    throw error;
  }
  const missing = [
    ...[...archive.files.keys()].filter(key => !seenFiles.has(key)),
    ...[...archive.directories].filter(key => !seenDirectories.has(key)),
  ].sort();
  if (missing.length > 0) return refuse(withPath("installed-file-missing", missing[0]!));
  return passed({ state: "state_INSTALLED", fileCount: seenFiles.size });
}
