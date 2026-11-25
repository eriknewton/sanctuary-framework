/**
 * state_INSTALLED: compare the target directory to the archive map.
 *
 * The contract is the content bytes and normalized names of regular files and
 * directories, excluding a top-level `node_modules` directory and `.DS_Store`
 * files. Links are never followed: a symlink, a special file or a hardlinked
 * file refuses, because each could make the bytes read here differ from what
 * the package's code would load. Concurrent writers are out of scope.
 */

import { createHash, timingSafeEqual } from "node:crypto";
import { constants as fsConstants, type Dirent } from "node:fs";
import { open, readdir } from "node:fs/promises";
import { join } from "node:path";
import type { Deadline } from "./deadline.js";
import { passed, type ArchiveEvidence, type ArchiveFile, type InstalledEvidence } from "./evidence.js";
import { nfc, simpleFold } from "./names.js";
import { refuse, withPath, type RefusalReason, type StepOutcome } from "./reasons.js";

const PRUNED_ROOT_DIRECTORY = "node_modules";
const IGNORED_FILE = ".ds_store";
/** Read size per call when hashing an installed file. */
const READ_CHUNK_BYTES = 1024 * 1024;
const OPEN_FILE_FLAGS = fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK;

class Refused extends Error {
  constructor(readonly reason: RefusalReason) {
    super(reason);
  }
}

/**
 * Hash one installed file through ONE descriptor opened no-follow: the type and
 * link count checked are those of the descriptor that is hashed, and reading
 * stops as soon as the bytes exceed the archive's size for that path.
 */
async function hashInstalledFile(path: Buffer, key: string, expected: ArchiveFile, deadline: Deadline): Promise<void> {
  let handle: Awaited<ReturnType<typeof open>>;
  try {
    handle = await open(path, OPEN_FILE_FLAGS);
  } catch {
    // ELOOP (a link swapped in) or any open failure: the object is not a plain readable file.
    throw new Refused(withPath("installed-object-type", key));
  }
  try {
    const stat = await handle.stat();
    // A hardlink shares its bytes with a path outside this check, so a second name could change them unseen.
    if (!stat.isFile() || stat.nlink > 1) throw new Refused(withPath("installed-object-type", key));
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(Math.min(READ_CHUNK_BYTES, expected.size + 1));
    let total = 0;
    for (;;) {
      if (deadline.expired()) throw new Refused("deadline-exceeded");
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > expected.size) throw new Refused(withPath("installed-file-differs", key));
      hash.update(buffer.subarray(0, bytesRead));
    }
    const digest = hash.digest();
    if (total !== expected.size || !timingSafeEqual(digest, Buffer.from(expected.sha256, "hex"))) {
      throw new Refused(withPath("installed-file-differs", key));
    }
  } catch (error) {
    if (error instanceof Refused) throw error;
    throw new Refused(withPath("installed-file-differs", key));
  } finally {
    await handle.close().catch(() => undefined);
  }
}

const decoder = new TextDecoder("utf-8", { fatal: true });

export async function state_INSTALLED(root: string, archive: ArchiveEvidence, deadline: Deadline): Promise<StepOutcome<InstalledEvidence>> {
  const seenKeys = new Set<string>();
  const seenFolds = new Set<string>();
  const seenFiles = new Set<string>();
  const seenDirectories = new Set<string>();

  async function walk(directory: Buffer, prefix: string): Promise<void> {
    let entries: Dirent<Buffer>[];
    try {
      entries = await readdir(directory, { withFileTypes: true, encoding: "buffer" });
    } catch {
      throw new Refused(withPath("installed-object-type", prefix === "" ? "." : prefix));
    }
    entries.sort((a, b) => Buffer.compare(a.name, b.name));
    for (const entry of entries) {
      if (deadline.expired()) throw new Refused("deadline-exceeded");
      let name: string;
      try {
        name = nfc(decoder.decode(entry.name));
      } catch {
        // A name that is not UTF-8 cannot equal any archive path.
        throw new Refused(withPath("installed-file-extra", `${prefix}${entry.name.toString("latin1")}`));
      }
      const key = prefix + name;
      // Two names with one NFC form, or one case-folded form, would be one path somewhere; both are collisions.
      const folded = simpleFold(key);
      if (seenKeys.has(key) || seenFolds.has(folded)) throw new Refused(withPath("installed-name-collision", key));
      seenKeys.add(key);
      seenFolds.add(folded);
      const path = Buffer.from(join(directory.toString("latin1"), entry.name.toString("latin1")), "latin1");
      const folds = simpleFold(name);

      // Type first, before any exclusion, so no name makes a link or a special file acceptable.
      if (!entry.isFile() && !entry.isDirectory()) throw new Refused(withPath("installed-object-type", key));
      if (prefix === "" && folds === PRUNED_ROOT_DIRECTORY) {
        // Dependencies are outside the contract; the directory is pruned without being read.
        if (!entry.isDirectory()) throw new Refused(withPath("installed-object-type", key));
        continue;
      }
      if (entry.isDirectory()) {
        if (!archive.directories.has(key)) throw new Refused(withPath("installed-dir-extra", key));
        seenDirectories.add(key);
        await walk(path, `${key}/`);
        continue;
      }
      const expected = archive.files.get(key);
      if (expected === undefined) {
        // Finder metadata is ignored only when the archive does not list a file of that name.
        if (folds === IGNORED_FILE) continue;
        throw new Refused(withPath("installed-file-extra", key));
      }
      await hashInstalledFile(path, key, expected, deadline);
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
  if (deadline.expired()) return refuse("deadline-exceeded");
  return passed({ state: "state_INSTALLED", fileCount: seenFiles.size });
}
