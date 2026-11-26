/**
 * state_ARCHIVE: stream-parse the verified tarball into a map of regular-file
 * paths to sha256 and size. Nothing is written to disk and nothing from the
 * tarball is executed or required, so a hostile archive can only fail to
 * parse; there is no extraction for a path trick to escape from.
 *
 * `tar` (node-tar, npm's own parser) is imported here with `await import()`
 * only, inside the step.
 */

import { createHash } from "node:crypto";
import { createGunzip } from "node:zlib";
import {
  ARCHIVE_PREFIX,
  MAX_ARCHIVE_ENTRIES,
  MAX_ARCHIVE_EXPANDED_BYTES,
  MAX_ARCHIVE_FILE_BYTES,
  MAX_ARCHIVE_PATH_LENGTH,
} from "./constants.js";
import type { Deadline } from "./deadline.js";
import { passed, type ArchiveEvidence, type ArchiveFile } from "./evidence.js";
import { nfc, simpleFold } from "./names.js";
import { refuse, withPath, type RefusalReason, type StepOutcome } from "./reasons.js";

/** The entry types the map accepts; npm packs only regular files. `OldFile` is the pre-POSIX regular-file type. */
const REGULAR_FILE_TYPES = new Set(["File", "OldFile"]);
const DIRECTORY_TYPE = "Directory";

/**
 * The map key for one archive path: exactly one leading `package/` removed,
 * NFC-normalized. Absolute paths, empty, `.` and `..` segments are refused, so
 * every key names one unambiguous location under the package root.
 */
export function archiveKey(rawPath: string, isDirectory: boolean): { ok: true; key: string } | { ok: false; reason: RefusalReason } {
  if (rawPath.length > MAX_ARCHIVE_PATH_LENGTH) return { ok: false, reason: "archive-oversize:path-length" };
  if (rawPath.startsWith("/")) return { ok: false, reason: "archive-invalid:absolute-path" };
  if (!rawPath.startsWith(ARCHIVE_PREFIX)) return { ok: false, reason: "archive-invalid:outside-package" };
  let rest = rawPath.slice(ARCHIVE_PREFIX.length);
  if (isDirectory && rest.endsWith("/")) rest = rest.slice(0, -1);
  if (isDirectory && rest === "") return { ok: true, key: "" };
  for (const segment of rest.split("/")) {
    if (segment === "..") return { ok: false, reason: "archive-invalid:dot-dot-segment" };
    if (segment === "" || segment === ".") return { ok: false, reason: "archive-invalid:empty-segment" };
  }
  return { ok: true, key: nfc(rest) };
}

function parentsOf(key: string): string[] {
  const parts = key.split("/");
  return parts.slice(1).map((_, index) => parts.slice(0, index + 1).join("/"));
}

/** Records entries and enforces duplicate, conflict and case-fold rules over files and every directory. */
class ArchiveMap {
  readonly files = new Map<string, ArchiveFile>();
  readonly directories = new Set<string>();
  readonly #explicitDirectories = new Set<string>();

  addDirectory(key: string, explicit: boolean): RefusalReason | null {
    if (key === "") return null;
    if (this.files.has(key)) return "archive-invalid:file-directory-conflict";
    if (explicit) {
      if (this.#explicitDirectories.has(key)) return "archive-invalid:duplicate";
      this.#explicitDirectories.add(key);
    }
    this.directories.add(key);
    for (const parent of parentsOf(key)) {
      if (this.files.has(parent)) return "archive-invalid:file-directory-conflict";
      this.directories.add(parent);
    }
    return null;
  }

  checkFile(key: string): RefusalReason | null {
    if (this.files.has(key)) return "archive-invalid:duplicate";
    if (this.directories.has(key)) return "archive-invalid:file-directory-conflict";
    for (const parent of parentsOf(key)) {
      if (this.files.has(parent)) return "archive-invalid:file-directory-conflict";
    }
    return null;
  }

  addFile(key: string, file: ArchiveFile): void {
    this.files.set(key, file);
    for (const parent of parentsOf(key)) this.directories.add(parent);
  }

  /** Two distinct keys, files or directories, that fold to one name would land on one path on a case-insensitive volume. */
  caseFoldCollision(): boolean {
    const seen = new Set<string>();
    for (const key of [...this.files.keys(), ...this.directories]) {
      const folded = simpleFold(key);
      if (seen.has(folded)) return true;
      seen.add(folded);
    }
    return false;
  }
}

interface TarEntry {
  type: string;
  path: string;
  size: number;
  on(event: "data", listener: (chunk: Buffer) => void): unknown;
  on(event: "end", listener: () => void): unknown;
  resume(): unknown;
}

export async function state_ARCHIVE(tarball: Buffer, deadline: Deadline): Promise<StepOutcome<ArchiveEvidence>> {
  const { Parser } = await import("tar");
  const map = new ArchiveMap();
  return new Promise<StepOutcome<ArchiveEvidence>>(resolve => {
    let settled = false;
    let entries = 0;
    let expanded = 0;
    const gunzip = createGunzip();
    const finish = (outcome: StepOutcome<ArchiveEvidence>): void => {
      if (settled) return;
      settled = true;
      deadline.signal.removeEventListener("abort", onAbort);
      gunzip.destroy();
      parser.abort(new Error("stopped"));
      resolve(outcome);
    };
    const fail = (reason: RefusalReason): void => finish(refuse(reason));
    const onAbort = (): void => fail("deadline-exceeded");

    const parser = new Parser({
      // Any warning (a checksum failure, an entry the parser would skip, truncation) is a refusal, never a skipped entry.
      onwarn: (code: string) => fail(`archive-invalid:${/^[A-Z_]{1,64}$/.test(code) ? code : "TAR_WARNING"}`),
      onReadEntry: (raw: unknown) => {
        const entry = raw as TarEntry;
        if (settled) return;
        if (deadline.expired()) return fail("deadline-exceeded");
        entries += 1;
        if (entries > MAX_ARCHIVE_ENTRIES) return fail("archive-oversize:entry-count");
        const isDirectory = entry.type === DIRECTORY_TYPE;
        if (!isDirectory && !REGULAR_FILE_TYPES.has(entry.type)) return fail(withPath("archive-entry-type", entry.path));
        const keyed = archiveKey(entry.path, isDirectory);
        if (!keyed.ok) return fail(keyed.reason);
        if (isDirectory) {
          const problem = map.addDirectory(keyed.key, true);
          if (problem !== null) return fail(problem);
          entry.resume();
          return;
        }
        if (entry.size > MAX_ARCHIVE_FILE_BYTES) return fail("archive-oversize:file-size");
        const problem = map.checkFile(keyed.key);
        if (problem !== null) return fail(problem);
        const hash = createHash("sha256");
        let size = 0;
        entry.on("data", chunk => {
          size += chunk.length;
          hash.update(chunk);
        });
        // node-tar warns (a refusal here) before it ends an entry short, so the byte count always equals entry.size.
        entry.on("end", () => {
          if (settled) return;
          map.addFile(keyed.key, { sha256: hash.digest("hex"), size });
        });
      },
    });
    parser.on("error", () => fail("archive-invalid:tar"));
    parser.on("end", () => {
      if (settled) return;
      if (map.caseFoldCollision()) return fail("archive-invalid:case-fold-collision");
      finish(passed({ state: "state_ARCHIVE", files: map.files, directories: map.directories }));
    });

    gunzip.on("data", (chunk: Buffer) => {
      if (settled) return;
      expanded += chunk.length;
      // Counted on the gunzipped stream itself, so a small archive that inflates hugely stops at the cap.
      if (expanded > MAX_ARCHIVE_EXPANDED_BYTES) return fail("archive-oversize:expanded-bytes");
      if (parser.write(chunk) === false) {
        gunzip.pause();
        parser.once("drain", () => gunzip.resume());
      }
    });
    gunzip.on("end", () => { if (!settled) parser.end(); });
    gunzip.on("error", () => fail("archive-invalid:gzip"));

    deadline.signal.addEventListener("abort", onAbort, { once: true });
    if (deadline.expired()) return fail("deadline-exceeded");
    gunzip.end(tarball);
  });
}
