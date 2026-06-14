/**
 * Sanctuary MCP Server — Filesystem Storage Backend
 *
 * Default storage backend using the local filesystem.
 * Files are stored as: {basePath}/{namespace}/{key}.enc
 *
 * Security invariants:
 * - Data at rest is CIPHERTEXT: state entries are encrypted before they reach
 *   this backend. Secure deletion makes a best-effort attempt to overwrite the
 *   file's bytes with random data (3 passes, each fsync'd) before unlinking, so
 *   any residual on the medium is overwritten random bytes or the prior
 *   ciphertext — never plaintext. In-place overwrite is NOT guaranteed on
 *   copy-on-write (APFS), journaled (ext4), or flash-FTL/SSD storage, where the
 *   filesystem or controller may write the new bytes to fresh blocks and leave
 *   the original blocks intact until reclaimed. This routine therefore does not
 *   promise unrecoverable erasure of the original on-disk bytes; the at-rest
 *   confidentiality guarantee rests on encryption, not on this overwrite.
 * - Directory creation uses restrictive permissions (0o700)
 * - File creation uses restrictive permissions (0o600)
 *
 * Path encoding (bijective, full-sweep #41):
 *   Distinct (namespace, key) inputs MUST produce distinct on-disk paths;
 *   otherwise an agent that can choose namespace/key strings within a tenant
 *   could overwrite or read another namespace by colliding on the sanitized
 *   form (multi-tenant isolation invariant). The encoder retains the safe
 *   set [A-Za-z0-9_.-] (so internal namespaces such as `_audit`, `_bridge`,
 *   etc. preserve their on-disk paths verbatim) and `!`-escapes every other
 *   character as `!XX` where XX is the upper-hex byte. The escape character
 *   `!` itself is NOT in the safe set, so a literal `!` in input encodes as
 *   `!21` and decoding remains unambiguous.
 *
 * Legacy fallback (forward compatibility):
 *   Pre-fix code used `replace(/[^a-zA-Z0-9_-]/g, "_")` for namespaces and
 *   `replace(/[^a-zA-Z0-9_.-]/g, "_")` for keys; non-bijective. read(),
 *   exists(), and delete() try the new path first; on ENOENT they fall back
 *   to the legacy path so existing fortresses with operator-supplied
 *   namespaces containing non-safe characters keep working. write() always
 *   uses the new bijective path. list() and totalSize() walk on-disk
 *   directory names directly and cannot disambiguate legacy collision-class
 *   pairs; they are forward-only by design.
 */

import { mkdir, open, readFile, unlink, readdir, rename, stat } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "../core/random.js";
import {
  assertSdwRawWriteAuthorized,
  isSdwNamespace,
} from "../sdw/write-gate.js";
import type {
  FilesystemStorageCapabilities,
  StorageBackend,
  StorageEntryMeta,
} from "./interface.js";

const SAFE_CHARS = /[^A-Za-z0-9_.-]/g;

function bijectiveEncode(name: string): string {
  return name.replace(SAFE_CHARS, (ch) =>
    "!" + ch.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  );
}

function bijectiveDecode(encoded: string): string {
  return encoded.replace(/!([0-9A-Fa-f]{2})/g, (_match, hex) =>
    String.fromCharCode(parseInt(hex, 16))
  );
}

// Legacy whitelist sanitizers, used ONLY for read-fallback against fortresses
// written before full-sweep #41. write() never produces these paths.
function legacyNamespaceSanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}
function legacyKeySanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

function encodedNamespacePath(basePath: string, namespace: string): string {
  return join(basePath, bijectiveEncode(namespace));
}

export class FilesystemStorage implements StorageBackend, FilesystemStorageCapabilities {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private entryPath(namespace: string, key: string): string {
    const safeNamespace = bijectiveEncode(namespace);
    const safeKey = bijectiveEncode(key);
    return join(this.basePath, safeNamespace, `${safeKey}.enc`);
  }

  namespacePath(namespace: string): string {
    if (isSdwNamespace(namespace)) {
      throw new Error("Filesystem paths for SDW namespaces are not exposed");
    }
    return encodedNamespacePath(this.basePath, namespace);
  }

  // Legacy on-disk paths produced by the pre-#41 sanitizer. Returned for
  // ENOENT-fallback in read/exists/delete; never written to.
  private legacyEntryPath(namespace: string, key: string): string {
    return join(
      this.basePath,
      legacyNamespaceSanitize(namespace),
      `${legacyKeySanitize(key)}.enc`
    );
  }

  async write(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const dirPath = encodedNamespacePath(this.basePath, namespace);
    const filePath = this.entryPath(namespace, key);

    await mkdir(dirPath, { recursive: true, mode: 0o700 });
    await this.atomicWriteFile(filePath, checkedData, false);
  }

  async writeDurable(
    namespace: string,
    key: string,
    data: Uint8Array
  ): Promise<void> {
    const checkedData = assertSdwRawWriteAuthorized(namespace, key, data);
    const dirPath = encodedNamespacePath(this.basePath, namespace);
    const filePath = this.entryPath(namespace, key);

    await mkdir(dirPath, { recursive: true, mode: 0o700 });
    await this.atomicWriteFile(filePath, checkedData, true);
  }

  private async atomicWriteFile(
    filePath: string,
    data: Uint8Array,
    syncFile: boolean
  ): Promise<void> {
    const dirPath = dirname(filePath);
    const tempPath = join(
      dirPath,
      `.${basename(filePath)}.${process.pid}.${Date.now()}.${Math.random()
        .toString(16)
        .slice(2)}.tmp`
    );
    const handle = await open(tempPath, "wx", 0o600);
    try {
      await handle.writeFile(data);
      if (syncFile) await handle.sync();
    } finally {
      await handle.close();
    }
    try {
      await rename(tempPath, filePath);
      if (syncFile) await this.fsyncDirectory(dirPath);
    } catch (err) {
      await unlink(tempPath).catch(() => undefined);
      throw err;
    }
  }

  private async fsyncDirectory(dirPath: string): Promise<void> {
    let handle;
    try {
      handle = await open(dirPath, "r");
      await handle.sync();
    } catch {
      // Directory fsync is best-effort across platforms/filesystems. The file
      // itself has already been fsynced before the atomic rename.
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const buf = await this.readAtPath(this.entryPath(namespace, key));
    if (buf !== null) return buf;
    // Legacy fallback: fortresses written before #41 used a non-bijective
    // sanitizer; if the new-form path is missing, try the legacy form.
    const legacy = this.legacyEntryPath(namespace, key);
    if (legacy === this.entryPath(namespace, key)) return null;
    return this.readAtPath(legacy);
  }

  private async readAtPath(filePath: string): Promise<Uint8Array | null> {
    try {
      const buf = await readFile(filePath);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return null;
      }
      throw err;
    }
  }

  async delete(
    namespace: string,
    key: string,
    secureOverwrite = true
  ): Promise<boolean> {
    const newPath = this.entryPath(namespace, key);
    if (await this.deleteAtPath(newPath, secureOverwrite)) return true;
    // Legacy fallback: existing fortresses may have data at the old path.
    const legacy = this.legacyEntryPath(namespace, key);
    if (legacy === newPath) return false;
    return this.deleteAtPath(legacy, secureOverwrite);
  }

  private async deleteAtPath(
    filePath: string,
    secureOverwrite: boolean
  ): Promise<boolean> {
    try {
      if (secureOverwrite) {
        // Read the file to determine its size
        const fileStat = await stat(filePath);
        const size = fileStat.size;

        // A zero-byte file has no content to overwrite (and randomBytes(0)
        // rejects a non-positive length); skip straight to unlink.
        // Overwrite with random bytes (3 passes for defense in depth). Each
        // pass is fsync'd so the bytes are flushed to the medium rather than
        // left in the page cache; this is best-effort durability, not a
        // guarantee of in-place overwrite on CoW / journaled / flash-FTL
        // filesystems (see the header comment).
        for (let pass = 0; size > 0 && pass < 3; pass++) {
          const randomData = randomBytes(size);
          const fileHandle = await open(filePath, "r+");
          try {
            // write() may short-write, so loop until every byte is on the fd
            // before fsync; otherwise a pass could flush only a prefix and
            // leave the suffix as prior ciphertext.
            let offset = 0;
            while (offset < randomData.length) {
              const { bytesWritten } = await fileHandle.write(
                randomData,
                offset,
                randomData.length - offset,
                offset
              );
              if (bytesWritten === 0) break;
              offset += bytesWritten;
            }
            await fileHandle.sync();
          } finally {
            await fileHandle.close();
          }
        }
      }

      // Remove the file
      await unlink(filePath);
      return true;
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return false;
      }
      throw err;
    }
  }

  async list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    const dirPath = encodedNamespacePath(this.basePath, namespace);

    try {
      const files = await readdir(dirPath);
      const entries: StorageEntryMeta[] = [];

      for (const file of files) {
        if (!file.endsWith(".enc")) continue;

        const encodedKey = file.slice(0, -4); // Remove .enc extension
        const key = bijectiveDecode(encodedKey);
        if (prefix && !key.startsWith(prefix)) continue;

        const filePath = join(dirPath, file);
        const fileStat = await stat(filePath);

        entries.push({
          key,
          namespace,
          size_bytes: fileStat.size,
          modified_at: fileStat.mtime.toISOString(),
        });
      }

      return entries.sort((a, b) => a.key.localeCompare(b.key));
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        "code" in err &&
        (err as NodeJS.ErrnoException).code === "ENOENT"
      ) {
        return [];
      }
      throw err;
    }
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    const newPath = this.entryPath(namespace, key);
    try {
      await stat(newPath);
      return true;
    } catch {
      // Legacy fallback for pre-#41 fortresses.
      const legacy = this.legacyEntryPath(namespace, key);
      if (legacy === newPath) return false;
      try {
        await stat(legacy);
        return true;
      } catch {
        return false;
      }
    }
  }

  async listNamespaces(): Promise<string[]> {
    let dirNames: string[];
    try {
      dirNames = await readdir(this.basePath);
    } catch {
      return []; // Base path does not exist yet — empty fortress.
    }
    const namespaces: string[] = [];
    for (const dirName of dirNames) {
      try {
        const s = await stat(join(this.basePath, dirName));
        if (!s.isDirectory()) continue;
      } catch {
        continue;
      }
      // Skip empty namespace directories: a namespace with no entries holds
      // nothing to rotate, and surfacing it would only trip the rotation
      // walker's unknown-namespace abort for leftover empty dirs.
      try {
        const files = await readdir(join(this.basePath, dirName));
        if (!files.some((f) => f.endsWith(".enc"))) continue;
      } catch {
        continue;
      }
      // bijectiveDecode is total (unmatched bytes pass through), so legacy
      // pre-#41 sanitized directory names still surface — as their raw names
      // — and the rotation walker's unknown-namespace abort catches them
      // (fail closed) instead of silently skipping a namespace.
      namespaces.push(bijectiveDecode(dirName));
    }
    return namespaces.sort();
  }

  async totalSize(): Promise<number> {
    let total = 0;

    try {
      const namespaces = await readdir(this.basePath);
      for (const ns of namespaces) {
        const nsPath = join(this.basePath, ns);
        const nsStat = await stat(nsPath);
        if (!nsStat.isDirectory()) continue;

        const files = await readdir(nsPath);
        for (const file of files) {
          const filePath = join(nsPath, file);
          const fileStat = await stat(filePath);
          total += fileStat.size;
        }
      }
    } catch {
      // If base path doesn't exist yet, total is 0
    }

    return total;
  }
}
