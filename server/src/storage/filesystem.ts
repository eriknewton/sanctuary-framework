/**
 * Sanctuary MCP Server — Filesystem Storage Backend
 *
 * Default storage backend using the local filesystem.
 * Files are stored as: {basePath}/{namespace}/{key}.enc
 *
 * Security invariants:
 * - Secure deletion overwrites file content with random bytes before unlinking
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
 *   `replace(/[^a-zA-Z0-9_.-]/g, "_")` for keys — non-bijective. read(),
 *   exists(), and delete() try the new path first; on ENOENT they fall back
 *   to the legacy path so existing fortresses with operator-supplied
 *   namespaces containing non-safe characters keep working. write() always
 *   uses the new bijective path. list() and totalSize() walk on-disk
 *   directory names directly and cannot disambiguate legacy collision-class
 *   pairs — they are forward-only by design.
 */

import { mkdir, readFile, writeFile, unlink, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "../core/random.js";
import type { StorageBackend, StorageEntryMeta } from "./interface.js";

const SAFE_CHARS = /[^A-Za-z0-9_.\-]/g;

function bijectiveEncode(name: string): string {
  return name.replace(SAFE_CHARS, (ch) =>
    "!" + ch.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()
  );
}

// Legacy whitelist sanitizers — used ONLY for read-fallback against fortresses
// written before full-sweep #41. write() never produces these paths.
function legacyNamespaceSanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}
function legacyKeySanitize(name: string): string {
  return name.replace(/[^a-zA-Z0-9_.-]/g, "_");
}

export class FilesystemStorage implements StorageBackend {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private entryPath(namespace: string, key: string): string {
    const safeNamespace = bijectiveEncode(namespace);
    const safeKey = bijectiveEncode(key);
    return join(this.basePath, safeNamespace, `${safeKey}.enc`);
  }

  private namespacePath(namespace: string): string {
    return join(this.basePath, bijectiveEncode(namespace));
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
    const dirPath = this.namespacePath(namespace);
    const filePath = this.entryPath(namespace, key);

    // Create namespace directory with restrictive permissions
    await mkdir(dirPath, { recursive: true, mode: 0o700 });

    // Write file with restrictive permissions (owner read/write only)
    await writeFile(filePath, data, { mode: 0o600 });
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

        // Overwrite with random bytes (3 passes for defense in depth)
        for (let pass = 0; pass < 3; pass++) {
          const randomData = randomBytes(size);
          await writeFile(filePath, randomData, { mode: 0o600 });
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
    const dirPath = this.namespacePath(namespace);

    try {
      const files = await readdir(dirPath);
      const entries: StorageEntryMeta[] = [];

      for (const file of files) {
        if (!file.endsWith(".enc")) continue;

        const key = file.slice(0, -4); // Remove .enc extension
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
