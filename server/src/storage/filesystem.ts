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
 */

import { mkdir, readFile, writeFile, unlink, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { randomBytes } from "../core/random.js";
import type { StorageBackend, StorageEntryMeta } from "./interface.js";

export class FilesystemStorage implements StorageBackend {
  private basePath: string;

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  private entryPath(namespace: string, key: string): string {
    // Sanitize namespace and key to prevent path traversal
    const safeNamespace = namespace.replace(/[^a-zA-Z0-9_-]/g, "_");
    const safeKey = key.replace(/[^a-zA-Z0-9_.-]/g, "_");
    return join(this.basePath, safeNamespace, `${safeKey}.enc`);
  }

  private namespacePath(namespace: string): string {
    const safeNamespace = namespace.replace(/[^a-zA-Z0-9_-]/g, "_");
    return join(this.basePath, safeNamespace);
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
    const filePath = this.entryPath(namespace, key);
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
    const filePath = this.entryPath(namespace, key);

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
    const filePath = this.entryPath(namespace, key);
    try {
      await stat(filePath);
      return true;
    } catch {
      return false;
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
