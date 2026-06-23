import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SdwMemoryBackendAdapter } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { conformanceKitForMemoryBackendAdapter } from "./memory-backend-conformance.js";

const FORTRESS_ID = "fortress:test";
const MASTER_KEY = new Uint8Array(32).fill(23);
const NOW = "2026-06-22T00:00:00.000Z";

conformanceKitForMemoryBackendAdapter(
  async () => {
    const storagePath = await mkdtemp(join(tmpdir(), "sdw-memory-conformance-"));
    const storage = new FilesystemStorage(storagePath);
    const adapter = new SdwMemoryBackendAdapter({
      storage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
      ownerRef: "conformance-archive",
      maxChunkChars: 16,
      now: () => NOW,
    });

    return {
      adapter,
      readStoredBytes: () => readStoredBytes(storagePath),
      cleanup: () => rm(storagePath, { recursive: true, force: true }),
    };
  },
  {
    suiteName: "SDW MemoryBackendAdapter conformance",
    expectedRoundTripMinChunkCount: 2,
  },
);

async function readStoredBytes(root: string): Promise<readonly Uint8Array[]> {
  const out: Uint8Array[] = [];
  await collectStoredBytes(root, out);
  return out;
}

async function collectStoredBytes(dir: string, out: Uint8Array[]): Promise<void> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error instanceof Error && "code" in error && (error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }

  for (const entry of entries) {
    const entryPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      await collectStoredBytes(entryPath, out);
    } else if (entry.isFile()) {
      out.push(new Uint8Array(await readFile(entryPath)));
    }
  }
}
