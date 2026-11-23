/**
 * A temporary fortress directory holding both local stores, seeded with
 * committed results through the real store API. The caller closes it.
 */
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateRandomKey } from "../../../src/core/random.js";
import { LocalOplog, type OplogRow } from "../../../src/local-recompile/oplog.js";
import { LocalResultsStore } from "../../../src/local-recompile/results-store.js";
import { deriveLocalStoreKeys } from "../../../src/local-recompile/store-keys.js";
import { resolveCustodyLockRoot } from "../../../src/storage/cross-process-lock.js";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";

export const LOCK_ROOT = resolveCustodyLockRoot(process.getuid!(), { env: process.env, platform: process.platform });
// A fixed 32-hex seat; the results store names seats by 128-bit ids.
const SEAT = "a".repeat(32);
// Far enough ahead that no sweep in a test marks a pending object.
const DEADLINE_AHEAD_MS = 60 * 60 * 1_000;

export function requestId(n: number): string {
  return n.toString(16).padStart(32, "0");
}

export interface OperatorFixture {
  path: string;
  storage: FilesystemStorage;
  masterKey: Uint8Array;
  seed(n: number, summary: string, createdAt?: number): Promise<string>;
  seedPending(n: number): Promise<string>;
  rows(): Promise<OplogRow[]>;
  hasResult(id: string): Promise<boolean>;
  close(): Promise<void>;
}

export async function operatorFixture(): Promise<OperatorFixture> {
  const path = await mkdtemp(join(tmpdir(), "local-operator-"));
  const storage = new FilesystemStorage(join(path, "state"));
  const masterKey = generateRandomKey();
  const keys = deriveLocalStoreKeys(masterKey);
  let clock = 1_800_000_000_000;
  const now = () => clock;
  const oplog = new LocalOplog(storage, Uint8Array.from(keys.oplogKey), { runtimeRoot: LOCK_ROOT, now });
  const results = new LocalResultsStore(storage, Uint8Array.from(keys.resultsKey), oplog, { runtimeRoot: LOCK_ROOT, now });
  await oplog.ensure();
  await results.ensure();
  const pending = async (n: number) => {
    clock += 1_000;
    const id = requestId(n);
    await results.putPending({ request_id: id, seat: SEAT, kind: "summarize", deadline: clock + DEADLINE_AHEAD_MS });
    return id;
  };
  return {
    path,
    storage,
    masterKey,
    seed: async (n, summary) => {
      const id = await pending(n);
      await results.markCommitted(id, {
        summary,
        refs: [JSON.stringify({ n: 1, namespace: "notes", key: "one" })],
        chunk_cites: ["1"],
        model_runtime_tag: "qwen2.5:1.5b",
        model_manifest_digest: "1".repeat(64),
        truncated: "false",
      });
      return id;
    },
    seedPending: pending,
    rows: async () => {
      const status = await oplog.status();
      return oplog.readRows(status.base_seq, status.rows);
    },
    hasResult: async (id) => (await results.get(id, { includeUncommitted: true })) !== null,
    close: async () => {
      results.close();
      oplog.close();
      await rm(path, { recursive: true, force: true });
    },
  };
}
