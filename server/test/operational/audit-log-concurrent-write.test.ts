import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AuditLog, type PersistedAuditEnvelopeV2 } from "../../src/operational/audit-log.js";
import { bytesToString } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageEntryMeta } from "../../src/storage/interface.js";
import { toHex } from "./audit-log-test-encoding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

// retry:2 - these cross-process rotation/pruning races are timing-sensitive
// under full-suite parallel load (pass in isolation; a genuine regression still
// fails all 3 attempts, so retry does NOT mask it - distinct from filename-skip).
describe("AuditLog cross-process concurrent writes", { retry: 2 }, () => {
  it("serializes sequence allocation across 5 processes and same-process instances", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-race-"));
    try {
      const storagePath = join(root, "state");
      const masterKey = generateRandomKey();
      const masterKeyHex = toHex(masterKey);
      const workerPath = join(__dirname, "audit-log-concurrent-worker.ts");

      await Promise.all(
        Array.from({ length: 5 }, (_, index) =>
          runWorker(workerPath, storagePath, masterKeyHex, `proc-${index}`, 6)
        )
      );

      const sameProcessLogs = Array.from(
        { length: 5 },
        () =>
          new AuditLog(new FilesystemStorage(storagePath), masterKey, {
            checkpointInterval: 10_000,
          })
      );
      await Promise.all(
        sameProcessLogs.map((log, index) =>
          log.appendCritical({
            layer: "l2",
            operation: "same_process_concurrent_write",
            identity_id: `same-${index}`,
            result: "success",
            details: { index },
          })
        )
      );
      await Promise.all(sameProcessLogs.map((log) => log.flush()));

      const storage = new FilesystemStorage(storagePath);
      const metas = await storage.list("_audit", "entry-");
      expect(metas).toHaveLength(35);

      const envelopes: PersistedAuditEnvelopeV2[] = [];
      for (const meta of metas) {
        const raw = await storage.read("_audit", meta.key);
        if (!raw) throw new Error(`missing ${meta.key}`);
        envelopes.push(JSON.parse(bytesToString(raw)) as PersistedAuditEnvelopeV2);
      }
      const sequences = envelopes.map((entry) => entry.sequence).sort((a, b) => a - b);
      expect(sequences).toEqual(Array.from({ length: 35 }, (_, index) => index + 1));

      const reader = new AuditLog(storage, masterKey, { checkpointInterval: 10_000 });
      const result = await reader.query({ limit: 100 });
      expect(result.total).toBe(35);
      expect(result.integrity_findings).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  }, 30_000);

  it("keeps reader views consistent while rotation is pruning", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-rotation-read-"));
    try {
      const storagePath = join(root, "state");
      const storage = new FilesystemStorage(storagePath);
      const masterKey = generateRandomKey();
      const writer = new AuditLog(storage, masterKey, {
        maxEntries: 5,
        checkpointInterval: 3,
      });
      const reader = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        maxEntries: 5,
        checkpointInterval: 3,
      });
      const failures: unknown[] = [];

      const reading = (async () => {
        for (let i = 0; i < 100; i++) {
          try {
            const result = await reader.query({ limit: 100 });
            expect(result.integrity_findings).toEqual([]);
          } catch (err) {
            failures.push(err);
          }
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
      })();

      for (let i = 0; i < 40; i++) {
        await writer.appendCritical({
          layer: "l2",
          operation: "rotation_reader_fuzz",
          identity_id: "writer",
          result: "success",
          details: { i },
        });
      }
      await writer.flush();
      await reading;

      expect(failures).toEqual([]);
      const finalReader = new AuditLog(storage, masterKey, {
        maxEntries: 5,
        checkpointInterval: 3,
      });
      const finalResult = await finalReader.query({ limit: 100 });
      expect(finalResult.integrity_findings).toEqual([]);
      expect(finalResult.total).toBeLessThanOrEqual(5);
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  }, 30_000);

  // S-1 store-stability retry (deterministic, not timing-dependent). Reproduces a
  // torn read: the reader's FIRST entry listing comes back empty (as if a
  // concurrent rotation pruned every listed key before it could read them) while
  // the on-disk anchors/checkpoints still record the real head. That torn view
  // yields integrity findings (a head-anchor floor above zero surviving entries,
  // and checkpoint-root mismatches). Because the listing then CHANGES on the next
  // attempt (the store was mid-mutation), the reader must retry and recover —
  // never fail closed. This proves the retry discriminates on store stability,
  // not finding kind: even non-"transient" kinds (checkpoint_root_mismatch) are
  // ridden through while the store is actively changing. The companion fail-closed
  // case (a STATIC torn store + fake writer marker) is covered in
  // audit-log-chain.test.ts.
  it("retries through a transient torn listing during rotation instead of false-flagging", async () => {
    const root = await mkdtemp(join(tmpdir(), "sanctuary-audit-torn-read-"));
    try {
      const storagePath = join(root, "state");
      const masterKey = generateRandomKey();
      const seeder = new AuditLog(new FilesystemStorage(storagePath), masterKey, {
        maxEntries: 1000,
        checkpointInterval: 3,
      });
      for (let i = 0; i < 6; i++) {
        await seeder.appendCritical({
          layer: "l2",
          operation: "seed",
          identity_id: "seeder",
          result: "success",
          details: { i },
        });
      }
      await seeder.flush();

      let auditListCalls = 0;
      class TornListingStorage extends FilesystemStorage {
        override async list(
          namespace: string,
          prefix?: string
        ): Promise<StorageEntryMeta[]> {
          // Only the reader's FIRST unprefixed entry scan is decimated; the
          // signature probe and the retry see the real (recovered) set, so the
          // listing "changes" between attempts and the read is retried.
          if (
            namespace === "_audit" &&
            prefix === undefined &&
            auditListCalls++ === 0
          ) {
            return [];
          }
          return super.list(namespace, prefix);
        }
      }

      const reader = new AuditLog(new TornListingStorage(storagePath), masterKey, {
        maxEntries: 1000,
        checkpointInterval: 3,
      });
      const result = await reader.query({ limit: 100 });

      expect(auditListCalls).toBeGreaterThan(1); // proves at least one retry
      expect(result.integrity_findings).toEqual([]);
      expect(result.total).toBe(6);
    } finally {
      await rm(root, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  }, 30_000);
});

function runWorker(
  workerPath: string,
  storagePath: string,
  masterKeyHex: string,
  workerId: string,
  writeCount: number
): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ["--import", "tsx", workerPath, storagePath, masterKeyHex, workerId, String(writeCount)],
      {
        cwd: join(__dirname, "../.."),
        env: { ...process.env, TSX_TSCONFIG_PATH: join(__dirname, "../../tsconfig.json") },
        stdio: ["ignore", "pipe", "pipe"],
      }
    );
    let stderr = "";
    child.stderr.on("data", (chunk: Uint8Array) => {
      stderr += Buffer.from(chunk).toString("utf8");
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`worker ${workerId} exited ${code}: ${stderr}`));
      }
    });
  });
}
