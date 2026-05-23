import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { AuditLog, type PersistedAuditEnvelopeV2 } from "../../src/l2-operational/audit-log.js";
import { bytesToString } from "../../src/core/encoding.js";
import { generateRandomKey } from "../../src/core/random.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { toHex } from "./audit-log-test-encoding.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

describe("AuditLog cross-process concurrent writes", () => {
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
