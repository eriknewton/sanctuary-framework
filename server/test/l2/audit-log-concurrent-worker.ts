import { AuditLog } from "../../src/operational/audit-log.js";
import { fromHex } from "./audit-log-test-encoding.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";

const storagePath = process.argv[2];
const masterKeyHex = process.argv[3];
const workerId = process.argv[4] ?? "worker";
const writeCount = Number(process.argv[5] ?? "0");

if (!storagePath || !masterKeyHex || !Number.isSafeInteger(writeCount)) {
  throw new Error("usage: audit-log-concurrent-worker <storagePath> <masterKeyHex> <workerId> <writeCount>");
}

const storage = new FilesystemStorage(storagePath);
const auditLog = new AuditLog(storage, fromHex(masterKeyHex), {
  checkpointInterval: 10_000,
});

for (let i = 0; i < writeCount; i++) {
  await auditLog.appendCritical({
    layer: "l2",
    operation: "concurrent_write",
    identity_id: workerId,
    result: "success",
    details: { worker_id: workerId, index: i },
  });
}
await auditLog.flush();
