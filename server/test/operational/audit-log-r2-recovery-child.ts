import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { join } from "node:path";
const [root] = process.argv.slice(2);
const log = new AuditLog(new FilesystemStorage(join(root, "s")), Buffer.alloc(32, 1)); // AES-256 test key.
try {
  const recovered = await (log as unknown as { breakStaleAuditLock(path: string): Promise<boolean> })
    .breakStaleAuditLock(join(root, "s", "_audit", ".audit-write.lock"));
  process.stdout.write(JSON.stringify({ recovered }));
} catch (error) {
  process.stdout.write(JSON.stringify({ recovered: false, error: String(error) }));
}
