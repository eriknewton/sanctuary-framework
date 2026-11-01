/** Real-process tail witness. The parent owns HOME, commands, and child teardown. */
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { installInMemoryKeychainStore } from "../setup/keychain-memory-store.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry } from "../../scripts/measure-audit-append.js";
installInMemoryKeychainStore();
const [path, role, schedule] = process.argv.slice(2);
if (!path || !role) throw new Error("missing fixture arguments");

class ProcessStorage extends FilesystemStorage {
  auditListings = 0;
  anchorBefore: Uint8Array | null = null;
  intercept = false;
  override async listKeys(namespace: string, prefix?: string): Promise<string[]> {
    if (namespace === "_audit") this.auditListings++;
    return super.listKeys(namespace, prefix);
  }
  override async writeDurable(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (this.intercept && namespace === "_audit_checkpoints" && key === "__head_anchor") {
      if (schedule === "regressed" && this.anchorBefore) {
        await super.writeDurable(namespace, key, data);
        await super.writeDurable(namespace, key, this.anchorBefore);
      }
      process.send?.({ durable: true });
      // Parent kills this PID, leaving the durable entry and orphan lock exactly
      // at the interrupted or regressed anchor publication boundary.
      await new Promise<never>(() => {});
    }
    await super.writeDurable(namespace, key, data);
  }
}
const storage = new ProcessStorage(path);
const log = new AuditLog(storage, MEASURE_MASTER_KEY, MEASURE_CONFIG);
await log.query({ limit: 1 });
if (role === "B") {
  storage.anchorBefore = await storage.read("_audit_checkpoints", "__head_anchor");
  storage.intercept = true;
  await log.appendCritical(measureEntry(1));
} else {
  process.send?.({ ready: true });
  process.on("message", () => {
    void (async () => {
      storage.auditListings = 0;
      await log.appendCritical(measureEntry(2));
      process.send?.({ appended: true, sequence: log.currentInMemorySequence(), auditListings: storage.auditListings });
    })().catch((error) => { process.send?.({ error: String(error) }); process.exitCode = 1; });
  });
}
