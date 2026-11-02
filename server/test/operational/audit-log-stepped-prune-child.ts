/** Parent owns the temporary store and kills/reaps this process between steps. */
import { AuditLog } from "../../src/operational/audit-log.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { installInMemoryKeychainStore } from "../setup/keychain-memory-store.js";
import { MEASURE_CONFIG, MEASURE_MASTER_KEY, measureEntry } from "../../scripts/measure-audit-append.js";
installInMemoryKeychainStore();
const [path, capText] = process.argv.slice(2);
if (!path || !capText) throw new Error("missing fixture arguments");
class StepStorage extends FilesystemStorage {
  deleted = 0;
  override async delete(namespace: string, key: string): Promise<boolean> {
    const result = await super.delete(namespace, key);
    if (namespace === "_audit") this.deleted++;
    return result;
  }
  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (namespace === "_audit" && this.deleted === 1) {
      process.send?.({ betweenSteps: true });
      // IPC keeps the process alive until the parent kills it at this boundary.
      await new Promise<never>(() => {});
    }
    return super.read(namespace, key);
  }
}
const log = new AuditLog(new StepStorage(path), MEASURE_MASTER_KEY, { ...MEASURE_CONFIG, maxEntries: Number(capText) });
await log.appendCritical(measureEntry(Number(capText)));
