/** Isolated process-boundary witness for the daemon audit fence. Job 996. */
import { mkdir, readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import { FilesystemStorage } from "../../../src/storage/filesystem.js";
import { createDaemonAuditLog, AUDIT_DAEMON_NAMESPACE } from "../../../src/operational/audit-store-split.js";
import { __testSetAuditWriterUidForRole } from "../../../src/operational/audit-log.js";
import { exitWallDaemonOnAuditFence } from "../../../src/cli/castle-wall-full-agent-state.js";

const [root, mode, operation = "fixture"] = process.argv.slice(2);
if (!root || !mode || process.env.HOME === undefined || !process.env.HOME.startsWith(root)) throw new Error("isolated child HOME required");
const DEADLINE_MS = 1000; // must match DEADLINE_MS in test/operational/audit-log-process-exit-fence-process.test.ts.
const key = new Uint8Array(32).fill(0x31); // Public fixture material: 32 bytes for the master-key API.
__testSetAuditWriterUidForRole("root_daemon", 0);
const hang = async () => {
  process.send?.({ phase: "HANG" });
  await new Promise<never>(() => {});
};
class Storage extends FilesystemStorage {
  override async read(namespace: string, name: string) {
    if (mode === "load") await hang();
    return super.read(namespace, name);
  }
  override async writeDurable(namespace: string, name: string, bytes: Uint8Array) {
    const entry = namespace === AUDIT_DAEMON_NAMESPACE && name.startsWith("entry-");
    if (entry && mode === "before") await hang();
    await super.writeDurable(namespace, name, bytes);
    if (entry && mode === "after") await hang();
  }
}
const namespace = join(root, "state", AUDIT_DAEMON_NAMESPACE);
await mkdir(namespace, { recursive: true, mode: 0o700 });
const log = createDaemonAuditLog(new Storage(join(root, "state")), key, {
  checkpointInterval: 0,
  // Model the root daemon's operator-owned handoff without requiring real uid 0.
  createOwner: { uid: process.getuid!(), gid: process.getgid!() },
  __testAuditGuardLockRoot: join(root, "guard"),
  writeLockHoldDeadlineMs: DEADLINE_MS,
  processExitFence: { firstLoadDeadlineMs: DEADLINE_MS, exit: exitWallDaemonOnAuditFence },
});
const sequences = async () => {
  const names = (await readdir(namespace)).filter(name => name.startsWith("entry-")).sort();
  return Promise.all(names.map(async name => JSON.parse(await readFile(join(namespace, name), "utf8")).sequence as number));
};
// A live handle distinguishes synchronous exit from merely assigning exitCode.
const keepAlive = setInterval(() => {}, DEADLINE_MS);
process.send?.({ phase: "READY" });
try {
  const before = await sequences();
  await log.appendCritical({ layer: "l1", operation, identity_id: "fixture", result: "success" });
  const query = await log.query({});
  process.stdout.write(JSON.stringify({ before, after: await sequences(), findings: query.integrity_findings }) + "\n");
} finally {
  clearInterval(keepAlive);
  __testSetAuditWriterUidForRole("root_daemon", undefined);
  process.disconnect?.();
}
