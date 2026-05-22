import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { AuditLog, AuditPersistenceError } from "../../../../server/src/l2-operational/audit-log.js";
import { createL1Tools } from "../../../../server/src/l1-cognitive/tools.js";
import { StateStore } from "../../../../server/src/l1-cognitive/state-store.js";
import { generateRandomKey } from "../../../../server/src/core/random.js";
import { MemoryStorage } from "../../../../server/src/storage/memory.js";
import type { StorageEntryMeta } from "../../../../server/src/storage/interface.js";
import { registerFixture } from "../../registry.js";
import { captureError, outcome } from "./helpers.js";

const CLAIM_ID = "3";
const CLAIM_LABEL = "Critical audit durability (appendCritical)";

// Entrypoint: AuditLog.appendCritical in server/src/l2-operational/audit-log.ts.
// Mirrored tests: server/test/l1/audit-durability.test.ts and server/test/audit/critical-followup.test.ts.
// Matrix claim: Critical audit durability (appendCritical).

class RejectingAuditStorage extends MemoryStorage {
  failAuditWrites = true;

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit" && this.failAuditWrites) {
      const err = new Error("synthetic storage full") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    }
    return super.write(namespace, key, data);
  }
}

class PartialAuditStorage extends MemoryStorage {
  private partialKey: string | null = null;

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit") {
      this.partialKey = key;
      await super.write(namespace, key, data.slice(0, Math.max(1, data.length - 1)));
      return;
    }
    return super.write(namespace, key, data);
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (namespace === "_audit" && key === this.partialKey) {
      return super.read(namespace, key);
    }
    return super.read(namespace, key);
  }
}

class EioReadbackStorage extends MemoryStorage {
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    if (namespace === "_audit") {
      const err = new Error(`synthetic readback failure for ${key}`) as NodeJS.ErrnoException;
      err.code = "EIO";
      throw err;
    }
    return super.read(namespace, key);
  }
}

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

function makeRig(storage: MemoryStorage) {
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const { tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { auditLog, identityManager, stateStore, tools: tools as Tool[] };
}

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function appendOne(auditLog: AuditLog): Promise<void> {
  await auditLog.appendCritical({
    layer: "l1",
    operation: "synthetic_critical_append",
    identity_id: "synthetic",
    result: "success",
    details: { fixture: CLAIM_ID },
  });
}

function isAuditPersistenceError(
  err: unknown,
  classification?: AuditPersistenceError["classification"]
): boolean {
  return (
    err instanceof AuditPersistenceError &&
    (classification === undefined || err.classification === classification)
  );
}

registerFixture(CLAIM_ID, CLAIM_LABEL, "critical-audit-durability: happy path", async () => {
  const started = performance.now();
  const storage = new MemoryStorage();
  const auditLog = new AuditLog(storage, generateRandomKey());
  await appendOne(auditLog);
  const audit = await auditLog.query({ operation_type: "synthetic_critical_append" });
  const entries = await storage.list("_audit");
  const passed = audit.total === 1 && entries.length === 1 && audit.entries[0]?.result === "success";
  return outcome(started, passed, `expected one durable critical audit entry, got ${audit.total}`);
});

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "critical-audit-durability: storage write rejected fails closed",
  async () => {
    const started = performance.now();
    const storage = new RejectingAuditStorage();
    storage.failAuditWrites = false;
    const { identityManager, stateStore, tools } = makeRig(storage);
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", { label: "synthetic-writer" });
    storage.failAuditWrites = true;
    const err = await captureError(() =>
      callTool(tools, "state_write", {
        namespace: "memory",
        key: "k",
        value: "must not commit",
        identity_id: identity.identity_id,
      })
    );
    const read = await stateStore.read("memory", "k");
    const passed = isAuditPersistenceError(err, "storage_full") && read === null;
    return outcome(started, passed, `expected storage_full fail-closed write, got ${String(err)}`);
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "critical-audit-durability: storage partial-write fails closed",
  async () => {
    const started = performance.now();
    const auditLog = new AuditLog(new PartialAuditStorage(), generateRandomKey());
    const err = await captureError(() => appendOne(auditLog));
    const passed = isAuditPersistenceError(err, "partial_write");
    return outcome(started, passed, `expected partial_write, got ${String(err)}`);
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "critical-audit-durability: storage ENOSPC equivalent fails closed",
  async () => {
    const started = performance.now();
    const auditLog = new AuditLog(new RejectingAuditStorage(), generateRandomKey());
    const err = await captureError(() => appendOne(auditLog));
    const passed = isAuditPersistenceError(err, "storage_full");
    return outcome(started, passed, `expected storage_full, got ${String(err)}`);
  }
);

registerFixture(
  CLAIM_ID,
  CLAIM_LABEL,
  "critical-audit-durability: synchronous-API site coverage",
  async () => {
    const started = performance.now();
    const sourceRoot = existsSync(join(process.cwd(), "server", "src"))
      ? join(process.cwd(), "server", "src")
      : join(process.cwd(), "src");
    const sites: Array<[string, RegExp]> = [
      ["principal-policy/dashboard.ts", /await this\.auditLog\.appendCritical\(/],
      ["hub/hub-service.ts", /await this\.deps\.activitySources\.auditLog\.appendCritical\(/],
    ];
    const present = sites.every(([path, pattern]) =>
      pattern.test(readFileSync(join(sourceRoot, path), "utf8"))
    );
    const storage = new EioReadbackStorage();
    const auditLog = new AuditLog(storage, generateRandomKey());
    const err = await captureError(() => appendOne(auditLog));
    const listed: StorageEntryMeta[] = await storage.list("_audit");
    const passed = present && isAuditPersistenceError(err, "disk_failure") && listed.length === 1;
    return outcome(
      started,
      passed,
      "expected static sync-site coverage plus disk_failure readback classification"
    );
  }
);
