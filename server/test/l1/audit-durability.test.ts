import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import {
  AuditLog,
  AuditPersistenceError,
} from "../../src/l2-operational/audit-log.js";
import { generateRandomKey } from "../../src/core/random.js";
import { MemoryStorage } from "../../src/storage/memory.js";

type ToolResult = { content: Array<{ type: string; text: string }> };
type Tool = {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<ToolResult>;
};

class ToggleAuditFailureStorage extends MemoryStorage {
  failAuditWrites = false;

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === "_audit" && this.failAuditWrites) {
      const err = new Error("audit storage full") as NodeJS.ErrnoException;
      err.code = "ENOSPC";
      throw err;
    }
    return super.write(namespace, key, data);
  }
}

class PausingAuditStorage extends MemoryStorage {
  private pause:
    | {
        release: () => void;
        released: Promise<void>;
        paused: Promise<void>;
        markPaused: () => void;
      }
    | null = null;

  pauseNextAuditWrite(): { paused: Promise<void>; release: () => void } {
    let release!: () => void;
    let markPaused!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    const paused = new Promise<void>((resolve) => {
      markPaused = resolve;
    });
    this.pause = { release, released, paused, markPaused };
    return { paused, release };
  }

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    const pause = namespace === "_audit" ? this.pause : null;
    if (pause) {
      this.pause = null;
      pause.markPaused();
      await pause.released;
    }
    return super.write(namespace, key, data);
  }
}

function makeRig<T extends MemoryStorage>(storage: T) {
  const masterKey = generateRandomKey();
  const stateStore = new StateStore(storage, masterKey);
  const auditLog = new AuditLog(storage, masterKey);
  const l1 = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  return { ...l1, auditLog, masterKey, stateStore, storage };
}

async function callTool(
  tools: Tool[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text);
}

describe("L1 audit durability", () => {
  it("fails state_write closed when critical audit persistence fails", async () => {
    const { tools, identityManager, stateStore, storage } = makeRig(
      new ToggleAuditFailureStorage()
    );
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", { label: "writer" });

    storage.failAuditWrites = true;

    await expect(
      callTool(tools, "state_write", {
        namespace: "memory",
        key: "k",
        value: "secret",
        identity_id: identity.identity_id,
      })
    ).rejects.toMatchObject({
      name: "AuditPersistenceError",
      classification: "storage_full",
    } satisfies Partial<AuditPersistenceError>);

    await expect(stateStore.read("memory", "k")).resolves.toBeNull();
  });

  it("fails state_delete closed when critical audit persistence fails", async () => {
    const { tools, identityManager, stateStore, storage } = makeRig(
      new ToggleAuditFailureStorage()
    );
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", { label: "deleter" });
    await callTool(tools, "state_write", {
      namespace: "memory",
      key: "k",
      value: "keep me",
      identity_id: identity.identity_id,
    });

    storage.failAuditWrites = true;

    await expect(
      callTool(tools, "state_delete", {
        namespace: "memory",
        key: "k",
        reason: "test",
      })
    ).rejects.toMatchObject({
      name: "AuditPersistenceError",
      classification: "storage_full",
    } satisfies Partial<AuditPersistenceError>);

    const read = await stateStore.read("memory", "k");
    expect(read?.value).toBe("keep me");
  });

  it("awaits appendCritical before state_write returns or commits state", async () => {
    const storage = new PausingAuditStorage();
    const { tools, identityManager, stateStore } = makeRig(storage);
    await identityManager.load();
    const identity = await callTool(tools, "identity_create", { label: "awaited" });
    const auditBarrier = storage.pauseNextAuditWrite();
    let settled = false;

    const pendingWrite = callTool(tools, "state_write", {
      namespace: "memory",
      key: "k",
      value: "after audit",
      identity_id: identity.identity_id,
    }).then((result) => {
      settled = true;
      return result;
    });

    await auditBarrier.paused;
    expect(settled).toBe(false);
    await expect(stateStore.read("memory", "k")).resolves.toBeNull();

    auditBarrier.release();
    await expect(pendingWrite).resolves.toMatchObject({
      namespace: "memory",
      key: "k",
    });
    expect(settled).toBe(true);
    const read = await stateStore.read("memory", "k");
    expect(read?.value).toBe("after audit");
  });

  it("keeps the L1 critical operation list off best-effort append()", () => {
    const thisDir = dirname(fileURLToPath(import.meta.url));
    const source = readFileSync(
      join(thisDir, "../../src/l1-cognitive/tools.ts"),
      "utf-8"
    );
    expect(source).toContain('operation: "audit_event_sign" | "internal_receipt_sign"');
    expect(source).toContain('await recordCriticalAudit(auditLog, "l1", operation');
    expect(source).not.toMatch(/auditLog\?\.append\("l1", operation/);

    const literalCriticalOperations = [
      "identity_create",
      "identity_sign",
      "identity_rotate",
      "identity_set_primary",
      "state_write",
      "state_delete",
      "state_export",
      "state_import",
    ];

    for (const operation of literalCriticalOperations) {
      expect(source).toContain(`recordCriticalAudit(auditLog, "l1", "${operation}"`);
      expect(source).not.toMatch(
        new RegExp(`auditLog\\?\\.append\\("l1", "${operation}"`)
      );
    }
  });
});
