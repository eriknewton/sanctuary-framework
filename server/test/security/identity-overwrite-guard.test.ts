import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createIdentity } from "../../src/core/identity.js";
import { derivePurposeKey } from "../../src/core/key-derivation.js";
import * as random from "../../src/core/random.js";

interface ToolDef {
  name: string;
  handler: (args: Record<string, unknown>) => Promise<{
    content: Array<{ type: string; text: string }>;
  }>;
}

async function callTool(
  tools: ToolDef[],
  name: string,
  args: Record<string, unknown> = {}
): Promise<Record<string, unknown>> {
  const tool = tools.find((t) => t.name === name);
  if (!tool) throw new Error(`Tool not found: ${name}`);
  const result = await tool.handler(args);
  return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
}

async function makeHarness() {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();
  return { storage, masterKey, auditLog, identityManager, tools: tools as ToolDef[] };
}

async function criticalOps(auditLog: AuditLog, operation_type: string) {
  return await auditLog.query({ operation_type, limit: 10 });
}

describe("Finding RRR identity overwrite guard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("refuses identity_create when the generated identity already exists", async () => {
    const harness = await makeHarness();
    const actualRandomBytes = random.randomBytes;
    const fixedPrivateKey = new Uint8Array(32).fill(7);
    vi.spyOn(random, "randomBytes").mockImplementation((length: number) =>
      length === 32 ? new Uint8Array(fixedPrivateKey) : actualRandomBytes(length)
    );

    const first = await callTool(harness.tools, "identity_create", {
      label: "first",
    });
    const existingId = first.identity_id as string;
    const existing = harness.identityManager.get(existingId)!;

    await expect(
      callTool(harness.tools, "identity_create", { label: "second" })
    ).rejects.toThrow(/routine identity creation and import cannot replace/i);

    const unchanged = harness.identityManager.get(existingId)!;
    expect(unchanged.label).toBe(existing.label);
    expect(unchanged.public_key).toBe(existing.public_key);

    const audit = await criticalOps(harness.auditLog, "identity_create_overwrite_refused");
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.result).toBe("failure");
    expect(audit.entries[0]!.details).toEqual({
      attempted_operation: "identity_create",
    });
  });

  it("refuses identity_import when the identity already exists", async () => {
    const harness = await makeHarness();
    const identityEncKey = derivePurposeKey(harness.masterKey, "identity-encryption");
    const imported = createIdentity("imported", identityEncKey, "recovery-key");

    await callTool(harness.tools, "identity_import", {
      identity: imported.storedIdentity,
    });
    const existing = harness.identityManager.get(
      imported.publicIdentity.identity_id
    )!;

    await expect(
      callTool(harness.tools, "identity_import", {
        identity: { ...imported.storedIdentity, label: "overwrite-attempt" },
      })
    ).rejects.toThrow(/routine identity creation and import cannot replace/i);

    const unchanged = harness.identityManager.get(
      imported.publicIdentity.identity_id
    )!;
    expect(unchanged.label).toBe(existing.label);
    expect(unchanged.public_key).toBe(existing.public_key);

    const audit = await criticalOps(harness.auditLog, "identity_import_overwrite_refused");
    expect(audit.entries).toHaveLength(1);
    expect(audit.entries[0]!.result).toBe("failure");
    expect(audit.entries[0]!.details).toEqual({
      attempted_operation: "identity_import",
    });
  });

  it("allows identity_create with a fresh identity", async () => {
    const harness = await makeHarness();

    const created = await callTool(harness.tools, "identity_create", {
      label: "fresh",
    });

    expect(typeof created.identity_id).toBe("string");
    expect(harness.identityManager.get(created.identity_id as string)?.label).toBe(
      "fresh"
    );
    const audit = await criticalOps(harness.auditLog, "identity_create_overwrite_refused");
    expect(audit.entries).toHaveLength(0);
  });

  it("allows identity_import with a fresh identity", async () => {
    const harness = await makeHarness();
    const identityEncKey = derivePurposeKey(harness.masterKey, "identity-encryption");
    const imported = createIdentity("fresh-import", identityEncKey, "recovery-key");

    const result = await callTool(harness.tools, "identity_import", {
      identity: imported.storedIdentity,
    });

    expect(result.identity_id).toBe(imported.publicIdentity.identity_id);
    expect(result.imported).toBe(true);
    expect(
      harness.identityManager.get(imported.publicIdentity.identity_id)?.label
    ).toBe("fresh-import");
  });

  it("uses a generic denial that does not identify the colliding field", async () => {
    const harness = await makeHarness();
    const identityEncKey = derivePurposeKey(harness.masterKey, "identity-encryption");
    const imported = createIdentity("first", identityEncKey, "recovery-key");
    await callTool(harness.tools, "identity_import", {
      identity: imported.storedIdentity,
    });

    let message = "";
    try {
      await callTool(harness.tools, "identity_import", {
        identity: imported.storedIdentity,
      });
    } catch (err) {
      message = err instanceof Error ? err.message : String(err);
    }

    expect(message).toMatch(/routine identity creation and import cannot replace/i);
    expect(message).not.toContain("identity_id");
    expect(message).not.toContain("did");
    expect(message).not.toContain("public_key");
    expect(message).not.toContain(imported.publicIdentity.identity_id);
    expect(message).not.toContain(imported.publicIdentity.did);
    expect(message).not.toContain(imported.publicIdentity.public_key);
  });
});
