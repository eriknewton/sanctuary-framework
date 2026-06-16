/**
 * Regression test for drill Finding RRR (P2, 2026-05-08).
 *
 * Scenario: target fortress has a DIFFERENT active identity than the bundle
 * being imported. Without --force-rebind the import must refuse with
 * IDENTITY_OVERWRITE_REFUSED. With --force-rebind it must succeed.
 *
 * This test fails on a0c7dce (pre-fix) and passes after the guard predicate
 * is widened to detect mismatched local active identities.
 */
import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createL4Tools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";

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
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "recovery-key",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createL4Tools(
    storage,
    masterKey,
    identityManager,
    auditLog
  );
  return {
    storage,
    masterKey,
    auditLog,
    stateStore,
    identityManager,
    reputationStore,
    tools: [...l1Tools, ...l4Tools] as ToolDef[],
  };
}

describe("Finding RRR: identity overwrite guard for mismatched identities", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("refuses import when target fortress has a different active identity, allows with forceRebind", async () => {
    // Fortress A: create identity + export bundle
    const fortressA = await makeHarness();
    await callTool(fortressA.tools, "identity_create", { label: "agent-a" });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-rrr-"));
    tempDirs.push(bundleDir);
    await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage: fortressA.storage,
      masterKey: fortressA.masterKey,
      identityManager: fortressA.identityManager,
      auditLog: fortressA.auditLog,
      reputationStore: fortressA.reputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: [],
      keySource: "recovery-key",
    });

    // Fortress B: create its own DIFFERENT identity
    const fortressB = await makeHarness();
    await callTool(fortressB.tools, "identity_create", { label: "agent-b" });

    // Import A's bundle into B without forceRebind: must refuse
    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: fortressB.storage,
        masterKey: fortressB.masterKey,
        identityManager: fortressB.identityManager,
        auditLog: fortressB.auditLog,
        reputationStore: fortressB.reputationStore,
        activate: true,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect(caught?.code).toBe("IDENTITY_OVERWRITE_REFUSED");

    // With forceRebind: must succeed
    const forced = await importExitBundle({
      bundleDir,
      storage: fortressB.storage,
      masterKey: fortressB.masterKey,
      identityManager: fortressB.identityManager,
      auditLog: fortressB.auditLog,
      reputationStore: fortressB.reputationStore,
      activate: true,
      forceRebind: true,
    });
    expect(forced.activated).toBe(true);
    expect(forced.conflicts.public_identity_exists).toBe(true);
  });
});
