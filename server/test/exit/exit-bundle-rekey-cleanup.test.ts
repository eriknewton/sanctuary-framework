/**
 * Hardening wave 6 finding #78, exit-bundle re-key staged-artifact cleanup.
 *
 * When importExitBundle's re-key path fails partway through, every
 * staged artifact (public_identity, policy_set, audit_receipts,
 * commitments, placeholder_metadata, exit_imports record) and every
 * partially imported state entry MUST be removed before the error
 * propagates. The thrown ExitBundleImportError MUST carry the
 * REKEY_FAILED_AND_CLEANED code and a message that names the cleanup.
 *
 * Two distinct failure sites:
 *   (a) failure mid-encrypt, destination write throws on the second
 *       state entry (one entry already imported, then rollback)
 *   (b) failure mid-write, destination write throws on the first state
 *       entry (no rekey writes completed, staged artifacts still need cleanup)
 */

import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import { StateStore } from "../../src/l1-cognitive/state-store.js";
import { createL1Tools } from "../../src/l1-cognitive/tools.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { createL4Tools } from "../../src/l4-reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  ExitBundleImportError,
} from "../../src/exit/index.js";
import type { StorageBackend } from "../../src/storage/interface.js";

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
  const tool = tools.find((candidate) => candidate.name === name);
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

/**
 * Wrap a storage backend so writes to non-reserved namespaces throw on
 * the Nth attempt. The threshold counts only writes whose namespace
 * does not start with `_` (i.e., real user state entries from the
 * re-key path), so staged-artifact writes (which target `_exit_*`
 * namespaces) do not consume the budget.
 */
function failOnNthUserWrite(
  inner: StorageBackend,
  failOnCall: number
): StorageBackend {
  let count = 0;
  return {
    async write(namespace, key, data) {
      if (!namespace.startsWith("_")) {
        count++;
        if (count === failOnCall) {
          throw new Error(`injected: storage.write fault on call ${count}`);
        }
      }
      await inner.write(namespace, key, data);
    },
    async read(namespace, key) {
      return inner.read(namespace, key);
    },
    async delete(namespace, key, secureOverwrite) {
      return inner.delete(namespace, key, secureOverwrite);
    },
    async list(namespace, prefix) {
      return inner.list(namespace, prefix);
    },
    async exists(namespace, key) {
      return inner.exists(namespace, key);
    },
    async totalSize() {
      return inner.totalSize();
    },
  };
}

async function exportFromSourceWithState(
  source: Awaited<ReturnType<typeof makeHarness>>,
  bundleDir: string,
  _identityId: string,
  namespacesToInclude: string[]
) {
  return exportExitBundle({
      unpartitionedLegacyExport: true,
    bundleDir,
    storage: source.storage,
    masterKey: source.masterKey,
    identityManager: source.identityManager,
    auditLog: source.auditLog,
    reputationStore: source.reputationStore,
    policy: DEFAULT_POLICY,
    config: defaultConfig(),
    stateNamespaces: namespacesToInclude,
    keySource: "recovery-key",
  });
}

describe("Exit-bundle re-key staged-artifact cleanup (finding #78)", () => {
  const tempDirs: string[] = [];

  afterEach(async () => {
    for (const dir of tempDirs.splice(0)) {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it("rekey failure mid-encrypt: cleans up the partially imported entry plus every staged artifact", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    // Two state entries so the re-key loop has more than one item to
    // process; the second write will throw and the first one must
    // be cleaned up.
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k2",
      value: "v2",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-rekey-cleanup-mid-encrypt-"));
    tempDirs.push(bundleDir);
    await exportFromSourceWithState(source, bundleDir, sourceIdentityId, ["user-data"]);

    // Destination uses the SAME master key so re-key can succeed; we
    // inject a write fault so the second user-data write throws.
    const destInnerStorage = new MemoryStorage();
    // Destination needs its own identity to sign re-keyed entries; create
    // it through the un-faulted storage so the identity write does not
    // consume the fault budget. Then swap in the faulted storage for the
    // import path.
    const destMasterKey = source.masterKey; // shared so source/destination key derivation aligns
    const destAuditLog = new AuditLog(destInnerStorage, destMasterKey);
    const setupStateStore = new StateStore(destInnerStorage, destMasterKey);
    const { tools: setupTools, identityManager: destIdentityManager } = createL1Tools(
      setupStateStore,
      destInnerStorage,
      destMasterKey,
      "recovery-key",
      destAuditLog
    );
    await destIdentityManager.load();
    await callTool(setupTools as ToolDef[], "identity_create", {
      label: "dest-default",
    });
    // Now wrap with the faulted storage for the actual import.
    const destStorage = failOnNthUserWrite(destInnerStorage, 2);
    const { reputationStore: destReputationStore } = createL4Tools(
      destStorage,
      destMasterKey,
      destIdentityManager,
      destAuditLog
    );

    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destStorage,
        masterKey: destMasterKey,
        identityManager: destIdentityManager,
        auditLog: destAuditLog,
        reputationStore: destReputationStore,
        activate: true,
        sourceMasterKey: source.masterKey,
        forceRebind: true,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect(caught?.code).toBe("REKEY_FAILED_AND_CLEANED");
    expect(caught?.message).toContain("re-key failed");
    expect(caught?.message).toContain("Cleanup removed");
    expect(caught?.message).toContain("re-keyed entries");
    expect(caught?.message).toContain("staged artifacts");

    // The first user-data entry was imported by the destination, then
    // rolled back. Confirm it is gone.
    expect(await destInnerStorage.exists("user-data", "k1")).toBe(false);
    expect(await destInnerStorage.exists("user-data", "k2")).toBe(false);

    // Every staged artifact namespace is empty (no public_identity,
    // policy_set, exit_imports record, etc.).
    for (const ns of [
      "_exit_public_identities",
      "_exit_policy_sets",
      "_exit_audit_receipts",
      "_exit_commitments",
      "_exit_placeholder_metadata",
      "_exit_imports",
    ]) {
      const entries = await destInnerStorage.list(ns);
      expect(entries.length).toBe(0);
    }

    // Failure audit trail names the cleanup.
    await destAuditLog.flush();
    const audit = await destAuditLog.query({
      operation_type: "exit_bundle_rekey_failed_cleanup",
      limit: 10,
    });
    expect(audit.total).toBeGreaterThanOrEqual(1);
    const entry = audit.entries[0]!;
    expect(entry.result).toBe("failure");
    const details = entry.details as Record<string, unknown>;
    expect(details.import_id).toBeTruthy();
    expect(typeof details.removed_total).toBe("number");
  });

  it("rekey failure mid-write: cleans up every staged artifact even when zero state entries were imported", async () => {
    const source = await makeHarness();
    const sourceIdentity = await callTool(source.tools, "identity_create", {
      label: "source-agent",
    });
    const sourceIdentityId = sourceIdentity.identity_id as string;
    await callTool(source.tools, "state_write", {
      namespace: "user-data",
      key: "k1",
      value: "v1",
      identity_id: sourceIdentityId,
    });

    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-rekey-cleanup-mid-write-"));
    tempDirs.push(bundleDir);
    await exportFromSourceWithState(source, bundleDir, sourceIdentityId, ["user-data"]);

    // Destination throws on the FIRST user-data write, no rekey
    // entries make it in, but staged artifacts already landed.
    const destInnerStorage = new MemoryStorage();
    const destMasterKey = source.masterKey;
    const destAuditLog = new AuditLog(destInnerStorage, destMasterKey);
    const setupStateStore = new StateStore(destInnerStorage, destMasterKey);
    const { tools: setupTools, identityManager: destIdentityManager } = createL1Tools(
      setupStateStore,
      destInnerStorage,
      destMasterKey,
      "recovery-key",
      destAuditLog
    );
    await destIdentityManager.load();
    await callTool(setupTools as ToolDef[], "identity_create", {
      label: "dest-default",
    });
    // Wrap with faulted storage for the actual import; throw on the first
    // user-data write so no rekey entry makes it in.
    const destStorage = failOnNthUserWrite(destInnerStorage, 1);
    const { reputationStore: destReputationStore } = createL4Tools(
      destStorage,
      destMasterKey,
      destIdentityManager,
      destAuditLog
    );

    let caught: ExitBundleImportError | null = null;
    try {
      await importExitBundle({
        bundleDir,
        storage: destStorage,
        masterKey: destMasterKey,
        identityManager: destIdentityManager,
        auditLog: destAuditLog,
        reputationStore: destReputationStore,
        activate: true,
        sourceMasterKey: source.masterKey,
        forceRebind: true,
      });
    } catch (err) {
      caught = err as ExitBundleImportError;
    }
    expect(caught).toBeInstanceOf(ExitBundleImportError);
    expect(caught?.code).toBe("REKEY_FAILED_AND_CLEANED");

    // No user-data entry imported.
    expect(await destInnerStorage.exists("user-data", "k1")).toBe(false);
    // Every staged artifact namespace is empty.
    for (const ns of [
      "_exit_public_identities",
      "_exit_policy_sets",
      "_exit_audit_receipts",
      "_exit_commitments",
      "_exit_placeholder_metadata",
      "_exit_imports",
    ]) {
      const entries = await destInnerStorage.list(ns);
      expect(entries.length).toBe(0);
    }
  });
});
