/**
 * F1: `importExitBundle` activation is atomic under a hard process kill,
 * not just under a caught JS exception. A durable per-import rollback
 * journal (`writeImportJournal`, server/src/exit/bundle.ts) is written
 * BEFORE any staging write begins, using the exact snapshot data the
 * exception path already computes. `recoverInterruptedExitImportsOrThrow`
 * replays that journal through the SAME `restoreStorageSnapshots` the
 * exception path uses, and is called at the START of every
 * `importExitBundle` AND at "fortress open" for every `sanctuary exit`
 * subcommand (`openExitContext`, server/src/exit/cli.ts) and every other
 * fortress-owning composition point that derives a master key (see
 * `recoverInterruptedExitImportsOrThrow`'s doc comment for the inventory).
 * The `_exit_imports` completion record is staged `in_progress` first and
 * only promoted to its `activated_at`-stamped final form LAST, after the
 * reputation import and state re-key have both actually succeeded.
 *
 * This file has two halves:
 *  - in-process fault injection at three stage boundaries (AGENTS.md rule
 *    12), proving the journal-write/delete bookkeeping does not break the
 *    pre-existing exception-based rollback and cleans itself up correctly
 *    at each boundary;
 *  - a REAL child-process SIGKILL of the CLI import (rule 12's "AND a real
 *    child-process kill"), proving the durable-journal mechanism survives
 *    a kill the in-process fault-injection tests cannot exercise (a
 *    thrown JS exception always reaches the `catch` block; a SIGKILL never
 *    does). The kill is timed by POLLING for the journal write rather than
 *    a fixed delay, so the test proves it landed mid-flight instead of
 *    assuming a timing guess was right.
 *
 * Every fortress here is a disposable temp directory
 * (`mkdtemp`/`SANCTUARY_STORAGE_PATH`), never `~/.sanctuary` or the login
 * keychain (AGENTS.md "the operator's machine is not a fixture"), including
 * the child process spawned for the kill test.
 */

import { afterEach, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  ExitBundleImportError,
  ExitBundleStateImportIncompleteError,
  recoverInterruptedExitImports,
  recoverInterruptedExitImportsOrThrow,
  type ExportExitBundleResult,
} from "../../src/exit/bundle.js";

const HELPER_DIR = dirname(fileURLToPath(import.meta.url));
/** server/test/exit/exit-import-atomic-activation.test.ts -> server/src/cli.ts */
const CLI_SRC = join(HELPER_DIR, "../../src/cli.ts");
/**
 * Deliberately NOT `node_modules/.bin/tsx`: that binary is the tsx CLI,
 * which itself spawns a SECOND, real Node child process to run the target
 * script (confirmed by reading node_modules/tsx/dist/cli.mjs, which imports
 * node:child_process) - so `spawn("tsx", [...]).pid` names the WRAPPER, and
 * SIGKILL-ing it leaves its grandchild running orphaned, silently
 * continuing to write to the target fortress after the test believes the
 * import was killed. `node --import tsx/esm <script>` runs the whole thing
 * as ONE process, so the pid this test kills is the pid actually doing the
 * import. Found via this test flaking with a target that had partially
 * imported state AFTER `recoverInterruptedExitImports` reported nothing to
 * recover.
 */
const NODE_BIN = process.execPath;
const TSX_ESM_LOADER_ARGS = ["--import", "tsx/esm"];

// CONTRACT PIN: must match the namespace literals in server/src/exit/bundle.ts.
const EXIT_IMPORT_JOURNAL_NAMESPACE = "_exit_import_journal";
const EXIT_IMPORT_NAMESPACE = "_exit_imports";
const STAGED_ARTIFACT_NAMESPACES = [
  "_exit_public_identities",
  "_exit_policy_sets",
  "_exit_audit_receipts",
  "_exit_commitments",
  "_exit_placeholder_metadata",
  EXIT_IMPORT_NAMESPACE,
  EXIT_IMPORT_JOURNAL_NAMESPACE,
];

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

async function buildHarness(storage: StorageBackend, masterKey: Uint8Array) {
  const auditLog = new AuditLog(storage, masterKey);
  const stateStore = new StateStore(storage, masterKey);
  const { tools: l1Tools, identityManager } = createL1Tools(
    stateStore,
    storage,
    masterKey,
    "passphrase",
    auditLog
  );
  await identityManager.load();
  const { tools: l4Tools, reputationStore } = createReputationTools(
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

type Harness = Awaited<ReturnType<typeof buildHarness>>;

/** A source fortress with `entryCount` state entries and `attestationCount` attestations. */
async function makeSource(
  label: string,
  entryCount: number,
  attestationCount: number
): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", { label });
  const identityId = identity.identity_id as string;
  for (let i = 0; i < entryCount; i++) {
    const result = await callTool(harness.tools, "state_write", {
      namespace: `${label}-ns`,
      key: `k${i}`,
      value: `entry ${i} that must survive the exit`,
      identity_id: identityId,
    });
    if (result.error) throw new Error(`seed state_write failed: ${JSON.stringify(result)}`);
  }
  for (let i = 0; i < attestationCount; i++) {
    const result = await callTool(harness.tools, "reputation_record", {
      interaction_id: `${label}-ix-${i}`,
      counterparty_did: `did:key:z6Mk${label}counterparty${i}`,
      outcome: { type: "negotiation", result: "success" },
      context: `${label}-ctx`,
      identity_id: identityId,
    });
    if (result.error) throw new Error(`seed reputation_record failed: ${JSON.stringify(result)}`);
  }
  return { ...harness, identityId };
}

async function makeDestination(): Promise<Harness & { identityId: string }> {
  const harness = await buildHarness(new MemoryStorage(), generateRandomKey());
  const identity = await callTool(harness.tools, "identity_create", {
    label: "destination-signer",
  });
  return { ...harness, identityId: identity.identity_id as string };
}

async function exportBundle(
  source: Harness,
  bundleDir: string,
  stateNamespace: string
): Promise<ExportExitBundleResult> {
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
    stateNamespaces: [stateNamespace],
    keySource: "passphrase",
    mintStateRekeyKey: true,
  });
}

/**
 * Full-content snapshot of every namespace EXCEPT `_audit*` (audit entries
 * carry a real timestamp and always differ between two points in time, even
 * across a no-op - the drill's own `treehash.sh` excludes them for the same
 * reason). Two snapshots being string-equal is this test's "tree hash
 * unchanged" assertion.
 */
async function snapshotAll(storage: MemoryStorage): Promise<string> {
  const namespaces = await storage.listNamespaces();
  const rows: string[] = [];
  for (const ns of namespaces) {
    if (ns.startsWith("_audit")) continue;
    const entries: StorageEntryMeta[] = await storage.list(ns);
    for (const entry of entries) {
      const data = await storage.read(ns, entry.key);
      rows.push(`${ns}/${entry.key}:${data ? toBase64url(data) : "null"}`);
    }
  }
  return rows.sort().join("\n");
}

/**
 * Wraps a real StorageBackend and throws once `write()` is called for a
 * namespace matching `triggerNamespace`, simulating a process crash at that
 * exact stage boundary WITHOUT actually killing anything - the thrown error
 * is caught by `importExitBundle`'s own `catch` block, exercising the
 * pre-existing exception-based rollback (proven 3/3 in the drill's
 * "failure injection" form) together with this PR's new journal
 * write/delete bookkeeping. Fires at most once per instance.
 */
class FaultInjectingStorage implements StorageBackend {
  private fired = false;
  constructor(
    private readonly inner: StorageBackend,
    private readonly triggerNamespace: string
  ) {}
  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (!this.fired && namespace === this.triggerNamespace) {
      this.fired = true;
      throw new Error(`INJECTED_FAULT_AT_WRITE(${namespace})`);
    }
    return this.inner.write(namespace, key, data);
  }
  read(namespace: string, key: string): Promise<Uint8Array | null> {
    return this.inner.read(namespace, key);
  }
  delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    return this.inner.delete(namespace, key, secureOverwrite);
  }
  list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
    return this.inner.list(namespace, prefix);
  }
  exists(namespace: string, key: string): Promise<boolean> {
    return this.inner.exists(namespace, key);
  }
  totalSize(): Promise<number> {
    return this.inner.totalSize();
  }
  listNamespaces(): Promise<string[]> {
    return (this.inner as MemoryStorage).listNamespaces();
  }
}

describe("F1: durable rollback journal - in-process fault injection at each stage boundary", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });
  async function newBundleDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-atomic-"));
    tempDirs.push(dir);
    return dir;
  }

  it("fault after staging (before the reputation import writes its first attestation): rolls back cleanly and clears the journal", async () => {
    const source = await makeSource("atomic-poststage", 2, 3);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "atomic-poststage-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const before = await snapshotAll(destinationStorage);

    const faultStorage = new FaultInjectingStorage(destinationStorage, "_reputation");
    await expect(
      importExitBundle({
        bundleDir,
        storage: faultStorage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        // Deliberately NOT destination.reputationStore: that instance is
        // bound to the real (unwrapped) destinationStorage, so writes
        // through it would bypass faultStorage entirely. Omitting it makes
        // importExitBundle build its own ReputationStore from `opts.storage`
        // (faultStorage), which is what makes the injected fault reachable.
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toBeInstanceOf(ExitBundleImportError);

    const after = await snapshotAll(destinationStorage);
    expect(after).toBe(before);
    for (const ns of STAGED_ARTIFACT_NAMESPACES) {
      expect(await destinationStorage.list(ns)).toHaveLength(0);
    }
  });

  it("fault after the reputation import completes (before state re-key writes anything): rolls back cleanly and clears the journal", async () => {
    const source = await makeSource("atomic-postrep", 2, 3);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "atomic-postrep-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const before = await snapshotAll(destinationStorage);

    const faultStorage = new FaultInjectingStorage(destinationStorage, "atomic-postrep-ns");
    let caught: unknown;
    try {
      await importExitBundle({
        bundleDir,
        storage: faultStorage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        // Deliberately NOT destination.reputationStore: that instance is
        // bound to the real (unwrapped) destinationStorage, so writes
        // through it would bypass faultStorage entirely. Omitting it makes
        // importExitBundle build its own ReputationStore from `opts.storage`
        // (faultStorage), which is what makes the injected fault reachable.
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      });
    } catch (err) {
      caught = err;
    }
    // rekeyState wraps a per-entry write failure into the "incomplete
    // state" refusal, same family as ExitBundleImportError.
    expect(
      caught instanceof ExitBundleImportError ||
        caught instanceof ExitBundleStateImportIncompleteError
    ).toBe(true);
    // The reputation attestations DID get written before the injected
    // fault fired; the rollback must undo them too, not just the later
    // stage. This is the assertion that would fail if the journal only
    // captured staged-artifact locations and not the reputation ones.
    const after = await snapshotAll(destinationStorage);
    expect(after).toBe(before);
    expect(await destinationStorage.list("_reputation")).toHaveLength(0);
    for (const ns of STAGED_ARTIFACT_NAMESPACES) {
      expect(await destinationStorage.list(ns)).toHaveLength(0);
    }
  });

  it("fault mid-state-re-key (after one of two entries is written): rolls back BOTH entries, not just the one after the fault", async () => {
    const source = await makeSource("atomic-midrekey", 2, 1);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "atomic-midrekey-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const before = await snapshotAll(destinationStorage);

    // The state namespace's SECOND write is the injected fault (the first
    // succeeds, proving a partially-applied re-key - not just a
    // never-started one - is fully undone).
    class NthWriteFault implements StorageBackend {
      private writesToNamespace = 0;
      constructor(
        private readonly inner: StorageBackend,
        private readonly targetNamespace: string,
        private readonly failOnNthWrite: number
      ) {}
      async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (namespace === this.targetNamespace) {
          this.writesToNamespace++;
          if (this.writesToNamespace === this.failOnNthWrite) {
            throw new Error("INJECTED_FAULT_AT_NTH_STATE_WRITE");
          }
        }
        return this.inner.write(namespace, key, data);
      }
      read(namespace: string, key: string): Promise<Uint8Array | null> {
        return this.inner.read(namespace, key);
      }
      delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
        return this.inner.delete(namespace, key, secureOverwrite);
      }
      list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
        return this.inner.list(namespace, prefix);
      }
      exists(namespace: string, key: string): Promise<boolean> {
        return this.inner.exists(namespace, key);
      }
      totalSize(): Promise<number> {
        return this.inner.totalSize();
      }
      listNamespaces(): Promise<string[]> {
        return (this.inner as MemoryStorage).listNamespaces();
      }
    }
    const faultStorage = new NthWriteFault(destinationStorage, "atomic-midrekey-ns", 2);

    let caught: unknown;
    try {
      await importExitBundle({
        bundleDir,
        storage: faultStorage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        // Deliberately NOT destination.reputationStore: that instance is
        // bound to the real (unwrapped) destinationStorage, so writes
        // through it would bypass faultStorage entirely. Omitting it makes
        // importExitBundle build its own ReputationStore from `opts.storage`
        // (faultStorage), which is what makes the injected fault reachable.
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      });
    } catch (err) {
      caught = err;
    }
    expect(
      caught instanceof ExitBundleImportError ||
        caught instanceof ExitBundleStateImportIncompleteError
    ).toBe(true);
    const after = await snapshotAll(destinationStorage);
    expect(after).toBe(before);
    expect(await destinationStorage.list("atomic-midrekey-ns")).toHaveLength(0);
  });

  it("HIGH-A (coordinator gate, 2026-08-22, register id EXIT-JOURNAL-CONFINE-01): a journal carrying an unsupported key is rejected outright, never replayed - _meta/_identities stay untouched", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    // Plant real data in _meta and _identities so a wipe would be
    // directly observable, not just inferred from a count.
    await destinationStorage.write("_meta", "canary-meta-key", stringToBytes("canary-meta-value"));
    await destinationStorage.write(
      "_identities",
      "canary-identity-key",
      stringToBytes("canary-identity-value")
    );

    // A journal carrying a key outside the exact allowlisted set (N7,
    // coordinator gate, 2026-08-22) - the shape guard rejects it by
    // key-set equality regardless of what the extra key is named or
    // contains.
    const maliciousRecord = {
      import_id: "crafted-import",
      identity_id: "crafted-identity",
      started_at: new Date().toISOString(),
      snapshots: [],
      unsupported_field: [
        { namespace: "_meta", entries: [] },
        { namespace: "_identities", entries: [] },
      ],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "crafted-import",
      stringToBytes(JSON.stringify(maliciousRecord))
    );
    // Snapshot AFTER the malicious journal is written, so "before" and
    // "after" are apples to apples: recovery is expected to leave a
    // FAILED entry's journal in place (discoverable, not silently
    // dropped), not remove it.
    const before = await snapshotAll(destinationStorage);

    const result = await recoverInterruptedExitImports(
      destinationStorage,
      destination.auditLog
    );
    expect(result.recovered).toBe(0);
    expect(result.failed).toEqual(["crafted-import"]);

    const after = await snapshotAll(destinationStorage);
    expect(after).toBe(before);
    expect(await destinationStorage.read("_meta", "canary-meta-key")).not.toBeNull();
    expect(
      await destinationStorage.read("_identities", "canary-identity-key")
    ).not.toBeNull();

    // The open path stops with the named error rather than silently
    // proceeding against a fortress it could not fully recover.
    await expect(
      recoverInterruptedExitImportsOrThrow(destinationStorage, destination.auditLog)
    ).rejects.toMatchObject({ code: "INTERRUPTED_IMPORT_RECOVERY_FAILED" });
  });

  it("recoverInterruptedExitImports is a no-op on a fortress with no interrupted import", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const before = await snapshotAll(destinationStorage);
    const result = await recoverInterruptedExitImports(
      destinationStorage,
      destination.auditLog
    );
    expect(result.recovered).toBe(0);
    expect(result.failed).toEqual([]);
    const after = await snapshotAll(destinationStorage);
    expect(after).toBe(before);
  });

  it("a kill between the final promote write and the journal delete does NOT revert a successful import on the next recovery (coordinator gate finding, 2026-08-22)", async () => {
    // A storage wrapper that lets everything through EXCEPT the journal's
    // OWN delete call, which it silently drops - simulating a process kill
    // landing exactly between the import's last write (the `activated_at`
    // promote) and the journal cleanup that follows it. The import itself
    // completes successfully; only the journal's own removal is what a
    // kill at this point would leave undone.
    class DropJournalDeleteStorage implements StorageBackend {
      constructor(private readonly inner: StorageBackend) {}
      write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        return this.inner.write(namespace, key, data);
      }
      read(namespace: string, key: string): Promise<Uint8Array | null> {
        return this.inner.read(namespace, key);
      }
      async delete(
        namespace: string,
        key: string,
        secureOverwrite?: boolean
      ): Promise<boolean> {
        if (namespace === "_exit_import_journal") return true;
        return this.inner.delete(namespace, key, secureOverwrite);
      }
      list(namespace: string, prefix?: string): Promise<StorageEntryMeta[]> {
        return this.inner.list(namespace, prefix);
      }
      exists(namespace: string, key: string): Promise<boolean> {
        return this.inner.exists(namespace, key);
      }
      totalSize(): Promise<number> {
        return this.inner.totalSize();
      }
      listNamespaces(): Promise<string[]> {
        return (this.inner as MemoryStorage).listNamespaces();
      }
    }

    const source = await makeSource("atomic-postpromote", 2, 2);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "atomic-postpromote-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const wrapped = new DropJournalDeleteStorage(destinationStorage);

    const result = await importExitBundle({
      bundleDir,
      storage: wrapped,
      masterKey: destination.masterKey,
      identityManager: destination.identityManager,
      auditLog: destination.auditLog,
      activate: true,
      forceRebind: true,
      sourceRecoveryKey: exported.state_rekey_key,
      destinationSignerIdentityId: destination.identityId,
    });
    expect(result.activated).toBe(true);

    // The journal survived (the delete was dropped); the import's own data
    // is fully, successfully applied. Excluding the journal itself (which
    // recovery is EXPECTED to remove) from the comparison below, since the
    // property under test is "everything the import actually wrote stays
    // exactly as the import left it" - not "the journal survives too".
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(1);
    const stripJournal = (snapshot: string): string =>
      snapshot
        .split("\n")
        .filter((line) => !line.startsWith(`${EXIT_IMPORT_JOURNAL_NAMESPACE}/`))
        .join("\n");
    const afterSuccessfulImport = stripJournal(await snapshotAll(destinationStorage));

    // Recovery must recognize the import ALREADY completed (via the
    // `activated_at`-stamped record) and clear the stale journal WITHOUT
    // restoring its snapshot - restoring it would revert this successful
    // import back to its pre-image, which is the exact defect this test
    // pins closed.
    const recovery = await recoverInterruptedExitImports(
      destinationStorage,
      destination.auditLog
    );
    expect(recovery.recovered).toBe(1);
    expect(recovery.failed).toEqual([]);
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);

    const afterRecovery = stripJournal(await snapshotAll(destinationStorage));
    expect(afterRecovery).toBe(afterSuccessfulImport);
    expect(await destinationStorage.list("atomic-postpromote-ns")).toHaveLength(2);
  });
});

/**
 * `fs.rm(recursive:true)` can hit ENOTEMPTY under a genuine TOCTOU race if
 * anything is still writing into the tree while it walks - a real risk here
 * specifically because this describe block kills and waits on a REAL child
 * process. Retry a few times with a short backoff rather than let a slow
 * teardown fail the test; this does not affect the test's own assertions,
 * only best-effort cleanup after they have already run.
 */
async function rmWithRetry(dir: string): Promise<void> {
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      await rm(dir, { recursive: true, force: true });
      return;
    } catch (err) {
      if (attempt === 5) throw err;
      await new Promise((resolve) => setTimeout(resolve, 100 * attempt));
    }
  }
}

describe("F1: a real child-process SIGKILL mid-import leaves the target unable to be told apart from pre-import, after recovery", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rmWithRetry(dir)));
  });
  async function newTempDir(prefix: string): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), prefix));
    tempDirs.push(dir);
    return dir;
  }

  /** Full-content snapshot of a FilesystemStorage's `state` tree, same exclusions as `snapshotAll`. */
  async function snapshotFilesystem(storage: FilesystemStorage): Promise<string> {
    const namespaces = await storage.listNamespaces();
    const rows: string[] = [];
    for (const ns of namespaces) {
      if (ns.startsWith("_audit")) continue;
      const entries = await storage.list(ns);
      for (const entry of entries) {
        const data = await storage.read(ns, entry.key);
        rows.push(`${ns}/${entry.key}:${data ? toBase64url(data) : "null"}`);
      }
    }
    return rows.sort().join("\n");
  }

  it(
    "SIGKILL mid-import: target tree is byte-identical to pre-import after fortress-open recovery, and a subsequent clean import yields the same entry counts as a fresh target",
    async () => {
      // A moderately large bundle: big enough that the import takes long
      // enough for a fixed-delay SIGKILL to reliably land mid-flight
      // (proven via the `interrupted` assertion below, not assumed), small
      // enough to keep this test fast.
      const ENTRY_COUNT = 60;
      const ATTESTATION_COUNT = 40;

      const sourceDir = await newTempDir("sanctuary-exit-kill-source-");
      const targetDir = await newTempDir("sanctuary-exit-kill-target-");
      const bundleDir = await newTempDir("sanctuary-exit-kill-bundle-");
      const sourcePassphrase = "atomic-kill-source-disposable-passphrase";
      const targetPassphrase = "atomic-kill-target-disposable-passphrase";

      await mkdir(join(sourceDir, "state"), { recursive: true, mode: 0o700 });
      const sourceStorage = new FilesystemStorage(join(sourceDir, "state"));
      const sourceMasterKey = await resolveCliMasterKey(sourceStorage, {
        passphrase: sourcePassphrase,
        bootstrap: true,
        storagePathHint: sourceDir,
      });
      const source = await buildHarness(sourceStorage, sourceMasterKey);
      const identity = await callTool(source.tools, "identity_create", {
        label: "kill-source-identity",
      });
      const identityId = identity.identity_id as string;
      for (let i = 0; i < ENTRY_COUNT; i++) {
        const w = await callTool(source.tools, "state_write", {
          namespace: "kill-ns",
          key: `k${i}`,
          value: `entry ${i} that must survive the kill`,
          identity_id: identityId,
        });
        if (w.error) throw new Error(`seed state_write failed: ${JSON.stringify(w)}`);
      }
      for (let i = 0; i < ATTESTATION_COUNT; i++) {
        const r = await callTool(source.tools, "reputation_record", {
          interaction_id: `kill-ix-${i}`,
          counterparty_did: `did:key:z6MkKillCounterparty${i}`,
          outcome: { type: "negotiation", result: "success" },
          context: "kill-ctx",
          identity_id: identityId,
        });
        if (r.error) throw new Error(`seed reputation_record failed: ${JSON.stringify(r)}`);
      }
      await source.auditLog.flush();
      const exported = await exportBundle(source, bundleDir, "kill-ns");
      expect(exported.state_entry_count).toBe(ENTRY_COUNT);

      // Fresh reference target, imported WITHOUT interruption, to know what
      // "clean" looks like (entry counts, file layout).
      const referenceDir = await newTempDir("sanctuary-exit-kill-reference-");
      await mkdir(join(referenceDir, "state"), { recursive: true, mode: 0o700 });
      const referenceStorage = new FilesystemStorage(join(referenceDir, "state"));
      const referencePassphrase = "atomic-kill-reference-disposable-passphrase";
      const referenceMasterKey = await resolveCliMasterKey(referenceStorage, {
        passphrase: referencePassphrase,
        bootstrap: true,
        storagePathHint: referenceDir,
      });
      const reference = await buildHarness(referenceStorage, referenceMasterKey);
      const referenceIdentity = await callTool(reference.tools, "identity_create", {
        label: "kill-reference-signer",
      });
      const referenceIdentityId = referenceIdentity.identity_id as string;
      const referenceImport = await importExitBundle({
        bundleDir,
        storage: referenceStorage,
        masterKey: referenceMasterKey,
        identityManager: reference.identityManager,
        auditLog: reference.auditLog,
        reputationStore: reference.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: referenceIdentityId,
      });
      expect(referenceImport.activated).toBe(true);
      expect(referenceImport.state.imported_keys).toBe(ENTRY_COUNT);
      const referenceRepFiles = (await referenceStorage.list("_reputation")).length;

      // The REAL target: pre-seed it with its own signer identity (matching
      // the reference), then spawn `exit import` against it and SIGKILL it
      // mid-flight.
      await mkdir(join(targetDir, "state"), { recursive: true, mode: 0o700 });
      const targetStorage = new FilesystemStorage(join(targetDir, "state"));
      const targetMasterKey = await resolveCliMasterKey(targetStorage, {
        passphrase: targetPassphrase,
        bootstrap: true,
        storagePathHint: targetDir,
      });
      const target = await buildHarness(targetStorage, targetMasterKey);
      await callTool(target.tools, "identity_create", { label: "kill-target-signer" });
      await target.auditLog.flush();
      const beforeKill = await snapshotFilesystem(targetStorage);

      const childEnv: NodeJS.ProcessEnv = {
        ...process.env,
        SANCTUARY_STORAGE_PATH: targetDir,
        SANCTUARY_PASSPHRASE: targetPassphrase,
        SANCTUARY_DASHBOARD_AUTO_OPEN: "false",
        NODE_NO_WARNINGS: "1",
      };
      delete childEnv.SANCTUARY_RECOVERY_KEY;

      const child = spawn(
        NODE_BIN,
        [
          ...TSX_ESM_LOADER_ARGS,
          CLI_SRC,
          "exit",
          "import",
          bundleDir,
          "--activate",
          "--import-state",
          "--force-rebind",
          "--source-recovery-key",
          exported.state_rekey_key!,
          "--yes",
          "--skip-did-web-verify",
        ],
        { env: childEnv, stdio: "ignore" }
      );
      const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(
        (resolve) => {
          child.once("exit", (code, signal) => resolve({ code, signal }));
        }
      );
      // POLL for the write, don't guess a delay: a fixed sleep before the
      // kill was tried first and was flaky, killing the process before it
      // had written anything and proving nothing about atomicity. Instead,
      // poll the target's OWN durable journal namespace (written durably
      // BEFORE any staging write - see writeImportJournal's doc comment in
      // bundle.ts) until an entry appears, confirming staging has actually
      // begun, then wait a short beat longer to land inside the reputation
      // import or state re-key before sending SIGKILL.
      const pollDeadline = Date.now() + 20_000;
      let journalSeen = false;
      while (Date.now() < pollDeadline) {
        if (child.exitCode !== null || child.signalCode !== null) break;
        const journalEntries = await targetStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
        if (journalEntries.length > 0) {
          journalSeen = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      // Let it get further into the reputation import / state re-key before
      // killing, so the interrupted work is not just the journal write
      // itself. Poll for a REPUTATION write specifically (rather than a
      // fixed sleep) so the "writes had begun" assertion below is proven,
      // not assumed.
      let reputationWriteSeen = false;
      const reputationPollDeadline = Date.now() + 20_000;
      while (journalSeen && Date.now() < reputationPollDeadline) {
        if (child.exitCode !== null || child.signalCode !== null) break;
        const reputationEntries = await targetStorage.list("_reputation");
        if (reputationEntries.length > 0) {
          reputationWriteSeen = true;
          break;
        }
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      const stillRunning = child.exitCode === null && child.signalCode === null;
      if (stillRunning && child.pid) {
        process.kill(child.pid, "SIGKILL");
      }
      const exitInfo = await exited;
      expect(journalSeen).toBe(true);
      // LOW-F (coordinator gate, 2026-08-22): unconditional, not gated on
      // `stillRunning` - if the process had already exited before this
      // point, everything downstream ("interrupted mid-flight", "SIGKILL
      // landed") would be an unproven assumption the test was silently
      // passing on anyway. Asserting `stillRunning` itself is true makes
      // that assumption a checked precondition, not an implicit one.
      expect(stillRunning).toBe(true);
      // Prove the kill actually used SIGKILL (not, say, a normal exit
      // racing the poll loop) - a `signal` of anything else means this
      // run's "interrupted" evidence below is not about a hard kill at all.
      expect(exitInfo.signal).toBe("SIGKILL");
      // MEDIUM (coordinator gate, 2026-08-22): prove REPUTATION writes -
      // not just the journal write - had begun before the kill, so the
      // rollback this test exercises is undoing real per-attestation
      // writes, not only the journal bookkeeping.
      expect(reputationWriteSeen).toBe(true);

      // `journalSeen` above proves the journal write (and therefore at
      // least one storage write) happened before the kill, so the target
      // MUST differ from its pre-import state here - this is the direct,
      // non-probabilistic evidence that the kill genuinely landed
      // mid-flight, not a timing guess.
      const afterKill = await snapshotFilesystem(targetStorage);
      expect(afterKill).not.toBe(beforeKill);

      // Fortress-open recovery (`recoverInterruptedExitImports`, called by
      // `openExitContext` on every `sanctuary exit` subcommand): reopen the
      // SAME target storage and prove it heals back to pre-kill, with no
      // retry import at all.
      const reopenedStorage = new FilesystemStorage(join(targetDir, "state"));
      const reopenedAuditLog = new AuditLog(reopenedStorage, targetMasterKey);
      const recovery = await recoverInterruptedExitImports(reopenedStorage, reopenedAuditLog);
      await reopenedAuditLog.flush();
      const afterRecovery = await snapshotFilesystem(reopenedStorage);
      expect(afterRecovery).toBe(beforeKill);
      expect(recovery.recovered).toBe(1);
      expect(recovery.failed).toEqual([]);

      // MEDIUM (coordinator gate, 2026-08-22): idempotency - a SECOND
      // recovery call against the now-clean fortress (simulating a second
      // "fortress open" with no new interruption in between) must be a
      // pure no-op, not re-apply anything or error.
      const secondRecovery = await recoverInterruptedExitImports(
        reopenedStorage,
        reopenedAuditLog
      );
      expect(secondRecovery).toEqual({ recovered: 0, failed: [] });
      expect(await snapshotFilesystem(reopenedStorage)).toBe(beforeKill);

      // Now prove the SECOND half of F1's fix: a subsequent CLEAN import
      // (via the real CLI again, matching the drill's recovery leg) yields
      // EXACTLY the same entry/attestation counts as the untouched
      // reference import - never the drill's pre-fix 122-vs-121 duplicate.
      const retryEnv: NodeJS.ProcessEnv = {
        ...process.env,
        SANCTUARY_STORAGE_PATH: targetDir,
        SANCTUARY_PASSPHRASE: targetPassphrase,
        SANCTUARY_DASHBOARD_AUTO_OPEN: "false",
        NODE_NO_WARNINGS: "1",
      };
      delete retryEnv.SANCTUARY_RECOVERY_KEY;
      const retryOutput = await new Promise<string>((resolve, reject) => {
        const retryChild = spawn(
          NODE_BIN,
          [
            ...TSX_ESM_LOADER_ARGS,
            CLI_SRC,
            "exit",
            "import",
            bundleDir,
            "--activate",
            "--import-state",
            "--force-rebind",
            "--source-recovery-key",
            exported.state_rekey_key!,
            "--yes",
            "--skip-did-web-verify",
          ],
          { env: retryEnv, stdio: ["ignore", "pipe", "pipe"] }
        );
        let out = "";
        retryChild.stdout?.on("data", (chunk) => (out += String(chunk)));
        retryChild.stderr?.on("data", (chunk) => (out += String(chunk)));
        retryChild.once("exit", (code) => {
          if (code === 0) resolve(out);
          else reject(new Error(`retry import exited ${code}: ${out}`));
        });
        retryChild.once("error", reject);
      });
      expect(retryOutput).toContain("verdict: PASS");
      expect(retryOutput).toContain(`state_imported_keys: ${ENTRY_COUNT}`);

      const finalStorage = new FilesystemStorage(join(targetDir, "state"));
      const finalRepFiles = (await finalStorage.list("_reputation")).length;
      expect(finalRepFiles).toBe(referenceRepFiles);
      const finalImportRecords = await finalStorage.list(EXIT_IMPORT_NAMESPACE);
      expect(finalImportRecords).toHaveLength(1);
      const finalJournal = await finalStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
      expect(finalJournal).toHaveLength(0);
    },
    90_000
  );
});

describe("N4 (coordinator gate, 2026-08-22): write chokepoints refuse while an exit-import journal exists", () => {
  it("state_write refuses with the named error and audits when a journal is present, then succeeds once it is removed", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    // A well-formed journal (matches the exact key-set schema, N7) with no
    // snapshots - the point of this test is the WRITE REFUSAL, not the
    // journal's own content.
    const journalRecord = {
      import_id: "planted-n4-import",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-import",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const refused = await callTool(destination.tools, "state_write", {
      namespace: "n4-test-ns",
      key: "k",
      value: "should not be written",
      identity_id: destination.identityId,
    });
    expect(refused.error).toBe("exit_import_pending_recovery");
    expect(await destinationStorage.exists("n4-test-ns", "k")).toBe(false);

    const audited = await destination.auditLog.query({
      operation_type: "state_write_refused_pending_exit_import_recovery",
    });
    expect(audited.entries.length).toBeGreaterThan(0);
    expect(audited.entries[0]!.result).toBe("failure");

    // Journal removed: the SAME write now succeeds.
    await destinationStorage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-n4-import");
    const succeeded = await callTool(destination.tools, "state_write", {
      namespace: "n4-test-ns",
      key: "k",
      value: "written after recovery",
      identity_id: destination.identityId,
    });
    expect(succeeded.error).toBeUndefined();
    expect(await destinationStorage.exists("n4-test-ns", "k")).toBe(true);
  });

  it("reputation_record refuses with the named error and audits when a journal is present, then succeeds once it is removed", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    const journalRecord = {
      import_id: "planted-n4-reputation-import",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-reputation-import",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const refused = await callTool(destination.tools, "reputation_record", {
      interaction_id: "n4-test-ix",
      counterparty_did: "did:key:z6MkN4TestCounterparty",
      outcome: { type: "negotiation", result: "success" },
      context: "n4-test-ctx",
      identity_id: destination.identityId,
    });
    expect(refused.error).toBe("exit_import_pending_recovery");

    const audited = await destination.auditLog.query({
      operation_type: "reputation_record_refused_pending_exit_import_recovery",
    });
    expect(audited.entries.length).toBeGreaterThan(0);
    expect(audited.entries[0]!.result).toBe("failure");

    await destinationStorage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-n4-reputation-import");
    const succeeded = await callTool(destination.tools, "reputation_record", {
      interaction_id: "n4-test-ix",
      counterparty_did: "did:key:z6MkN4TestCounterparty",
      outcome: { type: "negotiation", result: "success" },
      context: "n4-test-ctx",
      identity_id: destination.identityId,
    });
    expect(succeeded.error).toBeUndefined();
  });

  it("state_delete refuses with the named error when a journal is present, then succeeds once it is removed", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    await callTool(destination.tools, "state_write", {
      namespace: "n4-delete-ns",
      key: "k",
      value: "value to protect from a stale restore",
      identity_id: destination.identityId,
    });
    expect(await destinationStorage.exists("n4-delete-ns", "k")).toBe(true);

    const journalRecord = {
      import_id: "planted-n4-delete-import",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-delete-import",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const refused = await callTool(destination.tools, "state_delete", {
      namespace: "n4-delete-ns",
      key: "k",
    });
    expect(refused.error).toBe("exit_import_pending_recovery");
    expect(await destinationStorage.exists("n4-delete-ns", "k")).toBe(true);

    await destinationStorage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-n4-delete-import");
    const succeeded = await callTool(destination.tools, "state_delete", {
      namespace: "n4-delete-ns",
      key: "k",
    });
    expect(succeeded.error).toBeUndefined();
    expect(await destinationStorage.exists("n4-delete-ns", "k")).toBe(false);
  });

  it("state_import refuses with the named error when a journal is present, then succeeds once it is removed", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    await callTool(destination.tools, "state_write", {
      namespace: "n4-import-ns",
      key: "k",
      value: "exported for re-import",
      identity_id: destination.identityId,
    });
    const exported = (await callTool(destination.tools, "state_export", {
      namespace: "n4-import-ns",
    })) as { bundle: string };

    const journalRecord = {
      import_id: "planted-n4-import-bundle",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-import-bundle",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const refused = await callTool(destination.tools, "state_import", {
      bundle: exported.bundle,
      conflict_resolution: "overwrite",
    });
    expect(refused.error).toBe("exit_import_pending_recovery");

    await destinationStorage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-n4-import-bundle");
    const succeeded = await callTool(destination.tools, "state_import", {
      bundle: exported.bundle,
      conflict_resolution: "overwrite",
    });
    expect(succeeded.error).toBeUndefined();
  });
});
