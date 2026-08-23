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
import { mkdtemp, mkdir, rm, open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { toBase64url, stringToBytes } from "../../src/core/encoding.js";
import { hashToString } from "../../src/core/hashing.js";
import {
  resolveCliMasterKey,
  ROTATION_JOURNAL_KEY,
} from "../../src/core/master-custody.js";
import {
  StateStore,
  STATE_ENVELOPE_VERSION_ANCHORS_KEY,
} from "../../src/cognitive/state-store.js";
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
  EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
  type ExportExitBundleResult,
} from "../../src/exit/bundle.js";

/**
 * CONTRACT PIN: must match locationDedupeKey in server/src/exit/bundle.ts -
 * the encoding a planted post-image record's key needs to match for
 * readPostImageHash (bundle.ts) to find it.
 */
function postImageKey(
  importId: string,
  namespace: string,
  key: string
): string {
  return `${importId}:${namespace.length}:${namespace}${key}`;
}

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
    // Canary data so a content check, not just a count, proves these
    // namespaces stay untouched.
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
      // HIGH-1 (Codex gate, 2026-08-22, register id EXIT-JOURNAL-DIVERGE-01):
      // a real SIGKILL's timing is not fully controlled by this test (only
      // "after a reputation write is observed"), so the kill CAN now land
      // in the narrow window between a write committing and this same
      // import's own post-image record for that write reaching disk - the
      // residual gap the no-lock design explicitly does not close. Recovery
      // must never silently discard that write: either it confirms the
      // write was its own (clean, byte-identical recovery) or it reports
      // the location diverged and leaves it untouched, never a third
      // silent outcome.
      // F3 (coordinator gate, 2026-08-22): both branches run the SAME
      // idempotency and clean-import-afterward checks below, not just the
      // clean branch - a diverged result is still a DETERMINATE, reportable
      // state, not a dead end this test stops verifying at.
      const cleanlyRecovered = recovery.failed.length === 0;
      if (cleanlyRecovered) {
        const afterRecovery = await snapshotFilesystem(reopenedStorage);
        expect(afterRecovery).toBe(beforeKill);
        expect(recovery.recovered).toBe(1);
      } else {
        expect(recovery.diverged.length).toBeGreaterThan(0);
        expect(recovery.recovered).toBe(0);
        // The journal is deliberately left in place on a diverged result
        // (recoverInterruptedExitImportsOrThrow is what a real fortress
        // open route enforces on top of this); assert it is still there,
        // not silently dropped.
        expect(await reopenedStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).not.toHaveLength(0);
        // MEDIUM-D (Codex gate, 2026-08-22): every diverged location, by
        // name, is byte-identical to what it held right after the kill -
        // "diverged" means untouched, proven per-location, not inferred
        // from the aggregate count.
        expect(recovery.divergedLocations.length).toBeGreaterThan(0);
        for (const loc of recovery.divergedLocations) {
          const postKillBytes = await targetStorage.read(loc.namespace, loc.key);
          const postRecoveryBytes = await reopenedStorage.read(loc.namespace, loc.key);
          expect(
            postRecoveryBytes ? toBase64url(postRecoveryBytes) : null
          ).toBe(postKillBytes ? toBase64url(postKillBytes) : null);
        }
      }

      // MEDIUM (coordinator gate, 2026-08-22): idempotency - a SECOND
      // recovery call with no new interruption in between must report the
      // SAME determinate outcome again, not drift: a pure no-op on the
      // clean branch, the SAME diverged locations again on the other (this
      // function never guesses on a repeat call any more than the first).
      const secondRecovery = await recoverInterruptedExitImports(
        reopenedStorage,
        reopenedAuditLog
      );
      if (cleanlyRecovered) {
        expect(secondRecovery).toEqual({
          recovered: 0,
          failed: [],
          diverged: [],
          divergedLocations: [],
        });
        expect(await snapshotFilesystem(reopenedStorage)).toBe(beforeKill);
      } else {
        expect(secondRecovery.recovered).toBe(0);
        expect(secondRecovery.diverged).toEqual(recovery.diverged);
      }

      // Now prove the SECOND half of F1's fix: a subsequent import attempt
      // (via the real CLI again, matching the drill's recovery leg) either
      // yields EXACTLY the same entry/attestation counts as the untouched
      // reference import (clean branch - never the drill's pre-fix
      // 122-vs-121 duplicate), or is refused outright by the SAME
      // fortress-open recovery gate the diverged state left in place
      // (diverged branch - a real "fortress open" must not silently run
      // against a fortress recovery could not confirm).
      const retryEnv: NodeJS.ProcessEnv = {
        ...process.env,
        SANCTUARY_STORAGE_PATH: targetDir,
        SANCTUARY_PASSPHRASE: targetPassphrase,
        SANCTUARY_DASHBOARD_AUTO_OPEN: "false",
        NODE_NO_WARNINGS: "1",
      };
      delete retryEnv.SANCTUARY_RECOVERY_KEY;
      const retryResult = await new Promise<{ code: number | null; out: string }>(
        (resolve, reject) => {
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
          retryChild.once("exit", (code) => resolve({ code, out }));
          retryChild.once("error", reject);
        }
      );

      if (cleanlyRecovered) {
        expect(retryResult.code).toBe(0);
        expect(retryResult.out).toContain("verdict: PASS");
        expect(retryResult.out).toContain(`state_imported_keys: ${ENTRY_COUNT}`);

        const finalStorage = new FilesystemStorage(join(targetDir, "state"));
        const finalRepFiles = (await finalStorage.list("_reputation")).length;
        expect(finalRepFiles).toBe(referenceRepFiles);
        const finalImportRecords = await finalStorage.list(EXIT_IMPORT_NAMESPACE);
        expect(finalImportRecords).toHaveLength(1);
        const finalJournal = await finalStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
        expect(finalJournal).toHaveLength(0);
      } else {
        // F3 (coordinator gate, 2026-08-22): a real "fortress open" (this
        // CLI invocation) must refuse outright against a fortress recovery
        // could not confirm - the SAME gate `recoverInterruptedExitImportsOrThrow`
        // enforces, reached here through the CLI's own openExitContext, not
        // called directly.
        expect(retryResult.code).not.toBe(0);
        expect(retryResult.out).toContain("could not be safely rolled back");
        const finalJournal = await reopenedStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE);
        expect(finalJournal).not.toHaveLength(0);
      }
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

  it("plants a real recoverable journal (a location whose current bytes already match the pre-image), runs recoverInterruptedExitImportsOrThrow directly, then a write succeeds", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    // Pre-existing bytes at a location the journal snapshots - captured
    // AFTER the write, so the journal's pre-image byte-for-byte matches
    // what is actually on disk right now (a genuine "nothing changed since"
    // no-op restore), not a placeholder that would trip HIGH-1's
    // divergence check.
    await callTool(destination.tools, "state_write", {
      namespace: "n4-recover-ns",
      key: "k",
      value: "pre-journal value",
      identity_id: destination.identityId,
    });
    const actualCurrentBytes = await destinationStorage.read("n4-recover-ns", "k");

    const journalRecord = {
      import_id: "planted-n4-real-recovery",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [
        {
          namespace: "n4-recover-ns",
          key: "k",
          data: actualCurrentBytes ? toBase64url(actualCurrentBytes) : null,
        },
      ],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-real-recovery",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const refusedBeforeRecovery = await callTool(destination.tools, "state_write", {
      namespace: "n4-recover-ns",
      key: "k2",
      value: "should still be refused",
      identity_id: destination.identityId,
    });
    expect(refusedBeforeRecovery.error).toBe("exit_import_pending_recovery");

    const result = await recoverInterruptedExitImportsOrThrow(
      destinationStorage,
      destination.auditLog
    );
    expect(result.recovered).toBe(1);
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);

    const succeeded = await callTool(destination.tools, "state_write", {
      namespace: "n4-recover-ns",
      key: "k2",
      value: "written after real recovery",
      identity_id: destination.identityId,
    });
    expect(succeeded.error).toBeUndefined();
    expect(await destinationStorage.exists("n4-recover-ns", "k2")).toBe(true);
  });

  it("N4-READ: state_read returns the value with no `_meta` version-anchor write while a journal exists", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    const written = await callTool(destination.tools, "state_write", {
      namespace: "n4-read-ns",
      key: "k",
      value: "readable while a journal is pending",
      identity_id: destination.identityId,
    });
    expect(written.error).toBeUndefined();

    const anchorBefore = await destinationStorage.read(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY
    );

    const journalRecord = {
      import_id: "planted-n4-read",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-n4-read",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const read = await callTool(destination.tools, "state_read", {
      namespace: "n4-read-ns",
      key: "k",
      identity_id: destination.identityId,
    });
    expect(read.value).toBe("readable while a journal is pending");

    const anchorAfter = await destinationStorage.read(
      "_meta",
      STATE_ENVELOPE_VERSION_ANCHORS_KEY
    );
    expect(anchorAfter ? toBase64url(anchorAfter) : null).toBe(
      anchorBefore ? toBase64url(anchorBefore) : null
    );
  });
});

describe("F2 (coordinator gate, 2026-08-22): exit-import refuses while a master rotation is in progress, in both directions", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });
  async function newBundleDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-f2-"));
    tempDirs.push(dir);
    return dir;
  }

  it("top-level check: importExitBundle throws ROTATION_IN_PROGRESS when a rotation journal already exists, mutating nothing", async () => {
    const source = await makeSource("f2-toplevel", 2, 1);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "f2-toplevel-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    await destinationStorage.write(
      "_meta",
      ROTATION_JOURNAL_KEY,
      stringToBytes("planted-rotation-journal-placeholder")
    );
    const before = await snapshotAll(destinationStorage);

    await expect(
      importExitBundle({
        bundleDir,
        storage: destinationStorage,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "ROTATION_IN_PROGRESS" });

    expect(await snapshotAll(destinationStorage)).toBe(before);
  });

  it("F1 re-check: a rotation journal that appears DURING this import's own journal write is caught, and the import cleans up its own journal", async () => {
    class InjectRotationJournalOnFirstWrite implements StorageBackend {
      injected = false;
      constructor(private readonly inner: StorageBackend) {}
      async write(namespace: string, key: string, value: Uint8Array): Promise<void> {
        await this.inner.write(namespace, key, value);
        // Fires exactly once, right after this import's OWN journal write
        // lands - simulating a rotation whose preflight passed and whose
        // journal write raced in between the top-of-function check and
        // writeImportJournal.
        if (!this.injected && namespace === EXIT_IMPORT_JOURNAL_NAMESPACE) {
          this.injected = true;
          await this.inner.write(
            "_meta",
            ROTATION_JOURNAL_KEY,
            stringToBytes("planted-mid-import-rotation-journal")
          );
        }
      }
      read(namespace: string, key: string): Promise<Uint8Array | null> {
        return this.inner.read(namespace, key);
      }
      delete(
        namespace: string,
        key: string,
        secureOverwrite?: boolean
      ): Promise<boolean> {
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

    const source = await makeSource("f2-midwrite", 2, 1);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "f2-midwrite-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    const wrapped = new InjectRotationJournalOnFirstWrite(destinationStorage);

    await expect(
      importExitBundle({
        bundleDir,
        storage: wrapped,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toMatchObject({ code: "ROTATION_IN_PROGRESS" });

    // The import's OWN journal is gone (clean rollback - nothing had been
    // staged yet, so the catch path's restore found every location
    // safe-noop and deleted it).
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    // Nothing from the bundle landed.
    expect(await destinationStorage.list(EXIT_IMPORT_NAMESPACE)).toHaveLength(0);
    expect(await destinationStorage.list("f2-midwrite-ns")).toHaveLength(0);
  });
});

describe("F3 (coordinator gate, 2026-08-22): post-image-confirmed restore, deterministic", () => {
  it("current bytes equal the recorded post-image: restored to the pre-image", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    const preImage = stringToBytes("pre-image value");
    const postImageBytes = stringToBytes("post-image value (this import's own write)");
    await destinationStorage.write("f3-ns", "k", postImageBytes);

    const journalRecord = {
      import_id: "planted-f3-safe-restore",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [
        {
          namespace: "f3-ns",
          key: "k",
          data: toBase64url(preImage),
        },
      ],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-f3-safe-restore",
      stringToBytes(JSON.stringify(journalRecord))
    );
    // MEDIUM-C (Codex gate, 2026-08-22): the post-image is a SEPARATE
    // per-location record now, not a field embedded in the journal.
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
      postImageKey("planted-f3-safe-restore", "f3-ns", "k"),
      stringToBytes(JSON.stringify({ hash: hashToString(postImageBytes) }))
    );

    const result = await recoverInterruptedExitImports(destinationStorage, destination.auditLog);
    expect(result.recovered).toBe(1);
    expect(result.failed).toEqual([]);
    expect(result.diverged).toEqual([]);
    const restored = await destinationStorage.read("f3-ns", "k");
    expect(restored ? toBase64url(restored) : null).toBe(toBase64url(preImage));
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
  });

  it("current bytes match neither the pre-image nor the recorded post-image: diverged, bytes left untouched, audited, remediation text present", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    const preImage = stringToBytes("pre-image value");
    const importsOwnPostImage = stringToBytes("post-image this import actually wrote");
    const thirdPartyBytes = stringToBytes("a DIFFERENT writer's bytes, after this import's own write");
    await destinationStorage.write("f3-ns", "k", thirdPartyBytes);

    const journalRecord = {
      import_id: "planted-f3-diverged",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [
        {
          namespace: "f3-ns",
          key: "k",
          data: toBase64url(preImage),
        },
      ],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE,
      postImageKey("planted-f3-diverged", "f3-ns", "k"),
      stringToBytes(JSON.stringify({ hash: hashToString(importsOwnPostImage) }))
    );
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-f3-diverged",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const result = await recoverInterruptedExitImports(destinationStorage, destination.auditLog);
    expect(result.recovered).toBe(0);
    expect(result.failed).toEqual(["planted-f3-diverged"]);
    expect(result.diverged).toEqual(["planted-f3-diverged"]);
    const untouched = await destinationStorage.read("f3-ns", "k");
    expect(untouched ? toBase64url(untouched) : null).toBe(toBase64url(thirdPartyBytes));
    // Journal is left in place, not deleted, on a diverged result.
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(1);

    const audited = await destination.auditLog.query({
      operation_type: "exit_bundle_recovery_diverged",
    });
    expect(audited.entries.length).toBeGreaterThan(0);
    expect(audited.entries[0]!.result).toBe("failure");

    await expect(
      recoverInterruptedExitImportsOrThrow(destinationStorage, destination.auditLog)
    ).rejects.toThrow(/At least one location changed since this import last touched/);
  });

  it("no post-image record exists at all (never recorded) and current differs from the pre-image: diverged, not silently restored", async () => {
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;

    const preImage = stringToBytes("pre-image value");
    const unrecordedWrite = stringToBytes("a write with no recorded post-image at all");
    await destinationStorage.write("f3-ns", "k", unrecordedWrite);

    const journalRecord = {
      import_id: "planted-f3-null-postimage",
      identity_id: destination.identityId,
      started_at: new Date().toISOString(),
      snapshots: [
        {
          namespace: "f3-ns",
          key: "k",
          data: toBase64url(preImage),
        },
      ],
    };
    await destinationStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      "planted-f3-null-postimage",
      stringToBytes(JSON.stringify(journalRecord))
    );

    const result = await recoverInterruptedExitImports(destinationStorage, destination.auditLog);
    expect(result.recovered).toBe(0);
    expect(result.diverged).toEqual(["planted-f3-null-postimage"]);
    const untouched = await destinationStorage.read("f3-ns", "k");
    expect(untouched ? toBase64url(untouched) : null).toBe(toBase64url(unrecordedWrite));
  });
});

describe("HIGH-B (coordinator gate, 2026-08-22): fortress-wide exit-admission lock", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("a held admission lock refuses recovery with the SAME operator remediation shape a refused journal uses, no auto-break", async () => {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-admission-"));
    tempDirs.push(dir);
    const storage = new FilesystemStorage(join(dir, "state"));
    // Force the namespace directory to exist (a fresh fortress has none of
    // its namespaces on disk yet).
    await storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "warm-namespace-dir", stringToBytes("x"));
    await storage.delete(EXIT_IMPORT_JOURNAL_NAMESPACE, "warm-namespace-dir", false);

    // Simulate a held lock exactly the way withPathLock itself creates one -
    // an O_EXCL create with the SAME payload shape, standing in for either a
    // live concurrent holder or a crashed one (no auto-stale-break means
    // this test cannot and does not need to distinguish the two; see
    // cross-process-lock.ts's module header for why).
    const lockDir = storage.namespacePath(EXIT_IMPORT_JOURNAL_NAMESPACE);
    const lockPath = join(lockDir, "admission.lock");
    const handle = await open(lockPath, "wx", 0o600);
    await handle.writeFile(
      JSON.stringify({ owner: "import", pid: 999_999, acquired_at: new Date(0).toISOString() })
    );
    await handle.close();

    const auditLog = new AuditLog(storage, generateRandomKey());
    await expect(recoverInterruptedExitImports(storage, auditLog)).rejects.toThrow(
      /Run any `sanctuary exit` verb .* to recover, then retry\. If no other Sanctuary operation is actually running .* inspect the lock directly .* before removing it - do not remove it first/
    );

    // The lock file itself is untouched by the failed acquire attempt (no
    // auto-break) - still there, still readable, still the original holder.
    const readHandle = await open(lockPath, "r");
    const stillLocked = JSON.parse(await readHandle.readFile("utf8"));
    await readHandle.close();
    expect(stillLocked.owner).toBe("import");
  }, 20_000);
});

describe("F4 (coordinator gate, 2026-08-22): a `_meta` write fault after entry bytes land must roll back cleanly, not diverge", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });
  async function newBundleDir(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), "sanctuary-exit-f4-"));
    tempDirs.push(dir);
    return dir;
  }

  it("Nth `_meta` write fault (after a later entry's own bytes and post-image already landed): recovery is clean, not diverged", async () => {
    class NthMetaWriteFaultStorage implements StorageBackend {
      private metaWrites = 0;
      constructor(
        private readonly inner: StorageBackend,
        private readonly faultOnMetaWriteNumber: number
      ) {}
      async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (namespace === "_meta") {
          this.metaWrites++;
          if (this.metaWrites === this.faultOnMetaWriteNumber) {
            throw new Error("F4 injected fault: simulated _meta write failure");
          }
        }
        return this.inner.write(namespace, key, data);
      }
      read(namespace: string, key: string): Promise<Uint8Array | null> {
        return this.inner.read(namespace, key);
      }
      delete(
        namespace: string,
        key: string,
        secureOverwrite?: boolean
      ): Promise<boolean> {
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

    const source = await makeSource("f4-metafault", 2, 0);
    const bundleDir = await newBundleDir();
    const exported = await exportBundle(source, bundleDir, "f4-metafault-ns");
    const destination = await makeDestination();
    const destinationStorage = destination.storage as MemoryStorage;
    // 3rd `_meta` write = the SECOND entry's version-anchor update (the
    // first entry's writer-key-registry write is #1, its own anchor
    // update is #2; the second entry's writer-key-registry write is
    // skipped - same signer, unchanged - so its anchor update is #3).
    // By this point entry 1's bytes AND post-image are already durably
    // recorded; entry 2's own MAIN ENTRY write (which happens before this
    // `_meta` update, inside the same stateStore.write call) has ALSO
    // already landed with its own post-image recorded (HIGH-A: recorded
    // per raw write, not batched at the end of the call).
    const wrapped = new NthMetaWriteFaultStorage(destinationStorage, 3);

    await expect(
      importExitBundle({
        bundleDir,
        storage: wrapped,
        masterKey: destination.masterKey,
        identityManager: destination.identityManager,
        auditLog: destination.auditLog,
        reputationStore: destination.reputationStore,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destination.identityId,
      })
    ).rejects.toThrow(/F4 injected fault/);

    // The exception-path cleanup inside importExitBundle already ran
    // restoreStorageSnapshots synchronously before rejecting - assert the
    // result directly rather than re-invoking recovery.
    expect(await destinationStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect(await destinationStorage.list("f4-metafault-ns")).toHaveLength(0);

    // A fresh fortress-open recovery pass finds nothing left to do (the
    // exception-path cleanup already resolved it cleanly).
    const recovery = await recoverInterruptedExitImports(destinationStorage, destination.auditLog);
    expect(recovery).toEqual({ recovered: 0, failed: [], diverged: [], divergedLocations: [] });
  });
});
