/**
 * F1 / HIGH-2 (coordinator gate, 2026-08-22): `recoverInterruptedExitImportsOrThrow`
 * (server/src/exit/bundle.ts) must be reachable from every fortress-owning
 * composition point that derives a master key, not only from
 * `importExitBundle` itself. This file has two halves:
 *
 *  - a STRUCTURAL PIN over the named call sites (the MCP composition root,
 *    `sanctuary exit` subcommands, and the CLI verbs listed in
 *    `recoverInterruptedExitImportsOrThrow`'s own doc comment), asserting
 *    the wiring survives a later edit rather than trusting a one-time
 *    review;
 *  - two tests that exercise recovery through the REAL open path -
 *    `createSanctuaryServer` (the MCP composition root) and
 *    `runExitCommand`/`openExitContext` via a NON-import subcommand - so
 *    the coverage is not just `importExitBundle`'s own internal recovery
 *    call answering for every caller.
 */

import { describe, expect, it, afterEach } from "vitest";
import { readFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { Writable } from "node:stream";
import { MemoryStorage } from "../../src/storage/memory.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { createSanctuaryServer } from "../../src/index.js";
import { runExitCommand } from "../../src/exit/cli.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { StateStore } from "../../src/cognitive/state-store.js";
import { createL1Tools } from "../../src/cognitive/tools.js";
import { createReputationTools } from "../../src/reputation/tools.js";
import { resolveCliMasterKey } from "../../src/core/master-custody.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { defaultConfig } from "../../src/config.js";
import {
  exportExitBundle,
  importExitBundle,
  type ExportExitBundleResult,
} from "../../src/exit/bundle.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { createTempHome, createTempFortress, TEST_PASSPHRASE } from "../helpers/temp-fortress.js";

const HELPER_DIR = dirname(fileURLToPath(import.meta.url));
const SERVER_ROOT = join(HELPER_DIR, "../..");

const EXIT_IMPORT_JOURNAL_NAMESPACE = "_exit_import_journal";

class StringWritable extends Writable {
  chunks: string[] = [];
  override _write(
    chunk: Buffer | string,
    _enc: BufferEncoding,
    cb: (err?: Error) => void
  ): void {
    this.chunks.push(typeof chunk === "string" ? chunk : chunk.toString("utf8"));
    cb();
  }
  get text(): string {
    return this.chunks.join("");
  }
}

describe("structural pin: every named fortress-open call site routes through recoverInterruptedExitImportsOrThrow", () => {
  /**
   * Expected count of `recoverInterruptedExitImportsOrThrow(` calls per
   * file, one entry per file named in that function's own doc comment
   * (server/src/exit/bundle.ts). A file dropping below its count means a
   * call site was removed without a documented reason; this test fails
   * loud rather than silently losing coverage. `cli/doctor.ts` is
   * DELIBERATELY absent - see its own "STATED BOUND" comment
   * (server/src/cli/doctor.ts, `resolveMasterKeyIfAvailable`) for why.
   */
  const EXPECTED: Array<{ file: string; count: number }> = [
    { file: "src/index.ts", count: 1 },
    { file: "src/dashboard-standalone.ts", count: 1 },
    { file: "src/cli/distress.ts", count: 1 },
    { file: "src/cli/transparency.ts", count: 4 },
    { file: "src/cli/anomaly.ts", count: 2 },
    { file: "src/exit/cli.ts", count: 1 },
  ];

  for (const { file, count } of EXPECTED) {
    it(`${file} calls recoverInterruptedExitImportsOrThrow at least ${count} time(s)`, () => {
      const source = readFileSync(join(SERVER_ROOT, file), "utf8");
      const matches = source.match(/recoverInterruptedExitImportsOrThrow\(/g) ?? [];
      expect(matches.length).toBeGreaterThanOrEqual(count);
    });
  }

  it("cli/doctor.ts states its recovery bound explicitly (deliberately NOT wired)", () => {
    const source = readFileSync(join(SERVER_ROOT, "src/cli/doctor.ts"), "utf8");
    expect(source).toContain("STATED BOUND (HIGH-2, coordinator gate, 2026-08-22)");
    expect(source).not.toContain("recoverInterruptedExitImportsOrThrow(");
  });

  it("importExitBundle's own top-of-function recovery uses the throwing wrapper, not the bare function", () => {
    const source = readFileSync(join(SERVER_ROOT, "src/exit/bundle.ts"), "utf8");
    // `recoverInterruptedExitImports\(` (bare open-paren immediately after
    // "Imports") does NOT match "...ImportsOrThrow(" - the extra
    // "OrThrow" text between "Imports" and "(" means the two names never
    // collide under this regex. Exactly two matches are expected: the
    // function's own definition, and the ONE call inside
    // recoverInterruptedExitImportsOrThrow's body. Every actual USE site
    // (importExitBundle, every fortress-open call site) must go through
    // the throwing wrapper instead.
    const bareMatches = source.match(/recoverInterruptedExitImports\(/g) ?? [];
    expect(bareMatches.length).toBe(2);
  });
});

describe("recovery through the REAL fortress-open path, not a direct call", () => {
  const tempDirs: string[] = [];
  afterEach(async () => {
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
  });

  it("createSanctuaryServer (the MCP composition root) recovers an interrupted import on a SECOND boot of the same storage", async () => {
    // createSanctuaryServer resolves + SAVES a config file off `loadConfig()`
    // even when an in-memory `storage` is injected - without redirecting
    // HOME first, that config write resolves to the OPERATOR'S real
    // ~/.sanctuary (assertHermeticStoragePath in src/paths.ts refuses it,
    // which is what caught this while writing the test). createTempHome
    // moves HOME only, leaving SANCTUARY_STORAGE_PATH alone, so the config
    // write lands in a disposable temp home instead.
    const tempHome = await createTempHome("sanctuary-boot-recovery-home");
    try {
      await runCreateSanctuaryServerRecoveryCheck();
    } finally {
      await tempHome.cleanup();
    }
  });

  async function runCreateSanctuaryServerRecoveryCheck(): Promise<void> {
    const storage = new MemoryStorage();
    const bootPassphrase = "boot-recovery-composition-root-disposable-passphrase";

    // First boot: establishes custody (first-run bootstrap). An explicit
    // passphrase avoids the separate no-credential "mint a recovery key"
    // degraded path, which is not what this test is about; the second boot
    // below needs the SAME credential to unlock the same custody envelope.
    const firstBoot = await createSanctuaryServer({ storage, passphrase: bootPassphrase });
    const masterKey = firstBoot.masterKey;

    // Seed a source fortress and export a bundle to import into `storage`.
    const sourceStorage = new MemoryStorage();
    const sourceAuditLog = new AuditLog(sourceStorage, masterKey);
    const sourceStateStore = new StateStore(sourceStorage, masterKey);
    const { tools: sourceTools, identityManager: sourceIdentityManager } = createL1Tools(
      sourceStateStore,
      sourceStorage,
      masterKey,
      "passphrase",
      sourceAuditLog
    );
    await sourceIdentityManager.load();
    const { tools: sourceRepTools, reputationStore: sourceReputationStore } =
      createReputationTools(sourceStorage, masterKey, sourceIdentityManager, sourceAuditLog);
    async function call(
      tools: Array<{ name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }> }> }>,
      name: string,
      args: Record<string, unknown>
    ): Promise<Record<string, unknown>> {
      const tool = tools.find((t) => t.name === name);
      if (!tool) throw new Error(`tool not found: ${name}`);
      const result = await tool.handler(args);
      return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
    }
    const identity = await call(sourceTools, "identity_create", { label: "boot-recovery-source" });
    await call(sourceTools, "state_write", {
      namespace: "boot-recovery-ns",
      key: "k0",
      value: "survives the interrupted import",
      identity_id: identity.identity_id,
    });
    await call(sourceRepTools, "reputation_record", {
      interaction_id: "boot-recovery-ix-0",
      counterparty_did: "did:key:z6MkBootRecoveryCounterparty",
      outcome: { type: "negotiation", result: "success" },
      context: "boot-recovery-ctx",
      identity_id: identity.identity_id,
    });
    const bundleDir = await mkdtemp(join(tmpdir(), "sanctuary-boot-recovery-bundle-"));
    tempDirs.push(bundleDir);
    const exported: ExportExitBundleResult = await exportExitBundle({
      unpartitionedLegacyExport: true,
      bundleDir,
      storage: sourceStorage,
      masterKey,
      identityManager: sourceIdentityManager,
      auditLog: sourceAuditLog,
      reputationStore: sourceReputationStore,
      policy: DEFAULT_POLICY,
      config: defaultConfig(),
      stateNamespaces: ["boot-recovery-ns"],
      keySource: "passphrase",
      mintStateRekeyKey: true,
    });

    // Interrupt an import into `storage` via a dropped-write fault (same
    // shape as the atomic-activation fault-injection tests): the journal
    // is written, staging proceeds, then a synthetic fault fires so the
    // import throws AND its exception-path cleanup is itself prevented
    // from running to completion, leaving the journal behind - modeling a
    // hard kill without timing-dependent subprocess machinery.
    class DropRekeyWriteStorage implements StorageBackend {
      constructor(private readonly inner: StorageBackend) {}
      async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (namespace === "boot-recovery-ns") {
          throw new Error("SIMULATED_KILL_DURING_STATE_REKEY");
        }
        return this.inner.write(namespace, key, data);
      }
      read(namespace: string, key: string): Promise<Uint8Array | null> {
        return this.inner.read(namespace, key);
      }
      delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
        // Also drop deletes to the fortress's OWN storage during cleanup,
        // modeling a kill that stops ALL further writes to disk, not just
        // the one that threw - this is what leaves the journal behind.
        if (namespace === EXIT_IMPORT_JOURNAL_NAMESPACE) return Promise.resolve(true);
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
    const wrapped = new DropRekeyWriteStorage(storage);
    const destIdentityManager = firstBoot.identityManager;
    await expect(
      importExitBundle({
        bundleDir,
        storage: wrapped,
        masterKey,
        identityManager: destIdentityManager,
        auditLog: firstBoot.auditLog,
        activate: true,
        forceRebind: true,
        sourceRecoveryKey: exported.state_rekey_key,
        destinationSignerIdentityId: destIdentityManager.getDefault()?.identity_id,
      })
    ).rejects.toThrow();

    // The journal survived (its delete was dropped too); prove it via the
    // REAL storage, not the wrapper.
    expect(await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).not.toHaveLength(0);

    // SECOND boot of createSanctuaryServer on the SAME storage: the real
    // MCP composition-root path, not a direct recoverInterruptedExitImports
    // call.
    const secondBoot = await createSanctuaryServer({ storage, passphrase: bootPassphrase });
    expect(secondBoot.masterKey).toBeInstanceOf(Uint8Array);
    expect(await storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
  }

  it("runExitCommand/openExitContext recovers an interrupted import via a NON-import subcommand (exit export), proving the fortress-open call site - not importExitBundle's own - is what fires", async () => {
    // `openExitContext` (server/src/exit/cli.ts) calls `loadConfig()` with
    // NO arguments, which reads `process.env.SANCTUARY_STORAGE_PATH`
    // DIRECTLY - the `env` object passed to `runExitCommand` only feeds
    // passphrase/recovery-key resolution, not the storage path. Seeding
    // through an explicit path while only passing `env` to `runExitCommand`
    // silently resolves the fortress to whatever `process.env` actually
    // holds (caught here as "credential does not unlock this fortress"
    // while writing the test, not a real-fortress write - see AGENTS.md
    // "the operator's machine is not a fixture"). `createTempFortress`
    // moves `process.env.HOME`/`SANCTUARY_STORAGE_PATH`/`SANCTUARY_PASSPHRASE`
    // together, which is what both the seeding step and `runExitCommand`
    // need to agree on the same fortress.
    const tempFortress = await createTempFortress("sanctuary-openctx-recovery");
    try {
      await runOpenExitContextRecoveryCheck(tempFortress.storagePath);
    } finally {
      await tempFortress.cleanup();
    }
  });

  async function runOpenExitContextRecoveryCheck(targetDir: string): Promise<void> {
    const targetPassphrase = TEST_PASSPHRASE;
    await mkdir(join(targetDir, "state"), { recursive: true, mode: 0o700 });
    const targetStorage = new FilesystemStorage(join(targetDir, "state"));
    const targetMasterKey = await resolveCliMasterKey(targetStorage, {
      passphrase: targetPassphrase,
      bootstrap: true,
      storagePathHint: targetDir,
    });
    const targetAuditLog = new AuditLog(targetStorage, targetMasterKey);
    const targetStateStore = new StateStore(targetStorage, targetMasterKey);
    const { tools: targetTools, identityManager: targetIdentityManager } = createL1Tools(
      targetStateStore,
      targetStorage,
      targetMasterKey,
      "passphrase",
      targetAuditLog
    );
    await targetIdentityManager.load();
    async function call(
      tools: Array<{ name: string; handler: (args: Record<string, unknown>) => Promise<{ content: Array<{ type: string; text: string }> }> }>,
      name: string,
      args: Record<string, unknown>
    ): Promise<Record<string, unknown>> {
      const tool = tools.find((t) => t.name === name);
      if (!tool) throw new Error(`tool not found: ${name}`);
      const result = await tool.handler(args);
      return JSON.parse(result.content[0]!.text) as Record<string, unknown>;
    }
    await call(targetTools, "identity_create", { label: "openctx-recovery-target" });
    await targetAuditLog.flush();

    // Directly plant a well-formed but interrupted-looking journal entry
    // (no real import needed for THIS half - the point is proving
    // openExitContext's own recovery call fires on ANY subcommand, not
    // reproducing an import interruption again).
    const importId = "planted-openctx-recovery-import";
    const journalRecord = {
      import_id: importId,
      identity_id: targetIdentityManager.getPrimaryIdentityId() ?? "unknown",
      started_at: new Date().toISOString(),
      snapshots: [],
      namespace_snapshots: [],
    };
    await targetStorage.write(
      EXIT_IMPORT_JOURNAL_NAMESPACE,
      importId,
      Buffer.from(JSON.stringify(journalRecord) + "\n", "utf8")
    );
    expect(await targetStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(1);

    // `exit export` never touches importExitBundle at all - if the journal
    // is gone afterward, it was openExitContext's own recovery call that
    // did it.
    const out = new StringWritable();
    const err = new StringWritable();
    const exportDir = await mkdtemp(join(tmpdir(), "sanctuary-openctx-recovery-export-"));
    tempDirs.push(exportDir);
    const code = await runExitCommand({
      argv: ["export", "--out", exportDir, "--yes", "--no-did-web"],
      out,
      err,
      env: { SANCTUARY_STORAGE_PATH: targetDir, SANCTUARY_PASSPHRASE: targetPassphrase },
    });
    expect(code).toBe(0);

    const reopenedStorage = new FilesystemStorage(join(targetDir, "state"));
    expect(await reopenedStorage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
  }
});
