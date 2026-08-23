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
import { readFileSync, readdirSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, dirname, relative, sep } from "node:path";
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

/**
 * MEDIUM-C (coordinator gate, 2026-08-22): the candidate set below is
 * MECHANICALLY DERIVED (every `src/**\/*.ts` file whose text contains both
 * `new FilesystemStorage(` and `new AuditLog(`), not hand-listed - a
 * hand-listed table cannot catch a NEW file added later that builds the
 * same pattern (18 such files existed, unlisted, when this was a
 * hand-listed table of 6). Every candidate must be either WIRED (calls
 * `recoverInterruptedExitImportsOrThrow`) or explicitly ALLOWLISTED with a
 * one-line reason below; `expect(...).toEqual(...)` on the full candidate
 * set (not `toBeGreaterThanOrEqual`) means a 19th (or Nth) site trips this
 * test the moment it exists, wired or not.
 */
function listTsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...listTsFiles(full));
    } else if (entry.isFile() && /\.tsx?$/.test(entry.name)) {
      out.push(full);
    }
  }
  return out;
}

function toRelSrcPath(absPath: string): string {
  return "src/" + relative(join(SERVER_ROOT, "src"), absPath).split(sep).join("/");
}

/**
 * ALLOWLIST (MEDIUM-C): every mechanically-derived candidate NOT wired
 * this fix round, with a one-line reason. Each entry is checked against
 * the LIVE candidate set below, so a stale entry (the file no longer
 * matches, or was wired since) fails loud rather than rotting silently.
 */
const ALLOWLIST: Record<string, string> = {
  "src/disclosure/broker/open.ts": "L3 secret-broker open helper; not wired this fix round, scope bounded to the named sites plus low-risk additions found while auditing.",
  "src/cli/erc8004.ts": "erc8004 verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/sentinel.ts": "sentinel verb family, multiple AuditLog sites across many verbs; not wired this fix round.",
  "src/cli/concierge.ts": "concierge verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/auto-trigger.ts": "auto-trigger verb family, multiple AuditLog sites across many verbs; not wired this fix round.",
  "src/cli/audit-chain-repair-plan.ts": "read-only repair-PLAN verb (proposes a plan, does not apply one); not wired this fix round.",
  "src/cli/memory-file.ts": "memory-file verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/did-web.ts": "did-web verb family, multiple AuditLog sites; not wired this fix round.",
  "src/cli/file-grant.ts": "read-only file-grant verb; not wired this fix round.",
  "src/cli/cortex-export.ts": "cortex-export verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/audit.ts": "read-only audit verb; not wired this fix round.",
  "src/cli/castle-wall-boot.ts": "castle-wall boot-install verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/castle-wall-observe.ts": "N2 (coordinator gate, 2026-08-22): writes observe-store state and critical audit entries (auditLog.appendCritical, observeStore.setState, removeCandidateAfterReview) - NOT read-only, corrected from an earlier false claim; not wired this fix round.",
  "src/cli/policy.ts": "policy verb family, multiple AuditLog sites; not wired this fix round.",
  "src/cli/checkpoint.ts": "checkpoint verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/castle-wall.ts": "Castle Wall CLI, many AuditLog sites across many verbs; not wired this fix round.",
  "src/cli/state-disclose.ts": "state-disclose verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/restore-attest.ts": "restore-attest verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/agents/cli.ts": "agents verb; not wired this fix round, same bounded-scope reason.",
  "src/dashboard/v1_1/dispatch.ts": "shared dashboard dispatch helper used by many routes; not wired this fix round.",
  "src/wrap/custody-flow.ts": "wrap custody-establishment flow; not wired this fix round, same bounded-scope reason.",
  "src/wrap/init.ts": "fortress first-run init; not wired this fix round, same bounded-scope reason.",
  "src/wrap/cli.ts": "wrap CLI, multiple AuditLog sites; not wired this fix round.",
  "src/templates/cli.ts": "templates verb; not wired this fix round, same bounded-scope reason.",
  "src/cli/identity.ts": "N1 (coordinator gate, 2026-08-22): derives a master key (identity create/import) with no local AuditLog; not wired this fix round, same bounded-scope reason.",
  "src/cli/federation-operator-signing.ts": "N1 (coordinator gate, 2026-08-22): derives a master key with no local AuditLog; not wired this fix round, same bounded-scope reason.",
  "src/cli/custody-unlock.ts": "N1 (coordinator gate, 2026-08-22): derives a master key with no local AuditLog; not wired this fix round, same bounded-scope reason.",
  "src/cli/doctor.ts": "deliberate exception, documented at resolveMasterKeyIfAvailable's own STATED BOUND comment: every check in this file is read-only and never-aborting by design, so it never calls the writing recovery path even where it derives a master key. Its own journal-presence check (checkInterruptedExitImport) is read-only and needs no credential.",
};

describe("structural pin: every named fortress-open call site routes through recoverInterruptedExitImportsOrThrow", () => {
  const srcDir = join(SERVER_ROOT, "src");
  // N1 (coordinator gate, 2026-08-22): the predicate also catches a file
  // that constructs a fortress storage backend and derives a master key
  // WITHOUT ever constructing an AuditLog - the earlier `new AuditLog(`
  // requirement missed exactly this shape (cli/identity.ts, doctor.ts,
  // federation-operator-signing.ts, custody-unlock.ts all derive a master
  // key with no local AuditLog).
  const MASTER_KEY_DERIVATION_RE =
    /resolveCliMasterKey\(|deriveFortressMasterKey\(|resolveMasterKey\(/;
  const candidates = listTsFiles(srcDir)
    .map(toRelSrcPath)
    .filter((relPath) => {
      const source = readFileSync(join(SERVER_ROOT, relPath), "utf8");
      if (!source.includes("new FilesystemStorage(")) return false;
      return (
        source.includes("new AuditLog(") || MASTER_KEY_DERIVATION_RE.test(source)
      );
    })
    .sort();

  it("every mechanically-derived candidate is wired or explicitly allowlisted, with no stale allowlist entries", () => {
    const wired: string[] = [];
    const unaccounted: string[] = [];
    for (const relPath of candidates) {
      const source = readFileSync(join(SERVER_ROOT, relPath), "utf8");
      const isWired = source.includes("recoverInterruptedExitImportsOrThrow(");
      const isAllowlisted = Object.prototype.hasOwnProperty.call(ALLOWLIST, relPath);
      if (isWired && isAllowlisted) {
        unaccounted.push(`${relPath}: both wired AND allowlisted - remove the stale allowlist entry`);
        continue;
      }
      if (isWired) {
        wired.push(relPath);
        continue;
      }
      if (isAllowlisted) {
        continue;
      }
      unaccounted.push(`${relPath}: neither wired nor allowlisted`);
    }
    // Every allowlist entry must correspond to a LIVE candidate - a file
    // that no longer matches the mechanical pattern (or was wired) leaves
    // a stale entry that silently stops meaning anything.
    for (const allowlistedPath of Object.keys(ALLOWLIST)) {
      if (!candidates.includes(allowlistedPath)) {
        unaccounted.push(`${allowlistedPath}: allowlisted but is no longer a candidate (stale entry - remove it)`);
      }
    }
    expect(unaccounted).toEqual([]);
    // Named-list pin: the wired set is expected to be EXACTLY this list.
    // A file dropping recovery silently is caught here; a NEW candidate
    // (wired or not) is already caught by the loop above regardless.
    expect(wired.sort()).toEqual(
      [
        "src/cli/anomaly.ts",
        "src/cli/distress.ts",
        "src/cli/memory-archive.ts",
        "src/cli/transparency.ts",
        "src/dashboard-standalone.ts",
        "src/exit/cli.ts",
        "src/index.ts",
      ].sort()
    );
  });

  it("cli/doctor.ts states its recovery bound explicitly (deliberately NOT wired to the throwing recovery path)", () => {
    const source = readFileSync(join(SERVER_ROOT, "src/cli/doctor.ts"), "utf8");
    expect(source).toContain("STATED BOUND (HIGH-2, coordinator gate, 2026-08-22)");
    expect(source).not.toContain("recoverInterruptedExitImportsOrThrow(");
    // Codex gate net-new (2026-08-22): doctor.ts DOES derive a master key
    // when credentials are present (resolveMasterKeyIfAvailable) - the
    // bound is about never calling the WRITING/THROWING recovery path,
    // not about never touching a master key at all. Pin the read-only
    // journal-presence check exists instead.
    expect(source).toContain("checkInterruptedExitImport");
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
    // openExitContext's own recovery call fires on ANY subcommand, using
    // the same planted-journal setup as the other cases in this file).
    const importId = "planted-openctx-recovery-import";
    const journalRecord = {
      import_id: importId,
      identity_id: targetIdentityManager.getPrimaryIdentityId() ?? "unknown",
      started_at: new Date().toISOString(),
      snapshots: [],
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
