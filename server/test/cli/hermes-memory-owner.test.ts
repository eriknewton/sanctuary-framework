/**
 * The Hermes owner verbs (memory-report, memory-show, memory-delete) run
 * in-process against temporary fortresses: refusals, the report's derived
 * fields and window integrity, the no-write reader, show's ordering and
 * escaping, and every arm of the delete continuing-path table.
 */
import { Server } from "node:net";
import { chmod, mkdir, mkdtemp, open, readdir, readFile, realpath, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { dirname, join, sep } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import * as custodyCredentialModule from "../../src/wrap/custody-credential.js";
import * as custodyModule from "../../src/core/master-custody.js";
import * as lockModule from "../../src/storage/cross-process-lock.js";
import {
  DELETE_PREVIEW_CHARS, HERMES_MEMORY_HELP, HERMES_MEMORY_OWNER_DELETE_OPERATION, createOwnerAuditReader,
  escapeForTerminal, framePassage, hermesKitFolder, hermesPackageRootFromEntry, runHermesMemory, truncateCodePoints,
  type OwnerDeleteOutcome,
} from "../../src/cli/hermes-memory.js";
import { CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME, unlockExistingMasterReadOnly } from "../../src/core/master-custody.js";
import { CUSTODY_RELEASE_FAILURE_MESSAGE } from "../../src/cli/custody-release-message.js";
import { MEMORY_CORPUS_SCAN_CAP } from "../../src/hermes-memory-bridge/index.js";
import { IdentityManager } from "../../src/cognitive/tools.js";
import { AuditLog, deriveAuditStoreSplitBoundaryMacKey, writeAuditStoreSplitBoundary } from "../../src/operational/audit-log.js";
import { KnownSignersStore } from "../../src/reputation/known-signers-store.js";
import {
  DEFAULT_MAX_CHUNK_CHARS, HERMES_INSERT_INTENT_KEY, HERMES_INSERT_INTENT_NAMESPACE, HERMES_SAVE_MAX_CHUNKS,
  MEMORY_BATCH_LOCK_NAMESPACE, SdwMemoryBackendAdapter, sdwMemoryCorpusBatchLockFile,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { CrossProcessLockError } from "../../src/storage/cross-process-lock.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { ReadOnlyStorageGuard } from "../../src/storage/read-only-guard.js";
import { AUDIT_SIGNING_HEAD_KEY, AUDIT_SIGNING_LATCH_V2_KEY, CHECKPOINT_NAMESPACE } from "../helpers/signing-fixture.js";
import {
  FIXTURE_AGENT_ID, FIXTURE_PACKAGE_VERSION, FIXTURE_PASSPHRASE, TerminalInput, TerminalSink, admittedRow, auditEntries, ownerFortress,
  fixturePackage, runCleanups, runVerb, seedBridgeRows, seedPassage, treeHashes, withSeedSession, type Cleanup, type OwnerFortress,
} from "../helpers/hermes-owner-fortress.js";

const stack: Cleanup[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await runCleanups(stack);
});

const CLOSING = "The Hermes memory relay is still stopped. Start it with: launchctl kickstart";
const CLOSING_INCOMPLETE = "The Hermes memory relay is still stopped. The record on this computer does not cover the full history. Leave it stopped until the coordinator has read a memory-report.";
const CLOSING_KEEP_STOPPED = "The Hermes memory relay is still stopped. Leave it stopped until the coordinator has read the memory-report.";
// A run that stops before reading the audit log cannot rule out an earlier unconfirmed delete.
const CLOSING_BEFORE_AUDIT_READ = "The Hermes memory relay is still stopped. The audit record could not be checked. Leave it stopped until the coordinator has read a memory-report.";
const CLOSING_AFTER_UNCONFIRMED = "The Hermes memory relay is still stopped. An earlier memory-delete was not confirmed, so leave it stopped until the coordinator has read";
const BARRIER_REFUSAL_START = "Stop the Hermes memory relay first";
const VERBS = ["memory-report", "memory-show", "memory-delete"] as const;
const verbArgs = (verb: typeof VERBS[number]): string[] =>
  verb === "memory-report" ? [verb] : verb === "memory-show" ? [verb, "--recent", "1"] : [verb, "--passage", "p1"];

function lastLine(text: string): string {
  return text.trimEnd().split("\n").at(-1) ?? "";
}

function report(run: { out: string }): Record<string, any> {
  return JSON.parse(run.out) as Record<string, any>;
}

function rowFor(parsed: Record<string, any>, entryId: string): Record<string, any> {
  const row = (parsed.rows as Record<string, any>[]).find(candidate => candidate.entryId === entryId && candidate.kind === "insert_admitted");
  if (row === undefined) throw new Error(`no admitted row ${entryId}`);
  return row;
}

async function corpusAndAudit(f: OwnerFortress) {
  return {
    corpus: await treeHashes(corpusDir(f)),
    audit: await treeHashes(f.storage.namespacePath("_audit")),
    checkpoints: await treeHashes(f.storage.namespacePath(CHECKPOINT_NAMESPACE)),
  };
}

const corpusDir = (f: OwnerFortress) => join(f.fortress, "state", SDW_DOCUMENT_CORPUS_NAMESPACE);

/** Replace one corpus record's ciphertext so it no longer decrypts or verifies. */
async function damageCorpusRecord(f: OwnerFortress, prefix: string, passageId: string): Promise<void> {
  const key = `${prefix}mem.${FIXTURE_AGENT_ID}.${passageId}`;
  const keys = (await f.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).map(entry => entry.key);
  const target = keys.find(candidate => candidate === key || candidate.startsWith(key + "."));
  if (target === undefined) throw new Error(`no corpus record ${key}`);
  await writeFile(join(corpusDir(f), `${target}.enc`), "unreadable fixture");
}

/** Let the standard adapter decide and persist a real quarantine for a damaged provenance companion. */
async function quarantine(f: OwnerFortress, passageId: string): Promise<void> {
  await damageCorpusRecord(f, "prov.", passageId);
  await withSeedSession(f, async ({ adapter }) => {
    await expect(adapter.getPassage(passageId)).rejects.toThrow();
  });
  const keys = (await f.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).map(entry => entry.key);
  expect(keys).toContain(`prov-status.mem.${FIXTURE_AGENT_ID}.${passageId}`);
}

/** Make the real exclusive lease's listener close reject, after the kernel has closed it. */
async function withReleaseFailure<T>(run: () => Promise<T>): Promise<T> {
  const failure = new CrossProcessLockError("custody lock listener close failed", "io");
  const close = Server.prototype.close;
  const barrier = lockModule.withExclusiveMasterRotationBarrier;
  let socketPath: string | undefined;
  const captured = new Set<Server>();
  vi.spyOn(lockModule, "withExclusiveMasterRotationBarrier").mockImplementation((storage, namespace, name, operation, options) =>
    barrier(storage, namespace, name, operation, { ...options, __testAfterExclusiveSocketAcquired: path => { socketPath = path; } }));
  vi.spyOn(Server.prototype, "close").mockImplementation(function(this: Server, callback) {
    if (socketPath === undefined || this.address() !== socketPath) return close.call(this, callback);
    captured.add(this);
    return close.call(this, error => { callback?.(error ?? failure); });
  });
  try {
    const result = await run();
    expect(captured.size).toBe(1); // The verb owns exactly one exclusive custody listener.
    return result;
  } finally {
    vi.mocked(Server.prototype.close).mockRestore();
    for (const lease of captured) {
      await new Promise<void>(resolve => close.call(lease, () => resolve()));
    }
  }
}

describe("hermes owner verbs: refusals", () => {
  it.each(VERBS)("%s refuses root before touching the fortress, and the closing line is last", async verb => {
    const f = await ownerFortress(stack);
    const before = await treeHashes(f.fortress);
    const resolve = vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential");
    const run = await runVerb(f, verbArgs(verb), { uid: 0 });
    expect(run.code).toBe(1);
    expect(run.err).toContain("not root");
    expect(lastLine(run.err).startsWith(CLOSING_BEFORE_AUDIT_READ)).toBe(true);
    expect(run.err).not.toContain("launchctl kickstart");
    expect(resolve).not.toHaveBeenCalled();
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it.each(["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"])("refuses an SSH session (%s) before custody", async variable => {
    const f = await ownerFortress(stack);
    const resolve = vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential");
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { env: { HOME: f.home, [variable]: "203.0.113.5 22" } });
      expect(run.code).toBe(1);
      expect(run.err).toContain("not over SSH");
    }
    expect(resolve).not.toHaveBeenCalled();
  });

  it("refuses a fortress not owned by the calling account", async () => {
    const f = await ownerFortress(stack);
    const before = await treeHashes(f.fortress);
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { uid: process.getuid!() + 1 });
      expect(run.code).toBe(1);
      expect(run.err).toContain("not owned by this account");
    }
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it("refuses a malformed --agent-id with a usage error before any fortress access", async () => {
    const f = await ownerFortress(stack);
    for (const bad of ["Agent", "-agent", "agent_owner", "a".repeat(64)]) {
      // A leading hyphen is only accepted in the --flag=value form; it must still fail the grammar there.
      const err = new TerminalSink();
      const code = await runHermesMemory({ argv: ["memory-report", "--fortress", f.fortress, `--agent-id=${bad}`],
        env: { HOME: f.home }, uid: process.getuid!(), ...fixturePackage(f), stderr: err, stdout: new TerminalSink() });
      expect(code).toBe(2);
      expect(err.text).toContain("--agent-id must be");
    }
  });

  it.each([...VERBS, "memory-unknown"])("a usage error from %s still ends with the closing line", async verb => {
    const f = await ownerFortress(stack);
    const err = new TerminalSink();
    const code = await runHermesMemory({ argv: [verb, "--fortress", f.fortress], env: { HOME: f.home }, uid: process.getuid!(),
      ...fixturePackage(f), stderr: err, stdout: new TerminalSink(), stdin: new TerminalInput() });
    expect(code).toBe(2);
    expect(err.text).toMatch(verb === "memory-unknown" ? /Usage:/u : /--agent-id is required/u);
    expect(lastLine(err.text).startsWith(CLOSING_BEFORE_AUDIT_READ)).toBe(true);
  });

  it.each(["memory-show", "memory-delete"] as const)("%s refuses without a terminal on stdin or stdout", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "terminal guard passage");
    const resolve = vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential");
    for (const [inTty, outTty] of [[false, true], [true, false], [false, false]]) {
      const stdin = new TerminalInput();
      stdin.isTTY = inTty;
      const stdout = new TerminalSink();
      stdout.isTTY = outTty;
      const run = await runVerb(f, verbArgs(verb), { stdin, stdout });
      expect(run.code).toBe(1);
      expect(run.err).toContain("needs a terminal");
      expect(run.out).not.toContain("terminal guard passage");
    }
    expect(resolve).not.toHaveBeenCalled();
  });

  it.each(VERBS)("%s refuses at once while a live shared custody lease is held", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "held lease passage");
    const before = await treeHashes(f.fortress);
    const lease = await lockModule.acquireMasterWriteBarrier(f.storage, CUSTODY_WRITE_LOCK_NAMESPACE, MASTER_ROTATION_BARRIER_NAME);
    try {
      const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
      const run = await runVerb(f, verbArgs(verb), { answer: "DELETE\n" });
      expect(run.code).toBe(1);
      expect(run.err).toContain(BARRIER_REFUSAL_START);
      expect(unlock).not.toHaveBeenCalled();
      lease.assertHeld();
    } finally { await lease.release(); }
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it.each(VERBS)("%s asks the exclusive barrier for kernel admission with zero wait", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "admission passage");
    const spy = vi.spyOn(lockModule, "withExclusiveMasterRotationBarrier");
    await runVerb(f, verbArgs(verb), { answer: "no\n" });
    expect(spy).toHaveBeenCalledOnce();
    expect(spy.mock.calls[0]![4]).toMatchObject({ timeoutMs: 0, requireKernelAdmission: true });
  });

  it.each(VERBS)("%s refuses a mistyped fortress whose state/_meta is missing and creates nothing", async verb => {
    const f = await ownerFortress(stack);
    const typo = join(f.home, "Library", "Application Support", "Sanctuary", "Fortresses", "fortress-typo");
    await mkdir(typo, { mode: 0o700 });
    const before = await treeHashes(typo);
    const barrier = vi.spyOn(lockModule, "withExclusiveMasterRotationBarrier");
    const err = new TerminalSink();
    const code = await runHermesMemory({ argv: [...verbArgs(verb).slice(0, 1), "--fortress", typo, "--agent-id", FIXTURE_AGENT_ID,
      ...verbArgs(verb).slice(1)], env: { HOME: f.home }, uid: process.getuid!(), ...fixturePackage(f), stdout: new TerminalSink(), stderr: err,
    stdin: new TerminalInput() });
    expect(code).toBe(1);
    expect(err.text).toContain("not an existing Sanctuary fortress");
    expect(barrier).not.toHaveBeenCalled();
    expect(await treeHashes(typo)).toEqual(before);
  });

  it("refuses every verb on an unfinished exit import before custody, with nothing changed", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "import guard passage");
    await withSeedSession(f, async () => { await f.storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-import", Buffer.from("{}\n")); });
    const before = await treeHashes(f.fortress);
    const resolve = vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential");
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { answer: "DELETE\n" });
      expect(run.code).toBe(1);
      expect(run.err).toContain("exit import did not finish");
      expect(run.out).not.toContain("import guard passage");
    }
    expect(resolve).not.toHaveBeenCalled();
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it("refuses a --since without an explicit offset", async () => {
    const f = await ownerFortress(stack);
    for (const since of ["2026-11-16T09:00:00", "2026-11-16", "yesterday"]) {
      const err = new TerminalSink();
      expect(await runHermesMemory({ argv: ["memory-report", "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, "--since", since],
        env: { HOME: f.home }, uid: process.getuid!(), ...fixturePackage(f), stderr: err, stdout: new TerminalSink() })).toBe(2);
      expect(err.text).toContain("--since must be an ISO time");
    }
  });

  it.each([
    { kind: "virgin" as const, expected: "no custody to open" },
    { kind: "fail-closed" as const, expected: "could not be opened from this Mac's keychain" },
  ])("refuses $kind custody before any unlock", async ({ kind, expected }) => {
    const f = await ownerFortress(stack);
    const before = await treeHashes(f.fortress);
    vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential").mockResolvedValue(kind === "virgin"
      ? { kind: "virgin" } : { kind: "fail-closed", message: "keychain locked fixture", report: {} as never });
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb));
      expect(run.code).toBe(1);
      expect(run.err).toContain(expected);
    }
    expect(unlock).not.toHaveBeenCalled();
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it.each(VERBS)("%s refuses a recovery key offered beside a host-local credential, before prompting or unlocking", async verb => {
    const f = await ownerFortress(stack);
    // The resolver verifies its candidate by unlocking; the verb's own unlock is what must not run.
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
    const load = vi.spyOn(IdentityManager.prototype, "load");
    const stdin = new TerminalInput();
    const stderr = new TerminalSink();
    const run = await runVerb(f, [...verbArgs(verb), "--recovery-key-prompt"], { stdin, stderr });
    expect(run.code).toBe(1);
    expect(run.err).toContain("already opens this fortress");
    expect(run.err).not.toContain("Recovery key (not shown)");
    expect(stdin.rawMode).toBe(false);
    expect(unlock.mock.calls.some(call => "recoveryKey" in call[1])).toBe(false);
    expect(load).not.toHaveBeenCalled();
  });

  it("refuses a recovery key in the environment and removes it before any unlock", async () => {
    const f = await ownerFortress(stack);
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
    const env: NodeJS.ProcessEnv = { HOME: f.home, SANCTUARY_RECOVERY_KEY: "recovery fixture value" };
    const run = await runVerb(f, ["memory-report"], { env });
    expect(run.code).toBe(1);
    expect(run.err).toContain("never from SANCTUARY_RECOVERY_KEY");
    expect(env.SANCTUARY_RECOVERY_KEY).toBeUndefined();
    expect(unlock).not.toHaveBeenCalled();
  });

  it.each(VERBS)("%s refuses --recovery-key-prompt on a virgin fortress without prompting", async verb => {
    const f = await ownerFortress(stack);
    vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential").mockResolvedValue({ kind: "virgin" });
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
    const run = await runVerb(f, [...verbArgs(verb), "--recovery-key-prompt"]);
    expect(run.code).toBe(1);
    expect(run.err).toContain("no custody to open");
    expect(run.err).not.toContain("Recovery key (not shown)");
    expect(unlock).not.toHaveBeenCalled();
  });

  it("break-glass recovery-key prompt that is left unanswered times out with nothing changed", async () => {
    const f = await ownerFortress(stack);
    const before = await treeHashes(f.fortress);
    vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential")
      .mockResolvedValue({ kind: "fail-closed", message: "keychain locked fixture", report: {} as never });
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly");
    const stdin = new TerminalInput();
    const run = await runVerb(f, ["memory-report", "--recovery-key-prompt"], { stdin, promptTimeoutMs: 50 });
    expect(run.code).toBe(1);
    expect(run.err).toContain("Recovery key (not shown)");
    expect(run.err).toContain("timed out");
    expect(stdin.rawMode).toBe(false);
    expect(unlock).not.toHaveBeenCalled();
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it.each(VERBS)("%s uses a break-glass recovery key typed at the no-echo prompt as the only unlock source", async verb => {
    const f = await ownerFortress(stack);
    vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential")
      .mockResolvedValue({ kind: "fail-closed", message: "keychain locked fixture", report: {} as never });
    const unlock = vi.spyOn(custodyModule, "unlockExistingMasterReadOnly").mockRejectedValue(new Error("wrong recovery key fixture"));
    const stdin = new TerminalInput();
    const stderr = new TerminalSink();
    stderr.on("data", () => { if (stderr.text.includes("Recovery key (not shown)")) setImmediate(() => stdin.write("typed-recovery-key\r")); });
    const run = await runVerb(f, [...verbArgs(verb), "--recovery-key-prompt"], { stdin, stderr });
    expect(run.code).toBe(1);
    expect(unlock).toHaveBeenCalledOnce();
    expect(unlock.mock.calls[0]![1]).toEqual({ recoveryKey: "typed-recovery-key", storagePathHint: expect.any(String) });
    expect(run.err).not.toContain("typed-recovery-key");
    expect(stdin.rawMode).toBe(false);
  });

  it.each(["success", "refusal", "unclassified"] as const)("zeroes the host-local keychain key and the master key on every exit (%s)", async exit => {
    const f = await ownerFortress(stack);
    const real = custodyModule.unlockExistingMasterReadOnly;
    const keychainKey = new Uint8Array(32).fill(7);
    let master: Uint8Array | undefined;
    vi.spyOn(custodyCredentialModule, "resolveHostLocalBootCredential")
      .mockResolvedValue({ kind: "keychain-key", key: keychainKey, provenance: {} as never });
    vi.spyOn(custodyModule, "unlockExistingMasterReadOnly").mockImplementation(async (storage, options) => {
      expect(options.keychainKey).toBe(keychainKey);
      master = await real(storage, { passphrase: FIXTURE_PASSPHRASE });
      return master;
    });
    // A refusal after unlock (unreadable identity) and an unexpected throw after unlock (known signers) are the other exit classes.
    if (exit === "refusal") vi.spyOn(IdentityManager.prototype, "load").mockResolvedValue({ loaded: 0, failed: 1 } as never);
    if (exit === "unclassified") vi.spyOn(KnownSignersStore.prototype, "loadAll").mockRejectedValue(new Error("known signers fixture"));
    const run = await runVerb(f, ["memory-report"]);
    expect(run.code, run.err).toBe(exit === "success" ? 0 : 1);
    if (exit === "refusal") expect(run.err).toContain("identity could not be read");
    if (exit === "unclassified") expect(run.err).toContain("could not finish");
    expect(master).toBeDefined();
    expect(keychainKey.every(byte => byte === 0)).toBe(true);
    expect(master!.every(byte => byte === 0)).toBe(true);
  });

  it("refuses the report when the window's admitted rows belong to a different --agent-id", async () => {
    const f = await ownerFortress(stack);
    await seedBridgeRows(f, [admittedRow("p1", "other agent text", "e1", "agent-other")]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code).toBe(1);
    expect(run.err).toContain("different agent id");
    expect(run.out).toBe("");
  });

  it.each(["agent_id", "document_id"] as const)("refuses the report on a scope mismatch in %s", async field => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "scope passage");
    const row = admittedRow("p1", "scope passage", "e1");
    await seedBridgeRows(f, [{ ...row, [field]: field === "agent_id" ? FIXTURE_AGENT_ID : "mem.agent-owner.p2" }]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code).toBe(1);
    expect(run.err).toMatch(/different agent id|does not match the --agent-id owner scope/u);
    expect(lastLine(run.err)).toContain(CLOSING);
    expect(run.out).toBe("");
  });

  it("states when a window has no admitted rows and makes no absence claim", async () => {
    const f = await ownerFortress(stack);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.admitted_rows).toBe(0);
    expect(parsed.window.absence_claims_supported).toBe(false);
    expect(parsed.window.note).toContain("No insert_admitted rows");
  });

  it.each(VERBS)("%s keeps its finished output when the barrier release fails, and exits nonzero", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "release failure passage");
    await seedBridgeRows(f, [admittedRow("p1", "release failure passage", "e1")]);
    const run = await withReleaseFailure(() => runVerb(f, verb === "memory-report" ? [verb, "--since", f.since] : verbArgs(verb),
      { answer: "DELETE\n" }));
    expect(run.code).toBe(1);
    expect(run.err).toContain(CUSTODY_RELEASE_FAILURE_MESSAGE);
    expect(lastLine(run.err)).toContain(CLOSING);
    if (verb === "memory-report") expect(report(run).admitted_rows).toBe(1);
    if (verb === "memory-show") expect(run.out).toContain("release failure passage");
    if (verb === "memory-delete") {
      expect(run.out).toContain("deleted\n");
      const outcomes = (await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION)).map(entry => entry.details?.outcome);
      expect(outcomes).toEqual(["intent", "deleted"]);
    }
  });
});

describe("hermes owner verbs: memory-report", () => {
  it("derives present, digest, later failure and resave for each admitted-row case", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "committed", "committed text", { tags: ["turn-capture"] });
    await seedPassage(f, "unconfirmed", "unconfirmed text");
    await seedPassage(f, "quarantined", "quarantined text");
    await seedPassage(f, "resaved", "resaved text, second save");
    await quarantine(f, "quarantined");
    await seedBridgeRows(f, [
      admittedRow("committed", "committed text", "e-committed"),
      admittedRow("unconfirmed", "unconfirmed text", "e-unconfirmed"),
      { kind: "insert_unconfirmed", entryId: "e-unconfirmed", passage_id: "unconfirmed", agent_id: "agent:agent-owner", requester_verified: false },
      admittedRow("crashed", "crashed before commit", "e-crashed"),
      admittedRow("quarantined", "quarantined text", "e-quarantined"),
      admittedRow("resaved", "resaved text, first save", "e-resaved-1"),
      admittedRow("resaved", "resaved text, second save", "e-resaved-2"),
    ]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window).toMatchObject({ chain_verified: true, fully_retained: true, ever_pruned: false, absence_claims_supported: true });
    expect(rowFor(parsed, "e-committed")).toMatchObject({ present: "present", digest_matches: true, later_failure: false,
      resaved: false, tags: ["turn-capture"] });
    expect(rowFor(parsed, "e-unconfirmed")).toMatchObject({ present: "present", later_failure: true });
    expect(rowFor(parsed, "e-crashed")).toMatchObject({ present: "absent", digest_matches: null, tags: null, later_failure: false });
    expect(rowFor(parsed, "e-quarantined")).toMatchObject({ present: "indeterminate", digest_matches: null });
    expect(rowFor(parsed, "e-resaved-1")).toMatchObject({ resaved: true, present: "present", digest_matches: false });
    expect(rowFor(parsed, "e-resaved-2")).toMatchObject({ resaved: false, present: "present", digest_matches: true });
    expect(parsed.owner_scope_passage_count).toBe(4);
    expect(parsed.provenance).toMatchObject({ fortress_id: f.fortressId, agent_id: FIXTURE_AGENT_ID, signed: false,
      package_version: FIXTURE_PACKAGE_VERSION, chain_head_sequence: expect.any(Number) });
  });

  it.each(["insert_refused", "insert_unconfirmed"] as const)("correlates %s with its admitted passage across runs", async kind => {
    const f = await ownerFortress(stack);
    const entryId = "hermes-entry-1";
    await seedPassage(f, "earlier", "earlier passage");
    await seedPassage(f, "later", "later passage");
    await seedBridgeRows(f, [
      admittedRow("earlier", "earlier passage", entryId),
      admittedRow("later", "later passage", entryId),
      { kind, entryId, passage_id: "later" },
    ]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === "insert_admitted")).toMatchObject([
      { passage_id: "earlier", present: "present", digest_matches: true, later_failure: false },
      { passage_id: "later", later_failure: true },
    ]);
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it.each(["insert_refused", "insert_unconfirmed"] as const)("bounds %s correlation at the next admission of its entry id", async kind => {
    const f = await ownerFortress(stack);
    const entryId = "hermes-entry-1";
    await seedPassage(f, "shared", "shared passage");
    await seedBridgeRows(f, [
      admittedRow("shared", "shared passage", entryId),
      admittedRow("shared", "shared passage", entryId),
      { kind, entryId, passage_id: "shared" },
    ]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === "insert_admitted")).toMatchObject([
      { passage_id: "shared", later_failure: false, resaved: true },
      { passage_id: "shared", later_failure: true, resaved: false },
    ]);
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it.each(["insert_refused", "insert_unconfirmed"] as const)("retains unmatched %s rows without assigning them to another passage", async kind => {
    const f = await ownerFortress(stack);
    const entryId = "hermes-entry-1";
    await seedPassage(f, "saved", "saved passage");
    const terminals = [{ kind, entryId, passage_id: "other" }, { kind, entryId }];
    await seedBridgeRows(f, [admittedRow("saved", "saved passage", entryId), ...terminals]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(rowFor(parsed, entryId)).toMatchObject({ passage_id: "saved", later_failure: "indeterminate" });
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === kind)).toMatchObject(terminals);
    for (const row of parsed.rows.filter((row: Record<string, any>) => row.kind === kind)) {
      expect(row).not.toHaveProperty("later_failure");
    }
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it.each(["insert_refused", "insert_unconfirmed"] as const)("keeps %s correlation indeterminate for incomplete admission identities", async kind => {
    const f = await ownerFortress(stack);
    const entryId = "hermes-entry-1";
    const passageId = "undefined";
    const text = "identity passage";
    await seedPassage(f, passageId, text);
    const complete = admittedRow(passageId, text, entryId);
    const admissions = [
      { ...complete, entryId: undefined },
      { ...complete, passage_id: undefined },
      { ...complete, entryId: undefined, passage_id: undefined },
      complete,
    ];
    const terminal = { kind, entryId: "hermes-entry-other", passage_id: "other" };
    await seedBridgeRows(f, [...admissions, terminal]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === "insert_admitted")).toMatchObject([
      { later_failure: "indeterminate" },
      { later_failure: "indeterminate" },
      { later_failure: "indeterminate" },
      { later_failure: false },
    ]);
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === kind)).toMatchObject([terminal]);
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it.each(["insert_refused", "insert_unconfirmed"] as const)("keeps correlation indeterminate when an %s row carries no entry id", async kind => {
    const f = await ownerFortress(stack);
    const entryId = "hermes-entry-1";
    const passageId = "saved";
    const text = "identity passage";
    await seedPassage(f, passageId, text);
    const terminal = { kind, passage_id: "other" };
    await seedBridgeRows(f, [admittedRow(passageId, text, entryId), terminal]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.absence_claims_supported).toBe(true);
    expect(rowFor(parsed, entryId)).toMatchObject({ passage_id: passageId, later_failure: "indeterminate" });
    expect(parsed.rows.filter((row: Record<string, any>) => row.kind === kind)).toMatchObject([terminal]);
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it("marks every earlier admitted row as a later failure after a latch row", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "before", "before latch");
    await seedPassage(f, "after", "after latch");
    await seedBridgeRows(f, [admittedRow("before", "before latch", "e1"), admittedRow("before", "before latch", "e1"),
      { kind: "latch", reason: "indeterminate" },
      admittedRow("after", "after latch", "e2")]);
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(rowFor(parsed, "e1").later_failure).toBe(true);
    expect(rowFor(parsed, "e2").later_failure).toBe(false);
  });

  it("reads a deleted then resaved passage id as resaved, and the delete as an outcome", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "first words");
    await seedBridgeRows(f, [admittedRow("p1", "first words", "e1")]);
    expect((await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" })).code).toBe(0);
    await seedPassage(f, "p1", "second words");
    await seedBridgeRows(f, [admittedRow("p1", "second words", "e2")]);
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(rowFor(parsed, "e1")).toMatchObject({ resaved: true, digest_matches: false });
    expect(rowFor(parsed, "e2")).toMatchObject({ resaved: false, present: "present", digest_matches: true });
    expect(parsed.owner_deletes).toEqual([{ passage_id: "p1", document_id: "mem.agent-owner.p1",
      attempts: [{ intent_at: expect.any(String), outcome: "deleted", outcome_at: expect.any(String) }] }]);
  });

  it("makes every absence indeterminate when the window is not fully retained", async () => {
    const f = await ownerFortress(stack);
    await seedBridgeRows(f, [admittedRow("crashed", "never committed", "e1")]);
    const parsed = report(await runVerb(f, ["memory-report", "--since", "2000-01-01T00:00:00Z"]));
    expect(parsed.window).toMatchObject({ fully_retained: false, absence_claims_supported: false });
    expect(rowFor(parsed, "e1")).toMatchObject({ present: "indeterminate", later_failure: "indeterminate", resaved: "indeterminate" });
    // Positive control: the same fortress with a fully retained window reads the passage as absent.
    const control = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(rowFor(control, "e1")).toMatchObject({ present: "absent", later_failure: false, resaved: false });
  });

  it("makes every absence indeterminate when pruning is unknown", async () => {
    const f = await ownerFortress(stack);
    await seedBridgeRows(f, [admittedRow("crashed", "never committed", "e1")]);
    vi.spyOn(AuditLog.prototype, "getRetentionUsage").mockResolvedValue({ entryCount: 1, totalSizeBytes: 1, everPruned: null });
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.window).toMatchObject({ ever_pruned: null, absence_claims_supported: false });
    expect(rowFor(parsed, "e1").present).toBe("indeterminate");
  });

  it("makes every absence indeterminate on an unverified chain", async () => {
    const f = await ownerFortress(stack);
    await seedBridgeRows(f, [admittedRow("crashed", "never committed", "e1"), { kind: "memory_recall", passage_ids: [] }]);
    await withSeedSession(f, async () => {
      const keys = (await f.storage.list("_audit")).map(entry => entry.key).filter(key => key.startsWith("entry-")).sort();
      // Damage the last entry: the chain no longer verifies, while the admitted row still decrypts.
      await f.storage.write("_audit", keys.at(-1)!, Buffer.from("tampered audit entry fixture"));
    });
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    const parsed = report(run);
    expect(parsed.window.chain_verified).toBe(false);
    expect(parsed.window.absence_claims_supported).toBe(false);
    expect(rowFor(parsed, "e1").present).toBe("indeterminate");
  });

  it("never outputs passage text, query text or any digest other than the bridge's text digest", async () => {
    const f = await ownerFortress(stack);
    const token = "zebra-quartz-71aa3c";
    await seedPassage(f, "p1", `the secret word is ${token}`);
    await seedBridgeRows(f, [admittedRow("p1", `the secret word is ${token}`, "e1"),
      { kind: "memory_recall", term_count: 1, passage_ids: ["p1"], query_sha256: "query-digest-fixture", truncated: false,
        agent_id: "agent:agent-owner", requester_verified: false }]);
    const run = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(run.code, run.err).toBe(0);
    expect(run.out).not.toContain(token);
    expect(run.out).not.toContain("query-digest-fixture");
    expect(run.out).not.toContain("query_sha256");
    expect(report(run).rows.find((row: Record<string, unknown>) => row.kind === "memory_recall"))
      .toMatchObject({ passage_ids: ["p1"], truncated: false });
  });

  it("caps output rows, keeps the newest, and says truncated", async () => {
    const f = await ownerFortress(stack);
    const extra = 3;
    await withSeedSession(f, async ({ audit }) => {
      for (let index = 0; index < MEMORY_CORPUS_SCAN_CAP + extra; index++) {
        void audit.append("l1", "hermes_memory_bridge", "hermes-memory-bridge",
          { kind: "memory_recall", passage_ids: [], truncated: false, reason: String(index) });
      }
      await audit.flush();
    });
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.truncated).toBe(true);
    expect(parsed.truncated_note).toContain("not a witness");
    expect(parsed.rows).toHaveLength(MEMORY_CORPUS_SCAN_CAP);
    // The oldest `extra` rows are the ones dropped; the newest is kept.
    expect(parsed.rows[0].reason).toBe(String(extra));
    expect(parsed.rows.at(-1).reason).toBe(String(MEMORY_CORPUS_SCAN_CAP + extra - 1));
  }, 120_000);

  it("a truncated report never supports an absence claim, and its note names truncation", async () => {
    const f = await ownerFortress(stack);
    await seedBridgeRows(f, [admittedRow("gone-1", "never stored", "e-gone-1")]);
    // Positive control: the untruncated window supports absence, so the crashed save reads absent.
    const control = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(control.truncated).toBe(false);
    expect(control.window.absence_claims_supported).toBe(true);
    expect(rowFor(control, "e-gone-1")).toMatchObject({ present: "absent", later_failure: false });
    await withSeedSession(f, async ({ audit }) => {
      for (let index = 0; index < MEMORY_CORPUS_SCAN_CAP; index++) {
        void audit.append("l1", "hermes_memory_bridge", "hermes-memory-bridge",
          { kind: "memory_recall", passage_ids: [], truncated: false, reason: String(index) });
      }
      await audit.flush();
    });
    await seedBridgeRows(f, [admittedRow("gone-2", "never stored either", "e-gone-2")]);
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.truncated).toBe(true);
    expect(parsed.window.absence_claims_supported).toBe(false);
    expect(parsed.window.note).toContain("truncated");
    expect(rowFor(parsed, "e-gone-2")).toMatchObject({ present: "indeterminate", later_failure: "indeterminate", resaved: "indeterminate" });
  }, 120_000);

  it("flags save recoveries beyond the row cap as truncated", async () => {
    const f = await ownerFortress(stack);
    await withSeedSession(f, async ({ audit }) => {
      for (let index = 0; index <= MEMORY_CORPUS_SCAN_CAP; index++) {
        void audit.append("l3", "hermes_save_recovered", "operator", { outcome: "kept", records_removed: index });
      }
      await audit.flush();
    });
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.save_recoveries).toHaveLength(MEMORY_CORPUS_SCAN_CAP);
    expect(parsed.save_recoveries_truncated).toBe(true);
    expect(parsed.save_recoveries.at(-1).records_removed).toBe(MEMORY_CORPUS_SCAN_CAP);
  }, 120_000);

  it.each([true, false])("removes a partial --out file, or names it when it cannot be removed (removable=%s)", async removable => {
    const f = await ownerFortress(stack);
    const reports = join(f.root, "reports");
    await mkdir(reports, { mode: 0o700 });
    const target = join(reports, "report.json");
    const probe = await open(join(f.root, "probe"), "w");
    const fileHandle = Object.getPrototypeOf(probe) as { sync: () => Promise<void> };
    await probe.close();
    vi.spyOn(fileHandle, "sync").mockImplementation(async () => {
      // The file exists with partial content when the failure arrives; a read-only parent blocks its removal.
      if (!removable) await chmod(reports, 0o500);
      throw new Error("sync fixture");
    });
    const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", target]);
    vi.restoreAllMocks();
    await chmod(reports, 0o700);
    expect(run.code).toBe(1);
    expect(run.err).toContain("could not be written in full");
    expect(lastLine(run.err)).toContain(CLOSING);
    if (removable) {
      expect(run.err).toContain("the partial file was removed");
      expect(await stat(target).then(() => true, () => false)).toBe(false);
    } else {
      expect(run.err).toContain(`a partial file remains at ${JSON.stringify(target)}`);
      expect(await stat(target).then(() => true, () => false)).toBe(true);
    }
    expect(run.err).not.toContain("The command could not finish");
  });

  it("shows a typed --out path with its control and direction characters escaped", async () => {
    const f = await ownerFortress(stack);
    const reports = join(f.root, "reports");
    await mkdir(reports, { mode: 0o700 });
    // An escape sequence, a C1 control and a right-to-left override in the file name the operator typed.
    const target = join(reports, "r\u001b]0;x\u0007\u009b\u202e.json");
    const probe = await open(join(f.root, "probe"), "w");
    const fileHandle = Object.getPrototypeOf(probe) as { sync: () => Promise<void> };
    await probe.close();
    vi.spyOn(fileHandle, "sync").mockImplementation(async () => {
      await chmod(reports, 0o500);
      throw new Error("sync fixture");
    });
    const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", target]);
    vi.restoreAllMocks();
    await chmod(reports, 0o700);
    expect(run.err).toContain("a partial file remains at");
    for (const raw of ["\u001b", "\u0007", "\u009b", "\u202e"]) expect(run.err).not.toContain(raw);
    expect(run.err).toContain("\\u{009B}");
    // Positive control: the same name written successfully is named escaped on stdout too.
    const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(reports, "ok\u202e.json")]);
    expect(ok.code, ok.err).toBe(0);
    expect(ok.out).toContain("Report written to");
    expect(ok.out).not.toContain("\u202e");
  });

  it("a report that was written and synced but did not close says the whole report is on disk", async () => {
    const f = await ownerFortress(stack);
    const reports = join(f.root, "reports");
    await mkdir(reports, { mode: 0o700 });
    const target = join(reports, "report.json");
    const probe = await open(join(f.root, "probe"), "w");
    const fileHandle = Object.getPrototypeOf(probe) as { sync: () => Promise<void> };
    await probe.close();
    const realSync = fileHandle.sync;
    // The report verb writes nothing in the fortress, so the only sync is the report file's own. Its close is
    // an instance field, so the handle that synced gets a close that really closes and then reports failure.
    vi.spyOn(fileHandle, "sync").mockImplementation(async function(this: { close: () => Promise<void> }) {
      await realSync.call(this);
      const realClose = this.close;
      this.close = async () => { await realClose(); throw new Error("close fixture"); };
    });
    const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", target]);
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(run.err).toContain(`the whole report was written and synced to ${JSON.stringify(target)}`);
    expect(run.err).not.toContain("The command could not finish");
    expect(JSON.parse(await readFile(target, "utf8")).report).toBe("sanctuary hermes memory-report");
  });

  it("writes --out as a new 0600 file and refuses every unsafe destination", async () => {
    const f = await ownerFortress(stack);
    const reports = join(f.root, "reports");
    await mkdir(reports, { mode: 0o700 });
    const target = join(reports, "report.json");
    const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", target]);
    expect(ok.code, ok.err).toBe(0);
    expect(lastLine(ok.err)).toContain(CLOSING);
    // One open handle for the mode check and the read, so both observe the same file.
    const written = await open(target, "r");
    try {
      expect((await written.stat()).mode & 0o777).toBe(0o600);
      expect(JSON.parse(await written.readFile("utf8")).report).toBe("sanctuary hermes memory-report");
    } finally {
      await written.close();
    }
    const loose = join(f.root, "loose");
    await mkdir(loose, { mode: 0o755 });
    await chmod(loose, 0o755);
    await symlink(reports, join(f.root, "link"));
    await mkdir(join(f.root, "kit"), { mode: 0o700 });
    const cases: Array<[string, string]> = [
      [target, "already exists"],
      [join(f.root, "link", "new.json"), "symlink"],
      [join(loose, "new.json"), "mode 0700"],
      [join(f.fortress, "new.json"), "inside the fortress"],
      [join(f.root, "kit", "new.json"), "inside the fortress or the kit folder"],
      ["relative.json", "absolute path"],
    ];
    for (const [out, why] of cases) {
      const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", out]);
      expect(run.code, out).toBe(1);
      expect(run.err, out).toContain("--out refused");
      expect(run.err, out).toContain(why);
    }
  });

  it("locates the package root from the entry module in the kit's B/B_RUNTIME/pkg/dist/cli.js layout and in the source tree", async () => {
    const f = await ownerFortress(stack);
    const kit = join(f.root, "B");
    const pkg = join(kit, "B_RUNTIME", "pkg");
    await mkdir(join(pkg, "dist"), { recursive: true, mode: 0o700 });
    await writeFile(join(pkg, "package.json"), JSON.stringify({ name: "@sanctuary-framework/mcp-server", version: "9.9.9-layout" }));
    await writeFile(join(pkg, "dist", "cli.js"), "");
    expect(hermesPackageRootFromEntry(pathToFileURL(join(pkg, "dist", "cli.js")).href)).toBe(pkg);
    expect(hermesKitFolder(pkg)).toBe(kit);
    const serverRoot = dirname(fileURLToPath(new URL("../../package.json", import.meta.url)));
    expect(hermesPackageRootFromEntry(new URL("../../src/cli.ts", import.meta.url).href)).toBe(serverRoot);
  });

  it("refuses --out anywhere in the kit folder above the package root it is given, and allows a folder beside the kit", async () => {
    const f = await ownerFortress(stack);
    const kit = join(f.root, "B");
    const pkg = join(kit, "B_RUNTIME", "pkg");
    await mkdir(join(pkg, "dist"), { recursive: true, mode: 0o700 });
    const inKit = join(kit, "reports");
    const inRuntime = join(kit, "B_RUNTIME", "reports");
    const beside = join(f.root, "hermes-memory-reports");
    for (const folder of [inKit, inRuntime, beside]) await mkdir(folder, { mode: 0o700 });
    await chmod(kit, 0o700);
    for (const folder of [inKit, inRuntime]) {
      const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(folder, "r.json")],
        { packageVersion: "9.9.9-layout", packageRoot: pkg });
      expect(run.code, folder).toBe(1);
      expect(run.err, folder).toContain("inside the fortress or the kit folder");
    }
    // Positive control: the same run with a destination beside the kit writes the report with the exact version.
    const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(beside, "r.json")],
      { packageVersion: "9.9.9-layout", packageRoot: pkg });
    expect(ok.code, ok.err).toBe(0);
    expect(JSON.parse(await readFile(join(beside, "r.json"), "utf8")).provenance.package_version).toBe("9.9.9-layout");
  });

  it("refuses --out in the kit folder when pkg is a symlink, from both the invoked entry and the real package root", async () => {
    const f = await ownerFortress(stack);
    const kit = join(f.root, "B");
    const runtime = join(kit, "B_RUNTIME");
    // The link target sits outside B, so the real path names a second layout that must be refused too.
    const realPkg = join(f.root, "store", "lib", "mcp-server");
    await mkdir(join(realPkg, "dist"), { recursive: true, mode: 0o700 });
    await mkdir(runtime, { recursive: true, mode: 0o700 });
    await symlink(realPkg, join(runtime, "pkg"));
    const inKit = join(kit, "reports");
    const inRealLayout = join(f.root, "store", "reports");
    const beside = join(f.root, "hermes-memory-reports");
    for (const folder of [inKit, inRealLayout, beside]) await mkdir(folder, { mode: 0o700 });
    const layouts = {
      // As Node runs the bundle: the module URL is the real path, while argv[1] is the symlinked path.
      "as node runs it": { packageRoot: realPkg, invokedEntry: join(runtime, "pkg", "dist", "cli.js") },
      // A direct caller that passes the symlinked package root and no invoked entry.
      "symlinked root only": { packageRoot: join(runtime, "pkg"), invokedEntry: undefined },
    };
    for (const [name, layout] of Object.entries(layouts)) {
      for (const folder of [inKit, inRealLayout]) {
        const run = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(folder, `${name}.json`)],
          { packageVersion: "9.9.9-layout", ...layout });
        expect(run.code, `${name} ${folder}`).toBe(1);
        expect(run.err, `${name} ${folder}`).toContain("inside the fortress or the kit folder");
      }
      // Positive control: the same layout still writes a report beside the kit.
      const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(beside, `${name}.json`)],
        { packageVersion: "9.9.9-layout", ...layout });
      expect(ok.code, ok.err).toBe(0);
    }
  });

  it("ignores an invoked entry outside the package layout, such as a bin link, and still writes a report beside the kit", async () => {
    const f = await ownerFortress(stack);
    const kit = join(f.root, "B");
    const runtime = join(kit, "B_RUNTIME");
    const pkg = join(runtime, "pkg");
    await mkdir(join(pkg, "dist"), { recursive: true, mode: 0o700 });
    await writeFile(join(pkg, "dist", "cli.js"), "");
    await mkdir(join(runtime, "bin"), { mode: 0o700 });
    await symlink(join(pkg, "dist", "cli.js"), join(runtime, "bin", "sanctuary"));
    const inKit = join(kit, "reports");
    const beside = join(f.root, "hermes-memory-reports");
    for (const folder of [inKit, beside]) await mkdir(folder, { mode: 0o700 });
    // As Node sets argv[1] when the command runs through a bin link: the link path, not dist/cli.js.
    const entries = {
      "kit bin link": join(runtime, "bin", "sanctuary"),
      "node_modules bin link": join(kit, "node_modules", ".bin", "sanctuary"),
    };
    for (const [name, invokedEntry] of Object.entries(entries)) {
      const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(beside, `${name}.json`)],
        { packageVersion: "9.9.9-layout", packageRoot: pkg, invokedEntry });
      expect(ok.code, `${name}: ${ok.err}`).toBe(0);
      expect(ok.err, name).not.toContain("inside the fortress or the kit folder");
      // Positive control: the kit folder named by the package root is still refused with the same entry.
      const refused = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(inKit, `${name}.json`)],
        { packageVersion: "9.9.9-layout", packageRoot: pkg, invokedEntry });
      expect(refused.code, name).toBe(1);
      expect(refused.err, name).toContain("inside the fortress or the kit folder");
    }
  });

  it("never treats the filesystem root or the owner's home as the kit folder", async () => {
    const f = await ownerFortress(stack);
    const inHome = join(f.home, "hermes-memory-reports");
    const beside = join(f.root, "hermes-memory-reports");
    for (const folder of [inHome, beside]) await mkdir(folder, { mode: 0o700 });
    const layouts = {
      // Two folders above this root is the filesystem root.
      "kit folder would be the filesystem root": { packageRoot: join(sep, "sanctuary-owner-absent", "pkg"), out: join(beside, "root.json") },
      // B_RUNTIME directly in the home folder makes the home folder the kit folder.
      "kit folder would be the home folder": { packageRoot: join(f.home, "B_RUNTIME", "pkg"), out: join(inHome, "home.json") },
    };
    for (const [name, layout] of Object.entries(layouts)) {
      const ok = await runVerb(f, ["memory-report", "--since", f.since, "--out", layout.out],
        { packageVersion: "9.9.9-layout", packageRoot: layout.packageRoot, invokedEntry: join(layout.packageRoot, "dist", "cli.js") });
      expect(ok.code, `${name}: ${ok.err}`).toBe(0);
      expect(JSON.parse(await readFile(layout.out, "utf8")).provenance.package_version, name).toBe("9.9.9-layout");
    }
    // Positive control: the fortress inside the home folder is still refused.
    const inFortress = await runVerb(f, ["memory-report", "--since", f.since, "--out", join(f.fortress, "r.json")],
      { packageVersion: "9.9.9-layout", packageRoot: join(f.home, "B_RUNTIME", "pkg"), invokedEntry: undefined });
    expect(inFortress.code).toBe(1);
  });

  it("lists an intent with no outcome as interrupted and names save recoveries and a leftover lock", async () => {
    const f = await ownerFortress(stack);
    await withSeedSession(f, async ({ audit }) => {
      await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION, identity_id: "operator",
        result: "success", details: { passage_id: "p9", document_id: "mem.agent-owner.p9", text_sha256: null, outcome: "intent" } });
      await audit.appendCritical({ layer: "l3", operation: "hermes_save_recovered", identity_id: "operator",
        result: "success", details: { outcome: "kept", records_removed: 1 } });
    });
    await mkdir(f.storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), { mode: 0o700, recursive: true });
    await writeFile(join(f.storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), sdwMemoryCorpusBatchLockFile()), "");
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.owner_deletes).toEqual([{ passage_id: "p9", document_id: "mem.agent-owner.p9",
      attempts: [{ intent_at: expect.any(String), outcome: "interrupted", outcome_at: null }] }]);
    expect(parsed.save_recoveries).toEqual([{ timestamp: expect.any(String), outcome: "kept", records_removed: 1 }]);
    expect(parsed.save_recoveries_truncated).toBe(false);
    expect(parsed.corpus_batch_lock).toMatchObject({ present: true, next_step: expect.stringContaining("coordinator") });
  });
});

describe("hermes owner verbs: no writes", () => {
  it("builds the owner audit reader read-only, and the module constructs no other reader", async () => {
    const reader = createOwnerAuditReader(new ReadOnlyStorageGuard(new FilesystemStorage("/nonexistent-owner-reader")), new Uint8Array(32));
    expect((reader as unknown as { readOnly: boolean }).readOnly).toBe(true);
    const source = await readFile(fileURLToPath(new URL("../../src/cli/hermes-memory.ts", import.meta.url)), "utf8");
    const constructions = source.match(/new AuditLog\([^)]*\)/gu) ?? [];
    // Exactly one read-only reader and the delete's own writer; no third construction can bypass readOnly.
    expect(constructions).toEqual([
      "new AuditLog(storage, masterKey, { readOnly: true, integrityMode: \"lenient\" })",
      "new AuditLog(context.storage, context.masterKey)",
    ]);
    expect(source.indexOf("new AuditLog(context.storage, context.masterKey)")).toBeGreaterThan(source.indexOf("async function deletePassage("));
  });

  it("report and show take no audit write lock and leave the whole fortress tree byte-identical on a recovery-due chain", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "no write passage");
    await seedPassage(f, "p2", "second no write passage");
    await withSeedSession(f, async ({ masterKey }) => {
      const writer = new AuditLog(f.storage, masterKey, { checkpointInterval: 1 });
      for (const passage of ["p1", "p2"]) {
        await writer.appendCritical({ layer: "l1", operation: "hermes_memory_bridge", identity_id: "hermes-memory-bridge",
          result: "success", details: { ...admittedRow(passage, passage === "p1" ? "no write passage" : "second no write passage", `e-${passage}`) } });
      }
      // Deleting both signing controls arms the load path's recovery batch, which a writable reader would run.
      await f.storage.delete(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_LATCH_V2_KEY);
      await f.storage.delete(CHECKPOINT_NAMESPACE, AUDIT_SIGNING_HEAD_KEY);
    });
    // Fixture sanity: the recovery condition is armed, so the absence of writes below is not vacuous.
    const storage = new ReadOnlyStorageGuard(f.storage);
    const master = await unlockExistingMasterReadOnly(storage, { passphrase: FIXTURE_PASSPHRASE });
    try {
      const findings = await new AuditLog(storage, master, { readOnly: true, integrityMode: "lenient" }).getIntegrityFindings();
      expect(findings.map(finding => finding.kind)).toContain("checkpoint_signing_floor_recovered");
    } finally { master.fill(0); }
    const before = await corpusAndAudit(f);
    // The whole tree, not only the namespaces: raw-filesystem paths (custody resolver, barrier) are covered too.
    const treeBefore = await treeHashes(f.fortress);
    const lockSpy = vi.spyOn(AuditLog.prototype as unknown as { withAuditWriteLock: () => Promise<unknown> }, "withAuditWriteLock");
    const writeSpy = vi.spyOn(FilesystemStorage.prototype, "write");
    const deleteSpy = vi.spyOn(FilesystemStorage.prototype, "delete");
    const reportRun = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(reportRun.code, reportRun.err).toBe(0);
    const showRun = await runVerb(f, ["memory-show", "--recent", "2"]);
    expect(showRun.code, showRun.err).toBe(0);
    const onePassage = await runVerb(f, ["memory-show", "--passage", "p1"]);
    expect(onePassage.code, onePassage.err).toBe(0);
    expect(lockSpy).not.toHaveBeenCalled();
    expect(writeSpy).not.toHaveBeenCalled();
    expect(deleteSpy).not.toHaveBeenCalled();
    expect(await corpusAndAudit(f)).toEqual(before);
    expect(await treeHashes(f.fortress)).toEqual(treeBefore);
    // Positive control: one stray file beside the barrier's own folder changes the tree hash.
    await writeFile(join(f.storage.namespacePath(CUSTODY_WRITE_LOCK_NAMESPACE), "stray-control"), "x");
    expect(await treeHashes(f.fortress)).not.toEqual(treeBefore);
  });

  it("the tree witness sees a retargeted symlink and fails on an unreadable root instead of hashing it as empty", async () => {
    const f = await ownerFortress(stack);
    const root = join(f.root, "witness");
    await mkdir(root, { mode: 0o700 });
    await writeFile(join(root, "one"), "1");
    await writeFile(join(root, "two"), "1");
    await symlink("one", join(root, "link"));
    const before = await treeHashes(root);
    await unlink(join(root, "link"));
    await symlink("two", join(root, "link"));
    expect(await treeHashes(root)).not.toEqual(before);
    // Positive control: an unchanged tree hashes the same, so the difference above is the retarget.
    expect(await treeHashes(root)).toEqual(await treeHashes(root));
    await chmod(root, 0o000);
    try {
      await expect(treeHashes(root)).rejects.toThrow();
    } finally { await chmod(root, 0o700); }
  });

  it("report and show leave a quarantine undecided: no status record is written for damaged provenance", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "damaged provenance passage");
    await seedBridgeRows(f, [admittedRow("p1", "damaged provenance passage", "e1")]);
    await damageCorpusRecord(f, "prov.", "p1");
    const before = await corpusAndAudit(f);
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(rowFor(parsed, "e1").present).toBe("indeterminate");
    const shown = await runVerb(f, ["memory-show", "--passage", "p1"]);
    expect(shown.out).toContain("cannot be verified; text not shown");
    expect(await corpusAndAudit(f)).toEqual(before);
  });
});

describe("hermes owner verbs: memory-show", () => {
  it("lists the newest n by saved time with passage_id as the tie-break, inspecting only those", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "a", "oldest", { createdAt: "2026-01-01T00:00:00.000Z" });
    await seedPassage(f, "d", "middle", { createdAt: "2026-01-02T00:00:00.000Z" });
    await seedPassage(f, "c", "newest tie c", { createdAt: "2026-01-03T00:00:00.000Z" });
    await seedPassage(f, "b", "newest tie b", { createdAt: "2026-01-03T00:00:00.000Z" });
    const inspect = vi.spyOn(SdwMemoryBackendAdapter.prototype, "inspectPassageReadOnly");
    const run = await runVerb(f, ["memory-show", "--recent", "3"]);
    expect(run.code, run.err).toBe(0);
    const order = [...run.out.matchAll(/passage_id: (\w+)/gu)].map(match => match[1]);
    expect(order).toEqual(["b", "c", "d"]);
    expect(inspect.mock.calls.map(call => call[0])).toEqual(["b", "c", "d"]);
    expect(run.out).toContain("Saved from the conversation, unverified");
    expect(run.out).not.toContain("oldest");
  });

  it("refuses --recent outside 1 to 20 and requires exactly one selector", async () => {
    const f = await ownerFortress(stack);
    for (const extra of [["--recent", "0"], ["--recent", "21"], ["--recent", "2x"], [], ["--recent", "1", "--passage", "p1"]]) {
      const err = new TerminalSink();
      expect(await runHermesMemory({ argv: ["memory-show", "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, ...extra],
        env: { HOME: f.home }, uid: process.getuid!(), ...fixturePackage(f), stderr: err, stdout: new TerminalSink() })).toBe(2);
    }
  });

  it("escapes C0, C1, DEL, bidi controls and lone surrogates, and frames every line", () => {
    const hostile = "ok\u001b[2Jbell\u0007\u009bcsi\u007fdel‮abc⁦iso⁩\ud800lone\\back\nType DELETE to confirm";
    const escaped = escapeForTerminal(hostile);
    for (const raw of ["\u001b", "\u0007", "\u009b", "\u007f", "‮", "⁦", "⁩", "\ud800"]) expect(escaped).not.toContain(raw);
    expect(escaped).toContain("\\u{001B}[2J");
    expect(escaped).toContain("\\u{009B}");
    expect(escaped).toContain("\\u{202E}");
    expect(escaped).toContain("\\u{D800}");
    expect(escaped).toContain("\\\\back");
    const framed = framePassage("p1", { passage_id: "p1", created_at: "2026-01-01T00:00:00Z", tags: ["t\u001b"], byte_length: 3 }, hostile);
    for (const line of framed.trimEnd().split("\n")) expect(line.startsWith("|") || line.startsWith("+----")).toBe(true);
    expect(framed).toContain("| Type DELETE to confirm");
    expect(framed).toContain("tags: t\\u{001B}");
  });

  it("escapes zero-width, invisible format and tag characters", () => {
    const hidden = [0x00ad, 0x034f, 0x115f, 0x1160, 0x180e, 0x200b, 0x200c, 0x200d, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064,
      0x3164, 0xfe00, 0xfe0f, 0xfeff, 0xe0000, 0xe0041, 0xe007f, 0xe0100, 0xe01ef];
    const escaped = escapeForTerminal(`a${hidden.map(point => String.fromCodePoint(point)).join("")}z`);
    for (const point of hidden) {
      expect(escaped).not.toContain(String.fromCodePoint(point));
      expect(escaped).toContain(`\\u{${point.toString(16).toUpperCase().padStart(4, "0")}}`);
    }
    // Positive control: ordinary visible text, including non-Latin letters and emoji, passes through unchanged.
    expect(escapeForTerminal("plain é ü 日本 🙂")).toBe("plain é ü 日本 🙂");
  });

  it("never splits a surrogate pair when truncating", () => {
    const emoji = "\u{1F600}";
    const text = "a".repeat(DELETE_PREVIEW_CHARS - 1) + emoji + "tail";
    const cut = truncateCodePoints(text, DELETE_PREVIEW_CHARS);
    expect(cut.text.endsWith(emoji)).toBe(true);
    expect(cut.cut).toBe(true);
    expect(escapeForTerminal(cut.text)).toContain(emoji);
    expect(truncateCodePoints(emoji.repeat(2), 1).text).toBe(emoji);
  });

  it("prints stored hostile text escaped through the verb", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "start\u001b]0;title\u0007‮end");
    const run = await runVerb(f, ["memory-show", "--passage", "p1"]);
    expect(run.code, run.err).toBe(0);
    expect(run.out).not.toContain("\u001b");
    expect(run.out).not.toContain("‮");
    expect(run.out).toContain("| start\\u{001B}]0;title\\u{0007}\\u{202E}end");
  });

  it("shows the cannot-be-verified line, never the text, for a quarantined passage", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "quarantined words stay hidden", { tags: ["kept-tag"] });
    await quarantine(f, "p1");
    const run = await runVerb(f, ["memory-show", "--passage", "p1"]);
    expect(run.code, run.err).toBe(0);
    expect(run.out).toContain("cannot be verified; text not shown");
    expect(run.out).toContain("tags: kept-tag");
    expect(run.out).not.toContain("quarantined words");
  });
});

describe("hermes owner verbs: memory-delete", () => {
  async function deleteFixture(text = "delete me please") {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", text);
    await seedPassage(f, "keep", "an unrelated passage");
    return f;
  }
  const outcomes = async (f: OwnerFortress) =>
    (await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION)).map(entry => entry.details);
  const docPresent = async (f: OwnerFortress, passage = "p1") =>
    (await f.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${FIXTURE_AGENT_ID}.${passage}`)) !== null;

  it("deletes after DELETE: intent row, then the deleted row, then success; other passages stay", async () => {
    const f = await deleteFixture();
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code, run.err).toBe(0);
    expect(run.out).toContain("| delete me please");
    expect(run.out.trimEnd().endsWith("deleted")).toBe(true);
    expect(lastLine(run.err).startsWith(CLOSING)).toBe(true);
    expect(await docPresent(f)).toBe(false);
    expect(await docPresent(f, "keep")).toBe(true);
    const rows = await outcomes(f);
    expect(rows).toEqual([
      expect.objectContaining({ passage_id: "p1", document_id: "mem.agent-owner.p1", outcome: "intent", text_sha256: expect.any(String) }),
      expect.objectContaining({ passage_id: "p1", outcome: "deleted" }),
    ]);
    const entries = await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION);
    expect(entries.every(entry => entry.layer === "l3" && entry.identity_id === "operator")).toBe(true);
  });

  it.each(["delete", "DELETE now", "", "Delete"])("a wrong confirmation (%j) deletes nothing and writes no row", async answer => {
    const f = await deleteFixture();
    const before = await treeHashes(f.fortress);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: `${answer}\n` });
    expect(run.code).toBe(1);
    expect(run.err).toContain("did not match");
    expect(lastLine(run.err)).toContain(CLOSING);
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it("an unanswered confirmation times out and deletes nothing", async () => {
    const f = await deleteFixture();
    const before = await treeHashes(f.fortress);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { promptTimeoutMs: 50 });
    expect(run.code).toBe(1);
    expect(run.err).toContain("No answer within the time limit");
    expect(lastLine(run.err)).toContain(CLOSING);
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it("deletes a quarantined passage, found by its raw record, with the cannot-be-verified preview", async () => {
    const f = await deleteFixture();
    await quarantine(f, "p1");
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code, run.err).toBe(0);
    expect(run.out).toContain("cannot be verified; text not shown");
    expect(run.out).not.toContain("delete me please");
    expect(await docPresent(f)).toBe(false);
    expect((await outcomes(f))[0]).toMatchObject({ outcome: "intent", text_sha256: null });
  });

  it("shows only the first 80 characters in the preview", async () => {
    const f = await deleteFixture("x".repeat(DELETE_PREVIEW_CHARS) + "HIDDEN-TAIL");
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "no\n" });
    expect(run.out).toContain("x".repeat(DELETE_PREVIEW_CHARS));
    expect(run.out).not.toContain("HIDDEN-TAIL");
    expect(run.out).toContain("[preview ends here]");
  });

  it("refuses an invalid passage id and a missing record, naming the problem", async () => {
    const f = await deleteFixture();
    const err = new TerminalSink();
    expect(await runHermesMemory({ argv: ["memory-delete", "--fortress", f.fortress, "--agent-id", FIXTURE_AGENT_ID, "--passage", "Bad Id"],
      env: { HOME: f.home }, uid: process.getuid!(), ...fixturePackage(f), stderr: err, stdout: new TerminalSink(), stdin: new TerminalInput() })).toBe(2);
    expect(err.text).toContain("not a valid passage id");
    const missing = await runVerb(f, ["memory-delete", "--passage", "nope"], { answer: "DELETE\n" });
    expect(missing.code).toBe(1);
    expect(missing.err).toContain("No saved passage with that id");
    expect(lastLine(missing.err)).toContain(CLOSING);
    expect(await outcomes(f)).toEqual([]);
  });

  it.each([
    { name: "an unfinished save intent", expected: "recover-save" },
    { name: "a leftover corpus lock", expected: "Ask the coordinator" },
    { name: "an interrupted earlier delete", expected: "interrupted" },
    { name: "an interrupted exit import", expected: "exit import did not finish" },
  ])("refuses $name before any prompt", async ({ name, expected }) => {
    const f = await deleteFixture();
    if (name === "an unfinished save intent") {
      // Presence alone is the refusal marker; an unreadable intent must refuse exactly like a readable one.
      await mkdir(join(f.fortress, "state", HERMES_INSERT_INTENT_NAMESPACE), { mode: 0o700, recursive: true });
      await writeFile(join(f.fortress, "state", HERMES_INSERT_INTENT_NAMESPACE, `${HERMES_INSERT_INTENT_KEY}.enc`), "intent fixture");
    } else if (name === "a leftover corpus lock") {
      await mkdir(f.storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), { mode: 0o700, recursive: true });
      await writeFile(join(f.storage.namespacePath(MEMORY_BATCH_LOCK_NAMESPACE), sdwMemoryCorpusBatchLockFile()), "");
    } else if (name === "an interrupted earlier delete") {
      await withSeedSession(f, async ({ audit }) => {
        await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION, identity_id: "operator",
          result: "success", details: { passage_id: "keep", document_id: "mem.agent-owner.keep", text_sha256: null, outcome: "intent" } });
      });
    } else {
      await withSeedSession(f, async () => { await f.storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "planted-import", Buffer.from("{}\n")); });
    }
    const before = await treeHashes(f.fortress);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain(expected);
    expect(run.out).not.toContain("Type DELETE");
    expect(await treeHashes(f.fortress)).toEqual(before);
  });

  it("a writer adapter that cannot be built refuses before the intent row, so a later delete is not blocked", async () => {
    const f = await deleteFixture();
    const realLoadAll = KnownSignersStore.prototype.loadAll;
    let loads = 0;
    // The first load is the read-only reader in the prologue; the second is the delete's writer adapter.
    const loadAll = vi.spyOn(KnownSignersStore.prototype, "loadAll").mockImplementation(function(this: KnownSignersStore) {
      return ++loads === 2 ? Promise.reject(new Error("known signers fixture")) : realLoadAll.call(this);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(loads).toBe(2);
    expect(run.err).toContain("The delete could not be prepared (error). Nothing was deleted.");
    expect(lastLine(run.err)).toContain(CLOSING);
    expect(run.err).not.toContain("could not finish");
    expect(await docPresent(f)).toBe(true);
    expect(await outcomes(f)).toEqual([]);
    loadAll.mockRestore();
    // Positive control: with the fault gone, the same delete runs and records both rows.
    const again = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(again.code, again.err).toBe(0);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "deleted"]);
  });

  it("intent row append failure deletes nothing", async () => {
    const f = await deleteFixture();
    vi.spyOn(AuditLog.prototype, "appendCritical").mockRejectedValueOnce(new Error("audit refused fixture"));
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("could not be recorded in the audit log. Nothing was deleted.");
    expect.soft(lastLine(run.err)).toBe(CLOSING_KEEP_STOPPED);
    expect.soft(run.out + run.err).not.toContain("launchctl kickstart");
    expect(await docPresent(f)).toBe(true);
  });

  it("an intent append that throws after its row landed says the delete is recorded as interrupted", async () => {
    const f = await deleteFixture();
    const real = AuditLog.prototype.appendCritical;
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementationOnce(async function(this: AuditLog, entry) {
      await real.call(this, entry);
      throw new Error("append committed then threw fixture");
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("the intent row is recorded, so this delete is recorded as interrupted. Nothing was deleted.");
    expect.soft(lastLine(run.err)).toBe(CLOSING_KEEP_STOPPED);
    expect.soft(run.out + run.err).not.toContain("launchctl kickstart");
    expect(run.err).toContain("bring a memory-report to the coordinator");
    expect(await docPresent(f)).toBe(true);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent"]);
  });

  it("an intent append that throws when the chain cannot be read back says the intent may be recorded", async () => {
    const f = await deleteFixture();
    let appendFailed = false;
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementationOnce(async () => {
      appendFailed = true;
      throw new Error("audit refused fixture");
    });
    const realQuery = AuditLog.prototype.query;
    vi.spyOn(AuditLog.prototype, "query").mockImplementation(function(this: AuditLog, ...args: Parameters<AuditLog["query"]>) {
      if (appendFailed) return Promise.reject(new Error("re-read fixture"));
      return realQuery.apply(this, args);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(appendFailed).toBe(true);
    expect(run.err).toContain("the intent may be recorded. Nothing was deleted.");
    expect.soft(lastLine(run.err)).toBe(CLOSING_KEEP_STOPPED);
    expect.soft(run.out + run.err).not.toContain("launchctl kickstart");
    expect(await docPresent(f)).toBe(true);
  });

  it("a throw before any mutation (incomplete passage at preimage capture) records not_attempted", async () => {
    const f = await deleteFixture();
    await withSeedSession(f, async () => {
      const chunk = (await f.storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE)).find(entry => entry.key.startsWith("chunk.mem.agent-owner.p1."))!;
      await f.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, chunk.key, false);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("Nothing was deleted.");
    expect(await docPresent(f)).toBe(true);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "not_attempted"]);
    expect((await outcomes(f))[1]).toMatchObject({ error_category: "passage_incomplete" });
  });

  it("a lock-acquire failure before any mutation records not_attempted", async () => {
    const f = await deleteFixture();
    const real = lockModule.withCrossProcessLock;
    vi.spyOn(lockModule, "withCrossProcessLock").mockImplementation((storage, namespace, file, operation, options) =>
      namespace === MEMORY_BATCH_LOCK_NAMESPACE ? Promise.reject(new CrossProcessLockError("contended fixture", "contention"))
        : real(storage, namespace, file, operation, options));
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("The delete could not start (lock_contention). Nothing was deleted.");
    expect(lastLine(run.err)).toContain(CLOSING);
    expect(await docPresent(f)).toBe(true);
    expect((await outcomes(f))[1]).toMatchObject({ outcome: "not_attempted", error_category: "lock_contention" });
  });

  it("a passage gone by the time the delete runs records not_found", async () => {
    const f = await deleteFixture();
    const stdout = new TerminalSink();
    const stdin = new TerminalInput();
    let answered = false;
    stdout.on("data", () => {
      if (answered || !stdout.text.includes("Type DELETE")) return;
      answered = true;
      void (async () => {
        // Another actor removes the raw record after the pre-checks and before the delete runs.
        await unlink(join(corpusDir(f), `doc.mem.${FIXTURE_AGENT_ID}.p1.enc`));
        stdin.write("DELETE\n");
      })();
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { stdout, stdin });
    expect(run.code).toBe(1);
    expect(run.err).toContain("already gone");
    expect(lastLine(run.err)).toContain(CLOSING);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "not_found"]);
  });

  it("a throw after mutation began with the record restored records failed_restored", async () => {
    const f = await deleteFixture();
    const realDelete = FilesystemStorage.prototype.delete;
    let corpusDeletes = 0;
    vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function(this: FilesystemStorage, ns, key, secure) {
      // The document record goes first; failing the second delete forces the adapter's verified restore.
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE && ++corpusDeletes === 2) throw new Error("second delete fixture");
      return realDelete.call(this, ns, key, secure);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("rolled back. Nothing was deleted. You may run it again.");
    // Positive control for the kept-stopped closing line: a whole rollback may restart the relay.
    expect(lastLine(run.err).startsWith(CLOSING)).toBe(true);
    vi.mocked(FilesystemStorage.prototype.delete).mockRestore();
    expect(await docPresent(f)).toBe(true);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "failed_restored"]);
  });

  it("a throw after mutation began with the record gone records failed_unrestored and names the coordinator", async () => {
    const f = await deleteFixture();
    const realDelete = FilesystemStorage.prototype.delete;
    let corpusDeletes = 0;
    vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function(this: FilesystemStorage, ns, key, secure) {
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE && ++corpusDeletes === 2) throw new Error("second delete fixture");
      return realDelete.call(this, ns, key, secure);
    });
    // The restore cannot write the document record back, so the re-read finds it absent.
    const realWrite = FilesystemStorage.prototype.write;
    vi.spyOn(FilesystemStorage.prototype, "write").mockImplementation(async function(this: FilesystemStorage, ns, key, bytes) {
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith("doc.")) throw new Error("restore fixture");
      return realWrite.call(this, ns, key, bytes);
    });
    const writeDurable = (FilesystemStorage.prototype as unknown as { writeDurable?: (...args: unknown[]) => Promise<unknown> }).writeDurable;
    if (writeDurable) {
      vi.spyOn(FilesystemStorage.prototype as unknown as { writeDurable: (...args: unknown[]) => Promise<unknown> }, "writeDurable")
        .mockImplementation(async function(this: FilesystemStorage, ...args: unknown[]) {
          if (args[0] === SDW_DOCUMENT_CORPUS_NAMESPACE && String(args[1]).startsWith("doc.")) throw new Error("restore fixture");
          return writeDurable.apply(this, args);
        });
    }
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain("removed from memory, cleanup incomplete");
    expect(run.err).toContain("coordinator");
    expectRelayKeptStopped(run.err);
    vi.restoreAllMocks();
    expect(await docPresent(f)).toBe(false);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "failed_unrestored"]);
  });

  /** Fail the nth corpus delete, so the adapter's verified restore runs after a mutation began. */
  function failCorpusDelete(nth: number): void {
    const realDelete = FilesystemStorage.prototype.delete;
    let corpusDeletes = 0;
    vi.spyOn(FilesystemStorage.prototype, "delete").mockImplementation(async function(this: FilesystemStorage, ns, key, secure) {
      if (ns === SDW_DOCUMENT_CORPUS_NAMESPACE && ++corpusDeletes === nth) throw new Error("corpus delete fixture");
      return realDelete.call(this, ns, key, secure);
    });
  }
  const STILL_LISTED = "treat the passage as still listed, and it may still be recalled";
  /** The relay must stay stopped after these outcomes, so the closing line gives no start command. */
  const expectRelayKeptStopped = (err: string) => {
    expect(lastLine(err)).toBe(CLOSING_KEEP_STOPPED);
    expect(err).not.toContain("launchctl kickstart");
  };

  it.each(["quarantined", "unsigned"] as const)("a %s passage whose delete throws and rolls back cleanly records failed_restored", async kind => {
    const f = await deleteFixture();
    if (kind === "quarantined") await quarantine(f, "p1");
    else await withSeedSession(f, async () => { await f.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, `prov.mem.${FIXTURE_AGENT_ID}.p1`, false); });
    const before = await treeHashes(corpusDir(f));
    // The passage cannot be verified before or after, so only a byte comparison can show the rollback was whole.
    failCorpusDelete(2);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(run.out).toContain("cannot be verified; text not shown");
    expect(run.err).toContain("rolled back. Nothing was deleted. You may run it again.");
    expect(run.err).not.toContain("removed from memory");
    expect(lastLine(run.err).startsWith(CLOSING)).toBe(true);
    expect(await treeHashes(corpusDir(f))).toEqual(before);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "failed_restored"]);
  });

  it("a rollback that restores the document but not its provenance companion records indeterminate, never removed or rolled back", async () => {
    const f = await deleteFixture();
    // Document, then companion, then status: failing the status delete leaves both earlier records to restore.
    failCorpusDelete(3);
    // The restore writes the document back but cannot write the provenance companion back.
    const refuseCompanion = (ns: unknown, key: unknown) => ns === SDW_DOCUMENT_CORPUS_NAMESPACE && String(key).startsWith("prov.");
    const realWrite = FilesystemStorage.prototype.write;
    vi.spyOn(FilesystemStorage.prototype, "write").mockImplementation(async function(this: FilesystemStorage, ns, key, bytes) {
      if (refuseCompanion(ns, key)) throw new Error("companion restore fixture");
      return realWrite.call(this, ns, key, bytes);
    });
    const writeDurable = (FilesystemStorage.prototype as unknown as { writeDurable?: (...args: unknown[]) => Promise<unknown> }).writeDurable;
    if (writeDurable) {
      vi.spyOn(FilesystemStorage.prototype as unknown as { writeDurable: (...args: unknown[]) => Promise<unknown> }, "writeDurable")
        .mockImplementation(async function(this: FilesystemStorage, ...args: unknown[]) {
          if (refuseCompanion(args[0], args[1])) throw new Error("companion restore fixture");
          return writeDurable.apply(this, args);
        });
    }
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(await docPresent(f)).toBe(true);
    expect(await f.storage.read(SDW_DOCUMENT_CORPUS_NAMESPACE, `prov.mem.${FIXTURE_AGENT_ID}.p1`)).toBeNull();
    expect(run.err).toContain(STILL_LISTED);
    expect(run.err).not.toContain("rolled back");
    expect(run.err).not.toContain("removed from memory");
    expectRelayKeptStopped(run.err);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "indeterminate"]);
    // The next command the delete prescribes, a memory-report, keeps the relay stopped too.
    const next = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(next.code, next.err).toBe(0);
    expect(lastLine(next.err)).toBe(`${CLOSING_AFTER_UNCONFIRMED} this report.`);
    expect(next.err).not.toContain("launchctl kickstart");
  });

  it("a clean rollback whose chunk re-read fails records indeterminate, never removed", async () => {
    const f = await deleteFixture();
    failCorpusDelete(2);
    let rolledBack = false;
    const realAdapterDelete = SdwMemoryBackendAdapter.prototype.deletePassage;
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "deletePassage").mockImplementation(async function(this: SdwMemoryBackendAdapter, id) {
      try { return await realAdapterDelete.call(this, id); } catch (error) { rolledBack = true; throw error; }
    });
    // The adapter's own restore verification reads every record back first; only the verb's later re-read fails.
    const realRead = FilesystemStorage.prototype.read;
    vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(async function(this: FilesystemStorage, ns, key) {
      if (rolledBack && ns === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith(`chunk.mem.${FIXTURE_AGENT_ID}.p1.`)) throw new Error("chunk re-read fixture");
      return realRead.call(this, ns, key);
    });
    const before = await treeHashes(corpusDir(f));
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(rolledBack).toBe(true);
    expect(await treeHashes(corpusDir(f))).toEqual(before);
    expect(run.err).toContain(STILL_LISTED);
    expect(run.err).not.toContain("removed from memory");
    expectRelayKeptStopped(run.err);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "indeterminate"]);
  });

  it("keeps unresolved deletes stopped across owner commands R1", async () => {
    const f = await deleteFixture();
    failCorpusDelete(2);
    let rolledBack = false;
    const realAdapterDelete = SdwMemoryBackendAdapter.prototype.deletePassage;
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "deletePassage").mockImplementation(async function(this: SdwMemoryBackendAdapter, id) {
      try { return await realAdapterDelete.call(this, id); } catch (error) { rolledBack = true; throw error; }
    });
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "compareWithPassageRawSnapshot").mockRejectedValue(new Error("re-read fixture"));
    const real = AuditLog.prototype.appendCritical;
    let calls = 0;
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementation(function(this: AuditLog, entry) {
      return ++calls === 2 ? Promise.reject(new Error("outcome audit fixture")) : real.call(this, entry);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(rolledBack).toBe(true);
    expect(run.err).toContain('The delete outcome "indeterminate" could not be written to the audit log');
    expectRelayKeptStopped(run.err);
    for (const verb of VERBS) {
      const later = await runVerb(f, verbArgs(verb), { answer: "no\n" });
      expect.soft(lastLine(later.err)).toContain(CLOSING_AFTER_UNCONFIRMED);
      expect.soft(later.err).not.toContain("launchctl kickstart");
    }
  });

  it("a passage with more chunks than one Hermes save can hold is never reported as rolled back", async () => {
    const f = await deleteFixture("y".repeat(DEFAULT_MAX_CHUNK_CHARS * HERMES_SAVE_MAX_CHUNKS + 1));
    failCorpusDelete(2);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(await docPresent(f)).toBe(true);
    expect(run.err).toContain(STILL_LISTED);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "indeterminate"]);
    // Positive control: a passage at exactly the cap is snapshotted whole and rolls back as restored.
    await seedPassage(f, "at-cap", "z".repeat(DEFAULT_MAX_CHUNK_CHARS * HERMES_SAVE_MAX_CHUNKS));
    failCorpusDelete(2);
    const atCap = await runVerb(f, ["memory-delete", "--passage", "at-cap"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(atCap.err).toContain("rolled back. Nothing was deleted.");
  });

  it.each(["throws", "does not decode"] as const)("a document read that %s while the delete takes its snapshot refuses before the intent row", async failure => {
    const f = await deleteFixture();
    const documentStorageKey = `doc.mem.${FIXTURE_AGENT_ID}.p1`;
    let inSnapshot = false;
    let planted = 0;
    const realSnapshot = SdwMemoryBackendAdapter.prototype.snapshotPassageRawRecords;
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "snapshotPassageRawRecords").mockImplementation(async function(this: SdwMemoryBackendAdapter, id) {
      inSnapshot = true;
      try { return await realSnapshot.call(this, id); } finally { inSnapshot = false; }
    });
    // A transient failure: only the snapshot's first document read fails; every other read sees the record.
    const realRead = FilesystemStorage.prototype.read;
    vi.spyOn(FilesystemStorage.prototype, "read").mockImplementation(async function(this: FilesystemStorage, ns, key) {
      const bytes = await realRead.call(this, ns, key);
      if (!inSnapshot || ns !== SDW_DOCUMENT_CORPUS_NAMESPACE || key !== documentStorageKey || bytes === null) return bytes;
      if (++planted > 1) return bytes;
      if (failure === "throws") throw new Error("snapshot read fixture");
      const damaged = Uint8Array.from(bytes);
      damaged[damaged.length - 1]! ^= 0xff;
      return damaged;
    });
    const before = await treeHashes(f.fortress);
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(run.err).toMatch(/The delete could not be prepared \([a-z_]+\)\. Nothing was deleted\./u);
    expect(run.err).not.toContain("removed from memory");
    expect(await outcomes(f)).toEqual([]);
    expect(await docPresent(f)).toBe(true);
    expect(await treeHashes(f.fortress)).toEqual(before);
    // The snapshot stopped at its first document read, so the plant was reached exactly once.
    expect(planted).toBe(1);
    // Positive control: with the read restored, the same passage is snapshotted and deleted.
    const retried = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(retried.code, retried.err).toBe(0);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "deleted"]);
  });

  it("the raw-record snapshot only reads, and compares equal until one record changes", async () => {
    const f = await deleteFixture();
    await withSeedSession(f, async ({ adapter }) => {
      const before = await treeHashes(f.fortress);
      const snapshot = await adapter.snapshotPassageRawRecords("p1");
      expect(await treeHashes(f.fortress)).toEqual(before);
      expect(snapshot.complete).toBe(true);
      // The document, the companion, the status slot and one chunk for this short passage.
      expect(snapshot.records.map(record => record.key.split(".")[0])).toEqual(["doc", "prov", "prov-status", "chunk"]);
      expect(await adapter.compareWithPassageRawSnapshot(snapshot)).toBe("equal");
      await damageCorpusRecord(f, "chunk.", "p1");
      expect(await adapter.compareWithPassageRawSnapshot(snapshot)).toBe("changed");
      await f.storage.delete(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${FIXTURE_AGENT_ID}.p1`, false);
      expect(await adapter.compareWithPassageRawSnapshot(snapshot)).toBe("document_absent");
    });
  });

  it.each([
    { name: "after mutation began", mutationBegan: true },
    { name: "before any mutation", mutationBegan: false },
  ])("a delete that throws $name and whose re-read fails records indeterminate, never removed", async ({ mutationBegan }) => {
    const f = await deleteFixture();
    let deleteRan = false;
    const realAdapterDelete = SdwMemoryBackendAdapter.prototype.deletePassage;
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "deletePassage").mockImplementation(async function(this: SdwMemoryBackendAdapter, id) {
      deleteRan = true;
      return realAdapterDelete.call(this, id);
    });
    if (mutationBegan) {
      failCorpusDelete(2);
    } else {
      const real = lockModule.withCrossProcessLock;
      vi.spyOn(lockModule, "withCrossProcessLock").mockImplementation((storage, namespace, file, operation, options) =>
        namespace === MEMORY_BATCH_LOCK_NAMESPACE ? Promise.reject(new CrossProcessLockError("contended fixture", "contention"))
          : real(storage, namespace, file, operation, options));
    }
    // Every read-back after the delete started fails, so the verb has no evidence of the passage's state.
    for (const method of ["inspectPassageReadOnly", "hasRawDocumentRecord", "compareWithPassageRawSnapshot"] as const) {
      const real = SdwMemoryBackendAdapter.prototype[method] as (this: SdwMemoryBackendAdapter, arg: never) => Promise<unknown>;
      vi.spyOn(SdwMemoryBackendAdapter.prototype, method).mockImplementation(async function(this: SdwMemoryBackendAdapter, arg: never) {
        if (deleteRan) throw new Error("re-read fixture");
        return real.call(this, arg);
      } as never);
    }
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    vi.restoreAllMocks();
    expect(run.code).toBe(1);
    expect(deleteRan).toBe(true);
    expect(run.err).toContain(STILL_LISTED);
    expect(run.err).toContain("coordinator");
    expect(run.err).not.toContain("removed from memory");
    expect(run.err).not.toContain("Nothing was deleted");
    expectRelayKeptStopped(run.err);
    expect((await outcomes(f)).map(row => row?.outcome)).toEqual(["intent", "indeterminate"]);
  });

  it("keeps an unsettled delete stopped with its audit diagnostic R1", async () => {
    const f = await deleteFixture();
    const real = AuditLog.prototype.appendCritical;
    let calls = 0;
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementation(function(this: AuditLog, entry) {
      calls++;
      return calls === 2 ? Promise.reject(new Error("outcome audit fixture")) : real.call(this, entry);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(run.code).toBe(1);
    expect(run.err).toContain('The delete outcome "deleted" could not be written to the audit log; it is not retried.');
    expect(run.out).not.toContain("deleted\n");
    expect(calls).toBe(2);
    vi.restoreAllMocks();
    expect.soft(lastLine(run.err)).toBe(CLOSING_KEEP_STOPPED);
    expect.soft(run.err).not.toContain("launchctl kickstart");
    const later = await runVerb(f, ["memory-report", "--since", f.since]);
    expect.soft(lastLine(later.err)).toContain(CLOSING_AFTER_UNCONFIRMED);
    expect.soft(later.err).not.toContain("launchctl kickstart");
  });

  it("an intent with no outcome makes the next delete refuse and the report say interrupted", async () => {
    const f = await deleteFixture();
    // A force kill leaves exactly this state: the intent row and no outcome.
    await withSeedSession(f, async ({ audit }) => {
      await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION, identity_id: "operator",
        result: "success", details: { passage_id: "p1", document_id: "mem.agent-owner.p1", text_sha256: null, outcome: "intent" } });
    });
    const next = await runVerb(f, ["memory-delete", "--passage", "keep"], { answer: "DELETE\n" });
    expect(next.code).toBe(1);
    expect(next.err).toContain("interrupted");
    expect(await docPresent(f, "keep")).toBe(true);
    const parsed = report(await runVerb(f, ["memory-report", "--since", f.since]));
    expect(parsed.owner_deletes[0].attempts[0].outcome).toBe("interrupted");
  });

  it("ignores all five signals from an accepted DELETE until the delete returns", async () => {
    const f = await deleteFixture();
    const installed: string[] = [];
    const removed: string[] = [];
    let duringDelete: string[] = [];
    const realDelete = SdwMemoryBackendAdapter.prototype.deletePassage;
    vi.spyOn(SdwMemoryBackendAdapter.prototype, "deletePassage").mockImplementation(async function(this: SdwMemoryBackendAdapter, id) {
      duringDelete = installed.filter(signal => !removed.includes(signal));
      return realDelete.call(this, id);
    });
    const run = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n",
      signals: { on: signal => { installed.push(signal); }, off: signal => { removed.push(signal); } } });
    expect(run.code, run.err).toBe(0);
    expect(duringDelete.sort()).toEqual(["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGTSTP"]);
    expect(removed.sort()).toEqual(["SIGHUP", "SIGINT", "SIGQUIT", "SIGTERM", "SIGTSTP"]);
  });
});

describe("hermes owner verbs: closing line after an earlier delete", () => {
  /** Seed owner-delete attempts on passages as completed rows: an intent, then its outcome. */
  async function seedDeleteAttempts(f: OwnerFortress, attempts: readonly (readonly [string, OwnerDeleteOutcome])[]) {
    await withSeedSession(f, async ({ audit }) => {
      for (const [passage, outcome] of attempts) {
        for (const recorded of ["intent", outcome] as const) {
          await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION, identity_id: "operator",
            result: "success", details: { passage_id: passage, document_id: `mem.${FIXTURE_AGENT_ID}.${passage}`, text_sha256: null, outcome: recorded } });
        }
      }
    });
  }
  const expectKeptStoppedAfterEarlierDelete = (err: string, readThisReport: boolean) => {
    expect(lastLine(err)).toBe(`${CLOSING_AFTER_UNCONFIRMED} ${readThisReport ? "this report" : "a memory-report"}.`);
    expect(err).not.toContain("launchctl kickstart");
  };

  it.each(["indeterminate", "failed_unrestored"] as const)("after a %s delete, later memory-report and memory-show runs keep the relay stopped", async outcome => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "a passage whose delete was not confirmed");
    await seedDeleteAttempts(f, [["p1", outcome]]);
    const reported = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(reported.code, reported.err).toBe(0);
    expect(report(reported).owner_deletes).toEqual([expect.objectContaining({ passage_id: "p1",
      attempts: [expect.objectContaining({ outcome })] })]);
    expectKeptStoppedAfterEarlierDelete(reported.err, true);
    const shown = await runVerb(f, ["memory-show", "--recent", "1"]);
    expect(shown.code, shown.err).toBe(0);
    expectKeptStoppedAfterEarlierDelete(shown.err, false);
  });

  it.each(["failed_restored", "not_attempted", "deleted"] as const)("after a %s delete, a later memory-report ends with the start command", async outcome => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "a passage whose delete was settled");
    await seedDeleteAttempts(f, [["p1", outcome]]);
    const reported = await runVerb(f, ["memory-report", "--since", f.since]);
    expect(reported.code, reported.err).toBe(0);
    expect(lastLine(reported.err).startsWith(CLOSING)).toBe(true);
  });

  it("a later attempt that changes nothing does not settle an unconfirmed delete; a later confirmed delete of the same passage does", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "first passage");
    await seedPassage(f, "keep", "an unrelated passage");
    await seedDeleteAttempts(f, [["p1", "indeterminate"], ["p1", "failed_restored"], ["p1", "not_attempted"]]);
    expectKeptStoppedAfterEarlierDelete((await runVerb(f, ["memory-report", "--since", f.since])).err, true);
    // A confirmed delete of another passage leaves the earlier one unconfirmed.
    await seedPassage(f, "other", "another passage");
    const other = await runVerb(f, ["memory-delete", "--passage", "other"], { answer: "DELETE\n" });
    expect(other.code, other.err).toBe(0);
    expectKeptStoppedAfterEarlierDelete(other.err, false);
    // Confirming the delete of the same passage settles it, in that run and in every later one.
    const same = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(same.code, same.err).toBe(0);
    expect(lastLine(same.err).startsWith(CLOSING)).toBe(true);
    expect(lastLine((await runVerb(f, ["memory-report", "--since", f.since])).err).startsWith(CLOSING)).toBe(true);
  });

  it("keeps unresolved owner state stopped before audit access R1", async () => {
    const f = await ownerFortress(stack);
    await seedDeleteAttempts(f, [["p1", "indeterminate"]]);
    const err = new TerminalSink();
    expect(await runHermesMemory({ argv: ["memory-report", "--fortress", f.fortress], env: { HOME: f.home }, uid: process.getuid!(),
      ...fixturePackage(f), stderr: err, stdout: new TerminalSink() })).toBe(2);
    expect(lastLine(err.text)).toBe(CLOSING_BEFORE_AUDIT_READ);
    expect(err.text).not.toContain("launchctl kickstart");
  });
});

describe("hermes owner verbs: help text", () => {
  it("states the operator rules and failure modes without em-dashes", () => {
    for (const text of Object.values(HERMES_MEMORY_HELP)) expect(text).not.toContain("—");
    // Shipped text names the relay, never the operator's private agent name.
    for (const text of Object.values(HERMES_MEMORY_HELP)) expect(text).not.toMatch(/\bCoS\b/u);
    for (const verb of VERBS) expect(HERMES_MEMORY_HELP[verb]).toContain("the Hermes memory relay stopped");
    expect(HERMES_MEMORY_HELP["memory-delete"]).toContain("audit log keeps its fingerprint");
    expect(HERMES_MEMORY_HELP["memory-delete"]).toContain("Hermes's session store keeps the original turn");
    expect(HERMES_MEMORY_HELP["memory-delete"]).toContain("APFS is not physical erasure");
    expect(HERMES_MEMORY_HELP["memory-delete"]).toContain("save the same words again");
    expect(HERMES_MEMORY_HELP["memory-show"]).toContain("scrollback");
    expect(HERMES_MEMORY_HELP["memory-report"]).toContain("not a witness");
    for (const verb of ["memory-report", "memory-show", "memory-delete"] as const) {
      expect(HERMES_MEMORY_HELP[verb]).toContain("has been checked, covers the full history, and no unresolved delete is identified.");
      expect(HERMES_MEMORY_HELP[verb]).toContain("Only if the last line says to start the relay:");
      expect(HERMES_MEMORY_HELP[verb]).toContain("cannot be\nzeroed inside a JavaScript process");
      expect(HERMES_MEMORY_HELP[verb]).toContain("B_RUNTIME/bin/node B_RUNTIME/pkg/dist/cli.js");
    }
  });
});

/** Owner restart advice and report destinations honor checked scope and containment. 1514 */
describe("owner evidence and destinations 1514", () => {
  const OWNER_ONLY = 0o700;
  const OTHER_DOCUMENT = "mem.agent-other.p1";
  const OWN_DOCUMENT = `mem.${FIXTURE_AGENT_ID}.p1`;

  async function appendOwnerRows(f: OwnerFortress, rows: readonly (readonly [string, OwnerDeleteOutcome])[]) {
    await withSeedSession(f, async ({ audit }) => {
      for (const [documentId, outcome] of rows) {
        await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION,
          identity_id: "operator", result: "success",
          details: { document_id: documentId, passage_id: "p1", text_sha256: null, outcome } });
      }
    });
  }

  it("settles deletes within their full document and passage scope R3", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "owner scope passage");
    await appendOwnerRows(f, [[OTHER_DOCUMENT, "intent"], [OTHER_DOCUMENT, "indeterminate"]]);
    const deleted = await runVerb(f, ["memory-delete", "--passage", "p1"], { answer: "DELETE\n" });
    expect(deleted.code, deleted.err).toBe(0);
    expect.soft(lastLine(deleted.err)).toContain(CLOSING_AFTER_UNCONFIRMED);
    expect.soft(deleted.err).not.toContain("launchctl kickstart");
    const reported = await runVerb(f, ["memory-report", "--since", f.since]);
    expect.soft(lastLine(reported.err)).toContain(CLOSING_AFTER_UNCONFIRMED);
    expect.soft(reported.err).not.toContain("launchctl kickstart");
    expect.soft(report(reported).owner_deletes).toEqual([
      expect.objectContaining({ document_id: OTHER_DOCUMENT, passage_id: "p1",
        attempts: [expect.objectContaining({ outcome: "indeterminate" })] }),
      expect.objectContaining({ document_id: OWN_DOCUMENT, passage_id: "p1",
        attempts: [expect.objectContaining({ outcome: "deleted" })] }),
    ]);
  });

  it("pairs intent and outcome evidence within the same document R3", async () => {
    const f = await ownerFortress(stack);
    await appendOwnerRows(f, [[OTHER_DOCUMENT, "intent"], [OWN_DOCUMENT, "deleted"]]);
    const reported = await runVerb(f, ["memory-report", "--since", f.since]);
    expect.soft(report(reported).owner_deletes).toEqual([
      expect.objectContaining({ document_id: OTHER_DOCUMENT,
        attempts: [expect.objectContaining({ outcome: "interrupted", outcome_at: null })] }),
    ]);
    expect.soft(lastLine(reported.err)).toContain(CLOSING_AFTER_UNCONFIRMED);
    expect.soft(reported.err).not.toContain("launchctl kickstart");
  });

  it.each([
    { evidence: "unverified", verified: false, everPruned: false },
    { evidence: "retention null", verified: true, everPruned: null },
    { evidence: "retention undefined", verified: true, everPruned: undefined },
    { evidence: "pruned", verified: true, everPruned: true },
  ])("uses checked audit evidence for restart advice: $evidence R2a", async ({ verified, everPruned }) => {
    const f = await ownerFortress(stack);
    await seedPassage(f, "p1", "audit evidence passage");
    const realVerdict = AuditLog.prototype.getAuditChainVerdict;
    vi.spyOn(AuditLog.prototype, "getAuditChainVerdict").mockImplementation(async function(this: AuditLog) {
      const verdict = await realVerdict.call(this);
      return verified ? verdict : { ...verdict, status: "findings" };
    });
    const realUsage = AuditLog.prototype.getRetentionUsage;
    vi.spyOn(AuditLog.prototype, "getRetentionUsage").mockImplementation(async function(this: AuditLog) {
      const usage = await realUsage.call(this);
      // The runtime reader also accepts records whose retention field is absent.
      return { ...usage, everPruned } as Awaited<ReturnType<typeof realUsage>>;
    });
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { answer: "no\n" });
      if (verb === "memory-report") expect.soft(report(run).start_guidance?.withheld_by).toEqual([
        !verified ? "audit_unverified" : everPruned === true ? "history_pruned" : "retention_unknown",
      ]);
      if (everPruned === true) {
        // DEBT(HERMES-OWNER-HOLD-RETENTION)
        expect.soft(lastLine(run.err)).toBe(CLOSING_INCOMPLETE);
        expect.soft(run.err).not.toContain("launchctl kickstart");
      } else {
        expect.soft(lastLine(run.err)).toContain("record could not be checked");
        expect.soft(lastLine(run.err)).toContain("Leave it stopped");
        expect.soft(run.err).not.toContain("launchctl kickstart");
      }
    }
  });

  it.each(["fortress", "kit"] as const)("protects all descendant folder names in the %s tree R4", async tree => {
    const root = await realpath(await mkdtemp(join(tmpdir(), "owner-destination-")));
    stack.push(() => rm(root, { recursive: true, force: true }));
    const home = join(root, "home");
    const fortress = join(home, "Library", "Application Support", "Sanctuary", "Fortresses", "fortress-owner");
    await mkdir(join(fortress, "state", CUSTODY_WRITE_LOCK_NAMESPACE), { recursive: true, mode: OWNER_ONLY });
    // Destination admission precedes custody, so this fixture needs only the owned directory shape.
    const f: OwnerFortress = { root, home, fortress, storage: new FilesystemStorage(join(fortress, "state")),
      fortressId: "fortress-owner", since: new Date().toISOString(), bridgeEnv: {} };
    const kit = join(f.root, "kit");
    await mkdir(kit, { mode: OWNER_ONLY });
    const folder = join(tree === "fortress" ? f.fortress : kit, "..reports");
    await mkdir(folder, { mode: OWNER_ONLY });
    const beforeFortress = await treeHashes(f.fortress);
    const beforeKit = await treeHashes(kit);
    const run = await runVerb(f, ["memory-report", "--out", join(folder, "report.json")]);
    expect.soft(run.code, run.err).toBe(1);
    expect.soft(run.err).toContain("inside the fortress or the kit folder");
    expect.soft(await treeHashes(f.fortress)).toEqual(beforeFortress);
    expect.soft(await treeHashes(kit)).toEqual(beforeKit);
  });

  it("protects the home runtime while permitting the home report folder R5", async () => {
    const f = await ownerFortress(stack);
    const runtime = join(f.home, "B_RUNTIME");
    const packageRoot = join(runtime, "pkg");
    const reports = join(f.home, "hermes-memory-reports");
    await mkdir(packageRoot, { recursive: true, mode: OWNER_ONLY });
    await chmod(runtime, OWNER_ONLY);
    await mkdir(reports, { mode: OWNER_ONLY });
    const options = { packageRoot, invokedEntry: join(packageRoot, "dist", "cli.js") };
    const beforeRuntime = await treeHashes(runtime);
    const beforeFortress = await treeHashes(f.fortress);
    const refused = await runVerb(f, ["memory-report", "--out", join(runtime, "report.json")], options);
    expect.soft(refused.code, refused.err).toBe(1);
    expect.soft(refused.err).toContain("inside the fortress or the kit folder");
    expect.soft(await treeHashes(runtime)).toEqual(beforeRuntime);
    const allowed = await runVerb(f, ["memory-report", "--out", join(reports, "report.json")], options);
    expect(allowed.code, allowed.err).toBe(0);
    expect(JSON.parse(await readFile(join(reports, "report.json"), "utf8")).report).toBe("sanctuary hermes memory-report");
    expect(await treeHashes(f.fortress)).toEqual(beforeFortress);
  });

  it("withholds restart advice until owner audit evidence is available R1", async () => {
    const out = new TerminalSink();
    const err = new TerminalSink();
    const code = await runHermesMemory({ argv: ["memory-report"], stdout: out, stderr: err,
      packageVersion: FIXTURE_PACKAGE_VERSION, packageRoot: dirname(fileURLToPath(import.meta.url)), invokedEntry: undefined });
    expect(code).toBe(2);
    expect.soft(lastLine(err.text)).toBe(CLOSING_BEFORE_AUDIT_READ);
    expect.soft(err.text).not.toContain("launchctl kickstart");
  });

  it("describes audit metadata retention limits in delete help R7", () => {
    expect.soft(HERMES_MEMORY_HELP["memory-delete"]).toContain("under the audit log's retention limits");
    expect.soft(HERMES_MEMORY_HELP["memory-delete"]).not.toContain("permanently");
  });
});


describe("owner start guidance requires complete evidence", () => {
  const PASSAGE = "p1";
  const DOCUMENT = `mem.${FIXTURE_AGENT_ID}.${PASSAGE}`;
  const details = (outcome: string) => ({ passage_id: PASSAGE, document_id: DOCUMENT, text_sha256: null, outcome });
  async function appendRows(f: OwnerFortress, rows: readonly Record<string, unknown>[]) {
    await withSeedSession(f, async ({ audit }) => {
      for (const row of rows) await audit.appendCritical({ layer: "l3", operation: HERMES_MEMORY_OWNER_DELETE_OPERATION,
        identity_id: "operator", result: "success", details: row });
    });
  }
  function incomplete(run: { err: string }) {
    expect.soft(lastLine(run.err)).toBe(CLOSING_INCOMPLETE);
    expect.soft(run.err).not.toContain("launchctl kickstart");
    expect.soft(run.err).not.toContain("could not be checked");
  }

  it("uses a complete retained record for all three closing decisions", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, PASSAGE, "retained passage");
    await appendRows(f, [details("intent"), details("indeterminate")]);
    const RETAINED_CAP = 4; // Small fixture ceiling, enough for a safe delete's two rows and a retained suffix.
    const FILLER_ROWS = RETAINED_CAP * 2; // Two full windows leave only ordinary fixture rows.
    await withSeedSession(f, async ({ masterKey }) => {
      const audit = new AuditLog(f.storage, masterKey, { maxEntries: RETAINED_CAP });
      for (let index = 0; index < FILLER_ROWS; index++) await audit.appendCritical({ layer: "l1",
        operation: "owner_fixture_ready", identity_id: "operator", result: "success" });
      expect((await audit.getRetentionUsage()).everPruned).toBe(true);
    });
    expect(await auditEntries(f, HERMES_MEMORY_OWNER_DELETE_OPERATION)).toEqual([]);
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { answer: "DELETE\n" });
      expect(run.code, run.err).toBe(0);
      incomplete(run);
      if (verb === "memory-report") {
        const parsed = report(run);
        expect(parsed.window.chain_verified).toBe(true);
        expect.soft(parsed.start_guidance).toEqual({ withheld_by: ["history_pruned"],
          retained_count: parsed.start_guidance?.returned_count, returned_count: expect.any(Number) });
      }
    }
  });

  it.each([
    { name: "orphan failed_unrestored", row: details("failed_unrestored") },
    { name: "orphan indeterminate", row: details("indeterminate") },
    { name: "unknown outcome", row: details("unknown") },
    { name: "missing outcome", row: { passage_id: PASSAGE, document_id: DOCUMENT } },
    { name: "malformed passage", row: { ...details("deleted"), passage_id: null } },
    { name: "malformed document", row: { ...details("deleted"), document_id: null } },
    { name: "malformed digest", row: { ...details("intent"), text_sha256: false } },
  ])("retains a hold for $name in the report decision", async ({ name, row }) => {
    const f = await ownerFortress(stack);
    const prefix = name.startsWith("orphan") ? [] : [details("intent")];
    await appendRows(f, [...prefix, row, details("intent"), details("deleted")]);
    const realUsage = AuditLog.prototype.getRetentionUsage;
    vi.spyOn(AuditLog.prototype, "getRetentionUsage").mockImplementation(async function(this: AuditLog) {
      return { ...await realUsage.call(this), everPruned: true };
    });
    const parsed = report(await runVerb(f, ["memory-report"]));
    expect(parsed.start_guidance?.withheld_by).toEqual(["history_pruned", "unresolved_delete"]);
    expect(parsed.window.chain_verified).toBe(true);
  });

  it("requires full row coverage with a valid sealed prefix", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, PASSAGE, "sealed fixture passage");
    await appendRows(f, [details("intent"), details("indeterminate")]);
    await withSeedSession(f, async ({ audit, masterKey }) => {
      const head = await audit.getChainHead();
      const macKey = deriveAuditStoreSplitBoundaryMacKey(masterKey);
      try {
        await writeAuditStoreSplitBoundary(join(f.fortress, "state"), macKey, {
          sealed_tip_sequence: head.sequence, sealed_base_sequence: 1, // The first audit sequence is one.
          sealed_tip_entry_hash: head.entry_hash, daemon_namespace: "_audit-daemon",
        });
      } finally { macKey.fill(0); }
      await new AuditLog(f.storage, masterKey).appendCritical({ layer: "l1", operation: "owner_fixture_ready",
        identity_id: "operator", result: "success" });
    });
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { answer: "no\n" });
      incomplete(run);
      if (verb === "memory-report") {
        const parsed = report(run);
        expect(parsed.window).toMatchObject({ chain_verified: true, ever_pruned: false });
        expect.soft(parsed.start_guidance?.withheld_by).toEqual(["row_count_mismatch"]);
        expect.soft(parsed.start_guidance?.retained_count).toBeGreaterThan(parsed.start_guidance?.returned_count);
      }
    }
  });

  it("requires equal counts from the usage-reading seam", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, PASSAGE, "window fixture passage");
    const realUsage = AuditLog.prototype.getRetentionUsage;
    const OMITTED_ROWS = 1; // Model one retained row beyond the reader's window; this is not a large real log.
    vi.spyOn(AuditLog.prototype, "getRetentionUsage").mockImplementation(async function(this: AuditLog) {
      const usage = await realUsage.call(this);
      return { ...usage, entryCount: usage.entryCount + OMITTED_ROWS };
    });
    for (const verb of VERBS) {
      const run = await runVerb(f, verbArgs(verb), { answer: "no\n" });
      incomplete(run);
      if (verb === "memory-report") expect.soft(report(run).start_guidance?.withheld_by).toEqual(["row_count_mismatch"]);
    }
  });

  it("keeps the complete pre-append view for the current delete", async () => {
    const f = await ownerFortress(stack);
    await seedPassage(f, PASSAGE, "current delete passage");
    const realUsage = AuditLog.prototype.getRetentionUsage;
    const realAppend = AuditLog.prototype.appendCritical;
    let appended = false;
    const usageSpy = vi.spyOn(AuditLog.prototype, "getRetentionUsage").mockImplementation(async function(this: AuditLog) {
      const usage = await realUsage.call(this);
      return { ...usage, everPruned: appended };
    });
    vi.spyOn(AuditLog.prototype, "appendCritical").mockImplementation(async function(this: AuditLog, ...args) {
      const result = await realAppend.apply(this, args);
      appended = true;
      return result;
    });
    const run = await runVerb(f, ["memory-delete", "--passage", PASSAGE], { answer: "DELETE\n" });
    expect(run.code, run.err).toBe(0);
    expect(appended).toBe(true);
    expect(usageSpy).toHaveBeenCalledOnce();
    expect(lastLine(run.err)).toContain(CLOSING);
    incomplete(await runVerb(f, ["memory-report"]));
  });

  it.each(["empty", "display failure"] as const)("permits show after a complete clear view: %s", async mode => {
    const f = await ownerFortress(stack);
    const stdout = new TerminalSink();
    if (mode === "display failure") {
      await seedPassage(f, PASSAGE, "display fixture passage");
      vi.spyOn(stdout, "write").mockImplementation(() => { throw new Error("display fixture"); });
    }
    const run = await runVerb(f, ["memory-show", "--recent", "1"], { stdout });
    expect(run.code).toBe(mode === "empty" ? 0 : 1);
    expect(lastLine(run.err)).toContain(CLOSING);
  });

  it.each(VERBS)("permits %s with a complete clear view", async verb => {
    const f = await ownerFortress(stack);
    await seedPassage(f, PASSAGE, "complete fixture passage");
    const run = await runVerb(f, verbArgs(verb), { answer: "DELETE\n" });
    expect(run.code, run.err).toBe(0);
    expect(lastLine(run.err)).toContain(CLOSING);
    if (verb === "memory-report") expect(report(run).start_guidance).toEqual({ withheld_by: [],
      retained_count: (await auditEntries(f)).length, returned_count: (await auditEntries(f)).length });
  });
});
