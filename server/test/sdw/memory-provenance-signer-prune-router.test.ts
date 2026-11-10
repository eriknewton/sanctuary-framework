import { ed25519 } from "@noble/curves/ed25519";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";
import { publicKeyToDid } from "../../src/core/identity.js";
import { AuditLog } from "../../src/operational/audit-log.js";
import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import { CallbackApprovalChannel } from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import { fingerprintIdentityId } from "../../src/agent-native/safety-base.js";
import type { MultiAgentIsolationGuard } from "../../src/sdw/memory-isolation.js";
import { KNOWN_SIGNERS_NAMESPACE, KnownSignersStore, knownSignerStorageKey } from "../../src/reputation/known-signers-store.js";
import { createServer } from "../../src/router.js";
import { MemoryProvenanceSignerPruner, MEMORY_PROVENANCE_SIGNER_PRUNE_OPERATION as OPERATION,
  MEMORY_PROVENANCE_SIGNER_PRUNE_PLAN_AUDIT as PLAN,
  MEMORY_PROVENANCE_SIGNER_PRUNE_COMPLETE_AUDIT as COMPLETE } from "../../src/sdw/memory-provenance-signer-prune.js";
import { createMemoryProvenanceSignerPruneTool } from "../../src/sdw/memory-provenance-signer-prune-tools.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { EXIT_IMPORT_JOURNAL_NAMESPACE, EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE } from "../../src/storage/exit-import-journal.js";
import { runJournaledMemoryProvenanceSignerPrune } from "../../src/exit/bundle.js";
import { EXIT_IMPORT_NAMESPACE, MAX_EXIT_IMPORT_JOURNAL_LOCATIONS } from "../../src/storage/exit-import-journal-record.js";
import type { CrossProcessLockLease, CrossProcessLockOptions } from "../../src/storage/cross-process-lock.js";
import { SignerPruneError } from "../../src/storage/signer-prune-outcome.js";
import { MemoryStorage } from "../../src/storage/memory.js";

const KEY_BYTES = 32; // Ed25519 seeds and the symmetric master key are 256 bits.
const MASTER_FIXTURE_BYTE = 1; // Deterministic test material, distinct from the signer seed.
const SIGNER_FIXTURE_BYTE = 2; // Independent deterministic signer test material.
const MASTER = new Uint8Array(KEY_BYTES).fill(MASTER_FIXTURE_BYTE);
const SECRET = "secret-key:/private/operator/fortress:arbitrary-signer";
const APPROVAL = { approvalAuditId: "approved-prune" };
const ONE_SIGNER = 1;
const ONE_APPEND = 1;
const ONE_JOURNAL = 1;
const ADMISSION_WAVES = 3; // Exercise an initial request and two later admission waves.
const CORPUS_LISTS_PER_SCAN = 3; // Documents, companions, statuses.

type Fault = "none" | "scan" | "relist" | "rollback" | "rollback-write" |
  "rollback-silent" | "diverged" | "cleanup" | "preflight" |
  "activation-write" | "activation-unknown" | "activation-conflict" | "activation-lost" |
  "journal-write" | "journal-unknown" | "journal-lost" | "stale-marker-read" | "rollback-cleanup";

class ScheduledStorage extends MemoryStorage {
  fault: Fault = "none";
  releaseFault = false;
  activationWritten = false;
  deleted = 0;
  journalWrites = 0;
  corpusLists = 0;
  active = 0;
  maximumActive = 0;

  override async withNamespaceLock<T>(namespace: string, name: string,
    operation: (lease: CrossProcessLockLease) => Promise<T>, options: CrossProcessLockOptions = {}): Promise<T> {
    return super.withNamespaceLock(namespace, name, async lease => {
      if (namespace !== EXIT_IMPORT_JOURNAL_NAMESPACE) return operation(lease);
      this.active++;
      this.maximumActive = Math.max(this.maximumActive, this.active);
      try {
        if (this.fault === "preflight") throw new Error(SECRET);
        return await operation(lease);
      } finally {
        this.active--;
        if (this.releaseFault) throw new Error(SECRET);
      }
    }, options);
  }

  override async list(namespace: string, prefix?: string) {
    const entries = await super.list(namespace, prefix);
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) {
      this.corpusLists++;
      if (this.fault === "scan") throw new Error(SECRET);
      if (this.fault === "relist" && this.corpusLists > CORPUS_LISTS_PER_SCAN) {
        return [...entries, { namespace, key: "doc.mem.changed", size_bytes: 0, modified_at: "" }];
      }
    }
    return entries;
  }

  override async write(namespace: string, key: string, bytes: Uint8Array): Promise<void> {
    if (namespace === EXIT_IMPORT_JOURNAL_NAMESPACE) this.journalWrites++;
    if (namespace === KNOWN_SIGNERS_NAMESPACE && this.deleted > 0) {
      if (this.fault === "rollback-write") throw new Error(SECRET);
      if (this.fault === "rollback-silent") return;
    }
    if (namespace === EXIT_IMPORT_JOURNAL_NAMESPACE && this.fault === "journal-lost") {
      throw new Error(SECRET);
    }
    if (namespace === EXIT_IMPORT_NAMESPACE && this.fault === "activation-lost") {
      throw new Error(SECRET);
    }
    const written = namespace === EXIT_IMPORT_NAMESPACE && this.fault === "activation-conflict"
      ? new TextEncoder().encode("conflicting-marker") : bytes;
    await super.write(namespace, key, written);
    if (namespace === EXIT_IMPORT_JOURNAL_NAMESPACE && this.fault.startsWith("journal-")) {
      throw new Error(SECRET);
    }
    if (namespace === EXIT_IMPORT_NAMESPACE && this.fault.startsWith("activation-")) {
      this.activationWritten = true;
      throw new Error(SECRET);
    }
  }

  override async read(namespace: string, key: string) {
    if ((namespace === EXIT_IMPORT_JOURNAL_NAMESPACE && this.journalWrites > 0 && this.fault === "journal-unknown") ||
        (namespace === EXIT_IMPORT_NAMESPACE && this.fault === "stale-marker-read")) {
      throw new Error(SECRET);
    }
    if (namespace === EXIT_IMPORT_NAMESPACE && this.activationWritten && this.fault === "activation-unknown") {
      throw new Error(SECRET);
    }
    return super.read(namespace, key);
  }

  override async delete(namespace: string, key: string, secure?: boolean): Promise<boolean> {
    if ((this.fault === "cleanup" || this.fault === "rollback-cleanup") && namespace === EXIT_IMPORT_JOURNAL_POSTIMAGE_NAMESPACE) {
      throw new Error(SECRET);
    }
    const removed = await super.delete(namespace, key, secure);
    if (namespace === KNOWN_SIGNERS_NAMESPACE && removed) {
      this.deleted++;
      if (this.fault === "diverged") {
        await super.write(namespace, key, new TextEncoder().encode(SECRET));
      }
      if (["rollback", "rollback-write", "rollback-silent", "rollback-cleanup", "diverged"].includes(this.fault)) {
        throw new Error(SECRET);
      }
    }
    return removed;
  }
}

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

class ScheduledAudit extends AuditLog {
  rejectOperation: string | undefined;
  rejectOperations: readonly string[] = [];
  holdOperation: string | undefined;
  readonly entered = deferred();
  readonly release = deferred();
  readonly settled: string[] = [];

  override async appendCritical(entry: Parameters<AuditLog["appendCritical"]>[0]) {
    if (entry.operation === this.holdOperation) {
      this.entered.resolve();
      await this.release.promise;
    }
    if (entry.operation === this.rejectOperation || this.rejectOperations.includes(entry.operation)) throw new Error(SECRET);
    const result = await super.appendCritical(entry);
    this.settled.push(entry.operation);
    return result;
  }
}

async function fixture(empty = false) {
  const storage = new ScheduledStorage();
  const known = new KnownSignersStore(storage, MASTER, { partition: "memory_provenance" });
  const publicKey = ed25519.getPublicKey(new Uint8Array(KEY_BYTES).fill(SIGNER_FIXTURE_BYTE));
  const did = publicKeyToDid(publicKey);
  const key = knownSignerStorageKey(did, "memory_provenance");
  if (!empty) await known.persistIfAbsent([{ did, publicKey }], "fixture");
  const before = await storage.read(KNOWN_SIGNERS_NAMESPACE, key);
  const cache = new Map(empty ? [] : [[did, publicKey]]);
  const audit = new ScheduledAudit(storage, MASTER);
  const forget = vi.fn((signer: string) => { cache.delete(signer); });
  const pruner = new MemoryProvenanceSignerPruner({
    storage, masterKey: MASTER, fortressId: "prune-fixture", knownSignersStore: known,
    resolveSignerPublicKey: (_identity, signer) => cache.get(signer),
    forgetSigner: forget, auditLog: audit,
  });
  const guard = vi.fn<MultiAgentIsolationGuard>(async () => ({ allowed: true }));
  const tool = createMemoryProvenanceSignerPruneTool({ pruner, auditLog: audit, isolationGuard: guard });
  return { storage, known, key, did, before, cache, audit, forget, pruner, guard, tool };
}

type Response = { content: Array<{ type: "text"; text: string }> };
function payload(response: Response): Record<string, unknown> {
  return JSON.parse(response.content[0]!.text) as Record<string, unknown>;
}
function expectFailure(response: Response, expected: Record<string, unknown>) {
  expect(response).toHaveProperty("isError", true);
  expect(payload(response)).toEqual(expected);
  expect(JSON.stringify(response)).not.toContain(SECRET);
}
async function expectUnchanged(f: Awaited<ReturnType<typeof fixture>>) {
  expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).toEqual(f.before);
  expect(f.storage.deleted).toBe(0);
  expect(f.forget).not.toHaveBeenCalled();
}

async function throughRouter(f: Awaited<ReturnType<typeof fixture>>) {
  const gateStorage = new MemoryStorage();
  const gate = new ApprovalGate(
    DEFAULT_POLICY,
    new BaselineTracker(gateStorage, MASTER),
    new CallbackApprovalChannel(async () => ({
      decision: "approve", decided_at: new Date().toISOString(), decided_by: "human",
    })),
    new AuditLog(gateStorage, MASTER),
    undefined, undefined, undefined,
    { currentSessionBinding: () => ({
      identity_id: "prune-fixture",
      requester_identity_fingerprint: fingerprintIdentityId("prune-fixture"),
    }) },
  );
  const server = createServer([f.tool], { gate, auditLog: f.audit });
  const client = new Client({ name: "signer-prune-witness", version: "1.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    return await client.callTool({ name: OPERATION, arguments: {} });
  } finally {
    await client.close();
    await server.close();
  }
}

describe("signer prune outcome ownership", () => {

  it.each(["location-bound", "interrupted-import"] as const)("keeps %s refusal before writes", async guard => {
    const f = await fixture();
    if (guard === "interrupted-import") {
      await f.storage.write(EXIT_IMPORT_JOURNAL_NAMESPACE, "interrupted", new TextEncoder().encode("{}"));
    }
    const operation = vi.fn(async () => undefined);
    const write = vi.spyOn(f.storage, "write");
    const remove = vi.spyOn(f.storage, "delete");
    const location = { namespace: KNOWN_SIGNERS_NAMESPACE, key: f.key };
    const locations = guard === "location-bound"
      ? Array.from({ length: MAX_EXIT_IMPORT_JOURNAL_LOCATIONS + 1 }, () => location) : [location];
    await expect(runJournaledMemoryProvenanceSignerPrune({
      storage: f.storage, identityId: "fixture", locations, operation,
    })).rejects.toMatchObject({ name: "SignerPruneError", outcome: { phase: "not-started" } });
    expect(operation).not.toHaveBeenCalled();
    expect(write).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
    await expectUnchanged(f);
  });

  it.each(["journal-write", "journal-unknown", "stale-marker-read"] as const)("requires recovery after %s uncertainty", async fault => {
    const f = await fixture();
    f.storage.fault = fault;
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), { error: "deletion state uncertain, recovery required" });
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(fault === "stale-marker-read" ? 0 : ONE_JOURNAL);
    expect(f.audit.settled).toEqual([PLAN]);
    await expectUnchanged(f);
  });

  it("denies a rejected journal publication only after proving absence", async () => {
    const f = await fixture();
    f.storage.fault = "journal-lost";
    const prune = vi.spyOn(f.pruner, "prune");
    const response = await f.tool.handler({}, undefined, APPROVAL);
    expect(payload(response)).toMatchObject({ denied: true });
    expect(f.audit.settled).toEqual([PLAN, OPERATION]);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    await expectUnchanged(f);
    await expect(prune.mock.results[0]!.value).rejects.toMatchObject({ name: "SignerPruneError", outcome: { phase: "not-started" } });
  });

  it("retains recovery status until rollback journal cleanup completes", async () => {
    const f = await fixture();
    f.storage.fault = "rollback-cleanup";
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), { error: "deletion state uncertain, recovery required" });
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).toEqual(f.before);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(ONE_JOURNAL);
    expect(f.storage.deleted).toBe(ONE_SIGNER);
    expect(f.forget).not.toHaveBeenCalled();
    expect(f.audit.settled).toEqual([PLAN]);
  });

  it("requires recovery for a conflicting activation marker", async () => {
    const f = await fixture();
    f.storage.fault = "activation-conflict";
    const prune = vi.spyOn(f.pruner, "prune");
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), { error: "deletion state uncertain, recovery required" });
    expect(await f.known.lookup(f.did)).toBeNull();
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(ONE_JOURNAL);
    expect(f.audit.settled).toEqual([PLAN]);
    expect(f.forget).not.toHaveBeenCalled();
    await expect(prune.mock.results[0]!.value).rejects.toMatchObject({ name: "SignerPruneError", outcome: { phase: "uncertain" } });
  });

  it("restores exact pre-images after activation-lost before audited denial", async () => {
    const f = await fixture();
    f.storage.fault = "activation-lost";
    const prune = vi.spyOn(f.pruner, "prune");
    f.audit.holdOperation = OPERATION;
    let returned = false;
    const work = f.tool.handler({}, undefined, APPROVAL).then(result => { returned = true; return result; });
    await new Promise<void>(resolve => setImmediate(resolve));
    const pending = !returned;
    f.audit.release.resolve();
    const response = await work;
    expect(pending).toBe(true);
    expect(payload(response)).toMatchObject({ denied: true });
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).toEqual(f.before);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    expect(f.storage.deleted).toBe(ONE_SIGNER);
    expect(f.audit.settled).toEqual([PLAN, OPERATION]);
    expect(f.forget).not.toHaveBeenCalled();
    await expect(prune.mock.results[0]!.value).rejects.toMatchObject({ name: "SignerPruneError", outcome: { phase: "rolled-back" } });
  });

  it("keeps raw storage causes out of default error rendering", async () => {
    const f = await fixture();
    f.storage.fault = "rollback";
    const error: unknown = await f.pruner.prune(APPROVAL).catch(cause => cause);
    expect(error).toBeInstanceOf(SignerPruneError);
    const failure = error as SignerPruneError;
    expect(failure.message).toBe("signer prune failed");
    expect(failure.message).not.toContain(SECRET);
    expect(String(failure)).not.toContain(SECRET);
    expect(failure.cause).toBeInstanceOf(SignerPruneError);
    expect((failure.cause as SignerPruneError).cause).toMatchObject({ message: SECRET });
  });

  it("tries every cache entry and awaits the commit audit after a cache fault", async () => {
    const f = await fixture();
    const otherSeed = SIGNER_FIXTURE_BYTE + 1; // Independent second signer.
    const publicKey = ed25519.getPublicKey(new Uint8Array(KEY_BYTES).fill(otherSeed));
    const did = publicKeyToDid(publicKey);
    await f.known.persistIfAbsent([{ did, publicKey }], "fixture");
    f.cache.set(did, publicKey);
    const signerCount = f.cache.size;
    f.forget.mockImplementationOnce(() => { throw new Error(SECRET); });
    f.audit.holdOperation = COMPLETE;
    let returned = false;
    const work = f.tool.handler({}, undefined, APPROVAL).then(result => { returned = true; return result; });
    await new Promise<void>(resolve => setImmediate(resolve));
    const pending = !returned;
    f.audit.release.resolve();
    const response = await work;
    expect(pending).toBe(true);
    expect(f.forget).toHaveBeenCalledTimes(signerCount);
    expect(f.storage.deleted).toBe(signerCount);
    expect(f.cache.size).toBe(ONE_SIGNER);
    expectFailure(response, { error: "deletion committed, finalization unavailable", committed: true, audited: true });
    const rows = (await f.audit.query({ operation_type: COMPLETE })).entries;
    expect(rows).toHaveLength(ONE_APPEND);
    expect(rows[0]!.details).toMatchObject({ deleted: signerCount, finalization_failed: true });
  });

  it("keeps empty-plan finalization not started after audit rejection", async () => {
    const f = await fixture(true);
    f.audit.rejectOperation = COMPLETE;
    await expect(f.pruner.prune(APPROVAL)).rejects.toMatchObject({
      name: "SignerPruneError", outcome: { phase: "not-started", finalization: "not-started", completionAudit: "failed" },
    });
    await expectUnchanged(f);
  });

  it.each(["isolation", "authorization"] as const)("settles the %s denial audit before returning", async kind => {
    const f = await fixture();
    if (kind === "isolation") f.guard.mockResolvedValue({ allowed: false, reason: "owner_scope_conflict" });
    const append = vi.spyOn(f.audit, "appendCritical");
    const prune = vi.spyOn(f.pruner, "prune");
    f.audit.holdOperation = OPERATION;
    let returned = false;
    const work = f.tool.handler({}, undefined, kind === "isolation" ? APPROVAL : undefined)
      .then(result => { returned = true; return result; });
    // A base implementation returns without entering the denial append; use a
    // bounded event-loop turn rather than waiting forever for absent behavior.
    await new Promise<void>(resolve => setImmediate(resolve));
    const pending = !returned;
    f.audit.release.resolve();
    const result = await work;
    expect(append).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ operation: OPERATION, result: "failure" }));
    expect(pending).toBe(true);
    expect(prune).not.toHaveBeenCalled();
    expect(payload(result)).toMatchObject({ denied: true });
    expect(f.audit.settled).toEqual([OPERATION]);
    await expectUnchanged(f);
  });

  it.each(["isolation", "authorization", "guard-error"] as const)("reports audit unavailability for %s denial", async kind => {
    const f = await fixture();
    if (kind === "isolation") f.guard.mockResolvedValue({ allowed: false, reason: "owner_scope_conflict" });
    if (kind === "guard-error") f.guard.mockRejectedValue(new Error(SECRET));
    const prune = vi.spyOn(f.pruner, "prune");
    const append = vi.spyOn(f.audit, "appendCritical");
    f.audit.rejectOperation = OPERATION;
    const work = f.tool.handler({}, undefined, kind === "authorization" ? undefined : APPROVAL);
    await expect(work).resolves.toHaveProperty("isError", true);
    const response = await work;
    expectFailure(response, { error: "audit unavailable" });
    expect(append).toHaveBeenCalledTimes(ONE_APPEND);
    expect(prune).not.toHaveBeenCalled();
    await expectUnchanged(f);
  });

  it.each(["scan", "relist", "preflight"] as const)("audits a proved no-mutation %s failure", async fault => {
    const f = await fixture();
    f.storage.fault = fault;
    const result = await f.tool.handler({}, undefined, APPROVAL);
    expect(payload(result)).toMatchObject({ denied: true });
    expect(f.audit.settled).toEqual([OPERATION]);
    await expectUnchanged(f);
  });

  it.each(["scan", "relist", "preflight", "validation", "plan"] as const)("does not hide failure-audit rejection after %s refusal", async fault => {
    const f = await fixture();
    if (fault === "scan" || fault === "relist" || fault === "preflight") f.storage.fault = fault;
    f.audit.rejectOperations = fault === "plan" ? [PLAN, OPERATION] : [OPERATION];
    const approval = fault === "validation" ? { approvalAuditId: "invalid/approval" } : APPROVAL;
    expectFailure(await f.tool.handler({}, undefined, approval), { error: "audit unavailable" });
    await expectUnchanged(f);
    expect(f.storage.journalWrites).toBe(0);
  });

  it("refuses invalid approval with audited evidence and no mutation", async () => {
    const f = await fixture();
    const result = await f.tool.handler({}, undefined, { approvalAuditId: "invalid/approval" });
    expect(payload(result)).toMatchObject({ denied: true });
    expect(f.audit.settled).toEqual([OPERATION]);
    await expectUnchanged(f);
  });

  it("keeps journal publication and deletion behind a settled plan", async () => {
    const f = await fixture();
    f.audit.rejectOperation = PLAN;
    const result = await f.tool.handler({}, undefined, APPROVAL);
    expect(payload(result)).toMatchObject({ denied: true });
    expect(f.storage.journalWrites).toBe(0);
    expect(f.audit.settled).toEqual([OPERATION]);
    await expectUnchanged(f);
  });

  it("audits an empty successful plan without inventing a committed deletion", async () => {
    const f = await fixture(true);
    const result = await f.tool.handler({}, undefined, APPROVAL);
    expect(payload(result)).toMatchObject({ pruned: true, deleted: 0 });
    expect(f.audit.settled).toEqual([PLAN, COMPLETE]);
    expect(f.storage.journalWrites).toBe(0);
  });

  it("reports an empty-plan completion failure without claiming deletion", async () => {
    const f = await fixture(true);
    f.audit.rejectOperation = COMPLETE;
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), { error: "audit unavailable" });
    expect(f.audit.settled).toEqual([PLAN]);
    await expectUnchanged(f);
  });

  it("restores exact pre-images before an audited rollback denial", async () => {
    const f = await fixture();
    f.storage.fault = "rollback";
    const result = await f.tool.handler({}, undefined, APPROVAL);
    expect(payload(result)).toMatchObject({ denied: true });
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).toEqual(f.before);
    expect(f.storage.deleted).toBe(ONE_SIGNER);
    expect(f.audit.settled).toEqual([PLAN, OPERATION]);
    expect(f.forget).not.toHaveBeenCalled();
  });

  it.each(["rollback-write", "rollback-silent", "diverged"] as const)("requires recovery for %s restoration", async fault => {
    const f = await fixture();
    f.storage.fault = fault;
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), { error: "deletion state uncertain, recovery required" });
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).not.toEqual(f.before);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(ONE_JOURNAL);
    expect(f.audit.settled).toEqual([PLAN]);
    expect(f.forget).not.toHaveBeenCalled();
  });

  it("preserves commitment when journal cleanup fails after activation", async () => {
    const f = await fixture();
    f.storage.fault = "cleanup";
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), {
      error: "deletion committed, cleanup incomplete", committed: true, audited: false,
    });
    expect(await f.known.lookup(f.did)).toBeNull();
    expect(await f.storage.list(EXIT_IMPORT_NAMESPACE)).toHaveLength(ONE_SIGNER);
    expect(f.forget).not.toHaveBeenCalled();
    expect(f.audit.settled).toEqual([PLAN]);
  });

  it.each(["activation-write", "activation-unknown"] as const)("preserves durable evidence after %s rejection", async fault => {
    const f = await fixture();
    f.storage.fault = fault;
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), fault === "activation-write" ? {
      error: "deletion committed, cleanup incomplete", committed: true, audited: false,
    } : { error: "deletion state uncertain, recovery required" });
    expect(await f.known.lookup(f.did)).toBeNull();
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(ONE_JOURNAL);
    expect(f.audit.settled).toEqual([PLAN]);
  });

  it.each([false, true])("records committed deletion when cache finalization throws with audit rejection=%s", async rejectAudit => {
    const f = await fixture();
    f.forget.mockImplementation(() => { throw new Error(SECRET); });
    if (rejectAudit) f.audit.rejectOperation = COMPLETE;
    const append = vi.spyOn(f.audit, "appendCritical");
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), {
      error: "deletion committed, finalization unavailable", committed: true, audited: !rejectAudit,
    });
    expect(await f.known.lookup(f.did)).toBeNull();
    expect(f.cache.has(f.did)).toBe(true);
    expect(append).toHaveBeenLastCalledWith(expect.objectContaining({
      operation: COMPLETE, result: "success", details: expect.objectContaining({
        deleted: ONE_SIGNER, finalization_failed: true,
      }),
    }));
    expect(f.audit.settled).toEqual(rejectAudit ? [PLAN] : [PLAN, COMPLETE]);
    const rows = (await f.audit.query({ operation_type: COMPLETE })).entries;
    expect(rows).toHaveLength(rejectAudit ? 0 : ONE_APPEND);
    if (!rejectAudit) expect(rows[0]!.details).toMatchObject({ deleted: ONE_SIGNER, finalization_failed: true });
  });

  it.each([false, true])("preserves committed deletion on completion-audit failure through router=%s", async routed => {
    const f = await fixture();
    f.audit.rejectOperation = COMPLETE;
    const response = routed ? await throughRouter(f) : await f.tool.handler({}, undefined, APPROVAL);
    expect(response).toHaveProperty("isError", true);
    expect(response.content).toEqual([{ type: "text", text: JSON.stringify({
      error: "deletion committed, audit unavailable", committed: true, audited: false,
    }, null, 2) }]);
    expect(JSON.stringify(response)).not.toContain(SECRET);
    expect(JSON.stringify(response)).not.toContain(f.did);
    expect(await f.known.lookup(f.did)).toBeNull();
    expect(f.cache.has(f.did)).toBe(false);
    expect(f.audit.settled).toEqual([PLAN]);
  });

  it("preserves isolation audit failure through SDK dispatch", async () => {
    const f = await fixture();
    f.guard.mockResolvedValue({ allowed: false, reason: "owner_scope_conflict" });
    f.audit.rejectOperation = OPERATION;
    const response = await throughRouter(f);
    expect(response).toHaveProperty("isError", true);
    expect(response.content).toEqual([{ type: "text", text: JSON.stringify({ error: "audit unavailable" }, null, 2) }]);
    await expectUnchanged(f);
  });

  it.each(["success", "audit", "cleanup", "cache", "uncertain"] as const)("retains %s evidence across outer release failure", async prior => {
    const f = await fixture();
    f.storage.releaseFault = true;
    if (prior === "audit") f.audit.rejectOperation = COMPLETE;
    if (prior === "cleanup") f.storage.fault = "cleanup";
    if (prior === "cache") f.forget.mockImplementation(() => { throw new Error(SECRET); });
    if (prior === "uncertain") f.storage.fault = "rollback-write";
    const errors = {
      success: "deletion committed, lock finalization unavailable",
      audit: "deletion committed, audit unavailable",
      cleanup: "deletion committed, cleanup incomplete",
      cache: "deletion committed, finalization unavailable",
      uncertain: "deletion state uncertain, recovery required",
    };
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), {
      error: errors[prior], ...(prior === "uncertain" ? {} : { committed: true, audited: prior === "success" || prior === "cache" }),
    });
    expect(await f.storage.read(KNOWN_SIGNERS_NAMESPACE, f.key)).toBeNull();
  });

  it("retains empty-plan audit evidence across outer release failure", async () => {
    const f = await fixture(true);
    f.storage.releaseFault = true;
    expectFailure(await f.tool.handler({}, undefined, APPROVAL), {
      error: "lock finalization unavailable", committed: false, audited: true,
    });
  });

  it.each(["resolve", "reject"] as const)("owns delayed completion %s across repeated admissions", async settlement => {
    const f = await fixture();
    f.audit.holdOperation = COMPLETE;
    let returned = 0;
    const cancellation = new AbortController();
    const first = f.tool.handler({}, undefined, { ...APPROVAL, signal: cancellation.signal })
      .then(result => { returned++; return result; });
    await f.audit.entered.promise;
    cancellation.abort();
    const later = Array.from({ length: ADMISSION_WAVES - 1 }, () =>
      f.tool.handler({}, undefined, APPROVAL).then(result => { returned++; return result; }));
    await new Promise<void>(resolve => setImmediate(resolve));
    const beforeSettlement = { returned, deletes: f.storage.deleted, journals: f.storage.journalWrites };
    if (settlement === "resolve") f.audit.release.resolve();
    else f.audit.release.reject(new Error(SECRET));
    const [result, ...remaining] = await Promise.all([first, ...later]);
    expect(beforeSettlement).toEqual({ returned: 0, deletes: ONE_SIGNER, journals: ONE_JOURNAL });
    expect(f.storage.maximumActive).toBe(ONE_SIGNER);
    expect(f.storage.deleted).toBe(ONE_SIGNER);
    expect(f.cache.size).toBe(0);
    expect(await f.storage.list(EXIT_IMPORT_JOURNAL_NAMESPACE)).toHaveLength(0);
    if (settlement === "resolve") {
      expect(payload(result!)).toMatchObject({ pruned: true, deleted: ONE_SIGNER });
      expect(f.audit.settled.filter(op => op === COMPLETE)).toHaveLength(ADMISSION_WAVES);
      for (const empty of remaining) expect(payload(empty)).toMatchObject({ pruned: true, deleted: 0 });
    } else {
      expectFailure(result!, { error: "deletion committed, audit unavailable", committed: true, audited: false });
      for (const empty of remaining) expectFailure(empty, { error: "audit unavailable" });
    }
  });
});
