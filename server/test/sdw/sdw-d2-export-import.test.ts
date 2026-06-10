/**
 * SDW D2 — Option A+ export/import tests (Erik-ratified 2026-06-09).
 *
 * Every ratified invariant has a test that fails without the implementation:
 * 1. Single Tier-1 approval freezes a ciphertext-inventory digest computed
 *    WITHOUT decrypting anything.
 * 2. Drift between approval and signing → export fails closed (nothing
 *    decrypted, signed, or written; honest audit event with both digests).
 * 3. Deny ⇒ nothing decrypted, signed, or written.
 * 4. Manifest signed exclusively through core/identity.ts sign() — key
 *    material never enters SDW export code, responses, or logs.
 * 5. Import verifies the manifest signature BEFORE any approval prompt;
 *    rejected bodies are never logged verbatim.
 * 6. Approval-channel payloads carry metadata only (hard constraint #1).
 */

import { mkdtemp, readFile, readdir, rm, writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { ApprovalGate } from "../../src/principal-policy/gate.js";
import { BaselineTracker } from "../../src/principal-policy/baseline.js";
import {
  AutoApproveChannel,
  CallbackApprovalChannel,
} from "../../src/principal-policy/approval-channel.js";
import { DEFAULT_POLICY } from "../../src/principal-policy/loader.js";
import type { ApprovalRequest } from "../../src/principal-policy/types.js";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { generateRandomKey } from "../../src/core/random.js";
import { createIdentity, verify } from "../../src/core/identity.js";
import { fromBase64url, bytesToString } from "../../src/core/encoding.js";
import type { ToolDefinition } from "../../src/router.js";
import {
  ApprovalProofStore,
  FIXED_DENIAL_MESSAGE,
  fingerprintIdentityId,
  normalizedArgsHash,
  type SessionBinding,
} from "../../src/agent-native/safety-base.js";

import { SdwWorkingStateStore } from "../../src/sdw/working-state-store.js";
import { SdwDocumentCorpusStore } from "../../src/sdw/document-corpus-store.js";
import { SdwQueryHistoryStore } from "../../src/sdw/query-history-store.js";
import type { SdwTxn, SdwTransactional } from "../../src/sdw/lmdb-backend.js";
import { assertSdwRawWriteAuthorized, prepareSdwBackendWrite } from "../../src/sdw/write-gate.js";
import { stateKey } from "../../src/sdw/grammar.js";
import {
  SDW_DOCUMENT_CORPUS_NAMESPACE,
  SDW_QUERY_HISTORY_NAMESPACE,
  SDW_WORKING_STATE_NAMESPACE,
  type SdwWorkingStateRecord,
  type SdwDocumentRecord,
} from "../../src/sdw/records.js";
import {
  buildSignedSdwExportBundle,
  computeSdwExportRecordHash,
  enumerateSdwExportInventory,
  sdwManifestBodyDigest,
  sdwManifestCanonicalBytes,
  SdwExportScopeDriftError,
  type SdwExportInventorySource,
  type SdwStateExportBundle,
  type SdwExportSigningKey,
} from "../../src/sdw/export.js";
import {
  decodeSdwExportBundle,
  importSdwExportBundle,
  verifySdwExportManifest,
  SdwImportVerificationError,
} from "../../src/sdw/import.js";
import { createSdwTools, type SdwToolsOptions } from "../../src/sdw/tools.js";

const SOURCE_FORTRESS = "fortress:source";
const TARGET_FORTRESS = "fortress:target";
const NOW = "2026-06-09T00:00:00.000Z";

const tempDirs: string[] = [];
afterEach(async () => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop()!;
    await rm(dir, { recursive: true, force: true });
  }
});

async function makeExportDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "sdw-d2-test-"));
  tempDirs.push(dir);
  return dir;
}

/**
 * In-memory vault implementing both the async StorageBackend (writes pass the
 * SDW write gate, mirroring MemoryStorage) and the synchronous
 * SdwExportInventorySource the gate-time enumeration uses.
 */
class TestSdwVault implements StorageBackend, SdwTransactional, SdwExportInventorySource {
  private readonly data = new Map<string, Uint8Array>();

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.data.set(
      `${namespace}\0${key}`,
      new Uint8Array(assertSdwRawWriteAuthorized(namespace, key, data)),
    );
  }

  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const value = this.data.get(`${namespace}\0${key}`);
    return value === undefined ? null : new Uint8Array(value);
  }

  async delete(namespace: string, key: string): Promise<boolean> {
    return this.data.delete(`${namespace}\0${key}`);
  }

  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    const entries: StorageEntryMeta[] = [];
    for (const [composite, data] of this.data) {
      const [entryNamespace, key] = composite.split("\0", 2) as [string, string];
      if (entryNamespace !== namespace || !key.startsWith(prefix)) continue;
      entries.push({ namespace, key, size_bytes: data.byteLength, modified_at: NOW });
    }
    return entries.sort((a, b) => a.key.localeCompare(b.key));
  }

  async exists(namespace: string, key: string): Promise<boolean> {
    return this.data.has(`${namespace}\0${key}`);
  }

  async totalSize(): Promise<number> {
    let total = 0;
    for (const value of this.data.values()) total += value.byteLength;
    return total;
  }

  async sdwTransaction<T>(fn: (txn: SdwTxn) => Promise<T>): Promise<T> {
    const txn: SdwTxn = {
      write: async (namespace, key, data) => this.write(namespace, key, data),
      writePersistable: async (persistable, encryptionKey, fortressId) => {
        const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
        await this.write(prepared.namespace, prepared.storageKey, prepared.data);
      },
      read: async (namespace, key) => this.read(namespace, key),
      delete: async (namespace, key) => this.delete(namespace, key),
    };
    return fn(txn);
  }

  listNamespaceSync(namespace: string): ReadonlyArray<{ key: string; data: Uint8Array }> {
    const entries: Array<{ key: string; data: Uint8Array }> = [];
    for (const [composite, data] of this.data) {
      const [entryNamespace, key] = composite.split("\0", 2) as [string, string];
      if (entryNamespace !== namespace) continue;
      entries.push({ key, data: new Uint8Array(data) });
    }
    return entries;
  }

  /** Test-only raw mutation (simulating an external writer / disk adversary). */
  rawSetForTest(namespace: string, key: string, data: Uint8Array): void {
    this.data.set(`${namespace}\0${key}`, new Uint8Array(data));
  }

  countForTest(): number {
    return this.data.size;
  }

  keysForTest(namespace: string): string[] {
    return this.listNamespaceSync(namespace).map((entry) => entry.key);
  }
}

function workingStateRecord(stateId: string, summary: string): SdwWorkingStateRecord {
  return {
    kind: "working_state",
    version: 1,
    state_id: stateId,
    scope: "task",
    owner_ref: "agent:test",
    status: "active",
    created_at: NOW,
    updated_at: NOW,
    content_type: "application/json",
    state: { kind: "task_checkpoint", task_ref: "task-1", summary },
  };
}

function documentRecord(documentId: string): SdwDocumentRecord {
  return {
    kind: "document",
    version: 1,
    document_id: documentId,
    source: { kind: "paste", title: "test-doc" },
    content_hash: "abc123",
    chunk_count: 0,
    created_at: NOW,
    updated_at: NOW,
  };
}

interface Fortress {
  vault: TestSdwVault;
  masterKey: Uint8Array;
  auditLog: AuditLog;
  workingStore: SdwWorkingStateStore;
  corpusStore: SdwDocumentCorpusStore;
  queryStore: SdwQueryHistoryStore;
}

function makeFortress(fortressId: string): Fortress {
  const vault = new TestSdwVault();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(new MemoryStorage(), generateRandomKey());
  return {
    vault,
    masterKey,
    auditLog,
    workingStore: new SdwWorkingStateStore({ storage: vault, masterKey, fortressId }),
    corpusStore: new SdwDocumentCorpusStore({ storage: vault, masterKey, fortressId }),
    queryStore: new SdwQueryHistoryStore({ storage: vault, masterKey, fortressId }),
  };
}

interface Signing {
  signingKey: SdwExportSigningKey;
  publicKeyB64: string;
  resolvePublicKey: (keyRef: string) => Uint8Array | null;
}

function makeSigning(): Signing {
  const keyEncryptionKey = generateRandomKey();
  const { publicIdentity, storedIdentity } = createIdentity(
    "sdw-export-signer",
    keyEncryptionKey,
    "passphrase",
  );
  return {
    signingKey: {
      keyRef: publicIdentity.identity_id,
      encryptedPrivateKey: storedIdentity.encrypted_private_key,
      encryptionKey: keyEncryptionKey,
    },
    publicKeyB64: publicIdentity.public_key,
    resolvePublicKey: (keyRef) =>
      keyRef === publicIdentity.identity_id
        ? fromBase64url(publicIdentity.public_key)
        : null,
  };
}

const OPERATOR_SESSION: SessionBinding = {
  identity_id: "operator",
  requester_identity_fingerprint: fingerprintIdentityId("operator"),
};

function makeGate(
  auditLog: AuditLog,
  channel: AutoApproveChannel | CallbackApprovalChannel,
  proofStore?: ApprovalProofStore,
): ApprovalGate {
  const baseline = new BaselineTracker(new MemoryStorage(), generateRandomKey());
  return new ApprovalGate(
    DEFAULT_POLICY,
    baseline,
    channel,
    auditLog,
    undefined,
    undefined,
    undefined,
    {
      approvalProofStore: proofStore ?? new ApprovalProofStore(),
      currentSessionBinding: () => OPERATOR_SESSION,
    },
  );
}

type RouterCallResult =
  | { kind: "denied_pre_prompt" }
  | { kind: "denied_gate" }
  | { kind: "handled"; payload: Record<string, unknown> };

/**
 * Mirrors the exact router order in src/router.ts (createServer's
 * CallToolRequestSchema handler): approvalTargetArgs runs first (a throw
 * denies WITHOUT prompting), the gate evaluates the gate-time args, denial
 * short-circuits before the handler, and only then does the handler run with
 * the ORIGINAL args.
 */
async function callThroughGate(
  tool: ToolDefinition,
  args: Record<string, unknown>,
  gate: ApprovalGate,
  approvalRef?: string,
): Promise<RouterCallResult> {
  let gateArgs: Record<string, unknown>;
  try {
    gateArgs = tool.approvalTargetArgs?.(args) ?? args;
  } catch {
    return { kind: "denied_pre_prompt" };
  }
  const result = await gate.evaluate(
    tool.name,
    gateArgs,
    approvalRef ? { approval_ref: approvalRef } : undefined,
  );
  if (!result.allowed) return { kind: "denied_gate" };
  const response = await tool.handler(args);
  return {
    kind: "handled",
    payload: JSON.parse(response.content[0]!.text) as Record<string, unknown>,
  };
}

function findTool(tools: ToolDefinition[], name: string): ToolDefinition {
  const tool = tools.find((candidate) => candidate.name === name);
  if (!tool) throw new Error(`missing tool ${name}`);
  return tool;
}

function expectThrowCategory(fn: () => unknown, category: string): void {
  let caught: unknown;
  try {
    fn();
  } catch (error) {
    caught = error;
  }
  expect(caught).toBeInstanceOf(SdwImportVerificationError);
  expect((caught as SdwImportVerificationError).category).toBe(category);
}

async function seedSourceVault(fortress: Fortress): Promise<void> {
  await fortress.workingStore.put(workingStateRecord("state-1", "first checkpoint"), "user_content");
  await fortress.workingStore.put(workingStateRecord("state-2", "second checkpoint"), "agent_derived_clean");
  await fortress.corpusStore.putDocument(documentRecord("doc-1"), "user_content");
  await fortress.queryStore.appendFromAudit({
    audit_event_id: "audit-evt-1",
    query_id: "query-1",
    occurred_at: NOW,
    actor: { kind: "operator" },
    channel: "mcp",
    operation: "state_read",
    prompt_or_query: "what is in the corpus",
  });
}

interface Harness {
  source: Fortress;
  signing: Signing;
  exportDir: string;
  tools: ToolDefinition[];
  exportTool: ToolDefinition;
  importTool: ToolDefinition;
  deleteTool: ToolDefinition;
}

async function makeExportHarness(
  overrides: Partial<SdwToolsOptions> = {},
): Promise<Harness> {
  const source = makeFortress(SOURCE_FORTRESS);
  await seedSourceVault(source);
  const signing = makeSigning();
  const exportDir = await makeExportDir();
  const tools = createSdwTools({
    storage: source.vault,
    inventory: source.vault,
    auditLog: source.auditLog,
    fortressId: SOURCE_FORTRESS,
    exportDir,
    signingKey: signing.signingKey,
    resolvePublicKey: signing.resolvePublicKey,
    resolveSourceMasterKey: () => null,
    targetMasterKey: source.masterKey,
    ...overrides,
  });
  return {
    source,
    signing,
    exportDir,
    tools,
    exportTool: findTool(tools, "sdw_export"),
    importTool: findTool(tools, "sdw_import"),
    deleteTool: findTool(tools, "sdw_export_delete"),
  };
}

async function auditOps(auditLog: AuditLog, operation: string) {
  await auditLog.flush();
  const { entries } = await auditLog.query({ operation_type: operation, limit: 100 });
  return entries;
}

// ─────────────────────────────────────────────────────────────────────────────

describe("SDW D2 policy enrollment", () => {
  it("classifies sdw_export, sdw_import, sdw_export_delete as Tier 1 in the default policy", () => {
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("sdw_export");
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("sdw_import");
    expect(DEFAULT_POLICY.tier1_always_approve).toContain("sdw_export_delete");
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("sdw_export");
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("sdw_import");
    expect(DEFAULT_POLICY.tier3_always_allow).not.toContain("sdw_export_delete");
  });
});

describe("SDW D2 ciphertext-inventory digest (invariant 1)", () => {
  it("computes the scope digest without decrypting and binds namespace, key, ciphertext, and length canonically", async () => {
    const fortress = makeFortress(SOURCE_FORTRESS);
    await seedSourceVault(fortress);

    const inventory = enumerateSdwExportInventory(fortress.vault);
    expect(inventory.record_count).toBe(4);
    expect(inventory.total_bytes).toBeGreaterThan(0);

    // Namespace request order must not matter (canonical ordering).
    const reordered = enumerateSdwExportInventory(fortress.vault, [
      SDW_DOCUMENT_CORPUS_NAMESPACE,
      SDW_WORKING_STATE_NAMESPACE,
      SDW_QUERY_HISTORY_NAMESPACE,
    ]);
    const forward = enumerateSdwExportInventory(fortress.vault, [
      SDW_WORKING_STATE_NAMESPACE,
      SDW_QUERY_HISTORY_NAMESPACE,
      SDW_DOCUMENT_CORPUS_NAMESPACE,
    ]);
    expect(reordered.scope_digest).toBe(forward.scope_digest);

    // Swapping two records' ciphertexts between keys MUST change the digest
    // (anti record-reordering second preimage).
    const keys = fortress.vault.keysForTest(SDW_WORKING_STATE_NAMESPACE);
    const [keyA, keyB] = keys as [string, string];
    const bytesA = (await fortress.vault.read(SDW_WORKING_STATE_NAMESPACE, keyA))!;
    const bytesB = (await fortress.vault.read(SDW_WORKING_STATE_NAMESPACE, keyB))!;
    const before = enumerateSdwExportInventory(fortress.vault).scope_digest;
    fortress.vault.rawSetForTest(SDW_WORKING_STATE_NAMESPACE, keyA, bytesB);
    fortress.vault.rawSetForTest(SDW_WORKING_STATE_NAMESPACE, keyB, bytesA);
    const after = enumerateSdwExportInventory(fortress.vault).scope_digest;
    expect(after).not.toBe(before);

    // Moving a ciphertext to another namespace under the same key also changes it.
    fortress.vault.rawSetForTest(SDW_WORKING_STATE_NAMESPACE, keyA, bytesA);
    fortress.vault.rawSetForTest(SDW_WORKING_STATE_NAMESPACE, keyB, bytesB);
    expect(enumerateSdwExportInventory(fortress.vault).scope_digest).toBe(before);
    fortress.vault.rawSetForTest(SDW_DOCUMENT_CORPUS_NAMESPACE, keyA, bytesA);
    expect(enumerateSdwExportInventory(fortress.vault).scope_digest).not.toBe(before);
  });

  it("excludes environment-bound state: catalog/meta namespaces are not exportable and chain-head keys are skipped", async () => {
    const fortress = makeFortress(SOURCE_FORTRESS);
    await seedSourceVault(fortress);

    expect(() => enumerateSdwExportInventory(fortress.vault, ["_sdw_catalog"])).toThrow();
    expect(() => enumerateSdwExportInventory(fortress.vault, ["_sdw_meta"])).toThrow();

    // appendFromAudit wrote a chain-head record; it must not be in scope.
    const queryKeys = fortress.vault.keysForTest(SDW_QUERY_HISTORY_NAMESPACE);
    expect(queryKeys.some((key) => key.startsWith("chain-head."))).toBe(true);
    const inventory = enumerateSdwExportInventory(fortress.vault, [SDW_QUERY_HISTORY_NAMESPACE]);
    expect(inventory.records.every((record) => !record.key.startsWith("chain-head."))).toBe(true);
    expect(inventory.records.some((record) => record.key.startsWith("query."))).toBe(true);
  });

  it("freezes the digest into the Tier-1 approval context shown to the human", async () => {
    const harness = await makeExportHarness();
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);

    const expected = enumerateSdwExportInventory(harness.source.vault);
    const result = await callThroughGate(
      harness.exportTool,
      { export_name: "migration-1" },
      gate,
    );
    expect(result.kind).toBe("handled");
    expect(prompts).toHaveLength(1);
    const summary = prompts[0]!.context.args_summary as Record<string, unknown>;
    expect(summary.scope_digest).toBe(expected.scope_digest);
    expect(summary.record_count).toBe(expected.record_count);
    expect(summary.total_bytes).toBe(expected.total_bytes);
  });
});

describe("SDW D2 export roundtrip + signing boundary (invariants 1, 4)", () => {
  it("exports an approved bundle whose signed manifest verifies against the canonical body bytes", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());

    const result = await callThroughGate(
      harness.exportTool,
      { export_name: "migration-1" },
      gate,
    );
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;
    expect(payload.exported).toBe(true);
    expect(payload.record_count).toBe(4);

    const bundleJson = await readFile(payload.destination_path as string, "utf8");
    const bundle = JSON.parse(bundleJson) as SdwStateExportBundle;

    // Signature verifies over EXACTLY the canonical manifest bytes — proving
    // sign() received the canonical body, nothing else.
    const canonical = sdwManifestCanonicalBytes(bundle.manifest.body);
    const valid = verify(
      canonical,
      fromBase64url(bundle.manifest.signature.value),
      fromBase64url(harness.signing.publicKeyB64),
    );
    expect(valid).toBe(true);
    expect(bundle.manifest.signature.alg).toBe("ed25519");
    expect(bundle.manifest.signature.key_ref).toBe(harness.signing.signingKey.keyRef);
    expect(payload.manifest_body_digest).toBe(sdwManifestBodyDigest(bundle.manifest.body));

    // The chain ties together: approval → scope digest → completion event.
    const scopeEvents = await auditOps(harness.source.auditLog, "sdw_export_scope_approved");
    const completedEvents = await auditOps(harness.source.auditLog, "sdw_export_completed");
    const approveEvents = await auditOps(harness.source.auditLog, "gate_approve:sdw_export");
    expect(approveEvents).toHaveLength(1);
    expect(scopeEvents).toHaveLength(1);
    expect(completedEvents).toHaveLength(1);
    expect(scopeEvents[0]!.details!.scope_digest).toBe(payload.scope_digest);
    expect(scopeEvents[0]!.details!.export_audit_event_id).toBe(bundle.export_audit_event_id);
    expect(completedEvents[0]!.details!.export_audit_event_id).toBe(bundle.export_audit_event_id);
    expect(completedEvents[0]!.details!.manifest_body_digest).toBe(payload.manifest_body_digest);
    expect(bundle.manifest.body.export_audit_event_id).toBe(bundle.export_audit_event_id);

    // No private-key material anywhere in the bundle or the MCP response.
    const encryptedKeyBlob = harness.signing.signingKey.encryptedPrivateKey;
    expect(bundleJson).not.toContain(encryptedKeyBlob.ct);
    expect(bundleJson).not.toContain(encryptedKeyBlob.iv);
    expect(JSON.stringify(payload)).not.toContain(encryptedKeyBlob.ct);

    // The manifest's record list matches the bundle exactly, and chain-head
    // records were excluded.
    expect(bundle.manifest.body.records).toHaveLength(4);
    expect(
      bundle.stores.flatMap((store) => store.records.map((record) => record.key)),
    ).not.toContain(
      harness.source.vault
        .keysForTest(SDW_QUERY_HISTORY_NAMESPACE)
        .find((key) => key.startsWith("chain-head."))!,
    );
  });

  it("imports into a second fortress with AAD rebound to the target identity", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "move" }, gate);
    expect(exported.kind).toBe("handled");
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundleBase64 = Buffer.from(await readFile(destination, "utf8")).toString("base64url");

    const target = makeFortress(TARGET_FORTRESS);
    const targetTools = createSdwTools({
      storage: target.vault,
      inventory: target.vault,
      auditLog: target.auditLog,
      fortressId: TARGET_FORTRESS,
      exportDir: await makeExportDir(),
      signingKey: makeSigning().signingKey,
      resolvePublicKey: harness.signing.resolvePublicKey,
      resolveSourceMasterKey: (ref) => (ref === "migration-slot" ? harness.source.masterKey : null),
      targetMasterKey: target.masterKey,
    });
    const importTool = findTool(targetTools, "sdw_import");
    const targetGate = makeGate(target.auditLog, new AutoApproveChannel());

    const imported = await callThroughGate(
      importTool,
      { bundle: bundleBase64, source_key_ref: "migration-slot" },
      targetGate,
    );
    expect(imported.kind).toBe("handled");
    const importPayload = (imported as { payload: Record<string, unknown> }).payload;
    expect(importPayload.imported).toBe(4);
    expect(importPayload.skipped_existing).toBe(0);
    expect(importPayload.source_fortress_id).toBe(SOURCE_FORTRESS);

    // Readable under the TARGET fortress identity + target master key.
    const recovered = await target.workingStore.get("task", "state-1");
    expect(recovered).not.toBeNull();
    expect(recovered!.state).toMatchObject({ summary: "first checkpoint" });
    const recoveredDoc = await target.corpusStore.getDocument("doc-1");
    expect(recoveredDoc).not.toBeNull();

    // NOT readable under the source identity: AAD was rebound, so decoding
    // the target bytes as the source fortress fails authentication.
    const sourceView = new SdwWorkingStateStore({
      storage: target.vault,
      masterKey: harness.source.masterKey,
      fortressId: SOURCE_FORTRESS,
    });
    await expect(sourceView.get("task", "state-1")).rejects.toMatchObject({
      category: "auth_failed",
    });

    const completed = await auditOps(target.auditLog, "sdw_import_completed");
    expect(completed).toHaveLength(1);
    expect(completed[0]!.details!.imported).toBe(4);
  });

  it("import skip/overwrite conflict accounting works on re-import", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "again" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundle = decodeSdwExportBundle(
      Buffer.from(await readFile(destination, "utf8")).toString("base64url"),
    );

    const target = makeFortress(TARGET_FORTRESS);
    const importParams = {
      bundle,
      storage: target.vault as StorageBackend,
      resolvePublicKey: harness.signing.resolvePublicKey,
      sourceMasterKey: harness.source.masterKey,
      targetMasterKey: target.masterKey,
      targetFortressId: TARGET_FORTRESS,
    };
    const first = await importSdwExportBundle(importParams);
    expect(first.imported).toBe(4);
    const second = await importSdwExportBundle(importParams);
    expect(second.imported).toBe(0);
    expect(second.skipped_existing).toBe(4);
    const third = await importSdwExportBundle({
      ...importParams,
      conflictResolution: "overwrite",
    });
    expect(third.imported).toBe(4);
    expect(third.overwritten).toBe(4);
  });

  it("export/import/tool sources never touch raw private-key material (structural scan)", async () => {
    const root = join(process.cwd(), "src", "sdw");
    const sources = new Map<string, string>();
    for (const file of await readdir(root)) {
      if (!file.endsWith(".ts")) continue;
      sources.set(file, await readFile(join(root, file), "utf8"));
    }
    const exportSource = sources.get("export.ts")!;
    const importSource = sources.get("import.ts")!;
    const toolsSource = sources.get("tools.ts")!;

    // export.ts: signs ONLY via core/identity sign(); no curve primitives, no
    // decryption of anything, no key-derivation, ever.
    expect(exportSource).toMatch(/import \{ sign \} from "\.\.\/core\/identity\.js"/);
    expect(exportSource).not.toMatch(/@noble/);
    expect(exportSource).not.toMatch(/\bed25519\s*\./); // no direct curve calls
    expect(exportSource).not.toMatch(/\bdecrypt\s*\(/); // never decrypts anything
    expect(exportSource).not.toMatch(/import\s*\{[^}]*\bdecrypt\b[^}]*\}/);
    expect(exportSource).not.toMatch(/derivePurposeKey|deriveNamespaceKey/);

    // import.ts: decrypts RECORD payloads only — never an identity key blob.
    expect(importSource).not.toMatch(/@noble/);
    expect(importSource).not.toMatch(/\bed25519\s*\./);
    expect(importSource).not.toMatch(/encryptedPrivateKey|encrypted_private_key/);

    // tools.ts: never decrypts and never references private-key fields.
    expect(toolsSource).not.toMatch(/\bdecrypt\s*\(/);
    expect(toolsSource).not.toMatch(/import\s*\{[^}]*\bdecrypt\b[^}]*\}/);
    expect(toolsSource).not.toMatch(/@noble/);
    expect(toolsSource).not.toMatch(/encrypted_private_key/);
  });
});

describe("SDW D2 drift fail-closed (invariant 2)", () => {
  it("aborts before signing when the vault changes between approval and assembly: honest audit, generic agent message, nothing written", async () => {
    const harness = await makeExportHarness();
    let approvedDigest = "";
    const channel = new CallbackApprovalChannel(async (request) => {
      approvedDigest = (request.context.args_summary as Record<string, unknown>)
        .scope_digest as string;
      // Mutate the vault DURING the human approval wait — the classic TOCTOU
      // window Option A+ closes.
      await harness.source.workingStore.put(
        workingStateRecord("state-3", "smuggled write during approval"),
        "user_content",
      );
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);

    const result = await callThroughGate(harness.exportTool, { export_name: "racy" }, gate);
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;

    // Agent sees ONLY the fixed denial — no drift detail, no digests
    // (invariant #7).
    expect(payload.denied).toBe(true);
    expect(payload.message).toBe(FIXED_DENIAL_MESSAGE);
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toMatch(/drift/i);
    expect(serialized).not.toContain(approvedDigest);

    // Nothing written.
    expect(await readdir(harness.exportDir)).toEqual([]);

    // Honest audit event carrying BOTH digests.
    const driftEvents = await auditOps(harness.source.auditLog, "sdw_export_scope_drift");
    expect(driftEvents).toHaveLength(1);
    expect(driftEvents[0]!.result).toBe("failure");
    expect(driftEvents[0]!.details!.approved_scope_digest).toBe(approvedDigest);
    expect(driftEvents[0]!.details!.current_scope_digest).not.toBe(approvedDigest);
    expect(await auditOps(harness.source.auditLog, "sdw_export_completed")).toHaveLength(0);
  });

  it("buildSignedSdwExportBundle throws SdwExportScopeDriftError on any added, removed, or rewritten record", async () => {
    const fortress = makeFortress(SOURCE_FORTRESS);
    await seedSourceVault(fortress);
    const signing = makeSigning();
    const approved = enumerateSdwExportInventory(fortress.vault);

    // Rewritten record.
    await fortress.workingStore.put(workingStateRecord("state-1", "rewritten body"), "user_content");
    expect(() =>
      buildSignedSdwExportBundle({
        inventory: approved,
        source: fortress.vault,
        fortressId: SOURCE_FORTRESS,
        exportAuditEventId: "sdw-export:test:1",
        signingKey: signing.signingKey,
      }),
    ).toThrow(SdwExportScopeDriftError);
  });

  it("an overlapping identical call cannot smuggle an unapproved vault state under an earlier approval", async () => {
    const harness = await makeExportHarness();
    let firstPrompt = true;
    const channel = new CallbackApprovalChannel(async (request) => {
      void request;
      if (firstPrompt) {
        firstPrompt = false;
        // While the FIRST prompt is pending, the agent mutates the vault and
        // fires an identical second request whose gate-time enumeration
        // stashes the NEW (unapproved) state. The first approval must NOT
        // ship that state: consumeOldest yields the first call's inventory,
        // and the drift recheck against the mutated store fails closed.
        await harness.source.workingStore.put(
          workingStateRecord("state-poison", "smuggled into overlap"),
          "user_content",
        );
        harness.exportTool.approvalTargetArgs!({ export_name: "overlap" });
      }
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);

    const result = await callThroughGate(harness.exportTool, { export_name: "overlap" }, gate);
    expect(result.kind).toBe("handled");
    expect((result as { payload: Record<string, unknown> }).payload.denied).toBe(true);
    expect(await readdir(harness.exportDir)).toEqual([]); // nothing shipped
    const drift = await auditOps(harness.source.auditLog, "sdw_export_scope_drift");
    expect(drift).toHaveLength(1);
  });

  it("a malformed namespaces argument fails closed before any prompt instead of widening scope", async () => {
    const harness = await makeExportHarness();
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);
    const result = await callThroughGate(
      harness.exportTool,
      { export_name: "bad-ns", namespaces: [42, "_sdw_working_state"] },
      gate,
    );
    expect(result.kind).toBe("denied_pre_prompt");
    expect(prompts).toHaveLength(0);
    expect(await readdir(harness.exportDir)).toEqual([]);
  });

  it("fails closed when the handler runs without a gate-bound approved inventory (no gate configured)", async () => {
    const harness = await makeExportHarness();
    const response = await harness.exportTool.handler({ export_name: "ungated" });
    const payload = JSON.parse(response.content[0]!.text) as Record<string, unknown>;
    expect(payload.denied).toBe(true);
    expect(payload.message).toBe(FIXED_DENIAL_MESSAGE);
    expect(await readdir(harness.exportDir)).toEqual([]);
    const denied = await auditOps(harness.source.auditLog, "sdw_export_denied");
    expect(denied).toHaveLength(1);
    expect(denied[0]!.details!.denial_class).toBe("approval_scope_binding_missing");
  });
});

describe("SDW D2 deny ⇒ nothing decrypted, signed, or written (invariant 3)", () => {
  it("a human deny stops the export pre-handler: no file, no export audit events, gate_deny recorded", async () => {
    const harness = await makeExportHarness();
    const channel = new CallbackApprovalChannel(async () => ({
      decision: "deny",
      decided_at: NOW,
      decided_by: "human",
    }));
    const gate = makeGate(harness.source.auditLog, channel);

    const result = await callThroughGate(harness.exportTool, { export_name: "nope" }, gate);
    expect(result.kind).toBe("denied_gate");
    expect(await readdir(harness.exportDir)).toEqual([]);
    expect(await auditOps(harness.source.auditLog, "gate_deny:sdw_export")).toHaveLength(1);
    expect(await auditOps(harness.source.auditLog, "sdw_export_scope_approved")).toHaveLength(0);
    expect(await auditOps(harness.source.auditLog, "sdw_export_completed")).toHaveLength(0);
  });

  it("a human deny on import writes nothing to the target vault", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "denyme" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundleBase64 = Buffer.from(await readFile(destination, "utf8")).toString("base64url");

    const target = makeFortress(TARGET_FORTRESS);
    const targetTools = createSdwTools({
      storage: target.vault,
      inventory: target.vault,
      auditLog: target.auditLog,
      fortressId: TARGET_FORTRESS,
      exportDir: await makeExportDir(),
      signingKey: makeSigning().signingKey,
      resolvePublicKey: harness.signing.resolvePublicKey,
      resolveSourceMasterKey: () => harness.source.masterKey,
      targetMasterKey: target.masterKey,
    });
    const denyGate = makeGate(
      target.auditLog,
      new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: NOW,
        decided_by: "human",
      })),
    );
    const result = await callThroughGate(
      findTool(targetTools, "sdw_import"),
      { bundle: bundleBase64, source_key_ref: "slot" },
      denyGate,
    );
    expect(result.kind).toBe("denied_gate");
    expect(target.vault.countForTest()).toBe(0);
    expect(await auditOps(target.auditLog, "sdw_import_completed")).toHaveLength(0);
  });

  it("a human deny on sdw_export_delete deletes nothing", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "keep" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundle = JSON.parse(await readFile(destination, "utf8")) as SdwStateExportBundle;
    const manifestArg = Buffer.from(JSON.stringify(bundle.manifest)).toString("base64url");

    const before = harness.source.vault.countForTest();
    const denyGate = makeGate(
      harness.source.auditLog,
      new CallbackApprovalChannel(async () => ({
        decision: "deny",
        decided_at: NOW,
        decided_by: "human",
      })),
    );
    const result = await callThroughGate(
      harness.deleteTool,
      { manifest: manifestArg },
      denyGate,
    );
    expect(result.kind).toBe("denied_gate");
    expect(harness.source.vault.countForTest()).toBe(before);
  });
});

describe("SDW D2 import verify-before-prompt + digest-only logging (invariant 5)", () => {
  async function exportedBundle(harness: Harness): Promise<SdwStateExportBundle> {
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "verify" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    return JSON.parse(await readFile(destination, "utf8")) as SdwStateExportBundle;
  }

  function encodeBundle(bundle: SdwStateExportBundle): string {
    return Buffer.from(JSON.stringify(bundle)).toString("base64url");
  }

  function importHarness(harness: Harness) {
    const target = makeFortress(TARGET_FORTRESS);
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(target.auditLog, channel);
    const tools = createSdwTools({
      storage: target.vault,
      inventory: target.vault,
      auditLog: target.auditLog,
      fortressId: TARGET_FORTRESS,
      exportDir: harness.exportDir,
      signingKey: makeSigning().signingKey,
      resolvePublicKey: harness.signing.resolvePublicKey,
      resolveSourceMasterKey: () => harness.source.masterKey,
      targetMasterKey: target.masterKey,
    });
    return { target, prompts, gate, importTool: findTool(tools, "sdw_import") };
  }

  it("a tampered record ciphertext is rejected BEFORE any approval prompt, with digest+category audit and no body logging", async () => {
    const harness = await makeExportHarness();
    const bundle = await exportedBundle(harness);
    const tamperedStores = bundle.stores.map((store) => ({
      ...store,
      records: store.records.map((record, index) =>
        index === 0 && store.namespace === SDW_WORKING_STATE_NAMESPACE
          ? {
              ...record,
              encrypted_payload: {
                ...record.encrypted_payload,
                ct: `${record.encrypted_payload.ct.slice(0, -4)}AAAA`,
              },
            }
          : record,
      ),
    }));
    const tampered: SdwStateExportBundle = { ...bundle, stores: tamperedStores };

    const { target, prompts, gate, importTool } = importHarness(harness);
    const result = await callThroughGate(
      importTool,
      { bundle: encodeBundle(tampered), source_key_ref: "slot" },
      gate,
    );
    expect(result.kind).toBe("denied_pre_prompt");
    expect(prompts).toHaveLength(0); // NO approval prompt fired.
    expect(target.vault.countForTest()).toBe(0);

    const rejections = await auditOps(target.auditLog, "sdw_import_manifest_rejected");
    expect(rejections).toHaveLength(1);
    expect(rejections[0]!.details!.category).toBe("record_hash_mismatch");
    expect(rejections[0]!.details!.manifest_body_digest).toBe(
      sdwManifestBodyDigest(bundle.manifest.body),
    );
    // Digest + category ONLY — never the body, records, or ciphertext.
    const serialized = JSON.stringify(rejections[0]);
    const sampleCiphertext = bundle.stores[0]!.records[0]!.encrypted_payload.ct;
    expect(serialized).not.toContain(sampleCiphertext);
    expect(serialized).not.toContain("encrypted_payload");
  });

  it("a forged manifest body (signature mismatch) is rejected without prompting", async () => {
    const harness = await makeExportHarness();
    const bundle = await exportedBundle(harness);
    const forged: SdwStateExportBundle = {
      ...bundle,
      manifest: {
        ...bundle.manifest,
        body: { ...bundle.manifest.body, created_at: "2027-01-01T00:00:00.000Z" },
      },
    };
    const { prompts, gate, importTool } = importHarness(harness);
    const result = await callThroughGate(
      importTool,
      { bundle: encodeBundle(forged), source_key_ref: "slot" },
      gate,
    );
    expect(result.kind).toBe("denied_pre_prompt");
    expect(prompts).toHaveLength(0);
  });

  it("an unlisted record, a missing listed record, an unknown signer, and a fortress-id mismatch are all rejected", async () => {
    const harness = await makeExportHarness();
    const bundle = await exportedBundle(harness);

    // Unlisted record present.
    const extraRecord = bundle.stores.find((store) => store.records.length > 0)!.records[0]!;
    const withExtra: SdwStateExportBundle = {
      ...bundle,
      stores: bundle.stores.map((store) =>
        store.namespace === SDW_DOCUMENT_CORPUS_NAMESPACE
          ? {
              ...store,
              records: [
                ...store.records,
                {
                  ...extraRecord,
                  key: "doc.smuggled",
                  aad_identity: {
                    fortress_id: SOURCE_FORTRESS,
                    namespace: SDW_DOCUMENT_CORPUS_NAMESPACE,
                    key: "doc.smuggled",
                  },
                },
              ],
            }
          : store,
      ),
    };
    expect(() =>
      verifySdwExportManifest(withExtra, harness.signing.resolvePublicKey),
    ).toThrow(SdwImportVerificationError);

    // Listed record absent.
    const withMissing: SdwStateExportBundle = {
      ...bundle,
      stores: bundle.stores.map((store) =>
        store.namespace === SDW_WORKING_STATE_NAMESPACE
          ? { ...store, records: store.records.slice(1) }
          : store,
      ),
    };
    expect(() =>
      verifySdwExportManifest(withMissing, harness.signing.resolvePublicKey),
    ).toThrow(SdwImportVerificationError);

    // Unknown signing key.
    expectThrowCategory(() => verifySdwExportManifest(bundle, () => null), "key_unknown");

    // Bundle/body fortress-id mismatch.
    const mismatched: SdwStateExportBundle = { ...bundle, source_fortress_id: "fortress:evil" };
    expectThrowCategory(
      () => verifySdwExportManifest(mismatched, harness.signing.resolvePublicKey),
      "manifest_mismatch",
    );
  });

  it("fails closed with ZERO writes when any single record fails decryption (two-phase import)", async () => {
    const harness = await makeExportHarness();
    const bundle = await exportedBundle(harness);

    // Tamper ONE record's ciphertext, then recompute its manifest hash and
    // re-sign the manifest with the legitimate key — signature and hashes all
    // verify, but the record cannot decrypt. The whole import must abort
    // before ANY write.
    const stores = bundle.stores.map((store) => ({
      ...store,
      records: store.records.map((record) =>
        store.namespace === SDW_DOCUMENT_CORPUS_NAMESPACE
          ? {
              ...record,
              encrypted_payload: {
                ...record.encrypted_payload,
                ct: `${record.encrypted_payload.ct.slice(0, -4)}BBBB`,
              },
            }
          : record,
      ),
    }));
    const tamperedHashes = new Map<string, string>();
    for (const store of stores) {
      for (const record of store.records) {
        tamperedHashes.set(
          `${store.namespace} ${record.key}`,
          computeSdwExportRecordHash(record.encrypted_payload),
        );
      }
    }
    const body = {
      ...bundle.manifest.body,
      records: bundle.manifest.body.records.map((record) => ({
        ...record,
        record_hash: tamperedHashes.get(`${record.namespace} ${record.key}`)!,
      })),
    };
    const { sign } = await import("../../src/core/identity.js");
    const signature = sign(
      sdwManifestCanonicalBytes(body),
      harness.signing.signingKey.encryptedPrivateKey,
      harness.signing.signingKey.encryptionKey,
    );
    const resigned: SdwStateExportBundle = {
      ...bundle,
      stores,
      manifest: {
        body,
        signature: {
          alg: "ed25519",
          key_ref: harness.signing.signingKey.keyRef,
          value: Buffer.from(signature).toString("base64url"),
        },
      },
    };

    const target = makeFortress(TARGET_FORTRESS);
    await expect(
      importSdwExportBundle({
        bundle: resigned,
        storage: target.vault,
        resolvePublicKey: harness.signing.resolvePublicKey,
        sourceMasterKey: harness.source.masterKey,
        targetMasterKey: target.masterKey,
        targetFortressId: TARGET_FORTRESS,
      }),
    ).rejects.toMatchObject({ category: "decrypt_failed" });
    expect(target.vault.countForTest()).toBe(0); // not even the valid records
  });

  it("an unavailable source key fails the import with no writes and a category-only audit", async () => {
    const harness = await makeExportHarness();
    const bundle = await exportedBundle(harness);
    const { target, gate, importTool } = importHarness(harness);
    const tools = createSdwTools({
      storage: target.vault,
      inventory: target.vault,
      auditLog: target.auditLog,
      fortressId: TARGET_FORTRESS,
      exportDir: harness.exportDir,
      signingKey: makeSigning().signingKey,
      resolvePublicKey: harness.signing.resolvePublicKey,
      resolveSourceMasterKey: () => null, // operator never configured the slot
      targetMasterKey: target.masterKey,
    });
    void importTool;
    const result = await callThroughGate(
      findTool(tools, "sdw_import"),
      { bundle: encodeBundle(bundle), source_key_ref: "missing-slot" },
      gate,
    );
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;
    expect(payload.denied).toBe(true);
    expect(target.vault.countForTest()).toBe(0);
    const failures = await auditOps(target.auditLog, "sdw_import_failed");
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details!.category).toBe("source_key_unavailable");
  });

  it("malformed bundles are rejected as a category, never echoed", () => {
    expectThrowCategory(() => decodeSdwExportBundle("not!!base64url@@"), "malformed_bundle");
    expectThrowCategory(
      () => decodeSdwExportBundle(Buffer.from('{"hello":1}').toString("base64url")),
      "malformed_bundle",
    );
    expectThrowCategory(() => decodeSdwExportBundle(""), "malformed_bundle");
  });
});

describe("SDW D2 approval-proof replay defenses", () => {
  it("a stored approval proof cannot be replayed against a mutated vault; single-use and expiry hold", async () => {
    const harness = await makeExportHarness();
    const proofStore = new ApprovalProofStore();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel(), proofStore);
    const args = { export_name: "proofed" };

    // Proof created against the CURRENT vault state (gate-time args include
    // the scope digest, so the envelope binds it automatically).
    const gateArgsAtProofTime = harness.exportTool.approvalTargetArgs!(args);
    const proof = gate.createApprovedProof({
      toolName: "sdw_export",
      args: gateArgsAtProofTime,
      session: OPERATOR_SESSION,
    });

    // Vault mutates after the proof was issued.
    await harness.source.workingStore.put(
      workingStateRecord("state-late", "post-proof mutation"),
      "user_content",
    );

    // Replay against the mutated vault: fresh gate-time enumeration produces a
    // different digest → normalized-args-hash mismatch → deny.
    const replayed = await callThroughGate(harness.exportTool, args, gate, proof.approval_ref);
    expect(replayed.kind).toBe("denied_gate");
    expect(await readdir(harness.exportDir)).toEqual([]);

    // A fresh proof for the CURRENT state: the abandoned pre-mutation stash
    // entry is consumed oldest-first and fails the drift recheck (FIFO
    // fail-closed posture — a stale entry can never ship, it can only cost a
    // retry), after which the retry with a new proof succeeds.
    const freshGateArgs = harness.exportTool.approvalTargetArgs!(args);
    const freshProof = gate.createApprovedProof({
      toolName: "sdw_export",
      args: freshGateArgs,
      session: OPERATOR_SESSION,
    });
    const staleRound = await callThroughGate(harness.exportTool, args, gate, freshProof.approval_ref);
    expect(staleRound.kind).toBe("handled");
    expect((staleRound as { payload: Record<string, unknown> }).payload.denied).toBe(true);
    expect(await readdir(harness.exportDir)).toEqual([]);

    const retryProof = gate.createApprovedProof({
      toolName: "sdw_export",
      args: harness.exportTool.approvalTargetArgs!(args),
      session: OPERATOR_SESSION,
    });
    const first = await callThroughGate(harness.exportTool, args, gate, retryProof.approval_ref);
    expect(first.kind).toBe("handled");
    expect((first as { payload: Record<string, unknown> }).payload.exported).toBe(true);

    // Double-consume: the same proof is dead.
    const second = await callThroughGate(harness.exportTool, args, gate, retryProof.approval_ref);
    expect(second.kind).toBe("denied_gate");

    // Expired proof: dead on arrival.
    const expiredProof = gate.createApprovedProof({
      toolName: "sdw_export",
      args: harness.exportTool.approvalTargetArgs!(args),
      session: OPERATOR_SESSION,
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const expired = await callThroughGate(harness.exportTool, args, gate, expiredProof.approval_ref);
    expect(expired.kind).toBe("denied_gate");
  });
});

describe("SDW D2 approval-channel payload is metadata only (constraint #1)", () => {
  it("the export approval request carries namespaces/counts/digest and never plaintext, ciphertext, bundles, or key material", async () => {
    const harness = await makeExportHarness();
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);
    await callThroughGate(harness.exportTool, { export_name: "meta-only" }, gate);

    expect(prompts).toHaveLength(1);
    const serialized = JSON.stringify(prompts[0]);
    // Record plaintext that exists in the vault must not appear.
    expect(serialized).not.toContain("first checkpoint");
    expect(serialized).not.toContain("second checkpoint");
    // Stored ciphertext must not appear either (metadata only).
    for (const entry of harness.source.vault.listNamespaceSync(SDW_WORKING_STATE_NAMESPACE)) {
      const envelope = JSON.parse(bytesToString(entry.data)) as { ct: string };
      expect(serialized).not.toContain(envelope.ct);
    }
    // Key material never appears.
    expect(serialized).not.toContain(harness.signing.signingKey.encryptedPrivateKey.ct);
    // The summary is exactly the A+ metadata shape.
    const summary = prompts[0]!.context.args_summary as Record<string, unknown>;
    expect(Object.keys(summary).sort()).toEqual([
      "export_name",
      "namespaces",
      "record_count",
      "scope_digest",
      "total_bytes",
    ]);
  });

  it("the import approval request carries the manifest digest but never the bundle", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "imeta" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundleJson = await readFile(destination, "utf8");
    const bundleBase64 = Buffer.from(bundleJson).toString("base64url");
    const bundle = JSON.parse(bundleJson) as SdwStateExportBundle;

    const target = makeFortress(TARGET_FORTRESS);
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const targetGate = makeGate(target.auditLog, channel);
    const tools = createSdwTools({
      storage: target.vault,
      inventory: target.vault,
      auditLog: target.auditLog,
      fortressId: TARGET_FORTRESS,
      exportDir: harness.exportDir,
      signingKey: makeSigning().signingKey,
      resolvePublicKey: harness.signing.resolvePublicKey,
      resolveSourceMasterKey: () => harness.source.masterKey,
      targetMasterKey: target.masterKey,
    });
    const result = await callThroughGate(
      findTool(tools, "sdw_import"),
      { bundle: bundleBase64, source_key_ref: "slot" },
      targetGate,
    );
    expect(result.kind).toBe("handled");
    expect(prompts).toHaveLength(1);
    const serialized = JSON.stringify(prompts[0]);
    expect(serialized).toContain(sdwManifestBodyDigest(bundle.manifest.body));
    expect(serialized).not.toContain(bundleBase64.slice(0, 200));
    expect(serialized).not.toContain(bundle.stores[0]!.records[0]!.encrypted_payload.ct);
    const summary = prompts[0]!.context.args_summary as Record<string, unknown>;
    expect(summary.signature_verified).toBe(true);
    expect(summary.bundle).toBeUndefined();
  });
});

describe("SDW D2 crash safety (atomic bundle write)", () => {
  it("a failure between sign and rename leaves NO partial bundle at the destination and audits the failure", async () => {
    const tempWrites: string[] = [];
    const unlinked: string[] = [];
    const harness = await makeExportHarness({
      fs: {
        writeFile: async (path, data) => {
          tempWrites.push(path);
          await writeFile(path, data, { mode: 0o600 });
        },
        rename: async () => {
          throw new Error("simulated crash between sign and rename");
        },
        unlink: async (path) => {
          unlinked.push(path);
          await unlink(path);
        },
      },
    });
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const result = await callThroughGate(harness.exportTool, { export_name: "crashy" }, gate);
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;
    expect(payload.denied).toBe(true);

    // Destination path absent; temp file cleaned up.
    expect(await readdir(harness.exportDir)).toEqual([]);
    expect(tempWrites).toHaveLength(1);
    expect(unlinked).toEqual(tempWrites);

    const failures = await auditOps(harness.source.auditLog, "sdw_export_failed");
    expect(failures).toHaveLength(1);
    expect(failures[0]!.details!.category).toBe("write_failed");
    expect(await auditOps(harness.source.auditLog, "sdw_export_completed")).toHaveLength(0);
  });

  it("the real fs path writes atomically (temp file then rename, mode 0600)", async () => {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const result = await callThroughGate(harness.exportTool, { export_name: "atomic" }, gate);
    expect(result.kind).toBe("handled");
    const files = await readdir(harness.exportDir);
    expect(files).toEqual(["atomic.sdw-export.json"]);
  });

  it("rejects export names that could traverse outside the export directory", async () => {
    const harness = await makeExportHarness();
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);
    for (const exportName of ["../escape", "a/b", ".hidden", "a..b/", ""]) {
      const result = await callThroughGate(harness.exportTool, { export_name: exportName }, gate);
      expect(result.kind).toBe("denied_pre_prompt");
    }
    expect(prompts).toHaveLength(0);
    expect(await readdir(harness.exportDir)).toEqual([]);
  });
});

describe("SDW D2 post-export delete", () => {
  async function exportedHarness() {
    const harness = await makeExportHarness();
    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const exported = await callThroughGate(harness.exportTool, { export_name: "predelete" }, gate);
    const destination = (exported as { payload: Record<string, unknown> }).payload
      .destination_path as string;
    const bundle = JSON.parse(await readFile(destination, "utf8")) as SdwStateExportBundle;
    const manifestArg = Buffer.from(JSON.stringify(bundle.manifest)).toString("base64url");
    return { harness, bundle, manifestArg };
  }

  it("deletes exactly the manifest-listed records and leaves later additions untouched", async () => {
    const { harness, bundle, manifestArg } = await exportedHarness();

    // A record added AFTER the export must survive.
    await harness.source.workingStore.put(
      workingStateRecord("state-post-export", "added after export"),
      "user_content",
    );
    const survivorKey = stateKey("task", "state-post-export");

    const gate = makeGate(harness.source.auditLog, new AutoApproveChannel());
    const result = await callThroughGate(harness.deleteTool, { manifest: manifestArg }, gate);
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;
    expect(payload.deleted).toBe(bundle.manifest.body.records.length);

    for (const record of bundle.manifest.body.records) {
      expect(await harness.source.vault.exists(record.namespace, record.key)).toBe(false);
    }
    expect(await harness.source.vault.exists(SDW_WORKING_STATE_NAMESPACE, survivorKey)).toBe(true);

    const completed = await auditOps(harness.source.auditLog, "sdw_export_delete_completed");
    expect(completed).toHaveLength(1);
    expect(completed[0]!.details!.deleted_count).toBe(bundle.manifest.body.records.length);
  });

  it("fails closed with ZERO deletes when a listed record changed since the export", async () => {
    const { harness, manifestArg } = await exportedHarness();
    const channel = new CallbackApprovalChannel(async () => {
      // Rewrite an exported record during the approval wait.
      await harness.source.workingStore.put(
        workingStateRecord("state-1", "mutated after export"),
        "user_content",
      );
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);

    const before = harness.source.vault.countForTest();
    const result = await callThroughGate(harness.deleteTool, { manifest: manifestArg }, gate);
    expect(result.kind).toBe("handled");
    const payload = (result as { payload: Record<string, unknown> }).payload;
    expect(payload.denied).toBe(true);
    expect(payload.message).toBe(FIXED_DENIAL_MESSAGE);
    expect(harness.source.vault.countForTest()).toBe(before); // nothing deleted

    const drift = await auditOps(harness.source.auditLog, "sdw_export_delete_drift");
    expect(drift).toHaveLength(1);
  });

  it("rejects a manifest signed by an unknown key before any prompt", async () => {
    const { harness, bundle } = await exportedHarness();
    const stranger = makeSigning();
    const forgedManifest = {
      body: bundle.manifest.body,
      signature: { ...bundle.manifest.signature, key_ref: stranger.signingKey.keyRef },
    };
    const prompts: ApprovalRequest[] = [];
    const channel = new CallbackApprovalChannel(async (request) => {
      prompts.push(request);
      return { decision: "approve", decided_at: NOW, decided_by: "human" };
    });
    const gate = makeGate(harness.source.auditLog, channel);
    const result = await callThroughGate(
      harness.deleteTool,
      { manifest: Buffer.from(JSON.stringify(forgedManifest)).toString("base64url") },
      gate,
    );
    expect(result.kind).toBe("denied_pre_prompt");
    expect(prompts).toHaveLength(0);
  });
});
