import { describe, expect, it } from "vitest";
import { readFile, readdir } from "node:fs/promises";
import { join, relative } from "node:path";
import ts from "typescript";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import { assertSdwRawWriteAuthorized, passageContentHash, prepareSdwBackendWrite, type Persistable } from "../../src/sdw/write-gate.js";
import type { SdwRecord } from "../../src/sdw/records.js";
import { SdwMemoryBackendAdapter, SDW_MEMORY_INTEGRITY_STATE } from "../../src/sdw/adapters/sdw-memory-backend.js";
import {
  TestSdwMemoryBackendAdapter,
  testMemoryProvenanceDependencies,
} from "./test-memory-backend.js";
import { exitV2ForeignImportIngress, memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { signMemoryOrigin } from "../../src/sdw/memory-provenance-contract.js";
import { ed25519 } from "@noble/curves/ed25519";
import { publicKeyToDid } from "../../src/core/identity.js";
import { documentChunkKey, documentKey, documentProvenanceKey, documentProvenanceStatusKey } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";

const MASTER_KEY = new Uint8Array(32).fill(19);
const NOW = "2026-08-24T12:00:00.000Z";
const DOCUMENT_ID = "mem.fleet-self.p1";
const composite = (key: string) => `${SDW_DOCUMENT_CORPUS_NAMESPACE}\0${key}`;

class RecordingStorage implements StorageBackend {
  readonly data = new Map<string, Uint8Array>();
  readonly operations: string[] = [];
  failDeleteKey: string | null = null;
  failWriteKey: string | null = null;

  async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.operations.push(`write:${key}`);
    if (key === this.failWriteKey) {
      this.failWriteKey = null;
      throw new Error(`injected write failure: ${key}`);
    }
    this.data.set(`${namespace}\0${key}`, new Uint8Array(assertSdwRawWriteAuthorized(namespace, key, data)));
  }
  async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const value = this.data.get(`${namespace}\0${key}`);
    return value === undefined ? null : new Uint8Array(value);
  }
  async delete(namespace: string, key: string, secure = false): Promise<boolean> {
    this.operations.push(`delete:${key}:${String(secure)}`);
    if (key === this.failDeleteKey) {
      this.failDeleteKey = null;
      throw new Error(`injected delete failure: ${key}`);
    }
    return this.data.delete(`${namespace}\0${key}`);
  }
  async list(namespace: string, prefix = ""): Promise<StorageEntryMeta[]> {
    return [...this.data.entries()].flatMap(([joined, value]) => {
      const split = joined.indexOf("\0");
      const ns = joined.slice(0, split);
      const key = joined.slice(split + 1);
      return ns === namespace && key.startsWith(prefix)
        ? [{ namespace, key, size_bytes: value.byteLength, modified_at: NOW }]
        : [];
    }).sort((a, b) => a.key.localeCompare(b.key));
  }
  async exists(namespace: string, key: string): Promise<boolean> { return this.data.has(`${namespace}\0${key}`); }
  async totalSize(): Promise<number> { return [...this.data.values()].reduce((n, value) => n + value.byteLength, 0); }
}

class TransactionalRecordingStorage extends RecordingStorage {
  async sdwTransaction<T>(fn: (txn: {
    writePersistable<R extends SdwRecord>(persistable: Persistable<R>, encryptionKey: Uint8Array, fortressId: string): Promise<void>;
    read(namespace: string, key: string): Promise<Uint8Array | null>;
    delete(namespace: string, key: string): Promise<boolean>;
  }) => Promise<T>): Promise<T> {
    const overlay = new Map<string, Uint8Array | null>();
    const result = await fn({
      writePersistable: async (persistable, encryptionKey, fortressId) => {
        const prepared = prepareSdwBackendWrite(persistable, encryptionKey, fortressId);
        this.operations.push(`txn-write:${prepared.storageKey}`);
        overlay.set(`${prepared.namespace}\0${prepared.storageKey}`, prepared.data);
      },
      read: async (namespace, key) => {
        const joined = `${namespace}\0${key}`;
        return overlay.has(joined) ? overlay.get(joined) ?? null : this.read(namespace, key);
      },
      delete: async (namespace, key) => {
        this.operations.push(`txn-delete:${key}`);
        overlay.set(`${namespace}\0${key}`, null);
        return true;
      },
    });
    for (const [key, value] of overlay) value === null ? this.data.delete(key) : this.data.set(key, value);
    return result;
  }
}

function deferred(): { readonly promise: Promise<void>; readonly resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

class StaleProvenanceReadStorage extends RecordingStorage {
  private provenanceReads = 0;
  readonly staleReadCaptured = deferred();
  readonly releaseStaleRead = deferred();

  override async read(namespace: string, key: string): Promise<Uint8Array | null> {
    const captured = await super.read(namespace, key);
    if (key === documentProvenanceKey(DOCUMENT_ID) && ++this.provenanceReads === 2) {
      this.staleReadCaptured.resolve();
      await this.releaseStaleRead.promise;
    }
    return captured;
  }
}

function adapter(storage: RecordingStorage, provenanceCandidateCap?: number): SdwMemoryBackendAdapter {
  return new TestSdwMemoryBackendAdapter({
    storage,
    masterKey: MASTER_KEY,
    fortressId: "fortress:test",
    ownerRef: "fleet-self",
    maxChunkChars: 4,
    now: () => NOW,
    provenanceCandidateCap,
  });
}

function input() {
  return {
    passage_id: "p1",
    text: "abcdefgh",
    provenanceContext: memoryInsertIngress(() => "test-producer", "user_content"),
  } as const;
}

describe("Memory Integrity C2 encrypted attachment", () => {
  it("C4 preserves a verified foreign origin signature and mints only destination admission", async () => {
    const storage = new RecordingStorage();
    const local = testMemoryProvenanceDependencies(MASTER_KEY);
    const foreignSeed = new Uint8Array(32).fill(77);
    const foreignKey = ed25519.getPublicKey(foreignSeed);
    const foreignDid = publicKeyToDid(foreignKey);
    const origin = signMemoryOrigin({
      origin_fortress_id: "foreign-fortress", owner_ref: "source-owner",
      passage_id: "source-passage", content_hash: passageContentHash("abcdefgh"),
      chunk_count: 2, author_agent_id: "foreign-agent", ingress_channel: "memory_insert",
      source_class: "user_content", recorded_at: NOW,
    }, { identity_id: "foreign-id", did: foreignDid, public_key: foreignKey,
      sign: (bytes) => ed25519.sign(bytes, foreignSeed) });
    if (!origin.ok) throw new Error(JSON.stringify(origin.error));
    const subject = new SdwMemoryBackendAdapter({
      storage, masterKey: MASTER_KEY, fortressId: "fortress:test", ownerRef: "fleet-self",
      maxChunkChars: 4, now: () => NOW, resolvePrimarySigningHandle: local.resolvePrimarySigningHandle,
      resolveSignerPublicKey: (identityId, did) => identityId === "foreign-id" && did === foreignDid
        ? foreignKey : local.resolveSignerPublicKey(identityId, did),
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    });
    await subject.insertPassage({ passage_id: "p1", text: "abcdefgh",
      provenanceContext: exitV2ForeignImportIngress({ origin: origin.value,
        originPublicKey: foreignKey, trustTier: "foreign_direct",
        transferLineageRef: "a".repeat(64) }) }, "user_content");
    const admitted = await subject.getPassageProvenance("p1");
    expect(admitted).toMatchObject({ status: "verified" });
    if (admitted.status !== "verified") return;
    expect(admitted.companion.origin).toEqual(origin.value);
    expect(admitted.companion.admission.body).toMatchObject({
      origin_trust_tier: "foreign_direct", verification_basis: "exit_v2_manifest_key",
      destination_fortress_id: "fortress:test", passage_id: "p1",
    });
  });
  it("freezes PRE_MIGRATION and writes chunks, provenance, then the visibility document", async () => {
    const storage = new RecordingStorage();
    await adapter(storage).insertPassage(input(), "user_content");
    expect(SDW_MEMORY_INTEGRITY_STATE).toBe("state_PRE_MIGRATION");
    expect(storage.operations.filter((op) => op.startsWith("write:"))).toEqual([
      `write:${documentChunkKey(DOCUMENT_ID, "000000", "c000000")}`,
      `write:${documentChunkKey(DOCUMENT_ID, "000001", "c000001")}`,
      `write:${documentProvenanceKey(DOCUMENT_ID)}`,
      `write:${documentKey(DOCUMENT_ID)}`,
    ]);
    expect(storage.data.has(composite(documentProvenanceKey(DOCUMENT_ID)))).toBe(true);
  });

  it("rejects a look-alike ingress object before writing", async () => {
    const storage = new RecordingStorage();
    const forged = { passage_id: "p1", text: "safe", provenanceContext: Object.freeze({}) as never };
    await expect(adapter(storage).insertPassage(forged, "user_content")).rejects.toMatchObject({ category: "invalid_identifier" });
    expect(storage.data.size).toBe(0);
  });

  it("reports a verified per-record companion and refuses a tampered companion via bounded quarantine", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "verified" });
    const key = composite(documentProvenanceKey(DOCUMENT_ID));
    const tampered = new Uint8Array(storage.data.get(key)!);
    tampered[tampered.length - 1] ^= 1;
    storage.data.set(key, tampered);
    await expect(subject.getPassageProvenance("p1")).resolves.toEqual({ status: "quarantined", reason: "auth_failed" });
    await expect(subject.getPassage("p1")).rejects.toMatchObject({ category: "auth_failed" });
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `prov-status.${DOCUMENT_ID}`))).toHaveLength(1);
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "quarantined" });
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `prov-status.${DOCUMENT_ID}`))).toHaveLength(1);
  });

  it("keeps legacy unsigned rows readable in PRE_MIGRATION", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    storage.data.delete(composite(documentProvenanceKey(DOCUMENT_ID)));
    await expect(subject.getPassage("p1")).resolves.toMatchObject({ text: "abcdefgh", provenance_status: "unsigned" });
    await expect(subject.getPassageProvenance("p1")).resolves.toEqual({ status: "unsigned" });
  });

  it("uses one atomic transactional overlay with document last, and document-first delete staging", async () => {
    const storage = new TransactionalRecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    expect(storage.operations.filter((op) => op.startsWith("txn-write:"))).toEqual([
      `txn-write:${documentChunkKey(DOCUMENT_ID, "000000", "c000000")}`,
      `txn-write:${documentChunkKey(DOCUMENT_ID, "000001", "c000001")}`,
      `txn-write:${documentProvenanceKey(DOCUMENT_ID)}`,
      `txn-write:${documentKey(DOCUMENT_ID)}`,
    ]);
    storage.operations.length = 0;
    await subject.deletePassage("p1");
    expect(storage.operations.filter((op) => op.startsWith("txn-delete:"))).toEqual([
      `txn-delete:${documentKey(DOCUMENT_ID)}`,
      `txn-delete:${documentProvenanceKey(DOCUMENT_ID)}`,
      `txn-delete:${documentProvenanceStatusKey(DOCUMENT_ID)}`,
      `txn-delete:${documentChunkKey(DOCUMENT_ID, "000000", "c000000")}`,
      `txn-delete:${documentChunkKey(DOCUMENT_ID, "000001", "c000001")}`,
    ]);
  });

  it.each([
    documentKey(DOCUMENT_ID),
    documentProvenanceKey(DOCUMENT_ID),
    documentProvenanceStatusKey(DOCUMENT_ID),
    documentChunkKey(DOCUMENT_ID, "000000", "c000000"),
    documentChunkKey(DOCUMENT_ID, "000001", "c000001"),
  ])("restores every exact ciphertext pre-image when filesystem delete fails at %s", async (failureKey) => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    const before = new Map([...storage.data].map(([key, value]) => [key, new Uint8Array(value)]));
    storage.operations.length = 0;
    storage.failDeleteKey = failureKey;
    await expect(subject.deletePassage("p1")).rejects.toThrow("injected delete failure");
    expect(storage.data).toEqual(before);
    await expect(subject.getPassage("p1")).resolves.toMatchObject({ provenance_status: "verified" });
  });

  it.each([
    documentKey(DOCUMENT_ID),
    documentProvenanceKey(DOCUMENT_ID),
    documentChunkKey(DOCUMENT_ID, "000000", "c000000"),
    documentChunkKey(DOCUMENT_ID, "000001", "c000001"),
  ])("returns partial_scope when delete rollback cannot restore the %s pre-image", async (restoreFailureKey) => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    storage.failDeleteKey = documentChunkKey(DOCUMENT_ID, "000001", "c000001");
    storage.failWriteKey = restoreFailureKey;
    await expect(subject.deletePassage("p1")).rejects.toMatchObject({ category: "partial_scope" });
  });

  it("returns partial_scope when a quarantined status pre-image cannot be restored", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    const provenanceKey = composite(documentProvenanceKey(DOCUMENT_ID));
    const tampered = new Uint8Array(storage.data.get(provenanceKey)!);
    tampered[tampered.length - 1] ^= 1;
    storage.data.set(provenanceKey, tampered);
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "quarantined" });
    storage.failDeleteKey = documentChunkKey(DOCUMENT_ID, "000001", "c000001");
    storage.failWriteKey = documentProvenanceStatusKey(DOCUMENT_ID);
    await expect(subject.deletePassage("p1")).rejects.toMatchObject({ category: "partial_scope" });
  });

  it("enforces the corpus-wide candidate cap before visibility while replacements and quarantine share existing slots", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage, 2);
    await subject.insertPassage(input(), "user_content");
    await subject.insertPassage({ ...input(), passage_id: "p2" }, "user_content");
    await expect(subject.insertPassage({ ...input(), passage_id: "p3" }, "user_content"))
      .rejects.toMatchObject({ category: "candidate_cap" });
    await expect(subject.getPassage("p3")).resolves.toBeNull();
    await expect(subject.putPassages([{ ...input(), text: "replacement" }], "user_content"))
      .resolves.toHaveLength(1);
    const provenanceKey = composite(documentProvenanceKey(DOCUMENT_ID));
    const tampered = new Uint8Array(storage.data.get(provenanceKey)!);
    tampered[0] ^= 1;
    storage.data.set(provenanceKey, tampered);
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "quarantined" });
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, "doc.mem."))).toHaveLength(2);
  });

  it("serializes concurrent first inserts against the one-slot corpus cap", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage, 1);
    const outcomes = await Promise.allSettled([
      subject.insertPassage(input(), "user_content"),
      subject.insertPassage({ ...input(), passage_id: "p2" }, "user_content"),
    ]);
    expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(1);
    expect((await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, "doc.mem."))).toHaveLength(1);
  });

  it("does not let a stale provenance reader quarantine a concurrently verified replacement", async () => {
    const storage = new StaleProvenanceReadStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    const provenanceKey = composite(documentProvenanceKey(DOCUMENT_ID));
    const tampered = new Uint8Array(storage.data.get(provenanceKey)!);
    tampered[tampered.length - 1] ^= 1;
    storage.data.set(provenanceKey, tampered);

    const staleRead = subject.getPassageProvenance("p1");
    await storage.staleReadCaptured.promise;
    const replacement = subject.putPassages([{ ...input(), text: "verified replacement" }], "user_content");
    await replacement;
    storage.releaseStaleRead.resolve();
    await expect(staleRead).rejects.toMatchObject({ category: "auth_failed" });
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "verified" });
    expect(storage.data.has(composite(documentProvenanceStatusKey(DOCUMENT_ID)))).toBe(false);
  });

  it("atomically clears a matching quarantine status when a valid replacement commits", async () => {
    const storage = new RecordingStorage();
    const subject = adapter(storage);
    await subject.insertPassage(input(), "user_content");
    const provenanceKey = composite(documentProvenanceKey(DOCUMENT_ID));
    const tampered = new Uint8Array(storage.data.get(provenanceKey)!);
    tampered[tampered.length - 1] ^= 1;
    storage.data.set(provenanceKey, tampered);
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "quarantined" });

    await subject.putPassages([{ ...input(), text: "valid replacement" }], "user_content");
    expect(storage.data.has(composite(documentProvenanceStatusKey(DOCUMENT_ID)))).toBe(false);
    await expect(subject.getPassageProvenance("p1")).resolves.toMatchObject({ status: "verified" });
    await expect(subject.getPassage("p1")).resolves.toMatchObject({ text: "valid replacement" });
  });

  it("production construction refuses missing primary signer wiring regardless of VITEST", () => {
    const prior = process.env.VITEST;
    process.env.VITEST = "true";
    try {
      expect(() => new SdwMemoryBackendAdapter({
        storage: new RecordingStorage(), masterKey: MASTER_KEY,
        fortressId: "fortress:test", ownerRef: "fleet-self",
      } as never)).toThrow("requires primary-identity provenance signing wiring");
      expect(() => new SdwMemoryBackendAdapter({
        storage: new RecordingStorage(), masterKey: MASTER_KEY,
        fortressId: "fortress:test", ownerRef: "fleet-self",
        ...testMemoryProvenanceDependencies(MASTER_KEY),
      } as never)).toThrow("requires durable memory-integrity state wiring");
    } finally {
      if (prior === undefined) delete process.env.VITEST;
      else process.env.VITEST = prior;
    }
  });

  it("freezes every production passage mutation seam behind a code-owned provenance context", async () => {
    const srcRoot = join(process.cwd(), "src");
    const files: string[] = [];
    const walk = async (dir: string): Promise<void> => {
      for (const entry of await readdir(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) await walk(path);
        else if (entry.isFile() && entry.name.endsWith(".ts")) files.push(path);
      }
    };
    await walk(srcRoot);
    const sources = new Map<string, string>();
    const sourceFiles = new Map<string, ts.SourceFile>();
    const mutationInventory: string[] = [];
    for (const file of files) {
      const path = relative(srcRoot, file).replaceAll("\\", "/");
      const source = await readFile(file, "utf8");
      sources.set(path, source);
      const sourceFile = ts.createSourceFile(path, source, ts.ScriptTarget.Latest, true);
      sourceFiles.set(path, sourceFile);
      const visit = (node: ts.Node): void => {
        if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
          const method = node.expression.name.text;
          if (["insertPassage", "putPassages", "putPassagesIfAbsent"].includes(method)) {
            mutationInventory.push(`${path}:${method}`);
          }
        }
        ts.forEachChild(node, visit);
      };
      visit(sourceFile);
    }
    expect(mutationInventory.sort()).toEqual([
      "exit/v2-memory-archive.ts:putPassagesIfAbsent",
      "sdw/adapters/claude-code-file-adapter.ts:putPassages",
      "sdw/adapters/codex-memory-file-adapter.ts:putPassages",
      "sdw/anthropic-memory-handler.ts:insertPassage",
      "sdw/anthropic-memory-handler.ts:insertPassage",
      "sdw/anthropic-memory-handler.ts:insertPassage",
      "sdw/memory-tools.ts:insertPassage",
      "sdw/memory-transcode.ts:putPassages",
      "sdw/memory-transcode.ts:putPassages",
    ]);
    const findFunction = (path: string, name: string): ts.FunctionLikeDeclaration => {
      const sourceFile = sourceFiles.get(path)!;
      let found: ts.FunctionLikeDeclaration | undefined;
      const visit = (node: ts.Node): void => {
        if ((ts.isFunctionDeclaration(node) && node.name?.text === name) ||
            (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === name &&
              node.initializer !== undefined && (ts.isArrowFunction(node.initializer) || ts.isFunctionExpression(node.initializer)))) {
          found = ts.isVariableDeclaration(node) ? node.initializer as ts.FunctionLikeDeclaration : node;
        }
        if (found === undefined) ts.forEachChild(node, visit);
      };
      visit(sourceFile);
      if (found === undefined) throw new Error(`missing production function ${path}:${name}`);
      return found;
    };
    const factoryProperties = (path: string, functionName: string, factory: string): number => {
      const fn = findFunction(path, functionName);
      let count = 0;
      const visit = (node: ts.Node): void => {
        if (ts.isPropertyAssignment(node) && node.name.getText() === "provenanceContext" &&
            ts.isCallExpression(node.initializer) && ts.isIdentifier(node.initializer.expression) &&
            node.initializer.expression.text === factory) count++;
        ts.forEachChild(node, visit);
      };
      visit(fn);
      return count;
    };
    expect(factoryProperties("sdw/anthropic-memory-handler.ts", "applyAnthropicMemoryCommand", "anthropicMemoryToolIngress")).toBe(2);
    expect(factoryProperties("sdw/anthropic-memory-handler.ts", "mutateByReplace", "anthropicMemoryToolIngress")).toBe(1);
    expect(factoryProperties("sdw/memory-tools.ts", "createSdwMemoryTools", "memoryInsertIngress")).toBe(1);
    expect(factoryProperties("sdw/adapters/claude-code-file-adapter.ts", "screenClaudeCodeMemorySnapshot", "fileImportIngress")).toBe(1);
    expect(factoryProperties("sdw/adapters/codex-memory-file-adapter.ts", "screenCodexMemorySnapshot", "fileImportIngress")).toBe(1);
    expect(factoryProperties("sdw/memory-transcode.ts", "archiveFileInput", "memoryTranscodeIngress")).toBe(1);
    expect(factoryProperties("sdw/memory-transcode.ts", "archiveManifestInput", "memoryTranscodeIngress")).toBe(1);
    expect(factoryProperties("exit/v2-memory-archive.ts", "importExitV2SdwMemoryArchive", "legacyExitV1ImportIngress")).toBe(1);
    expect(factoryProperties("exit/v2-memory-archive.ts", "importExitV2SdwMemoryArchive", "exitV2ForeignImportIngress")).toBe(1);
    expect(factoryProperties("exit/v2-memory-archive.ts", "importExitV2SdwMemoryArchive", "memoryTranscodeIngress")).toBe(1);

    const constructors: ts.NewExpression[] = [];
    for (const sourceFile of sourceFiles.values()) {
      const visit = (node: ts.Node): void => {
        if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) &&
            node.expression.text === "SdwMemoryBackendAdapter") constructors.push(node);
        ts.forEachChild(node, visit);
      };
      visit(sourceFile);
    }
    expect(constructors).toHaveLength(3);
    for (const constructor of constructors) {
      const options = constructor.arguments?.[0];
      expect(options !== undefined && ts.isObjectLiteralExpression(options)).toBe(true);
      const names = ts.isObjectLiteralExpression(options!)
        ? options.properties.filter(ts.isPropertyAssignment).map((property) => property.name.getText())
        : [];
      expect(names).toContain("resolvePrimarySigningHandle");
      expect(names).toContain("resolveSignerPublicKey");
      expect(names).toContain("resolveMemoryIntegrityState");
    }
    const adapterAst = sourceFiles.get("sdw/adapters/sdw-memory-backend.ts")!;
    let vitestAccesses = 0;
    const visitVitest = (node: ts.Node): void => {
      if (ts.isPropertyAccessExpression(node) && node.getText(adapterAst) === "process.env.VITEST") vitestAccesses++;
      ts.forEachChild(node, visitVitest);
    };
    visitVitest(adapterAst);
    expect(vitestAccesses).toBe(0);
  });
});
