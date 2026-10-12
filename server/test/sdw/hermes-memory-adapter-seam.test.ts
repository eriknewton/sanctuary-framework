import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import {
  createSdwMemoryAdapter,
  type HermesBridgeCommitCheck,
} from "../../src/index.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { StorageBackend, StorageEntryMeta } from "../../src/storage/interface.js";
import {
  SdwMemoryBackendAdapter,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { documentChunkKey, documentKey } from "../../src/sdw/grammar.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { memoryInsertIngress } from "../../src/sdw/memory-provenance-ingress.js";
import { testMemoryProvenanceDependencies } from "./test-memory-backend.js";
import { toBase64url } from "../../src/core/encoding.js";
import { hash } from "../../src/core/hashing.js";

const FORTRESS_ID = "fortress:hermes";
const MASTER_KEY = new Uint8Array(32).fill(13);
const OWNER_REF = "fleet-self";
const NOW = "2026-10-12T00:00:00.000Z";
const BRIDGE_TEST_SEAM_SYMBOL = "__hermesBridgeTestSeam";

function sha256Base64url(text: string): string {
  return toBase64url(hash(new TextEncoder().encode(text)));
}

function passageInput(passageId: string, text: string): {
  readonly passage_id: string;
  readonly text: string;
  readonly provenanceContext: ReturnType<typeof memoryInsertIngress>;
} {
  return {
    passage_id: passageId,
    text,
    provenanceContext: memoryInsertIngress(() => "agent:hermes-test", "user_content"),
  };
}

function makeAdapter(
  storage: StorageBackend,
  commitCheck: HermesBridgeCommitCheck,
): SdwMemoryBackendAdapter {
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  return createSdwMemoryAdapter({
    mode: "hermes-bridge",
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: OWNER_REF,
    resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
    resolveSignerPublicKey: deps.resolveSignerPublicKey,
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    commitCheck,
  });
}

function makeStandardAdapter(storage: StorageBackend): SdwMemoryBackendAdapter {
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  return createSdwMemoryAdapter({
    mode: "standard",
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: OWNER_REF,
    resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
    resolveSignerPublicKey: deps.resolveSignerPublicKey,
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
  });
}

async function ownerScopeKeys(
  storage: Pick<StorageBackend, "list">,
): Promise<readonly string[]> {
  const entries = await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE);
  return entries
    .map((entry) => entry.key)
    .filter((key) => key.includes(`mem.${OWNER_REF}.`))
    .sort();
}

async function documentEntries(storage: Pick<StorageBackend, "list">): Promise<readonly StorageEntryMeta[]> {
  return storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${OWNER_REF}.`);
}

function refusingCheck(message = "commit refused"): HermesBridgeCommitCheck {
  return {
    async assertAllowedToCommit(): Promise<void> {
      throw new SdwValidationError("operation_refused", message);
    },
  };
}

class RecordingStorage extends MemoryStorage {
  readonly writes: string[] = [];
  readonly deletes: string[] = [];

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    this.writes.push(`${namespace}\0${key}`);
    await super.write(namespace, key, data);
  }

  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    this.deletes.push(`${namespace}\0${key}`);
    return super.delete(namespace, key, secureOverwrite);
  }
}

class RollbackFailureStorage extends RecordingStorage {
  constructor(
    private readonly writeFailureKey: string,
    private readonly deleteFailureKey: string,
  ) {
    super();
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (key === this.writeFailureKey) {
      throw new Error("simulated document write failure");
    }
    await super.write(namespace, key, data);
  }

  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    if (key === this.deleteFailureKey) {
      throw new Error("simulated rollback delete failure");
    }
    return super.delete(namespace, key, secureOverwrite);
  }
}

class ParkingDocumentStorage extends RecordingStorage {
  parked = 0;
  private releaseParked: (() => void) | undefined;
  private readonly parkedPromise = new Promise<void>((resolve) => {
    this.releaseParked = resolve;
  });

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith(`doc.mem.${OWNER_REF}.`)) {
      this.parked += 1;
      await this.parkedPromise;
    }
    await super.write(namespace, key, data);
  }

  release(): void {
    this.releaseParked?.();
  }
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}

describe("Hermes bridge SDW memory adapter seam", () => {
  it("factory standard mode matches direct standard construction for ordinary inserts", async () => {
    const factoryStorage = new MemoryStorage();
    const directStorage = new MemoryStorage();
    const factory = makeStandardAdapter(factoryStorage);
    const deps = testMemoryProvenanceDependencies(MASTER_KEY);
    const direct = new SdwMemoryBackendAdapter({
      storage: directStorage,
      masterKey: MASTER_KEY,
      fortressId: FORTRESS_ID,
      ownerRef: OWNER_REF,
      resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
      resolveSignerPublicKey: deps.resolveSignerPublicKey,
      resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
      now: () => NOW,
    });

    const input = passageInput("factory-parity", "factory standard mode stays ordinary");
    await expect(factory.insertPassage(input, "user_content")).resolves.toMatchObject({
      passage_id: input.passage_id,
      text: input.text,
    });
    await expect(direct.insertPassage(input, "user_content")).resolves.toMatchObject({
      passage_id: input.passage_id,
      text: input.text,
    });
    await expect(factory.getPassage(input.passage_id)).resolves.toMatchObject({ text: input.text });
    await expect(direct.getPassage(input.passage_id)).resolves.toMatchObject({ text: input.text });
  });

  it("wired factory bridge mode reaches the commit check and refusal leaves no corpus records", async () => {
    const storage = new RecordingStorage();
    let calls = 0;
    const adapter = makeAdapter(storage, {
      async assertAllowedToCommit(context): Promise<void> {
        calls += 1;
        expect(context.passageId).toBe("refuse-1");
        expect(new TextDecoder().decode(context.passageTextUtf8)).toBe("do not commit");
        expect(context.getFrameUtf8Bytes).toBeGreaterThan(0);
        throw new SdwValidationError("operation_refused", "owner refused");
      },
    });

    await expect(
      adapter.insertPassage(passageInput("refuse-1", "do not commit"), "user_content"),
    ).rejects.toMatchObject({ category: "operation_refused" });

    expect(calls).toBe(1);
    expect(storage.writes).toEqual([]);
    expect(storage.deletes).toEqual([]);
    expect(await ownerScopeKeys(storage)).toEqual([]);
  });

  it("a passing bridge check commits one document and bridge mutators other than insert refuse", async () => {
    const storage = new RecordingStorage();
    const adapter = makeAdapter(storage, {
      async assertAllowedToCommit(): Promise<void> {},
    });

    await adapter.insertPassage(passageInput("ok-1", "commit me"), "user_content");

    expect(await documentEntries(storage)).toHaveLength(1);
    await expect(adapter.putPassages([passageInput("batch", "x")], "user_content"))
      .rejects.toMatchObject({ category: "operation_refused" });
    await expect(adapter.putPassagesIfAbsent([passageInput("absent", "x")], "user_content"))
      .rejects.toMatchObject({ category: "operation_refused" });
    await expect(adapter.deletePassage("ok-1"))
      .rejects.toMatchObject({ category: "operation_refused" });
  });

  it("plain SHA-256 mismatch refuses while the unmodified twin commits", async () => {
    const text = "approved bytes";
    const expectedHash = sha256Base64url(text);
    const mismatch = makeAdapter(new RecordingStorage(), {
      async assertAllowedToCommit(context): Promise<void> {
        if (context.passageTextSha256 !== expectedHash) {
          throw new SdwValidationError("operation_refused", "approved hash mismatch");
        }
      },
    });
    await expect(
      mismatch.insertPassage(passageInput("hash-mismatch", `${text}!`), "user_content"),
    ).rejects.toMatchObject({ category: "operation_refused" });

    const storage = new RecordingStorage();
    const unmodified = makeAdapter(storage, {
      async assertAllowedToCommit(context): Promise<void> {
        expect(context.passageTextSha256).toBe(expectedHash);
      },
    });
    await expect(
      unmodified.insertPassage(passageInput("hash-ok", text), "user_content"),
    ).resolves.toMatchObject({ passage_id: "hash-ok" });
    expect(await documentEntries(storage)).toHaveLength(1);
  });

  it("abort during the corpus lock wait refuses without writing", async () => {
    const storage = new RecordingStorage();
    const controller = new AbortController();
    let releaseFirst!: () => void;
    const firstParked = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let firstReachedCheck = false;
    const adapter = makeAdapter(storage, {
      abortSignal: controller.signal,
      async assertAllowedToCommit(context): Promise<void> {
        if (context.passageId === "first") {
          firstReachedCheck = true;
          await firstParked;
        }
      },
    });

    const first = adapter.insertPassage(passageInput("first", "holds lock"), "user_content");
    await waitUntil(() => firstReachedCheck);
    const second = adapter.insertPassage(passageInput("second", "must not write"), "user_content");
    controller.abort();

    await expect(second).rejects.toMatchObject({ category: "operation_aborted" });
    expect(storage.writes.filter((entry) => entry.includes("second"))).toEqual([]);
    releaseFirst();
    await first;
    await expect(adapter.getPassage("second")).resolves.toBeNull();
  });

  it("partial_scope during bridge insert latches later inserts with an operator reason", async () => {
    const documentId = `mem.${OWNER_REF}.latch-1`;
    const storage = new RollbackFailureStorage(
      documentKey(documentId),
      documentChunkKey(documentId, "000000", "c000000"),
    );
    const adapter = makeAdapter(storage, {
      async assertAllowedToCommit(): Promise<void> {},
    });

    await expect(
      adapter.insertPassage(passageInput("latch-1", "abcd"), "user_content"),
    ).rejects.toMatchObject({ category: "partial_scope" });

    expect(adapter.getHermesBridgeLatchReason()).toContain(SDW_DOCUMENT_CORPUS_NAMESPACE);
    await expect(
      adapter.insertPassage(passageInput("latch-2", "later"), "user_content"),
    ).rejects.toMatchObject({ category: "operation_refused" });
  });

  it("a parked document write proves one commit after a passed check without a product seam", async () => {
    const storage = new ParkingDocumentStorage();
    let checkCalls = 0;
    const adapter = makeAdapter(storage, {
      async assertAllowedToCommit(context): Promise<void> {
        checkCalls += 1;
        expect(context.passageId).toBe("parked");
      },
    });
    const insert = adapter.insertPassage(passageInput("parked", "commit once"), "user_content");

    await waitUntil(() => storage.parked === 1);
    expect(checkCalls).toBe(1);
    expect(await documentEntries(storage)).toHaveLength(0);
    storage.release();

    await expect(insert).resolves.toMatchObject({ passage_id: "parked" });
    expect(await documentEntries(storage)).toHaveLength(1);
    expect(storage.parked).toBe(1);
  });

  it("bridge test seam symbols are absent from product source", async () => {
    const files = await listSourceFiles(join(process.cwd(), "src"));
    const hits: string[] = [];
    for (const file of files) {
      const text = await readFile(file, "utf8");
      if (text.includes(BRIDGE_TEST_SEAM_SYMBOL)) hits.push(file);
    }
    expect(hits).toEqual([]);
  });
});

async function listSourceFiles(root: string): Promise<readonly string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const fullPath = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...await listSourceFiles(fullPath));
    } else if (entry.isFile() && fullPath.endsWith(".ts")) {
      files.push(fullPath);
    }
  }
  return files;
}
