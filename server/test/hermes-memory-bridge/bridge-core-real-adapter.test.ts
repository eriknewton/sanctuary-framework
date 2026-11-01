import { HERMES_TOOL_OUTCOMES } from "../../src/hermes-memory-bridge/public-results.js";
import { Buffer } from "node:buffer";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  createSdwMemoryAdapter,
} from "../../src/index.js";
import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  type HermesBridgeAuditRecord,
  HermesBridgeCore,
  type HermesBridgeCorePorts,
  type HermesTimerHandle,
  type NodeToRelayInput,
  parsePublicFrame,
  type RelayToNodeFrame,
} from "../../src/hermes-memory-bridge/index.js";
import { documentChunkKey, documentKey } from "../../src/sdw/grammar.js";
import {
  MEMORY_BATCH_LOCK_NAMESPACE,
  HERMES_INSERT_INTENT_KEY,
  HERMES_INSERT_INTENT_NAMESPACE,
  hermesBridgePassageTextDigest,
  SdwMemoryBackendAdapter,
  type SdwMemoryBackendAdapterOptions,
} from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryGetSuccessFrameUtf8Bytes } from "../../src/sdw/memory-tool-projection.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { SDW_DOCUMENT_CORPUS_NAMESPACE } from "../../src/sdw/records.js";
import { FilesystemStorage } from "../../src/storage/filesystem.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import type { CrossProcessLockLease, CrossProcessLockOptions } from "../../src/storage/cross-process-lock.js";
import type { NamespaceLockStorageCapabilities, StorageBackend } from "../../src/storage/interface.js";
import { testMemoryProvenanceDependencies } from "../sdw/test-memory-backend.js";

const MASTER_KEY = new Uint8Array(32).fill(17);
const OWNER_REF = "fleet-self";
const FORTRESS_ID = "fortress:hermes-core";
const BAD_SIGNER_AUTHORITY = { async isMarked(): Promise<boolean> { return false; } };
const encoder = new TextEncoder();

class ManualTimers {
  private nextId = 1;
  readonly live = new Map<HermesTimerHandle, { readonly ms: number; readonly fire: () => void }>();

  setTimer = (ms: number, fire: () => void): HermesTimerHandle => {
    const handle = { id: this.nextId++ };
    this.live.set(handle, { ms, fire });
    return handle;
  };

  clearTimer = (handle: HermesTimerHandle): void => {
    this.live.delete(handle);
  };

  fireFirst(): void {
    const first = this.live.entries().next().value as [HermesTimerHandle, { readonly fire: () => void }] | undefined;
    if (first === undefined) throw new Error("no timer to fire");
    this.live.delete(first[0]);
    first[1].fire();
  }
}

class RollbackFailureStorage extends MemoryStorage {
  constructor(
    private readonly writeFailureKey: string,
    private readonly deleteFailureKey: string,
  ) {
    super();
  }

  override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && key === this.writeFailureKey) {
      throw new Error("simulated document write failure");
    }
    await super.write(namespace, key, data);
  }

  override async delete(namespace: string, key: string, secureOverwrite?: boolean): Promise<boolean> {
    if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && key === this.deleteFailureKey) {
      throw new Error("simulated rollback delete failure");
    }
    return super.delete(namespace, key, secureOverwrite);
  }
}

class ParkingLockStorage extends MemoryStorage implements NamespaceLockStorageCapabilities {
  receivedAbortSignal = false;

  override async withNamespaceLock<T>(
    namespace: string,
    lockFileName: string,
    operation: (lease: CrossProcessLockLease) => Promise<T>,
    options: CrossProcessLockOptions = {},
  ): Promise<T> {
    if (namespace !== MEMORY_BATCH_LOCK_NAMESPACE) {
      return super.withNamespaceLock(namespace, lockFileName, operation, options);
    }
    if (lockFileName.length === 0) throw new Error("missing lock file name");
    this.receivedAbortSignal = options.abortSignal !== undefined;
    if (options.abortSignal?.aborted === true) {
      throw new SdwValidationError("operation_aborted", "namespace lock wait aborted");
    }
    await new Promise<never>((_resolve, reject) => {
      options.abortSignal?.addEventListener("abort", () => {
        reject(new SdwValidationError("operation_aborted", "namespace lock wait aborted"));
      }, { once: true });
    });
    throw new SdwValidationError("operation_aborted", "namespace lock wait aborted");
  }
}

async function makeStorage(): Promise<{ readonly storage: StorageBackend; readonly cleanup: () => Promise<void> }> {
  const root = await mkdtemp(join(tmpdir(), "hermes-core-"));
  return {
    storage: new FilesystemStorage(root),
    cleanup: () => rm(root, { recursive: true, force: true }),
  };
}

function makeAdapter(storage: StorageBackend, commitCheck: HermesBridgeCore["commitCheck"], corpusScanCap?: number): SdwMemoryBackendAdapter {
  const deps = testMemoryProvenanceDependencies(MASTER_KEY);
  const build = corpusScanCap === undefined ? createSdwMemoryAdapter : (options: SdwMemoryBackendAdapterOptions) => new SdwMemoryBackendAdapter(options);
  return build({
    mode: "hermes-bridge",
    ...(corpusScanCap === undefined ? {} : { corpusScanCap, listMaxLimit: corpusScanCap }),
    storage,
    masterKey: MASTER_KEY,
    fortressId: FORTRESS_ID,
    ownerRef: OWNER_REF,
    resolvePrimarySigningHandle: deps.resolvePrimarySigningHandle,
    resolveSignerPublicKey: deps.resolveSignerPublicKey,
    resolveMemoryIntegrityState: async () => "state_PRE_MIGRATION",
    badSignerAuthority: BAD_SIGNER_AUTHORITY,
    commitCheck,
  });
}

async function makeHarness(options: {
  readonly storage?: StorageBackend;
  readonly rejectCommitIntentAudit?: boolean;
  readonly corpusScanCap?: number;
} = {}) {
  const ownedStorage = options.storage === undefined ? await makeStorage() : undefined;
  const storage = options.storage ?? ownedStorage!.storage;
  const timers = new ManualTimers();
  const writes: NodeToRelayInput[] = [];
  const audits: HermesBridgeAuditRecord[] = [];
  const ownerPrompts: string[] = [];
  const abort = new AbortController();
  let adapter!: SdwMemoryBackendAdapter;
  const ports: HermesBridgeCorePorts = {
    writeFrame(input) {
      writes.push(input);
    },
    appendAudit(record) {
      audits.push(record);
      if (options.rejectCommitIntentAudit === true && record.kind === "insert_admitted") {
        return Promise.reject(new Error("audit failed"));
      }
      return Promise.resolve();
    },
    nowMs: () => 1_000,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    adapter: {
      recallPassages: async budget => budget.result(),
      insertPassage: (input, taint) => adapter.insertPassage(input, taint),
      getPassage: (passageId) => adapter.getPassage(passageId),
      searchPassages: (query) => adapter.searchPassages(query),
    },
    agentId: "fixture-agent",
    abort,
  };
  const core = new HermesBridgeCore(ports);
  const terminalEvents: string[] = [];
  const ledger = (core as any).ledger;
  const finish = ledger.finish.bind(ledger);
  ledger.finish = (entry: unknown, state: string, ...rest: unknown[]) => {
    terminalEvents.push(state);
    return finish(entry, state, ...rest);
  };
  adapter = makeAdapter(storage, core.commitCheck, options.corpusScanCap);
  return {
    core,
    adapter,
    storage,
    timers,
    writes,
    audits,
    ownerPrompts,
    terminalEvents,
    abort,
    cleanup: ownedStorage?.cleanup ?? (async () => undefined),
  };
}

function publicFrame(connectionId: string, frame: Record<string, unknown>): RelayToNodeFrame {
  const publicBytes = encoder.encode(JSON.stringify(frame));
  return { kind: "frame", connectionId, publicBytes, publicFrame: parsePublicFrame(publicBytes) };
}

function accept(core: HermesBridgeCore, connectionId = "c1"): void {
  core.relayFrame({ kind: "accepted", connectionId });
}

function insert(core: HermesBridgeCore, connectionId: string, requestId: string, passageId: string, text: string): void {
  core.relayFrame(publicFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_insert",
    arguments: { text, taint: "user_content", tags: ["hermes"], passage_id: passageId },
  }));
}

function memoryGet(core: HermesBridgeCore, connectionId: string, requestId: string, passageId: string): void {
  core.relayFrame(publicFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_get",
    arguments: { passage_id: passageId },
  }));
}

function responsePayload(write: NodeToRelayInput): Record<string, unknown> {
  if (write.type !== "response") throw new Error("expected response");
  return JSON.parse(Buffer.from(write.publicPayloadBytes).toString("utf8")) as Record<string, unknown>;
}

function responses(writes: readonly NodeToRelayInput[]): readonly Record<string, unknown>[] {
  return writes.filter((write) => write.type === "response").map(responsePayload);
}

async function waitForResponse(writes: readonly NodeToRelayInput[], requestId?: string): Promise<Record<string, unknown>> {
  await waitUntil(() => responses(writes).some((payload) => requestId === undefined || payload.request_id === requestId));
  const found = responses(writes).find((payload) => requestId === undefined || payload.request_id === requestId);
  if (found === undefined) throw new Error("response was not written");
  return found;
}

function probe(writes: readonly NodeToRelayInput[], connectionId = "c1"): Extract<NodeToRelayInput, { readonly type: "probe" }> {
  const found = writes.find((write): write is Extract<NodeToRelayInput, { readonly type: "probe" }> =>
    write.type === "probe" && write.connectionId === connectionId);
  if (found === undefined) throw new Error(`probe not written for ${connectionId}`);
  return found;
}

async function flush(turns = 12): Promise<void> {
  for (let index = 0; index < turns; index += 1) await Promise.resolve();
}

async function waitUntil(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error("condition was not reached");
}

async function waitForProbe(writes: readonly NodeToRelayInput[], connectionId = "c1"): Promise<Extract<NodeToRelayInput, { readonly type: "probe" }>> {
  await waitUntil(() => writes.some((write) => write.type === "probe" && write.connectionId === connectionId));
  return probe(writes, connectionId);
}

async function replyToProbe(h: Awaited<ReturnType<typeof makeHarness>>, connectionId = "c1"): Promise<void> {
  const entry = h.core.snapshot().ledger.entry;
  if (entry === undefined) throw new Error("missing approval entry");

  const sentProbe = await waitForProbe(h.writes, connectionId);
  h.core.relayFrame({ kind: "probe_reply", connectionId, nonce: sentProbe.nonce });
  await flush(20);
}

async function documentCount(storage: Pick<StorageBackend, "list">): Promise<number> {
  return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${OWNER_REF}.`)).length;
}

function terminalStates(h: Awaited<ReturnType<typeof makeHarness>>): readonly string[] { return h.terminalEvents; }
async function waitForTerminal(h: Awaited<ReturnType<typeof makeHarness>>, state: string): Promise<void> {
  await waitUntil(() => terminalStates(h).includes(state));
}

async function shortOutcome(promise: Promise<void>): Promise<"resolved" | "rejected" | "timeout"> {
  return Promise.race([
    promise.then(() => "resolved" as const, () => "rejected" as const),
    new Promise<"timeout">((resolve) => setTimeout(() => resolve("timeout"), 50)),
  ]);
}

async function withHarness<T>(
  options: Parameters<typeof makeHarness>[0],
  run: (h: Awaited<ReturnType<typeof makeHarness>>) => Promise<T>,
): Promise<T> {
  const h = await makeHarness(options);
  try {
    return await run(h);
  } finally {
    await h.cleanup();
  }
}

describe("HermesBridgeCore with real SDW adapter", () => {
  it("persists admission before the first encrypted chunk", async () => {
    let admitted = () => false;
    let chunks = 0;
    class ObservedStorage extends MemoryStorage {
      override async write(namespace: string, key: string, data: Uint8Array): Promise<void> {
        if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE && key.startsWith("chunk.")) {
          chunks++;
          expect(admitted(), "admission must be durable before any chunk write").toBe(true);
        }
        return super.write(namespace, key, data);
      }
    }
    await withHarness({ storage: new ObservedStorage() }, async h => {
      admitted = () => h.audits.filter(row => row.kind === "insert_admitted").length === 1;
      accept(h.core);
      insert(h.core, "c1", "ordered", "ordered", "ordered durable memory");
      await replyToProbe(h);
      expect(await waitForResponse(h.writes, "ordered")).toMatchObject({ type: "result" });
      expect(chunks).toBeGreaterThan(0);
      expect(await documentCount(h.storage)).toBe(1);
    });
  });

  it("commits an admitted passage and reads back byte-equal text", async () => {
    await withHarness({}, async (h) => {
      accept(h.core);
      h.core.relayFrame(publicFrame("c1", { type: "hello", request_id: "hello-1", protocol_version: "2026-10-12", client_name: "client" }));
      insert(h.core, "c1", "insert-1", "passage-full", "the passage bytes");
      await flush();
      expect(h.ownerPrompts).toEqual([]);

      await replyToProbe(h);
      const success = await waitForResponse(h.writes, "insert-1");
      expect(success?.type).toBe("result");
      expect(await documentCount(h.storage)).toBe(1);

      memoryGet(h.core, "c1", "get-1", "passage-full");
      const get = await waitForResponse(h.writes, "get-1");
      expect(get?.type).toBe("result");
      const content = (get?.payload as { content?: Array<{ text: string }> } | undefined)?.content;
      const body = JSON.parse(content?.[0]?.text ?? "{}") as { passage?: { text?: string } };
      expect(body.passage?.text).toBe("the passage bytes");
    });
  });

  it("pins stored insert provenance to the bridge class", async () => {
    await withHarness({}, async (h) => {
      accept(h.core);
      h.core.relayFrame(publicFrame("c1", {
        type: "tools_call",
        request_id: "insert-system-taint",
        name: "memory_insert",
        arguments: {
          text: "caller selected another class",
          taint: "system_generated",
          tags: ["hermes"],
          passage_id: "passage-system-taint",
        },
      }));
      await flush();
      await replyToProbe(h);
      expect(await waitForResponse(h.writes, "insert-system-taint")).toMatchObject({ type: "result" });
      expect(await documentCount(h.storage)).toBe(1);

      const provenance = await h.adapter.getPassageProvenance("passage-system-taint");
      expect(provenance.status).toBe("verified");
      if (provenance.status !== "verified") throw new Error("expected verified provenance");
      expect(provenance.companion.origin.body.source_class).toBe("user_content");
    });
  });

  it.each([
    ["cancel before probe reply", "CANCELED", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-cancel", "passage-cancel", "cancel me");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;

      const sentProbe = await waitForProbe(h.writes);
      h.core.relayFrame(publicFrame("c1", { type: "cancel", mcp_request_id: "insert-cancel" }));
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
      expect(await waitForResponse(h.writes, "insert-cancel")).toMatchObject({ type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
    }],
    ["closed during approval", "DISCONNECTED", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-closed", "passage-closed", "close me");
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      await flush();
      expect(h.writes).toEqual([]);
    }],
    ["deadline", "TIMED_OUT", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-deadline", "passage-deadline", "time me out");
      h.timers.fireFirst();
      await flush();
      expect(await waitForResponse(h.writes)).toMatchObject({ type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
    }],
    ["cancel before lock acquisition", "CANCELED", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-deny", "passage-deny", "deny me");
      const entry = h.core.snapshot().ledger.entry!;
      cancelInsert(h.core);
      await flush();
      expect(await waitForResponse(h.writes)).toMatchObject({ type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
      expect(h.timers.live.size).toBe(0);
    }],
  ])("refuses with the real adapter: %s", async (_name, terminal, run) => {
    await withHarness({}, async (h) => {
      await run(h);
      expect(await documentCount(h.storage)).toBe(0);
      await waitForTerminal(h, terminal);
    });
  });

  it("aborts a parked lock wait and writes no document", async () => {
    const storage = new ParkingLockStorage();
    await withHarness({ storage }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-stop", "passage-stop", "stop in lock");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;

      await flush();
      h.core.relayFrame({ kind: "relay_shutdown" });
      await waitForTerminal(h, "REFUSED");

      expect(storage.receivedAbortSignal).toBe(true);
      expect(h.abort.signal.aborted).toBe(true);
      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h)).toContain("REFUSED");
      expect(responses(h.writes).find((payload) => payload.request_id === "insert-stop")).toBeUndefined();
      expect(h.core.drained).toBe(true);
    });
  });

  it("rejects a direct commit check without async context while a real insert is parked", async () => {
    const storage = new ParkingLockStorage();
    await withHarness({ storage }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-direct", "passage-direct", "direct hook");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;

      await waitUntil(() => storage.receivedAbortSignal);

      const direct = h.core.commitCheck.assertAllowedToCommit({
        passageId: "passage-direct",
        documentId: `mem.${OWNER_REF}.passage-direct`,
        passageTextUtf8: Buffer.from("direct hook", "utf8"),
        passageTextSha256: hermesBridgePassageTextDigest("direct hook"),
        getFrameUtf8Bytes: memoryGetSuccessFrameUtf8Bytes({
          passage_id: "passage-direct",
          owner_ref: OWNER_REF,
          text: "direct hook",
          tags: ["hermes"],
          metadata: [],
          created_at: "2026-10-13T00:00:00.000Z",
          chunk_count: 1,
          content_hash: "hash-passage-direct",
          provenance_status: "verified",
        }),
      });

      expect(await shortOutcome(direct)).toBe("rejected");
      expect(h.writes.some((write) => write.type === "probe")).toBe(false);
      h.core.relayFrame({ kind: "relay_shutdown" });
      await waitForTerminal(h, "REFUSED");
      expect(await documentCount(h.storage)).toBe(0);
    });
  });

  it("busy-denies a second insert while one insert is in flight", async () => {
    await withHarness({}, async (h) => {
      accept(h.core, "c1");
      insert(h.core, "c1", "insert-one", "passage-one", "first");
      accept(h.core, "c2");
      insert(h.core, "c2", "insert-two", "passage-two", "second");
      await flush();

      expect(await documentCount(h.storage)).toBe(0);
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-two", type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
      expect(h.core.snapshot().ledger.entry?.state).toBe("INSERT_STARTED");
      cancelInsert(h.core);
      await flush();
    });
  });

  it("treats a never-issued probe reply as fatal without writing documents", async () => {
    await withHarness({}, async (h) => {
      accept(h.core);
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: "f".repeat(32) });
      await flush();

      expect(h.core.fatalBridge).toBe(true);
      expect(h.core.drained).toBe(true);
      expect(await documentCount(h.storage)).toBe(0);
      expect(h.writes).toEqual([]);
    });
  });

  it("discards a late closed-connection probe reply and keeps another connection usable", async () => {
    await withHarness({}, async (h) => {
      accept(h.core, "c1");
      insert(h.core, "c1", "insert-late", "passage-late", "late reply");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;

      const sentProbe = await waitForProbe(h.writes, "c1");
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
      await flush(20);

      accept(h.core, "c2");
      h.core.relayFrame(publicFrame("c2", { type: "hello", request_id: "hello-2", protocol_version: "2026-10-12", client_name: "client" }));
      await flush();

      expect(h.core.fatalBridge).toBe(false);
      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h)).toContain("DISCONNECTED");
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "hello-2", type: "result" });
    });
  });

  it("latches when admission audit rejects before storage writes", async () => {
    await withHarness({ rejectCommitIntentAudit: true }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-audit", "passage-audit", "audit refusal");
      await flush();
      await replyToProbe(h);
      await waitForTerminal(h, "REFUSED");

      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h)).toContain("REFUSED");
      expect(await waitForResponse(h.writes, "insert-audit")).toMatchObject({ type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });

      accept(h.core, "c2");
      insert(h.core, "c2", "insert-after-audit", "passage-after-audit", "later");
      await flush();
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-after-audit", type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
      expect(await documentCount(h.storage)).toBe(0);
    });
  });

  it("latches partial-scope outcomes after allow and writes no document record", async () => {
    const documentId = `mem.${OWNER_REF}.passage-partial`;
    const storage = new RollbackFailureStorage(
      documentKey(documentId),
      documentChunkKey(documentId, "000000", "c000000"),
    );
    await withHarness({ storage }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-partial", "passage-partial", "abcd");
      await flush();
      await replyToProbe(h);
      await waitForTerminal(h, "INDETERMINATE");

      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h)).toContain("INDETERMINATE");
      expect(h.audits.filter(audit => audit.kind === "insert_unconfirmed")).toHaveLength(1);
      expect(h.audits.filter(audit => audit.kind === "latch")).toHaveLength(1);
      expect(await waitForResponse(h.writes, "insert-partial")).toMatchObject({ type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });

      accept(h.core, "c2");
      insert(h.core, "c2", "insert-after-partial", "passage-after-partial", "later");
      await flush();
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-after-partial", type: "result", payload: HERMES_TOOL_OUTCOMES.unavailable });
      expect(await documentCount(h.storage)).toBe(0);
    });
  });
});

function cancelInsert(core: HermesBridgeCore): void {
  const entry = core.snapshot().ledger.entry!;
  const record = core.snapshot().lifecycle.records.find(record => record.id === entry.recordId)!;
  core.relayFrame(publicFrame(entry.connectionId, { type: "cancel", mcp_request_id: record.requestId }));
}

// Corpus capacity refuses before admission audit and keeps already saved passages searchable.
it("refuses bridge inserts at the owner corpus scan ceiling", async () => {
  const h = await makeHarness({ storage: new MemoryStorage(), corpusScanCap: 1 });
  try {
    accept(h.core);
    insert(h.core, "c1", "first", "first", "board meeting");
    await replyToProbe(h); await waitForResponse(h.writes, "first");
    const audits = h.audits.length;
    insert(h.core, "c1", "second", "second", "board meeting later");
    expect(await waitForResponse(h.writes, "second")).toMatchObject({ payload: HERMES_TOOL_OUTCOMES.unavailable });
    expect(h.audits).toHaveLength(audits);
    expect(await documentCount(h.storage)).toBe(1);
    expect((await h.adapter.searchPassages({ text: "board" })).map(row => row.passage.passage_id)).toEqual(["first"]);
  } finally { h.core.relayEof(); await flush(); await h.cleanup(); }
});

// Intent creation and deletion use the real adapter's encrypted checkpoint and rollback path.
it.each(["intent_write", "publish", "intent_delete"] as const)("preserves save recovery state on %s", async fault => {
  class FaultStorage extends MemoryStorage {
    corpusWrites = 0;
    override async write(namespace: string, key: string, data: Uint8Array) {
      if (fault === "intent_write" && namespace === HERMES_INSERT_INTENT_NAMESPACE) throw new Error("intent fixture");
      if (namespace === SDW_DOCUMENT_CORPUS_NAMESPACE) {
        this.corpusWrites++;
        if (fault === "publish" && key.startsWith("doc.")) throw new Error("publish fixture");
      }
      return super.write(namespace, key, data);
    }
    override async delete(namespace: string, key: string, secure?: boolean) {
      if (fault === "intent_delete" && namespace === HERMES_INSERT_INTENT_NAMESPACE) throw new Error("intent delete fixture");
      return super.delete(namespace, key, secure);
    }
  }
  const storage = new FaultStorage();
  const h = await makeHarness({ storage });
  try {
    accept(h.core); insert(h.core, "c1", "intent-save", "intent-save", "board meeting");
    await replyToProbe(h);
    const response = await waitForResponse(h.writes, "intent-save");
    expect(response).toMatchObject({ payload: fault === "publish" ? HERMES_TOOL_OUTCOMES.unconfirmed : HERMES_TOOL_OUTCOMES.unavailable });
    expect(await storage.read(HERMES_INSERT_INTENT_NAMESPACE, HERMES_INSERT_INTENT_KEY) === null).toBe(fault !== "intent_delete");
    expect(await documentCount(storage)).toBe(fault === "intent_delete" ? 1 : 0);
    if (fault === "intent_write") expect(storage.corpusWrites).toBe(0);
    if (fault === "intent_delete") expect(h.core.snapshot().ledger.latched).toBe(true);
  } finally { h.core.relayEof(); await flush(); await h.cleanup(); }
});
