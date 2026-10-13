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
  hermesBridgePassageTextDigest,
  type SdwMemoryBackendAdapter,
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

function makeAdapter(storage: StorageBackend, commitCheck: HermesBridgeCore["commitCheck"]): SdwMemoryBackendAdapter {
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
    badSignerAuthority: BAD_SIGNER_AUTHORITY,
    commitCheck,
  });
}

async function makeHarness(options: {
  readonly storage?: StorageBackend;
  readonly rejectCommitIntentAudit?: boolean;
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
      if (options.rejectCommitIntentAudit === true && record.kind === "commit_intent") {
        return Promise.reject(new Error("audit failed"));
      }
      return Promise.resolve();
    },
    nowMs: () => 1_000,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
    adapter: {
      insertPassage: (input, taint) => adapter.insertPassage(input, taint),
      getPassage: (passageId) => adapter.getPassage(passageId),
      searchPassages: (query) => adapter.searchPassages(query),
    },
    ownerSurface: {
      promptOwner(entryId) {
        ownerPrompts.push(entryId);
      },
    },
    abort,
  };
  const core = new HermesBridgeCore(ports);
  adapter = makeAdapter(storage, core.commitCheck);
  return {
    core,
    adapter,
    storage,
    timers,
    writes,
    audits,
    ownerPrompts,
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

async function approveAndReply(h: Awaited<ReturnType<typeof makeHarness>>, connectionId = "c1"): Promise<void> {
  const entry = h.core.snapshot().ledger.entry;
  if (entry === undefined) throw new Error("missing approval entry");
  h.core.ownerApprove(entry.id, entry.textSha256);
  const sentProbe = await waitForProbe(h.writes, connectionId);
  h.core.relayFrame({ kind: "probe_reply", connectionId, nonce: sentProbe.nonce });
  await flush(20);
}

async function documentCount(storage: Pick<StorageBackend, "list">): Promise<number> {
  return (await storage.list(SDW_DOCUMENT_CORPUS_NAMESPACE, `doc.mem.${OWNER_REF}.`)).length;
}

function terminalStates(audits: readonly HermesBridgeAuditRecord[]): readonly string[] {
  return audits
    .filter((audit) => audit.kind === "terminal" && audit.state !== undefined)
    .map((audit) => audit.state!);
}

async function waitForTerminal(audits: readonly HermesBridgeAuditRecord[], state: string): Promise<void> {
  await waitUntil(() => terminalStates(audits).includes(state));
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
  it("commits an approved passage and reads back byte-equal text", async () => {
    await withHarness({}, async (h) => {
      accept(h.core);
      h.core.relayFrame(publicFrame("c1", { type: "hello", request_id: "hello-1", protocol_version: "2026-10-12", client_name: "client" }));
      insert(h.core, "c1", "insert-1", "passage-full", "the passage bytes");
      await flush();
      expect(h.ownerPrompts).toEqual(["hermes-entry-1"]);

      await approveAndReply(h);
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

  it.each([
    ["cancel before probe reply", "CANCELED", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-cancel", "passage-cancel", "cancel me");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;
      h.core.ownerApprove(entry.id, entry.textSha256);
      const sentProbe = await waitForProbe(h.writes);
      h.core.relayFrame(publicFrame("c1", { type: "cancel", mcp_request_id: "insert-cancel" }));
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
      expect(await waitForResponse(h.writes, "insert-cancel")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
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
      expect(responses(h.writes).at(-1)).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    }],
    ["owner deny", "DENIED", async (h: Awaited<ReturnType<typeof makeHarness>>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-deny", "passage-deny", "deny me");
      const entry = h.core.snapshot().ledger.entry!;
      h.core.ownerDeny(entry.id);
      await flush();
      expect(responses(h.writes).at(-1)).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
      expect(h.timers.live.size).toBe(0);
    }],
  ])("refuses with the real adapter: %s", async (_name, terminal, run) => {
    await withHarness({}, async (h) => {
      await run(h);
      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h.audits)).toContain(terminal);
    });
  });

  it("aborts a parked lock wait and writes no document", async () => {
    const storage = new ParkingLockStorage();
    await withHarness({ storage }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-stop", "passage-stop", "stop in lock");
      await flush();
      const entry = h.core.snapshot().ledger.entry!;
      h.core.ownerApprove(entry.id, entry.textSha256);
      await flush();
      h.core.relayFrame({ kind: "relay_shutdown" });
      await waitForTerminal(h.audits, "REFUSED");

      expect(storage.receivedAbortSignal).toBe(true);
      expect(h.abort.signal.aborted).toBe(true);
      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h.audits)).toContain("REFUSED");
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
      h.core.ownerApprove(entry.id, entry.textSha256);
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
      await waitForTerminal(h.audits, "REFUSED");
      expect(await documentCount(h.storage)).toBe(0);
    });
  });

  it("busy-denies a second insert while one approval is pending", async () => {
    await withHarness({}, async (h) => {
      accept(h.core, "c1");
      insert(h.core, "c1", "insert-one", "passage-one", "first");
      accept(h.core, "c2");
      insert(h.core, "c2", "insert-two", "passage-two", "second");
      await flush();

      expect(await documentCount(h.storage)).toBe(0);
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-two", type: "error", message: HERMES_MEMORY_DENIAL });
      expect(h.core.snapshot().ledger.entry?.state).toBe("PENDING");
      h.core.ownerDeny(h.core.snapshot().ledger.entry!.id);
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
      h.core.ownerApprove(entry.id, entry.textSha256);
      const sentProbe = await waitForProbe(h.writes, "c1");
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
      await flush(20);

      accept(h.core, "c2");
      h.core.relayFrame(publicFrame("c2", { type: "hello", request_id: "hello-2", protocol_version: "2026-10-12", client_name: "client" }));
      await flush();

      expect(h.core.fatalBridge).toBe(false);
      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h.audits)).toContain("DISCONNECTED");
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "hello-2", type: "result" });
    });
  });

  it("latches when commit-intent audit rejects before storage writes", async () => {
    await withHarness({ rejectCommitIntentAudit: true }, async (h) => {
      accept(h.core);
      insert(h.core, "c1", "insert-audit", "passage-audit", "audit refusal");
      await flush();
      await approveAndReply(h);
      await waitForTerminal(h.audits, "REFUSED");

      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h.audits)).toContain("REFUSED");
      expect(await waitForResponse(h.writes, "insert-audit")).toMatchObject({ type: "error", message: HERMES_MEMORY_UNAVAILABLE });

      accept(h.core, "c2");
      insert(h.core, "c2", "insert-after-audit", "passage-after-audit", "later");
      await flush();
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-after-audit", type: "error", message: HERMES_MEMORY_UNAVAILABLE });
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
      await approveAndReply(h);
      await waitForTerminal(h.audits, "INDETERMINATE");

      expect(await documentCount(h.storage)).toBe(0);
      expect(terminalStates(h.audits)).toContain("INDETERMINATE");
      const terminal = h.audits.find((audit) => audit.kind === "terminal" && audit.state === "INDETERMINATE");
      expect(terminal?.lateEvents).toContain("latch");
      expect(await waitForResponse(h.writes, "insert-partial")).toMatchObject({ type: "error", message: HERMES_MEMORY_UNAVAILABLE });

      accept(h.core, "c2");
      insert(h.core, "c2", "insert-after-partial", "passage-after-partial", "later");
      await flush();
      expect(responses(h.writes).at(-1)).toMatchObject({ request_id: "insert-after-partial", type: "error", message: HERMES_MEMORY_UNAVAILABLE });
      expect(await documentCount(h.storage)).toBe(0);
    });
  });
});
