import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  MAX_RESULT_FRAME_BYTES,
  PUBLIC_RESULT_ENVELOPE_MAX_BYTES,
  HermesBridgeCore,
  type HermesBridgeAuditRecord,
  type HermesBridgeCorePorts,
  type HermesBridgeMemoryAdapter,
  type HermesTimerHandle,
  parseRelayToNode,
  parsePublicFrame,
  type NodeToRelayInput,
  type RelayToNodeFrame,
} from "../../src/hermes-memory-bridge/index.js";
import type { MemoryPassage, MemoryPassageInput, MemorySearchQuery, MemorySearchResult } from "../../src/sdw/adapters/memory-backend.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { memoryGetSuccessFrameUtf8Bytes } from "../../src/sdw/memory-tool-projection.js";
import type { PersistableTaint } from "../../src/sdw/provenance.js";

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
    const first = this.live.keys().next().value as HermesTimerHandle | undefined;
    if (first === undefined) throw new Error("no timer to fire");
    const timer = this.live.get(first);
    this.live.delete(first);
    timer?.fire();
  }
}

class Deferred<T> {
  promise: Promise<T>;
  resolve!: (value: T) => void;
  reject!: (error: unknown) => void;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

function rng(seed: number): () => number {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state >>>= 0;
    state ^= state << 5;
    state >>>= 0;
    return state / 4_294_967_296;
  };
}

function publicBytes(frame: Record<string, unknown>): Uint8Array {
  return encoder.encode(JSON.stringify(frame));
}

function relayFrame(connectionId: string, frame: Record<string, unknown>): RelayToNodeFrame {
  const bytes = publicBytes(frame);
  return { kind: "frame", connectionId, publicBytes: bytes, publicFrame: parsePublicFrame(bytes) };
}

function resultPayload(frame: NodeToRelayInput): Record<string, unknown> {
  if (frame.type !== "response") throw new Error("expected response");
  return JSON.parse(Buffer.from(frame.publicPayloadBytes).toString("utf8")) as Record<string, unknown>;
}

function passage(passageId: string, text: string): MemoryPassage {
  return {
    passage_id: passageId,
    owner_ref: "fleet-self",
    text,
    tags: ["hermes"],
    metadata: [],
    created_at: "2026-10-13T00:00:00.000Z",
    chunk_count: 1,
    content_hash: `hash-${passageId}`,
    provenance_status: "verified",
  };
}

function makeHarness(options: {
  readonly stalledAudit?: boolean;
  readonly deferredAudit?: boolean;
  readonly rejectAudit?: boolean;
  readonly writeProbeThrows?: boolean;
  readonly ownerPromptApproves?: boolean;
  readonly throwPort?: "insert" | "get" | "search" | "setTimer" | "clearTimer" | "nowMs";
  readonly clearTimerFailures?: number;
  readonly nowMsFailureCall?: number;
  readonly getExtraField?: boolean;
  readonly parkInsertLock?: boolean;
  readonly deferredSearch?: boolean;
} = {}) {
  const timers = new ManualTimers();
  const writes: NodeToRelayInput[] = [];
  const audits: HermesBridgeAuditRecord[] = [];
  const pendingAudits: Deferred<void>[] = [];
  const ownerPrompts: string[] = [];
  const insertTaints: PersistableTaint[] = [];
  const store = new Map<string, MemoryPassage>();
  const pendingGets: Deferred<MemoryPassage | null>[] = [];
  const pendingSearches: Deferred<readonly MemorySearchResult[]>[] = [];
  const insertLocks: Deferred<void>[] = [];
  const abort = new AbortController();
  let now = 1_000;
  let nowCalls = 0;
  let core: HermesBridgeCore;
  let clearTimerFailures = options.clearTimerFailures ?? 0;
  let clearTimerAttempts = 0;
  const releasedRecordIds: string[] = [];
  const routedRecordIdsByRequest = new Map<string, string>();
  const adapter: HermesBridgeMemoryAdapter = {
    insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage> {
      if (options.throwPort === "insert") throw new Error("insert port stopped");
      return (async () => {
        insertTaints.push(taint);
        const id = input.passage_id ?? `p-${store.size + 1}`;
        const inserted = passage(id, input.text);
        if (options.parkInsertLock === true) {
          const parked = new Deferred<void>();
          insertLocks.push(parked);
          await parked.promise;
        }
        await core.commitCheck.assertAllowedToCommit({
          passageId: id,
          documentId: `mem.${id}`,
          passageTextUtf8: Buffer.from(input.text, "utf8"),
          passageTextSha256: hermesBridgePassageTextDigest(input.text),
          getFrameUtf8Bytes: memoryGetSuccessFrameUtf8Bytes(inserted),
        });
        store.set(id, inserted);
        return inserted;
      })();
    },
    getPassage(passageId: string): Promise<MemoryPassage | null> {
      if (options.throwPort === "get") throw new Error("get port stopped");
      const deferred = new Deferred<MemoryPassage | null>();
      pendingGets.push(deferred);
      return deferred.promise.then((value) => {
        const found = value ?? store.get(passageId) ?? null;
        return options.getExtraField === true && found !== null
          ? ({ ...found, extra: "not public" } as MemoryPassage)
          : found;
      });
    },
    searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]> {
      if (options.throwPort === "search") throw new Error("search port stopped");
      const results = [...store.values()]
        .filter((entry) => entry.text.includes(query.text))
        .slice(0, query.limit ?? 10)
        .map((entry) => ({ passage: entry, match_count: 1 }));
      if (options.deferredSearch === true) {
        const deferred = new Deferred<readonly MemorySearchResult[]>();
        pendingSearches.push(deferred);
        return deferred.promise;
      }
      return Promise.resolve(results);
    },
  };
  const ports: HermesBridgeCorePorts = {
    writeFrame(input) {
      if (input.type === "probe" && options.writeProbeThrows === true) {
        throw new Error("writer stopped");
      }
      writes.push(input);
    },
    appendAudit(record) {
      audits.push(record);
      if (options.rejectAudit === true) return Promise.reject(new Error("audit failed"));
      if (options.deferredAudit === true) {
        const deferred = new Deferred<void>();
        pendingAudits.push(deferred);
        return deferred.promise;
      }
      return options.stalledAudit === true ? new Promise(() => undefined) : Promise.resolve();
    },
    nowMs: () => {
      nowCalls += 1;
      if (options.throwPort === "nowMs") throw new Error("clock port stopped");
      if (options.nowMsFailureCall === nowCalls) throw new Error("clock port stopped");
      return now;
    },
    setTimer: (ms, fire) => {
      if (options.throwPort === "setTimer") throw new Error("timer port stopped");
      return timers.setTimer(ms, fire);
    },
    clearTimer: (handle) => {
      clearTimerAttempts += 1;
      if (options.throwPort === "clearTimer") throw new Error("timer clear stopped");
      if (clearTimerFailures > 0) {
        clearTimerFailures -= 1;
        throw new Error("timer clear stopped");
      }
      timers.clearTimer(handle);
    },
    adapter,
    ownerSurface: {
      promptOwner(entryId) {
        ownerPrompts.push(entryId);
        if (options.ownerPromptApproves === true) {
          const textSha256 = core.snapshot().ledger.entry?.textSha256 ?? "";
          core.ownerApprove(entryId, textSha256);
        }
      },
    },
    abort,
  };
  core = new HermesBridgeCore(ports);
  const lifecycle = (core as unknown as {
    readonly lifecycle: {
      apply(event: unknown): { readonly actions?: readonly unknown[] };
      release(recordId: string): unknown;
    };
  }).lifecycle;
  const originalApply = lifecycle.apply.bind(lifecycle);
  lifecycle.apply = (event: unknown) => {
    const result = originalApply(event);
    for (const action of result.actions ?? []) {
      if (
        typeof action === "object" &&
        action !== null &&
        "type" in action &&
        action.type === "route_call" &&
        "requestId" in action &&
        "recordId" in action &&
        typeof action.requestId === "string" &&
        typeof action.recordId === "string"
      ) {
        routedRecordIdsByRequest.set(action.requestId, action.recordId);
      }
    }
    return result;
  };
  const originalRelease = lifecycle.release.bind(lifecycle);
  lifecycle.release = (recordId: string) => {
    releasedRecordIds.push(recordId);
    return originalRelease(recordId);
  };
  return {
    core,
    timers,
    writes,
    audits,
    pendingAudits,
    ownerPrompts,
    insertTaints,
    store,
    pendingGets,
    pendingSearches,
    insertLocks,
    abort,
    clearTimerAttempts: () => clearTimerAttempts,
    recordIdForRequest: (requestId: string) => routedRecordIdsByRequest.get(requestId),
    releasedRecordIds: () => [...releasedRecordIds],
    resolveAudits() {
      for (const audit of pendingAudits.splice(0)) audit.resolve();
    },
    tick: async (count = 1) => {
      for (let index = 0; index < count; index += 1) await Promise.resolve();
    },
    advance(ms: number) {
      now += ms;
    },
  };
}

function accept(core: HermesBridgeCore, connectionId = "c1"): void {
  core.relayFrame({ kind: "accepted", connectionId });
}

function insert(core: HermesBridgeCore, connectionId = "c1", requestId = "i1", text = "bridge text"): void {
  core.relayFrame(relayFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_insert",
    arguments: { text, taint: "user_content", tags: ["hermes"], passage_id: `p-${requestId}` },
  }));
}

function insertWithArgs(
  core: HermesBridgeCore,
  connectionId: string,
  requestId: string,
  args: Record<string, unknown>,
): void {
  core.relayFrame(relayFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_insert",
    arguments: args,
  }));
}

function memoryGet(core: HermesBridgeCore, connectionId: string, requestId: string, args: Record<string, unknown>): void {
  core.relayFrame(relayFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_get",
    arguments: args,
  }));
}

function memorySearch(core: HermesBridgeCore, connectionId: string, requestId: string): void {
  core.relayFrame(relayFrame(connectionId, {
    type: "tools_call",
    request_id: requestId,
    name: "memory_search",
    arguments: { query: "bridge" },
  }));
}

function unknownTool(core: HermesBridgeCore, connectionId: string, requestId: string): void {
  const publicPayload = publicBytes({
    type: "tools_call",
    request_id: requestId,
    name: "memory_delete",
    arguments: {},
  });
  const parsed = parseRelayToNode(publicBytes({
    type: "frame",
    connection_id: connectionId,
    frame_b64: Buffer.from(publicPayload).toString("base64"),
  }));
  if (parsed.kind !== "ok") throw new Error("private frame did not parse");
  core.relayFrame(parsed.frame);
}

function responsePayloads(writes: readonly NodeToRelayInput[]): Record<string, unknown>[] {
  return writes.filter((frame) => frame.type === "response").map(resultPayload);
}

function responseFor(writes: readonly NodeToRelayInput[], requestId: string): Record<string, unknown> | undefined {
  return responsePayloads(writes).find((payload) => payload.request_id === requestId);
}

function toolResultBody(response: Record<string, unknown> | undefined): Record<string, unknown> {
  const payload = response?.payload as { readonly content?: Array<{ readonly text?: string }> } | undefined;
  return JSON.parse(payload?.content?.[0]?.text ?? "{}") as Record<string, unknown>;
}

function terminalStates(audits: readonly HermesBridgeAuditRecord[]): string[] {
  return audits
    .filter((audit) => audit.kind === "terminal" && audit.state !== undefined)
    .map((audit) => `${audit.state}/${audit.reason}`);
}

function findNearCapText(): string {
  let low = 1;
  let high = MAX_RESULT_FRAME_BYTES;
  while (low < high) {
    const mid = Math.floor((low + high) / 2);
    const text = "x".repeat(mid);
    const bytes = memoryGetSuccessFrameUtf8Bytes(passage("p-big", text)) + PUBLIC_RESULT_ENVELOPE_MAX_BYTES;
    if (bytes <= MAX_RESULT_FRAME_BYTES) low = mid + 1;
    else high = mid;
  }
  return "x".repeat(low);
}

describe("HermesBridgeCore", () => {
  it("routes hello and tools_list through the lifecycle response step", () => {
    const h = makeHarness();
    accept(h.core);
    h.core.relayFrame(relayFrame("c1", { type: "hello", request_id: "h1", protocol_version: "2026-10-12", client_name: "client" }));
    h.core.relayFrame(relayFrame("c1", { type: "tools_list", request_id: "t1" }));

    expect(h.writes.map((frame) => frame.type)).toEqual(["response", "response"]);
    expect(resultPayload(h.writes[0]!).request_id).toBe("h1");
    expect(resultPayload(h.writes[1]!).request_id).toBe("t1");
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("applies the call window to hello calls", () => {
    const h = makeHarness();
    accept(h.core);
    for (let index = 1; index <= 61; index += 1) {
      h.core.relayFrame(relayFrame("c1", {
        type: "hello",
        request_id: `h${index}`,
        protocol_version: "2026-10-12",
        client_name: "client",
      }));
    }

    const last = resultPayload(h.writes.at(-1)!);
    expect(last).toMatchObject({ request_id: "h61", type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("denies non-catalog tool calls and releases the call record", () => {
    const h = makeHarness();
    accept(h.core);
    unknownTool(h.core, "c1", "missing-tool");
    for (let index = 1; index <= 60; index += 1) {
      h.core.relayFrame(relayFrame("c1", {
        type: "hello",
        request_id: `after-missing-${index}`,
        protocol_version: "2026-10-12",
        client_name: "client",
      }));
    }

    expect(responseFor(h.writes, "missing-tool")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(responseFor(h.writes, "after-missing-60")).toMatchObject({ type: "result" });
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it.each(([
    ["hello", "hello-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      h.core.relayFrame(relayFrame("c1", { type: "hello", request_id: "hello-release", protocol_version: "2026-10-12", client_name: "client" }));
    }],
    ["tools_list", "tools-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      h.core.relayFrame(relayFrame("c1", { type: "tools_list", request_id: "tools-release" }));
    }],
    ["unknown tool denial", undefined, async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      unknownTool(h.core, "c1", "unknown-release");
    }],
    ["rate-limit denial", "rate-release-61", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      for (let index = 1; index <= 61; index += 1) {
        h.core.relayFrame(relayFrame("c1", {
          type: "hello",
          request_id: `rate-release-${index}`,
          protocol_version: "2026-10-12",
          client_name: "client",
        }));
      }
    }],
    ["memory_get ok", "get-release", async (h: ReturnType<typeof makeHarness>) => {
      h.store.set("p-get-release", passage("p-get-release", "bridge text"));
      accept(h.core);
      memoryGet(h.core, "c1", "get-release", { passage_id: "p-get-release" });
      h.pendingGets[0]!.resolve(null);
      await h.tick(4);
    }],
    ["memory_get bad args", "get-bad-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      memoryGet(h.core, "c1", "get-bad-release", { passage_id: "../bad" });
    }],
    ["memory_search completes after relay close", "search-release", async (h: ReturnType<typeof makeHarness>) => {
      h.store.set("p-search-release", passage("p-search-release", "bridge searchable text"));
      accept(h.core);
      memorySearch(h.core, "c1", "search-release");
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      h.pendingSearches[0]!.resolve([{ passage: passage("p-search-release", "bridge searchable text"), match_count: 1 }]);
      await h.tick(4);
    }, { deferredSearch: true }],
    ["memory_search adapter rejection releases after relay close", "search-reject-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      memorySearch(h.core, "c1", "search-reject-release");
      h.core.relayFrame({ kind: "closed", connectionId: "c1" });
      h.pendingSearches[0]!.reject(new Error("search failed"));
      await h.tick(4);
    }, { deferredSearch: true }],
    ["memory_search bad args", "search-bad-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      h.core.relayFrame(relayFrame("c1", {
        type: "tools_call",
        request_id: "search-bad-release",
        name: "memory_search",
        arguments: { query: "" },
      }));
    }],
    ["memory_insert committed passage releases after success", "insert-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      insert(h.core, "c1", "insert-release", "bridge text");
      await h.tick();
      const entry = h.core.snapshot().ledger.entry!;
      h.core.ownerApprove(entry.id, entry.textSha256);
      await h.tick(2);
      const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
      h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
      await h.tick(8);
      expect(responseFor(h.writes, "insert-release")).toMatchObject({ type: "result" });
      expect(h.store.get("p-insert-release")?.text).toBe("bridge text");
    }],
    ["memory_insert bad args", "insert-bad-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      insertWithArgs(h.core, "c1", "insert-bad-release", { text: "", taint: "user_content" });
    }],
    ["memory_insert admission latched", "latched-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core, "c1");
      insert(h.core, "c1", "latch-source-release", "bridge text");
      await h.tick(2);
      accept(h.core, "c2");
      insert(h.core, "c2", "latched-release", "later text");
    }, { rejectAudit: true }],
    ["memory_insert admission busy", "busy-release", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core, "c1");
      accept(h.core, "c2");
      insert(h.core, "c1", "busy-source-release", "bridge text");
      await h.tick();
      insert(h.core, "c2", "busy-release", "later text");
      await h.tick();
      h.core.ownerDeny(h.core.snapshot().ledger.entry!.id);
      await h.tick(4);
    }],
  ] as const).map(([name, requestId, run, options]) => [name, requestId, run, options ?? {}] as const))(
    "releases the lifecycle record after %s",
    async (_name, requestId, run, options) => {
      const h = makeHarness(options);
      await run(h);
      await h.tick(12);

      if (requestId === undefined) {
        expect(h.recordIdForRequest("unknown-release")).toBeUndefined();
      } else {
        const recordId = h.recordIdForRequest(requestId);
        expect(recordId).toBeDefined();
        expect(h.releasedRecordIds()).toContain(recordId);
      }
      expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
    },
  );

  it("denies memory_get arguments outside the passage id allowlist before the adapter", () => {
    const h = makeHarness({ throwPort: "get" });
    accept(h.core);
    memoryGet(h.core, "c1", "get-bad", { passage_id: "../not-allowed" });

    expect(responseFor(h.writes, "get-bad")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.core.snapshot().stopped).toBe(false);
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("keeps release-demo calls from exhausting the lifecycle record capacity", async () => {
    const h = makeHarness();
    for (let index = 1; index <= 8; index += 1) {
      const connectionId = `c${index}`;
      accept(h.core, connectionId);
      h.core.relayFrame(relayFrame(connectionId, {
        type: "tools_call",
        request_id: `g${index}`,
        name: "memory_get",
        arguments: { passage_id: "absent" },
      }));
      h.core.relayFrame({ kind: "closed", connectionId });
      h.pendingGets[index - 1]!.resolve(null);
      await h.tick(6);
    }

    accept(h.core, "c9");
    h.core.relayFrame(relayFrame("c9", { type: "hello", request_id: "h9", protocol_version: "2026-10-12", client_name: "client" }));

    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
    expect(resultPayload(h.writes.at(-1)!).type).toBe("result");
    expect(resultPayload(h.writes.at(-1)!).request_id).toBe("h9");
  });

  it("commits an approved insert only after the probe reply and durable audits", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core);
    await h.tick();
    expect(h.ownerPrompts).toEqual(["hermes-entry-1"]);
    const entry = h.core.snapshot().ledger.entry;
    expect(entry?.state).toBe("PENDING");

    h.core.ownerApprove(entry!.id, entry!.textSha256);
    await h.tick(2);
    const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe");
    expect(probe).toBeDefined();
    expect(h.store.size).toBe(0);

    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe!.nonce });
    await h.tick(6);

    expect(h.store.get("p-i1")?.text).toBe("bridge text");
    const response = h.writes.find((frame) => frame.type === "response" && resultPayload(frame).request_id === "i1");
    expect(response).toBeDefined();
    expect(resultPayload(response!).type).toBe("result");
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("pins insert taint to user content before calling the adapter", async () => {
    const h = makeHarness();
    accept(h.core);
    insertWithArgs(h.core, "c1", "i-system", {
      text: "caller selected another class",
      taint: "system_generated",
      tags: ["hermes"],
      passage_id: "p-i-system",
    });
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(8);

    expect(h.insertTaints).toEqual(["user_content"]);
    expect(h.store.get("p-i-system")?.text).toBe("caller selected another class");
  });

  it("refuses an insert whose future get result would exceed the public frame bound", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core, "c1", "big", findNearCapText());
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(10);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "big")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(terminalStates(h.audits)).toContain("REFUSED/commit_binding_mismatch");
  });

  it("records public shutdown on a waiting insert with the peer shutdown reason", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core, "c1", "shutdown-before-start", "bridge text");
    await h.tick();
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    await h.tick(6);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "shutdown-before-start")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(terminalStates(h.audits)).toContain("CANCELED/peer_shutdown");
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("does not let a canceled read feed the live insert ledger", async () => {
    const h = makeHarness();
    accept(h.core, "c1");
    insert(h.core, "c1", "insert-live", "bridge text");
    await h.tick();
    accept(h.core, "c2");
    memoryGet(h.core, "c2", "read-cancel", { passage_id: "missing" });
    h.core.relayFrame(relayFrame("c2", { type: "cancel", mcp_request_id: "read-cancel" }));
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    h.pendingGets[0]!.resolve(null);
    await h.tick(10);

    expect(h.store.get("p-insert-live")?.text).toBe("bridge text");
    expect(responseFor(h.writes, "insert-live")).toMatchObject({ type: "result" });
  });

  it("serves committed reads while a later approved insert waits on durability", async () => {
    const h = makeHarness({ deferredAudit: true });
    accept(h.core, "c1");
    insert(h.core, "c1", "first-visible", "first bridge passage");
    await h.tick();
    const firstEntry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(firstEntry.id, firstEntry.textSha256);
    await h.tick(2);
    const firstProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: firstProbe.nonce });
    for (let pass = 0; pass < 3; pass += 1) {
      h.resolveAudits();
      await h.tick(8);
    }
    expect(h.store.get("p-first-visible")?.text).toBe("first bridge passage");

    accept(h.core, "c2");
    insert(h.core, "c2", "second-visible", "second bridge passage");
    await h.tick();
    const secondEntry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(secondEntry.id, secondEntry.textSha256);
    await h.tick(2);
    const secondProbe = h.writes
      .filter((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")
      .at(-1)!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c2", nonce: secondProbe.nonce });
    await h.tick(4);

    expect(h.core.snapshot().slot?.durabilityPending).toBeGreaterThan(0);
    expect(h.store.has("p-second-visible")).toBe(false);

    accept(h.core, "c3");
    memoryGet(h.core, "c3", "get-first-visible", { passage_id: "p-first-visible" });
    h.pendingGets[0]?.resolve(null);
    accept(h.core, "c4");
    memorySearch(h.core, "c4", "search-first-visible");
    await h.tick(8);

    expect(toolResultBody(responseFor(h.writes, "get-first-visible"))).toMatchObject({
      found: true,
      passage: { passage_id: "p-first-visible", text: "first bridge passage" },
    });
    expect(toolResultBody(responseFor(h.writes, "search-first-visible"))).toMatchObject({
      results: [{ passage: { passage_id: "p-first-visible" }, match_count: 1 }],
    });

    for (let pass = 0; pass < 3; pass += 1) {
      h.resolveAudits();
      await h.tick(8);
    }

    expect(h.store.get("p-first-visible")?.text).toBe("first bridge passage");
    expect(h.store.get("p-second-visible")?.text).toBe("second bridge passage");
    expect(responseFor(h.writes, "second-visible")).toMatchObject({ type: "result" });
  });

  it("denies an adapter get result that carries non-public fields", async () => {
    const h = makeHarness({ getExtraField: true });
    h.store.set("p-extra", passage("p-extra", "bridge text"));
    accept(h.core);
    memoryGet(h.core, "c1", "get-extra", { passage_id: "p-extra" });
    h.pendingGets[0]!.resolve(null);
    await h.tick(4);

    expect(responseFor(h.writes, "get-extra")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
  });

  it("returns only public search result keys", async () => {
    const h = makeHarness();
    h.store.set("p-search", passage("p-search", "bridge searchable text"));
    accept(h.core);
    memorySearch(h.core, "c1", "search-public");
    await h.tick(4);

    const response = responseFor(h.writes, "search-public") as {
      readonly payload?: { readonly content?: Array<{ readonly text?: string }> };
    };
    const body = JSON.parse(response.payload?.content?.[0]?.text ?? "{}") as {
      readonly results?: Array<{ readonly passage?: Record<string, unknown>; readonly match_count?: unknown }>;
    };
    const result = body.results?.[0];
    expect(Object.keys(result ?? {}).sort()).toEqual(["match_count", "passage"]);
    expect(Object.keys(result?.passage ?? {}).sort()).toEqual([
      "chunk_count",
      "content_hash",
      "created_at",
      "owner_ref",
      "passage_id",
      "tag_count",
    ]);
  });

  it("keeps the live insert slot when a second insert is busy-denied and then owner-denied", async () => {
    const h = makeHarness();
    accept(h.core, "c1");
    accept(h.core, "c2");
    insert(h.core, "c1", "first", "first text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    insert(h.core, "c2", "second", "second text");
    await h.tick();

    expect(responseFor(h.writes, "second")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.core.snapshot().slot?.entryId).toBe(entry.id);
    h.core.ownerDeny(entry.id);
    await h.tick(4);
    h.core.relayFrame({ kind: "relay_shutdown" });
    await h.tick(4);

    expect(responseFor(h.writes, "first")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
    expect(h.timers.live.size).toBe(0);
    expect(h.core.drained).toBe(true);
  });

  it("keeps the live insert deadline when a second insert is busy-denied", async () => {
    const h = makeHarness();
    accept(h.core, "c1");
    accept(h.core, "c2");
    insert(h.core, "c1", "first-timeout", "first text");
    insert(h.core, "c2", "second-timeout", "second text");
    await h.tick();
    h.timers.fireFirst();
    await h.tick(4);
    h.core.relayFrame({ kind: "relay_shutdown" });
    await h.tick(4);

    expect(responseFor(h.writes, "first-timeout")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(responseFor(h.writes, "second-timeout")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.timers.live.size).toBe(0);
    expect(h.core.drained).toBe(true);
  });

  it("keeps an approved insert live when a second insert is refused during the probe wait", async () => {
    const h = makeHarness();
    accept(h.core, "c1");
    accept(h.core, "c2");
    insert(h.core, "c1", "first-probe", "first text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    insert(h.core, "c2", "second-probe", "second text");
    await h.tick();
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(10);
    h.core.relayFrame({ kind: "relay_shutdown" });
    await h.tick(4);

    expect(responseFor(h.writes, "second-probe")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(responseFor(h.writes, "first-probe")).toMatchObject({ type: "result" });
    expect(h.store.get("p-first-probe")?.text).toBe("first text");
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.timers.live.size).toBe(0);
    expect(h.core.drained).toBe(true);
  });

  it("refuses an approved insert parked behind peer shutdown before probing", async () => {
    const h = makeHarness({ parkInsertLock: true });
    accept(h.core);
    insert(h.core, "c1", "peer-shutdown", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(4);
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    h.insertLocks[0]!.resolve();
    await h.tick(12);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "peer-shutdown")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.writes.filter((frame) => frame.type === "probe")).toHaveLength(0);
    expect(terminalStates(h.audits)).toContain("REFUSED/probe_refused");
  });

  it("denies an insert when approval deadline fires before the clock reaches its boundary", async () => {
    const h = makeHarness({ deferredAudit: true, parkInsertLock: true });
    accept(h.core);
    insert(h.core, "c1", "deadline-before-clock", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(4);

    expect(h.core.snapshot().slot?.insertInFlight).toBe(true);
    h.timers.fireFirst();
    h.insertLocks[0]!.resolve();
    await h.tick(4);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    h.resolveAudits();
    await h.tick(4);
    h.resolveAudits();
    await h.tick(12);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "deadline-before-clock")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(terminalStates(h.audits)).toContain("TIMED_OUT/deadline");
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("denies an insert when the approval deadline is seen during parked audit durability", async () => {
    const h = makeHarness({ deferredAudit: true });
    accept(h.core);
    insert(h.core, "c1", "deadline-during-durability", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(4);

    expect(h.core.snapshot().slot?.durabilityPending).toBeGreaterThan(0);
    h.timers.fireFirst();
    await h.tick(12);

    const recordId = h.recordIdForRequest("deadline-during-durability");
    expect(recordId).toBeDefined();
    expect(h.releasedRecordIds()).toContain(recordId);
    expect(h.pendingAudits.length).toBe(h.audits.length);
    expect(h.pendingAudits.length).toBeGreaterThan(0);
    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "deadline-during-durability")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(terminalStates(h.audits)).toContain("TIMED_OUT/deadline");
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("denies an insert when peer shutdown arrives during the durability wait", async () => {
    const h = makeHarness({ deferredAudit: true });
    accept(h.core);
    insert(h.core, "c1", "shutdown-during-audit", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(4);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(4);
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    h.resolveAudits();
    await h.tick(12);
    h.resolveAudits();
    await h.tick(12);
    h.core.relayFrame({ kind: "closed", connectionId: "c1" });
    await h.tick(4);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "shutdown-during-audit")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(h.writes.filter((frame) => frame.type === "response" && resultPayload(frame).request_id === "shutdown-during-audit")).toHaveLength(1);
    expect(terminalStates(h.audits)).toContain("CANCELED/cancel");
  });

  it("denies an insert when peer shutdown arrives before the probe reply", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core, "c1", "shutdown-before-reply", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(4);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(12);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "shutdown-before-reply")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
  });

  it("denies an insert when peer shutdown arrives after the probe reply while audit is stalled", async () => {
    const h = makeHarness({ deferredAudit: true });
    accept(h.core);
    insert(h.core, "c1", "shutdown-after-reply", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(4);
    const sentProbe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: sentProbe.nonce });
    await h.tick(4);
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    h.resolveAudits();
    await h.tick(12);
    h.resolveAudits();
    await h.tick(12);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "shutdown-after-reply")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
  });

  it("fires the approval deadline and clears the one-slot resources", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core);
    h.timers.fireFirst();
    await h.tick(2);

    const response = h.writes.find((frame) => frame.type === "response");
    expect(response).toBeDefined();
    expect(resultPayload(response!).message).toBe(HERMES_MEMORY_DENIAL);
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.timers.live.size).toBe(0);
  });

  it("turns audit rejection into unavailable admission for later inserts", async () => {
    const h = makeHarness({ rejectAudit: true });
    accept(h.core);
    insert(h.core);
    await h.tick(2);

    accept(h.core, "c2");
    insert(h.core, "c2", "i2", "later");

    const messages = h.writes.filter((frame) => frame.type === "response").map((frame) => resultPayload(frame).message);
    expect(messages).toContain(HERMES_MEMORY_UNAVAILABLE);
  });

  it("delivers promptOwner outside the admitting turn", async () => {
    const h = makeHarness({ ownerPromptApproves: true });
    accept(h.core);
    insert(h.core);
    expect(h.core.snapshot().ledger.entry?.state).toBe("PENDING");
    await h.tick(2);
    expect(h.core.snapshot().ledger.entry?.state).toBe("APPROVED");
  });

  it("treats a never-issued probe reply as a fatal bridge stop", async () => {
    const h = makeHarness();
    accept(h.core);
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: "f".repeat(32) });
    await h.tick(2);

    expect(h.core.fatalBridge).toBe(true);
    expect(h.core.drained).toBe(true);
  });

  it("clears the live probe synchronously when the connection closes", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core);
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;

    h.core.relayFrame({ kind: "closed", connectionId: "c1" });

    expect(h.core.snapshot().waiter.live).toBeUndefined();
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
    await h.tick(8);
    expect(h.core.fatalBridge).toBe(false);
    expect(h.store.size).toBe(0);
    expect(h.core.snapshot().slot).toBeUndefined();
  });

  it("drains a stopped insert even when durability is stalled", async () => {
    const h = makeHarness({ stalledAudit: true });
    accept(h.core);
    insert(h.core);
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(2);
    const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe")!;
    h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
    await h.tick(2);

    h.core.relayFrame({ kind: "relay_shutdown" });
    await h.tick(8);

    expect(h.core.drained).toBe(true);
    expect(h.store.size).toBe(0);
    expect(terminalStates(h.audits)).toContain("DISCONNECTED/connection_gone");
  });

  it("stops and drains when the probe write fails", async () => {
    const h = makeHarness({ writeProbeThrows: true });
    accept(h.core);
    insert(h.core);
    const entry = h.core.snapshot().ledger.entry!;
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(6);

    expect(h.abort.signal.aborted).toBe(true);
    expect(h.core.drained).toBe(true);
    expect(h.store.size).toBe(0);
    expect(terminalStates(h.audits)).toContain("DISCONNECTED/connection_gone");
  });

  it.each([
    ["insert", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      insert(h.core, "c1", "throw-insert", "bridge text");
      await h.tick();
      const entry = h.core.snapshot().ledger.entry!;
      h.core.ownerApprove(entry.id, entry.textSha256);
    }],
    ["get", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      memoryGet(h.core, "c1", "throw-get", { passage_id: "p" });
    }],
    ["search", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      memorySearch(h.core, "c1", "throw-search");
    }],
    ["setTimer", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      insert(h.core, "c1", "throw-set-timer", "bridge text");
    }],
    ["nowMs", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      h.core.relayFrame(relayFrame("c1", { type: "hello", request_id: "throw-clock", protocol_version: "2026-10-12", client_name: "client" }));
    }],
  ] as const)("stops and drains when the %s port throws synchronously", async (port, run) => {
    const h = makeHarness({ throwPort: port });
    await run(h);
    await h.tick(12);

    expect(h.core.snapshot().stopped).toBe(true);
    expect(h.core.drained).toBe(true);
    expect(h.core.snapshot().slot).toBeUndefined();
    expect(h.core.snapshot().waiter.live).toBeUndefined();
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("records admission before a deadline timer failure stops the bridge", async () => {
    const h = makeHarness({ throwPort: "setTimer" });
    accept(h.core);
    insert(h.core, "c1", "timer-audit", "bridge text");
    await h.tick(8);

    expect(h.audits.map((audit) => audit.kind)).toEqual(["created", "terminal"]);
    expect(terminalStates(h.audits)).toContain("REFUSED/stopped");
    expect(h.ownerPrompts).toEqual([]);
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("releases the insert record when the admission clock fails", async () => {
    const h = makeHarness({ nowMsFailureCall: 2 });
    accept(h.core);
    insert(h.core, "c1", "clock-admission", "bridge text");
    await h.tick(8);

    expect(h.core.snapshot().stopped).toBe(true);
    expect(h.core.drained).toBe(true);
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

  it("retries a timer clear during stop and ignores a late fire after cleanup", async () => {
    const h = makeHarness({ clearTimerFailures: 2 });
    accept(h.core);
    insert(h.core, "c1", "clear-retry", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    const lateFire = [...h.timers.live.values()][0]!.fire;
    h.core.ownerDeny(entry.id);
    await h.tick(8);

    expect(h.clearTimerAttempts()).toBe(3);
    expect(h.timers.live.size).toBe(0);
    expect(h.core.snapshot().stopped).toBe(true);
    expect(h.core.snapshot().slot).toBeUndefined();
    const responsesBeforeLateFire = h.writes.filter((frame) => frame.type === "response").length;
    lateFire();
    await h.tick(4);
    expect(h.writes.filter((frame) => frame.type === "response")).toHaveLength(responsesBeforeLateFire);
  });

  it("retains an uncleared timer when stop cleanup cannot clear it", async () => {
    const h = makeHarness({ throwPort: "clearTimer" });
    accept(h.core);
    insert(h.core, "c1", "clear-retained", "bridge text");
    await h.tick();
    h.core.ownerDeny(h.core.snapshot().ledger.entry!.id);
    await h.tick(8);

    expect(h.clearTimerAttempts()).toBeGreaterThan(1);
    expect(h.core.snapshot().stopCause).toBe("write_failure");
    expect(h.core.snapshot().slot?.hasDeadlineTimer).toBe(true);
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
    expect(h.core.drained).toBe(false);
  });

  it("runs multi-connection schedules against response, allow and drain oracles", async () => {
    const terminalStates = new Set<string>();
    const schedules = 600;
    for (let seed = 1; seed <= schedules; seed += 1) {
      const random = rng(seed * 2_654_435_761);
      const h = makeHarness();
      const requestId = `i${seed}`;
      const violations: string[] = [];
      let forbiddenForEntry = false;
      const ledger = (h.core as unknown as {
        ledger: { commitCheck: (entryId: string, input: unknown) => { readonly decision: string } };
      }).ledger;
      const originalCommitCheck = ledger.commitCheck.bind(ledger);
      ledger.commitCheck = (entryId: string, input: unknown) => {
        const result = originalCommitCheck(entryId, input);
        if (result.decision === "allow" && forbiddenForEntry) violations.push(`allow after dispatched refusal for ${entryId}`);
        return result;
      };
      const randomAwait = async () => h.tick(Math.floor(random() * 9));
      accept(h.core, "c1");
      accept(h.core, "c2");
      await randomAwait();
      insert(h.core, "c1", requestId, `text ${seed}`);
      await randomAwait();
      const entry = h.core.snapshot().ledger.entry;
      if (entry === undefined) throw new Error(`seed ${seed} did not create an entry`);

      switch (seed % 8) {
        case 0:
          h.core.ownerApprove(entry.id, entry.textSha256);
          await randomAwait();
          {
            const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe");
            if (probe !== undefined) h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
          }
          break;
        case 1:
          forbiddenForEntry = true;
          h.core.ownerDeny(entry.id);
          break;
        case 2:
          forbiddenForEntry = true;
          h.timers.fireFirst();
          break;
        case 3:
          forbiddenForEntry = true;
          h.core.relayFrame({ kind: "closed", connectionId: "c1" });
          break;
        case 4:
          forbiddenForEntry = true;
          h.core.relayFrame(relayFrame("c1", { type: "cancel", mcp_request_id: requestId }));
          break;
        case 5:
          forbiddenForEntry = true;
          h.core.relayFrame({ kind: "relay_shutdown" });
          break;
        case 6:
          insert(h.core, "c2", `second-${seed}`, "second text");
          await randomAwait();
          h.core.ownerApprove(entry.id, entry.textSha256);
          await randomAwait();
          {
            const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe");
            if (probe !== undefined) h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
          }
          break;
        case 7:
          memoryGet(h.core, "c2", `read-${seed}`, { passage_id: "absent" });
          if (random() < 0.5) h.core.relayFrame(relayFrame("c2", { type: "cancel", mcp_request_id: `read-${seed}` }));
          h.core.ownerApprove(entry.id, entry.textSha256);
          await randomAwait();
          {
            const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe");
            if (probe !== undefined) h.core.relayFrame({ kind: "probe_reply", connectionId: "c1", nonce: probe.nonce });
          }
          for (const pending of h.pendingGets) pending.resolve(null);
          break;
      }

      await h.tick(12);
      for (const pending of h.pendingGets) pending.resolve(null);
      for (const audit of h.audits) {
        if (audit.kind === "terminal" && audit.state !== undefined) terminalStates.add(audit.state);
      }
      const responses = h.writes.filter((frame) => frame.type === "response");
      const seenResponseIds = new Set<string>();
      for (const response of responses) {
        const payload = resultPayload(response);
        expect(seenResponseIds.has(payload.request_id as string), `seed ${seed} duplicate response ${String(payload.request_id)}`).toBe(false);
        seenResponseIds.add(payload.request_id as string);
      }
      if ([1, 2, 3, 4, 5].includes(seed % 8)) expect(h.store.size, `seed ${seed} store`).toBe(0);
      expect(violations, `seed ${seed} allow oracle`).toEqual([]);
      if (!h.core.drained) h.core.relayFrame({ kind: "relay_shutdown" });
      await h.tick(12);
      expect(h.core.snapshot().slot, `seed ${seed} slot`).toBeUndefined();
      expect(h.core.snapshot().waiter.live, `seed ${seed} live probe`).toBeUndefined();
      expect(h.timers.live.size, `seed ${seed} timers`).toBe(0);
      expect(h.core.drained, `seed ${seed} drained`).toBe(true);
    }
    expect(terminalStates).toEqual(new Set(["COMMITTED", "DENIED", "TIMED_OUT", "DISCONNECTED", "CANCELED", "REFUSED"]));
  });
});
