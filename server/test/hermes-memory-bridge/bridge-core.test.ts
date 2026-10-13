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
  readonly rejectAudit?: boolean;
  readonly writeProbeThrows?: boolean;
  readonly ownerPromptApproves?: boolean;
  readonly throwPort?: "insert" | "get" | "search" | "setTimer" | "clearTimer" | "nowMs";
  readonly getExtraField?: boolean;
} = {}) {
  const timers = new ManualTimers();
  const writes: NodeToRelayInput[] = [];
  const audits: HermesBridgeAuditRecord[] = [];
  const ownerPrompts: string[] = [];
  const insertTaints: PersistableTaint[] = [];
  const store = new Map<string, MemoryPassage>();
  const pendingGets: Deferred<MemoryPassage | null>[] = [];
  const abort = new AbortController();
  let now = 1_000;
  let core: HermesBridgeCore;
  const adapter: HermesBridgeMemoryAdapter = {
    insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage> {
      if (options.throwPort === "insert") throw new Error("insert port stopped");
      return (async () => {
        insertTaints.push(taint);
        const id = input.passage_id ?? `p-${store.size + 1}`;
        const inserted = passage(id, input.text);
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
      return Promise.resolve([...store.values()]
        .filter((entry) => entry.text.includes(query.text))
        .slice(0, query.limit ?? 10)
        .map((entry) => ({ passage: entry, match_count: 1 })));
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
      return options.stalledAudit === true ? new Promise(() => undefined) : Promise.resolve();
    },
    nowMs: () => {
      if (options.throwPort === "nowMs") throw new Error("clock port stopped");
      return now;
    },
    setTimer: (ms, fire) => {
      if (options.throwPort === "setTimer") throw new Error("timer port stopped");
      return timers.setTimer(ms, fire);
    },
    clearTimer: (handle) => {
      if (options.throwPort === "clearTimer") throw new Error("timer clear stopped");
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
  return {
    core,
    timers,
    writes,
    audits,
    ownerPrompts,
    insertTaints,
    store,
    pendingGets,
    abort,
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

function responsePayloads(writes: readonly NodeToRelayInput[]): Record<string, unknown>[] {
  return writes.filter((frame) => frame.type === "response").map(resultPayload);
}

function responseFor(writes: readonly NodeToRelayInput[], requestId: string): Record<string, unknown> | undefined {
  return responsePayloads(writes).find((payload) => payload.request_id === requestId);
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
    h.core.relayFrame(relayFrame("c1", {
      type: "tools_call",
      request_id: "missing-tool",
      name: "memory_delete",
      arguments: {},
    }));
    h.core.relayFrame(relayFrame("c1", {
      type: "hello",
      request_id: "after-missing",
      protocol_version: "2026-10-12",
      client_name: "client",
    }));

    expect(responseFor(h.writes, "missing-tool")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(responseFor(h.writes, "after-missing")).toMatchObject({ type: "result" });
    expect(h.core.snapshot().lifecycle.recordCount).toBe(0);
  });

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

  it("denies an adapter get result that carries non-public fields", async () => {
    const h = makeHarness({ getExtraField: true });
    h.store.set("p-extra", passage("p-extra", "bridge text"));
    accept(h.core);
    memoryGet(h.core, "c1", "get-extra", { passage_id: "p-extra" });
    h.pendingGets[0]!.resolve(null);
    await h.tick(4);

    expect(responseFor(h.writes, "get-extra")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
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

  it("refuses a peer-shutting insert at commit without writing a document", async () => {
    const h = makeHarness();
    accept(h.core);
    insert(h.core, "c1", "peer-shutdown", "bridge text");
    await h.tick();
    const entry = h.core.snapshot().ledger.entry!;
    h.core.relayFrame(relayFrame("c1", { type: "shutdown" }));
    h.core.ownerApprove(entry.id, entry.textSha256);
    await h.tick(8);

    expect(h.store.size).toBe(0);
    expect(responseFor(h.writes, "peer-shutdown")).toMatchObject({ type: "error", message: HERMES_MEMORY_DENIAL });
    expect(terminalStates(h.audits)).toContain("REFUSED/probe_refused");
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
    ["clearTimer", async (h: ReturnType<typeof makeHarness>) => {
      accept(h.core);
      insert(h.core, "c1", "throw-clear-timer", "bridge text");
      await h.tick();
      h.core.ownerDeny(h.core.snapshot().ledger.entry!.id);
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
