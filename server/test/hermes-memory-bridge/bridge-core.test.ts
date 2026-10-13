import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
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
} = {}) {
  const timers = new ManualTimers();
  const writes: NodeToRelayInput[] = [];
  const audits: HermesBridgeAuditRecord[] = [];
  const ownerPrompts: string[] = [];
  const store = new Map<string, MemoryPassage>();
  const pendingGets: Deferred<MemoryPassage | null>[] = [];
  const abort = new AbortController();
  let now = 1_000;
  let core: HermesBridgeCore;
  const adapter: HermesBridgeMemoryAdapter = {
    async insertPassage(input: MemoryPassageInput, _taint: PersistableTaint): Promise<MemoryPassage> {
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
    },
    getPassage(passageId: string): Promise<MemoryPassage | null> {
      const deferred = new Deferred<MemoryPassage | null>();
      pendingGets.push(deferred);
      return deferred.promise.then((value) => value ?? store.get(passageId) ?? null);
    },
    async searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]> {
      const results = [...store.values()]
        .filter((entry) => entry.text.includes(query.text))
        .slice(0, query.limit ?? 10)
        .map((entry) => ({ passage: entry, match_count: 1 }));
      return results;
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
    nowMs: () => now,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
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
  });

  it("runs seeded bridge schedules against independent response and liveness oracles", async () => {
    const terminalStates = new Set<string>();
    const schedules = 3_000;
    for (let seed = 1; seed <= schedules; seed += 1) {
      const random = rng(seed * 2_654_435_761);
      const h = makeHarness();
      const connectionId = "c1";
      const requestId = `i${seed}`;
      const randomAwait = async () => h.tick(Math.floor(random() * 9));
      accept(h.core, connectionId);
      await randomAwait();
      insert(h.core, connectionId, requestId, `text ${seed}`);
      await randomAwait();
      const entry = h.core.snapshot().ledger.entry;
      if (entry === undefined) throw new Error(`seed ${seed} did not create an entry`);

      switch (seed % 6) {
        case 0:
          h.core.ownerApprove(entry.id, entry.textSha256);
          await randomAwait();
          {
            const probe = h.writes.find((frame): frame is Extract<NodeToRelayInput, { type: "probe" }> => frame.type === "probe");
            if (probe !== undefined) h.core.relayFrame({ kind: "probe_reply", connectionId, nonce: probe.nonce });
          }
          break;
        case 1:
          h.core.ownerDeny(entry.id);
          break;
        case 2:
          h.timers.fireFirst();
          break;
        case 3:
          h.core.relayFrame({ kind: "closed", connectionId });
          break;
        case 4:
          h.core.relayFrame(relayFrame(connectionId, { type: "cancel", mcp_request_id: requestId }));
          break;
        case 5:
          h.core.relayFrame({ kind: "relay_shutdown" });
          break;
      }

      await h.tick(12);
      for (const audit of h.audits) {
        if (audit.kind === "terminal" && audit.state !== undefined) terminalStates.add(audit.state);
      }
      const responses = h.writes.filter((frame) => frame.type === "response");
      expect(responses.length, `seed ${seed} response count`).toBeLessThanOrEqual(1);
      if (responses.length === 1) {
        expect(resultPayload(responses[0]!).request_id, `seed ${seed} response id`).toBe(requestId);
      }
      if (seed % 6 !== 0) expect(h.store.size, `seed ${seed} store`).toBe(0);
      if (!h.core.drained) h.core.relayFrame({ kind: "relay_shutdown" });
      await h.tick(12);
      expect(h.core.snapshot().slot, `seed ${seed} slot`).toBeUndefined();
      expect(h.core.snapshot().lifecycle.recordCount, `seed ${seed} records`).toBe(0);
      expect(h.core.drained, `seed ${seed} drained`).toBe(true);
    }
    expect(terminalStates).toEqual(new Set(["COMMITTED", "DENIED", "TIMED_OUT", "DISCONNECTED", "CANCELED", "REFUSED"]));
  });
});
