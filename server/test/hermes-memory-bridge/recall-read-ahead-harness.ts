// Shared harness for the recall read-ahead schedule tests: the real bridge core and its admission records over the
// real encrypted adapter, on an in-memory store whose reads can be parked, rejected or delayed and are counted from
// issue to settlement, and whose writes are counted.
import { expect } from "vitest";
import { HermesBridgeCore, type HermesBridgeAuditRecord } from "../../src/hermes-memory-bridge/bridge-core.js";
import { parsePublicFrame, type NodeToRelayInput } from "../../src/hermes-memory-bridge/envelopes.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { KeyOrderMemoryStorage } from "../sdw/recall-score-first-fixture.js";
import { TestSdwMemoryBackendAdapter } from "../sdw/test-memory-backend.js";

export const CREATED = "2026-11-01T00:00:00.000Z";
export const BRIDGE_MASTER_KEY = new Uint8Array(32).fill(29);
export const BRIDGE_FORTRESS = "read-ahead-bridge";
/** How one read behaves: parked until released, rejected, delayed by event-loop turns, or passed through. */
export type ReadRule = "park" | "reject" | "park-then-reject" | { readonly turns: number } | undefined;

/** Counts every read from issue to settlement, and every write; reads follow the installed rule. */
export class ScheduledStorage extends KeyOrderMemoryStorage {
  issued = 0;
  settled = 0;
  inFlight = 0;
  peakInFlight = 0;
  writes = 0;
  rule: (key: string) => ReadRule = () => undefined;
  readonly parked: { readonly key: string; readonly tag: number; readonly release: () => void }[] = [];
  /** Tag stamped on reads parked from now on, so one call's parked reads can be released apart from another's. */
  tag = 0;
  /** Bytes served for a key in place of the stored ones, as a file replaced on disk reads back; the write gate refuses writing them. */
  readonly planted = new Map<string, Uint8Array>();
  override async write(...args: Parameters<MemoryStorage["write"]>) { this.writes++; return super.write(...args); }
  override async writeIfAbsent(...args: Parameters<MemoryStorage["writeIfAbsent"]>) { this.writes++; return super.writeIfAbsent(...args); }
  override async replaceIfEquals(...args: Parameters<MemoryStorage["replaceIfEquals"]>) { this.writes++; return super.replaceIfEquals(...args); }
  override async delete(...args: Parameters<MemoryStorage["delete"]>) { this.writes++; return super.delete(...args); }
  override async read(namespace: string, key: string) {
    this.issued++;
    this.inFlight++;
    this.peakInFlight = Math.max(this.peakInFlight, this.inFlight);
    try {
      const rule = this.rule(key);
      if (rule === "park" || rule === "park-then-reject") {
        await new Promise<void>(release => this.parked.push({ key, tag: this.tag, release }));
      } else if (typeof rule === "object") {
        for (let turn = rule.turns; turn > 0; turn--) await nextTurn();
      }
      if (rule === "reject" || rule === "park-then-reject") throw new Error("scheduled read failure");
      return this.planted.get(key)?.slice() ?? await super.read(namespace, key);
    } finally {
      this.inFlight--;
      this.settled++;
    }
  }
  /** Release parked reads: all of them, those carrying one tag, or those whose key matches. */
  release(which?: number | ((key: string) => boolean)): number {
    let released = 0;
    for (let index = this.parked.length - 1; index >= 0; index--) {
      const read = this.parked[index]!;
      if (typeof which === "number" && read.tag !== which) continue;
      if (typeof which === "function" && !which(read.key)) continue;
      this.parked.splice(index, 1)[0]!.release();
      released++;
    }
    return released;
  }
  resetCounts(): void {
    this.issued = 0; this.settled = 0; this.peakInFlight = this.inFlight; this.writes = 0;
  }
}

export function nextTurn(): Promise<void> {
  return new Promise<void>(resolve => setImmediate(resolve));
}

/** Wait, one event-loop turn at a time, until the condition holds; a bounded wait, never a wall-clock sleep. */
export async function turnsUntil(condition: () => boolean, maxTurns = 5000): Promise<void> {
  for (let turn = 0; turn < maxTurns && !condition(); turn++) await nextTurn();
  expect(condition()).toBe(true);
}

/** Wait a fixed number of event-loop turns; reads that are not parked finish well inside it in this in-memory store. */
export async function quiesce(turns = 25): Promise<void> {
  for (let turn = 0; turn < turns; turn++) await nextTurn();
}

export async function recallBridge(passages: readonly { readonly id: string; readonly text: string }[]) {
  const storage = new ScheduledStorage();
  const adapter = new TestSdwMemoryBackendAdapter({ storage, masterKey: BRIDGE_MASTER_KEY, fortressId: BRIDGE_FORTRESS,
    ownerRef: "agent", now: () => CREATED });
  for (const passage of passages) await adapter.insertPassage({ passage_id: passage.id, text: passage.text }, "user_content");
  storage.resetCounts();
  let now = 0;
  const writes: NodeToRelayInput[] = [], audits: HermesBridgeAuditRecord[] = [];
  const onAudit: ((row: HermesBridgeAuditRecord) => void)[] = [];
  const abort = new AbortController();
  const core = new HermesBridgeCore({ completeAuditInsert() {}, agentId: "agent", abort, adapter,
    writeFrame: frame => writes.push(frame), appendAudit: async row => { for (const hook of onAudit) hook(row); audits.push(row); },
    nowMs: () => now, setTimer: () => ({}), clearTimer() {} });
  const frame = (connectionId: string, value: Record<string, unknown>) => {
    const publicBytes = Buffer.from(JSON.stringify(value));
    core.relayFrame({ kind: "frame", connectionId, publicBytes, publicFrame: parsePublicFrame(publicBytes) });
  };
  const responses = (requestId: string) => writes.filter(row => row.type === "response" && row.requestId === requestId);
  const body = (requestId: string) => {
    const response = responses(requestId).at(-1);
    if (response?.type !== "response") throw new Error("response absent");
    return JSON.parse(JSON.parse(Buffer.from(response.publicPayloadBytes).toString()).payload.content[0].text) as Record<string, unknown>;
  };
  return {
    storage, adapter, core, writes, audits, onAudit, abort, responses, body,
    accept: (connectionId: string) => core.relayFrame({ kind: "accepted", connectionId }),
    close: (connectionId: string) => core.relayFrame({ kind: "closed", connectionId }),
    call: (connectionId: string, requestId: string, query = "board meeting") =>
      frame(connectionId, { type: "tools_call", request_id: requestId, name: "memory_recall", arguments: { query } }),
    cancel: (connectionId: string, requestId: string) => frame(connectionId, { type: "cancel", mcp_request_id: requestId }),
    recordCount: () => core.snapshot().lifecycle.recordCount,
    recallAudits: () => audits.filter(row => row.kind === "memory_recall"),
    advance: (ms: number) => { now += ms; },
  };
}
