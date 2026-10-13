import { describe, expect, it } from "vitest";
import {
  HERMES_MAX_CALL_RECORDS,
  HERMES_MAX_PUBLIC_CONNECTIONS,
  HermesConnectionLifecycle,
  classifyHermesPublicFrameSummary,
  type HermesLifecycleAction,
  type HermesLifecycleEvent,
} from "../../src/hermes-memory-bridge/index.js";

type PubFrame =
  | { t: "call"; rid: string; bad: boolean }
  | { t: "cancel"; rid: string; bad: boolean }
  | { t: "shutdown"; bad: boolean }
  | { t: "garbage" };

type ToNode =
  | { t: "accepted"; c: string }
  | { t: "frame"; c: string; f: PubFrame }
  | { t: "closed"; c: string }
  | { t: "relay_shutdown" };

type ToRelay = { t: "response"; c: string; rid: string } | { t: "close"; c: string };

class RelayConn {
  state: "S" | "I" | "P" | "C" = "S";
  closedSent = false;
  cur: string | undefined;

  constructor(
    readonly c: string,
    private readonly relay: RelayModel,
  ) {}

  closeOnce(): void {
    if (this.closedSent) return;
    this.state = "C";
    this.closedSent = true;
    this.relay.live -= 1;
    this.relay.toNode.push({ t: "closed", c: this.c });
  }

  poison(): void {
    if (!this.relay.closedIsAbsorbing || !this.closedSent) this.state = "P";
    this.closeOnce();
  }

  publicBatch(frames: readonly PubFrame[]): void {
    if (this.state === "C") return;
    for (const frame of frames) this.publicFrame(frame);
  }

  publicFrame(frame: PubFrame): void {
    if (frame.t === "garbage") {
      this.poison();
      return;
    }
    switch (this.state) {
      case "S":
        if (frame.t === "cancel") {
          this.relay.toNode.push({ t: "frame", c: this.c, f: frame });
          return;
        }
        if (frame.t === "shutdown") {
          this.relay.toNode.push({ t: "frame", c: this.c, f: frame });
          this.closeOnce();
          return;
        }
        this.state = "I";
        this.cur = frame.rid;
        this.relay.forwardedCalls += 1;
        this.relay.toNode.push({ t: "frame", c: this.c, f: frame });
        return;
      case "I":
        if (frame.t === "cancel") {
          this.relay.toNode.push({ t: "frame", c: this.c, f: frame });
          return;
        }
        if (frame.t === "shutdown") {
          this.relay.toNode.push({ t: "frame", c: this.c, f: frame });
          this.closeOnce();
          return;
        }
        return;
      case "P":
      case "C":
        return;
    }
  }

  nodeFrame(frame: ToRelay): void {
    if (this.state === "C") return;
    if (frame.t === "close") {
      this.closeOnce();
      return;
    }
    if (this.state !== "I" || this.cur === undefined) {
      this.relay.fatal.push(`response without in-flight call on ${this.c}`);
      return;
    }
    if (frame.rid !== this.cur) this.relay.mismatch.push(`${this.c} ${frame.rid} ${this.cur}`);
    this.state = "S";
    this.cur = undefined;
  }
}

class RelayModel {
  live = 0;
  next = 1;
  readonly conns = new Map<string, RelayConn>();
  readonly toNode: ToNode[] = [];
  readonly fatal: string[] = [];
  readonly mismatch: string[] = [];
  forwardedCalls = 0;
  shutdownSent = false;

  constructor(readonly closedIsAbsorbing: boolean) {}

  accept(): void {
    if (this.shutdownSent || this.live >= HERMES_MAX_PUBLIC_CONNECTIONS) return;
    const c = `c${this.next++}`;
    this.conns.set(c, new RelayConn(c, this));
    this.live += 1;
    this.toNode.push({ t: "accepted", c });
  }

  openConns(): RelayConn[] {
    return [...this.conns.values()].filter((conn) => conn.state !== "C");
  }
}

class NodeModel {
  readonly lc = new HermesConnectionLifecycle();
  readonly works = new Map<string, { c: string; rid: string }>();
  readonly toRelay: ToRelay[] = [];
  readonly fatal: string[] = [];
  sentAfterStop = 0;
  e9Missed = 0;
  boundViolations = 0;

  apply(event: HermesLifecycleEvent): void {
    const result = this.lc.apply(event);
    if (result.fatal) this.fatal.push(`${result.fatal.reason}`);
    this.act(result.actions);
    if (this.lc.recordCount > HERMES_MAX_CALL_RECORDS || this.lc.liveCount > HERMES_MAX_PUBLIC_CONNECTIONS) {
      this.boundViolations += 1;
    }
  }

  send(frame: ToRelay): void {
    if (this.lc.stopped) this.sentAfterStop += 1;
    this.toRelay.push(frame);
  }

  act(actions: readonly HermesLifecycleAction[]): void {
    for (const action of actions) {
      if (action.type === "route_call") this.works.set(action.recordId, { c: action.connectionId, rid: action.requestId });
      else if (action.type === "send_fixed_denial") this.send({ t: "response", c: action.connectionId, rid: action.requestId });
      else if (action.type === "send_close") this.send({ t: "close", c: action.connectionId });
    }
  }

  onRelay(frame: ToNode): void {
    if (frame.t === "accepted") {
      this.apply({ type: "accepted", connectionId: frame.c });
      return;
    }
    if (frame.t === "closed") {
      this.apply({ type: "relay_closed", connectionId: frame.c });
      return;
    }
    if (frame.t === "relay_shutdown") {
      const before = new Set(this.lc.recordsSnapshot().filter((record) => !record.pendingShutdown).map((record) => record.id));
      const result = this.lc.apply({ type: "relay_shutdown_or_eof" });
      const reached = new Set(result.actions.map((action) => ("recordId" in action ? action.recordId : "")));
      for (const id of before) if (!reached.has(id)) this.e9Missed += 1;
      return;
    }
    const publicFrame = frame.f;
    const summary =
      publicFrame.t === "call"
        ? { topLevelType: "tools_call", requestId: publicFrame.rid, strictValid: !publicFrame.bad }
        : publicFrame.t === "cancel"
          ? { topLevelType: "cancel", mcpRequestId: publicFrame.rid, strictValid: !publicFrame.bad }
          : { topLevelType: publicFrame.t === "shutdown" ? "shutdown" : "?", strictValid: publicFrame.t === "shutdown" ? !publicFrame.bad : false };
    const classified = classifyHermesPublicFrameSummary(summary);
    this.apply({ ...classified, connectionId: frame.c } as HermesLifecycleEvent);
  }

  settle(id: string, viaRelease: boolean): void {
    const work = this.works.get(id);
    if (work === undefined) return;
    this.works.delete(id);
    if (!viaRelease && this.lc.canWriteResponse(id)) {
      this.send({ t: "response", c: work.c, rid: work.rid });
      this.apply({ type: "node_response_written", connectionId: work.c, recordId: id });
    }
    this.act(this.lc.release(id).actions);
  }

  nodeClose(connectionId: string): void {
    if (this.lc.stopped || !this.lc.canSendClose(connectionId)) return;
    this.apply({ type: "node_close", connectionId, reason: "private_cap_overflow" });
  }
}

function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

function runSchedule(seed: number, closedIsAbsorbing: boolean, steps: number, allowShutdown: boolean) {
  const random = lcg(seed);
  const relay = new RelayModel(closedIsAbsorbing);
  const node = new NodeModel();
  let requestNumber = 0;
  const lastRequest = new Map<string, string>();
  const pick = <T>(items: readonly T[]): T | undefined => (items.length === 0 ? undefined : items[Math.floor(random() * items.length)]);
  const publicFrame = (connectionId: string): PubFrame => {
    const value = random();
    if (value < 0.45) {
      const rid = `r${requestNumber++}`;
      lastRequest.set(connectionId, rid);
      return { t: "call", rid, bad: random() < 0.15 };
    }
    if (value < 0.75) return { t: "cancel", rid: random() < 0.7 ? lastRequest.get(connectionId) ?? "zz" : "zz", bad: random() < 0.15 };
    if (value < 0.9) return { t: "shutdown", bad: random() < 0.15 };
    return { t: "garbage" };
  };
  const step = () => {
    const value = random();
    if (value < 0.1) relay.accept();
    else if (value < 0.3) {
      const conn = pick(relay.openConns());
      if (conn !== undefined && !relay.shutdownSent) conn.publicBatch(random() < 0.3 ? [publicFrame(conn.c), publicFrame(conn.c)] : [publicFrame(conn.c)]);
    } else if (value < 0.33) {
      const conn = pick(relay.openConns());
      if (conn !== undefined && !relay.shutdownSent) conn.closeOnce();
    } else if (value < 0.55) {
      const frame = relay.toNode.shift();
      if (frame !== undefined) node.onRelay(frame);
    } else if (value < 0.75) {
      const frame = node.toRelay.shift();
      if (frame !== undefined) relay.conns.get(frame.c)?.nodeFrame(frame);
    } else if (value < 0.92) {
      const id = pick([...node.works.keys()]);
      if (id !== undefined) node.settle(id, random() < 0.25);
    } else if (value < 0.95) {
      const connectionId = pick([...relay.conns.keys()]);
      if (connectionId !== undefined) node.nodeClose(connectionId);
    } else if (allowShutdown && value < 0.952 && !relay.shutdownSent) {
      relay.shutdownSent = true;
      relay.toNode.push({ t: "relay_shutdown" });
    }
  };
  for (let i = 0; i < steps; i += 1) step();
  for (let guard = 0; guard < 10000; guard += 1) {
    const toNode = relay.toNode.shift();
    if (toNode !== undefined) {
      node.onRelay(toNode);
      continue;
    }
    const toRelay = node.toRelay.shift();
    if (toRelay !== undefined) {
      relay.conns.get(toRelay.c)?.nodeFrame(toRelay);
      continue;
    }
    const workId = [...node.works.keys()][0];
    if (workId !== undefined) {
      node.settle(workId, false);
      continue;
    }
    break;
  }
  const stuckInFlight = node.lc.stopped ? 0 : [...relay.conns.values()].filter((conn) => conn.state === "I").length;
  return {
    nodeFatal: node.fatal,
    relayFatal: relay.fatal,
    mismatch: relay.mismatch,
    sentAfterStop: node.sentAfterStop,
    e9Missed: node.e9Missed,
    bound: node.boundViolations,
    stuckInFlight,
    endRows: node.lc.liveCount,
    relayLive: relay.live,
    endRecords: node.lc.recordCount,
    forwarded: relay.forwardedCalls,
  };
}

describe("Hermes lifecycle seeded relay-model probes", () => {
  it("keeps the node side quiescent under corrected relay schedules", () => {
    const bad: string[] = [];
    let forwarded = 0;
    for (let seed = 1; seed <= 500; seed += 1) {
      const result = runSchedule(seed, true, 300, false);
      forwarded += result.forwarded;
      if (
        result.nodeFatal.length ||
        result.relayFatal.length ||
        result.mismatch.length ||
        result.bound ||
        result.stuckInFlight ||
        result.endRows !== result.relayLive ||
        result.endRecords
      ) {
        bad.push(`${seed}: ${JSON.stringify(result)}`);
      }
    }
    expect(forwarded).toBeGreaterThan(0);
    expect(bad).toEqual([]);
  });

  it("reaches every waiting record and sends nothing after relay shutdown", () => {
    let missed = 0;
    let afterStop = 0;
    const bad: string[] = [];
    for (let seed = 1; seed <= 500; seed += 1) {
      const result = runSchedule(seed, true, 300, true);
      missed += result.e9Missed;
      afterStop += result.sentAfterStop;
      if (result.nodeFatal.length || result.relayFatal.length || result.mismatch.length || result.bound) {
        bad.push(`${seed}: ${JSON.stringify(result)}`);
      }
    }
    expect(missed).toBe(0);
    expect(afterStop).toBe(0);
    expect(bad).toEqual([]);
  });

  it("keeps the node side quiet when crossed responses arrive after closed rows", () => {
    let nodeFatal = 0;
    for (let seed = 1; seed <= 500; seed += 1) {
      const result = runSchedule(seed, false, 300, false);
      nodeFatal += result.nodeFatal.length;
    }
    expect(nodeFatal).toBe(0);
  });
});
