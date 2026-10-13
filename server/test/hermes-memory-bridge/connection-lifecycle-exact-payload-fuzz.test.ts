import { describe, expect, it } from "vitest";
import {
  HERMES_MAX_CALL_RECORDS,
  HERMES_MAX_PUBLIC_CONNECTIONS,
  HERMES_MEMORY_DENIAL_MESSAGE,
  HermesConnectionLifecycle,
  classifyHermesPublicFrameSummary,
  type HermesLifecycleAction,
  type HermesLifecycleEvent,
  type HermesLifecycleResult,
} from "../../src/hermes-memory-bridge/index.js";

function lcg(seed: number): () => number {
  let state = (seed * 2654435761) >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 4294967296;
  };
}

const NODE_SENDS = new Set<HermesLifecycleAction["type"]>(["send_close", "send_fixed_denial"]);

interface Stats {
  throws: string[];
  boundMax: number;
  boundViolations: number;
  liveViolations: number;
  nodeFatal: string[];
  sendFromBadState: string[];
  sendAfterStop: number;
  doubleAnswer: string[];
  unanswered: string[];
  adoptedRecord: number;
  actionAfterStop: number;
  payloadViolations: string[];
  duplicateClose: number;
  closesEmitted: number;
  relayShutdownDeliveries: number;
  relayShutdownMissed: number;
  calls: number;
}

function newStats(): Stats {
  return {
    throws: [],
    boundMax: 0,
    boundViolations: 0,
    liveViolations: 0,
    nodeFatal: [],
    sendFromBadState: [],
    sendAfterStop: 0,
    doubleAnswer: [],
    unanswered: [],
    adoptedRecord: 0,
    actionAfterStop: 0,
    payloadViolations: [],
    duplicateClose: 0,
    closesEmitted: 0,
    relayShutdownDeliveries: 0,
    relayShutdownMissed: 0,
    calls: 0,
  };
}

type Operation = { kind: "apply"; event: HermesLifecycleEvent } | { kind: "release"; recordId: string };

class Harness {
  readonly lifecycle = new HermesConnectionLifecycle();
  readonly acceptFloor = new Map<string, number>();
  readonly closedThisIncarnation = new Set<string>();
  readonly work = new Map<string, { connectionId: string; requestId: string }>();
  readonly ledger = new Map<number, { answers: number; excused: boolean; description: string }>();
  readonly recordToLedger = new Map<string, number>();
  readonly sent: { type: "response" | "close"; connectionId: string; requestId?: string }[] = [];
  private nextLedgerKey = 1;
  private currentCallKey: number | undefined;

  constructor(
    private readonly stats: Stats,
    private readonly tag: string,
  ) {}

  private internals() {
    return this.lifecycle as unknown as {
      rows: Map<string, { state: string; currentRecordId?: string }>;
      records: Map<string, { connectionId: string; requestId: string; state: string; pendingShutdown: boolean }>;
      nextRecordNumber: number;
    };
  }

  private run(operation: Operation): HermesLifecycleResult | { actions: readonly HermesLifecycleAction[] } {
    const pre = this.internals();
    const preRecords = new Map([...pre.records.entries()].map(([key, value]) => [key, { ...value }]));
    const preRows = new Map([...pre.rows.entries()].map(([connectionId, row]) => [connectionId, { ...row }]));
    const preStopped = this.lifecycle.stopped;
    let result: HermesLifecycleResult | { actions: readonly HermesLifecycleAction[] };
    try {
      result = operation.kind === "apply" ? this.lifecycle.apply(operation.event) : this.lifecycle.release(operation.recordId);
    } catch (error) {
      this.stats.throws.push(`${this.tag} ${JSON.stringify(operation)} ${(error as Error).message}`);
      return { actions: [] };
    }

    if (preStopped && result.actions.length > 0) this.stats.actionAfterStop += result.actions.length;
    if (operation.kind === "apply") this.checkApplyPayloads(operation.event, result as HermesLifecycleResult, preStopped, preRecords);
    else this.checkReleasePayloads(operation.recordId, result.actions, preRows);
    this.recordSentFrames(operation, result.actions, preRows);

    const fatal = (result as HermesLifecycleResult).fatal;
    if (fatal !== undefined) this.stats.nodeFatal.push(`${this.tag} ${fatal.reason}`);

    for (const action of result.actions) {
      if (!NODE_SENDS.has(action.type)) continue;
      const preState = preRows.get(action.connectionId)?.state ?? "UNKNOWN";
      if (preState === "NODE_CLOSED" || preState === "UNKNOWN") this.stats.sendFromBadState.push(`${this.tag} ${action.type} from ${preState}`);
      if (preStopped || this.lifecycle.stopped) this.stats.sendAfterStop += 1;
    }

    if (operation.kind === "apply" && operation.event.type === "relay_closed") {
      const currentRecordId = preRows.get(operation.event.connectionId)?.currentRecordId;
      const ledgerKey = currentRecordId === undefined ? undefined : this.recordToLedger.get(currentRecordId);
      const entry = ledgerKey === undefined ? undefined : this.ledger.get(ledgerKey);
      if (entry !== undefined && entry.answers === 0) entry.excused = true;
    }
    if (operation.kind === "apply" && operation.event.type === "relay_shutdown_or_eof") {
      for (const entry of this.ledger.values()) if (entry.answers === 0) entry.excused = true;
    }

    this.checkBoundsAndAdoption(operation);
    return result;
  }

  private checkApplyPayloads(
    event: HermesLifecycleEvent,
    result: HermesLifecycleResult,
    preStopped: boolean,
    preRecords: ReadonlyMap<string, { connectionId: string; requestId: string; pendingShutdown: boolean }>,
  ): void {
    const actions = result.actions;
    for (const action of actions) {
      if (event.type === "relay_shutdown_or_eof") {
        const expected = "recordId" in action ? preRecords.get(action.recordId) : undefined;
        if (
          action.type !== "deliver_control" ||
          action.control !== "shutdown" ||
          expected === undefined ||
          action.connectionId !== expected.connectionId ||
          action.requestId !== expected.requestId
        ) {
          this.stats.payloadViolations.push(`${this.tag} relay shutdown ${JSON.stringify(action)}`);
        }
        continue;
      }
      if (action.connectionId !== event.connectionId) this.stats.payloadViolations.push(`${this.tag} connection ${JSON.stringify(action)}`);
      if (action.type === "route_call" && event.type === "call" && (action.requestId !== event.requestId || action.kind !== event.kind)) {
        this.stats.payloadViolations.push(`${this.tag} route ${JSON.stringify(action)}`);
      }
      if (
        action.type === "send_fixed_denial" &&
        event.type === "call" &&
        (action.requestId !== event.requestId || action.responseClass !== "immediate" || action.message !== HERMES_MEMORY_DENIAL_MESSAGE)
      ) {
        this.stats.payloadViolations.push(`${this.tag} denial ${JSON.stringify(action)}`);
      }
      if (action.type === "deliver_control" && event.type === "cancel" && (action.control !== "cancel" || action.requestId !== event.mcpRequestId)) {
        this.stats.payloadViolations.push(`${this.tag} cancel ${JSON.stringify(action)}`);
      }
      if (action.type === "deliver_control" && event.type === "public_shutdown" && action.control !== "shutdown") {
        this.stats.payloadViolations.push(`${this.tag} shutdown ${JSON.stringify(action)}`);
      }
    }

    if (event.type === "accepted" && result.fatal === undefined && !preStopped) {
      this.acceptFloor.set(event.connectionId, this.internals().nextRecordNumber);
      this.closedThisIncarnation.delete(event.connectionId);
    }
    if (event.type === "relay_shutdown_or_eof" && !preStopped) {
      const pending = [...preRecords.values()].filter((record) => !record.pendingShutdown).length;
      this.stats.relayShutdownDeliveries += actions.length;
      if (actions.length !== pending) this.stats.relayShutdownMissed += 1;
    }
  }

  private checkReleasePayloads(recordId: string, actions: readonly HermesLifecycleAction[], preRows: ReadonlyMap<string, { currentRecordId?: string }>): void {
    for (const action of actions) {
      if (
        action.type !== "send_fixed_denial" ||
        action.responseClass !== "release" ||
        action.recordId !== recordId ||
        action.message !== HERMES_MEMORY_DENIAL_MESSAGE
      ) {
        this.stats.payloadViolations.push(`${this.tag} release ${JSON.stringify(action)}`);
      }
      const currentRecordId = preRows.get(action.connectionId)?.currentRecordId;
      if (currentRecordId !== recordId) this.stats.payloadViolations.push(`${this.tag} release current ${recordId} ${currentRecordId ?? "none"}`);
    }
  }

  private recordSentFrames(operation: Operation, actions: readonly HermesLifecycleAction[], preRows: ReadonlyMap<string, { currentRecordId?: string }>): void {
    for (const action of actions) {
      if (action.type === "send_close") {
        this.stats.closesEmitted += 1;
        if (this.closedThisIncarnation.has(action.connectionId)) this.stats.duplicateClose += 1;
        this.closedThisIncarnation.add(action.connectionId);
      }
      if (action.type === "route_call") {
        const ledgerKey = this.currentCallKey ?? -1;
        this.recordToLedger.set(action.recordId, ledgerKey);
        this.work.set(action.recordId, { connectionId: action.connectionId, requestId: action.requestId });
      } else if (action.type === "send_fixed_denial") {
        const ledgerKey = action.responseClass === "immediate" ? this.currentCallKey ?? -1 : this.recordToLedger.get(action.recordId) ?? -1;
        this.answer(ledgerKey, `denial:${action.responseClass}`);
        this.sent.push({ type: "response", connectionId: action.connectionId, requestId: action.requestId });
      } else if (action.type === "send_close") {
        const currentRecordId = preRows.get(action.connectionId)?.currentRecordId;
        const ledgerKey = currentRecordId === undefined ? undefined : this.recordToLedger.get(currentRecordId);
        if (ledgerKey !== undefined && this.ledger.get(ledgerKey)?.answers === 0) this.answer(ledgerKey, "close");
        this.sent.push({ type: "close", connectionId: action.connectionId });
      }
    }
    if (operation.kind === "apply" && operation.event.type === "accepted") this.closedThisIncarnation.delete(operation.event.connectionId);
  }

  private checkBoundsAndAdoption(operation: Operation): void {
    const recordCount = this.lifecycle.recordCount;
    if (recordCount > this.stats.boundMax) this.stats.boundMax = recordCount;
    if (recordCount > HERMES_MAX_CALL_RECORDS) this.stats.boundViolations += 1;
    if (this.lifecycle.liveCount > HERMES_MAX_PUBLIC_CONNECTIONS) this.stats.liveViolations += 1;

    const post = this.internals();
    for (const [connectionId, row] of post.rows) {
      if (row.currentRecordId === undefined || this.lifecycle.stopped) continue;
      const record = post.records.get(row.currentRecordId);
      const mintedNumber = Number(row.currentRecordId.slice(5));
      if (record === undefined || record.connectionId !== connectionId || mintedNumber < (this.acceptFloor.get(connectionId) ?? Infinity)) {
        this.stats.adoptedRecord += 1;
        this.stats.payloadViolations.push(`${this.tag} adoption ${connectionId} ${JSON.stringify(row)} ${JSON.stringify(operation)}`);
      }
    }
  }

  private answer(ledgerKey: number, how: string): void {
    const entry = this.ledger.get(ledgerKey);
    if (entry === undefined) return;
    entry.answers += 1;
    if (entry.answers > 1) this.stats.doubleAnswer.push(`${this.tag} ${entry.description} via ${how}`);
  }

  apply(event: HermesLifecycleEvent): HermesLifecycleResult {
    if (event.type !== "call") return this.run({ kind: "apply", event }) as HermesLifecycleResult;
    const ledgerKey = this.nextLedgerKey++;
    this.stats.calls += 1;
    this.ledger.set(ledgerKey, { answers: 0, excused: false, description: `${event.connectionId}/${event.requestId}` });
    this.currentCallKey = ledgerKey;
    const result = this.run({ kind: "apply", event }) as HermesLifecycleResult;
    this.currentCallKey = undefined;
    const acted = result.actions.some((action) => action.type === "route_call" || action.type === "send_fixed_denial");
    if (!acted) this.ledger.delete(ledgerKey);
    return result;
  }

  release(recordId: string): void {
    this.run({ kind: "release", recordId });
  }

  settle(recordId: string, viaRelease: boolean): void {
    const work = this.work.get(recordId);
    if (work === undefined) {
      this.release(recordId);
      return;
    }
    this.work.delete(recordId);
    if (!viaRelease && !this.lifecycle.stopped) {
      const preState = this.lifecycle.stateOf(work.connectionId);
      const written = this.apply({ type: "node_response_written", connectionId: work.connectionId, recordId });
      if (written.fatal === undefined && written.refusal === undefined) {
        if (preState === "NODE_CLOSED" || preState === "UNKNOWN" || this.lifecycle.stopped) {
          this.stats.sendFromBadState.push(`${this.tag} real response from ${preState}`);
        }
        this.answer(this.recordToLedger.get(recordId) ?? -1, "response");
        this.sent.push({ type: "response", connectionId: work.connectionId, requestId: work.requestId });
      }
    }
    this.release(recordId);
  }

  finish(): void {
    for (const entry of this.ledger.values()) {
      if (!entry.excused && entry.answers !== 1) this.stats.unanswered.push(`${this.tag} ${entry.description} answers=${entry.answers}`);
    }
  }
}

class RelayConnection {
  state: "start" | "in_flight" | "closed" = "start";
  currentRequestId: string | undefined;

  constructor(
    readonly connectionId: string,
    private readonly relay: Relay,
  ) {}

  close(): void {
    if (this.state === "closed") return;
    this.state = "closed";
    this.relay.live -= 1;
    this.relay.toNode.push({ type: "closed", connectionId: this.connectionId });
  }
}

type ToNode =
  | { type: "accepted"; connectionId: string }
  | { type: "call"; connectionId: string; requestId: string; bad: boolean }
  | { type: "cancel"; connectionId: string; requestId: string; bad: boolean }
  | { type: "shutdown"; connectionId: string; bad: boolean }
  | { type: "garbage"; connectionId: string }
  | { type: "closed"; connectionId: string }
  | { type: "relay_shutdown" };

class Relay {
  live = 0;
  next = 1;
  readonly connections = new Map<string, RelayConnection>();
  readonly toNode: ToNode[] = [];
  readonly fatal: string[] = [];
  relayShutdown = false;

  constructor(readonly reuseIds: boolean) {}

  accept(random: () => number, inFlightToRelay: Set<string> = new Set()): void {
    if (this.relayShutdown || this.live >= HERMES_MAX_PUBLIC_CONNECTIONS) return;
    let connectionId: string;
    if (this.reuseIds) {
      const free = ["a", "b", "c", "d", "e", "f"].filter(
        (id) => (this.connections.get(id)?.state ?? "closed") === "closed" && !this.pendingClosed(id) && !inFlightToRelay.has(id),
      );
      if (free.length === 0) return;
      connectionId = free[Math.floor(random() * free.length)];
    } else {
      connectionId = `c${this.next++}`;
    }
    this.connections.set(connectionId, new RelayConnection(connectionId, this));
    this.live += 1;
    this.toNode.push({ type: "accepted", connectionId });
  }

  pendingClosed(connectionId: string): boolean {
    return this.toNode.some((frame) => frame.type === "closed" && frame.connectionId === connectionId);
  }

  publicFrame(connection: RelayConnection, frame: Exclude<ToNode, { type: "accepted" | "closed" | "relay_shutdown" }>): void {
    if (connection.state === "closed") return;
    if (frame.type === "garbage") {
      if (connection.state === "start") {
        this.toNode.push(frame);
        return;
      }
      connection.close();
      return;
    }
    if (frame.type === "cancel") {
      this.toNode.push(frame);
      return;
    }
    if (frame.type === "shutdown") {
      this.toNode.push(frame);
      if (!frame.bad) connection.close();
      return;
    }
    if (connection.state === "in_flight") return;
    connection.state = "in_flight";
    connection.currentRequestId = frame.requestId;
    this.toNode.push(frame);
  }

  fromNode(frame: { type: "response" | "close"; connectionId: string; requestId?: string }): void {
    const connection = this.connections.get(frame.connectionId);
    if (connection === undefined || connection.state === "closed") return;
    if (frame.type === "close") {
      connection.close();
      return;
    }
    if (connection.state !== "in_flight") {
      this.fatal.push(`response without call ${frame.connectionId}`);
      return;
    }
    if (connection.currentRequestId !== frame.requestId) this.fatal.push(`response mismatch ${frame.connectionId}`);
    connection.state = "start";
    connection.currentRequestId = undefined;
  }
}

function toEvent(frame: ToNode): HermesLifecycleEvent {
  switch (frame.type) {
    case "accepted":
      return { type: "accepted", connectionId: frame.connectionId };
    case "closed":
      return { type: "relay_closed", connectionId: frame.connectionId };
    case "relay_shutdown":
      return { type: "relay_shutdown_or_eof" };
    case "call":
      return { ...classifyHermesPublicFrameSummary({ topLevelType: "tools_call", requestId: frame.requestId, strictValid: !frame.bad }), connectionId: frame.connectionId } as HermesLifecycleEvent;
    case "cancel":
      return { ...classifyHermesPublicFrameSummary({ topLevelType: "cancel", mcpRequestId: frame.requestId, strictValid: !frame.bad }), connectionId: frame.connectionId } as HermesLifecycleEvent;
    case "shutdown":
      return { ...classifyHermesPublicFrameSummary({ topLevelType: "shutdown", strictValid: !frame.bad }), connectionId: frame.connectionId } as HermesLifecycleEvent;
    case "garbage":
      return { ...classifyHermesPublicFrameSummary({ topLevelType: "?", strictValid: false }), connectionId: frame.connectionId } as HermesLifecycleEvent;
  }
}

function pick<T>(items: readonly T[], random: () => number): T | undefined {
  return items.length === 0 ? undefined : items[Math.floor(random() * items.length)];
}

function runRelay(seed: number, reuseIds: boolean, allowRelayShutdown: boolean, stats: Stats): void {
  const random = lcg(seed);
  const relay = new Relay(reuseIds);
  const harness = new Harness(stats, `${reuseIds ? "reuse" : "legal"}#${seed}`);
  let requestNumber = 0;
  const lastRequestId = new Map<string, string>();

  const deliverToNode = (): boolean => {
    const frame = relay.toNode.shift();
    if (frame === undefined) return false;
    harness.apply(toEvent(frame));
    return true;
  };
  const deliverToRelay = (): boolean => {
    const frame = harness.sent.shift();
    if (frame === undefined) return false;
    relay.fromNode(frame);
    return true;
  };

  for (let step = 0; step < 250; step += 1) {
    const value = random();
    if (value < 0.1) relay.accept(random, new Set(harness.sent.map((frame) => frame.connectionId)));
    else if (value < 0.3) {
      const connection = pick([...relay.connections.values()].filter((item) => item.state !== "closed"), random);
      if (connection !== undefined && !relay.relayShutdown) {
        const frameValue = random();
        if (frameValue < 0.45) {
          const requestId = `r${requestNumber++}`;
          lastRequestId.set(connection.connectionId, requestId);
          relay.publicFrame(connection, { type: "call", connectionId: connection.connectionId, requestId, bad: random() < 0.15 });
        } else if (frameValue < 0.72) {
          relay.publicFrame(connection, {
            type: "cancel",
            connectionId: connection.connectionId,
            requestId: random() < 0.7 ? lastRequestId.get(connection.connectionId) ?? "zz" : "zz",
            bad: random() < 0.15,
          });
        } else if (frameValue < 0.88) {
          relay.publicFrame(connection, { type: "shutdown", connectionId: connection.connectionId, bad: random() < 0.2 });
        } else {
          relay.publicFrame(connection, { type: "garbage", connectionId: connection.connectionId });
        }
      }
    } else if (value < 0.34) {
      const connection = pick([...relay.connections.values()].filter((item) => item.state !== "closed"), random);
      if (connection !== undefined && !relay.relayShutdown) connection.close();
    } else if (value < 0.55) deliverToNode();
    else if (value < 0.72) deliverToRelay();
    else if (value < 0.9) {
      const recordId = pick(
        harness.lifecycle.recordsSnapshot().map((record) => record.id),
        random,
      );
      if (recordId !== undefined) harness.settle(recordId, random() < 0.35);
    } else if (value < 0.95) {
      const connectionId = pick([...relay.connections.keys()], random);
      if (connectionId !== undefined && !harness.lifecycle.stopped) {
        harness.apply({ type: "node_close", connectionId, reason: random() < 0.5 ? "unparseable_call" : "private_cap_overflow" });
      }
    } else if (allowRelayShutdown && value < 0.953 && !relay.relayShutdown) {
      relay.relayShutdown = true;
      relay.toNode.push({ type: "relay_shutdown" });
    }
  }

  for (let guard = 0; guard < 20000; guard += 1) {
    if (deliverToNode()) continue;
    if (deliverToRelay()) continue;
    const recordId = harness.lifecycle.recordsSnapshot()[0]?.id;
    if (recordId !== undefined) {
      harness.settle(recordId, false);
      continue;
    }
    break;
  }

  harness.finish();
  if (!harness.lifecycle.stopped) {
    const stuck = [...relay.connections.values()].filter((connection) => connection.state === "in_flight").length;
    if (stuck > 0) stats.unanswered.push(`${reuseIds ? "reuse" : "legal"}#${seed} relay stuck ${stuck}`);
    if (harness.lifecycle.liveCount !== relay.live) stats.unanswered.push(`${reuseIds ? "reuse" : "legal"}#${seed} rows ${harness.lifecycle.liveCount} relay ${relay.live}`);
    if (harness.lifecycle.recordCount !== 0) stats.unanswered.push(`${reuseIds ? "reuse" : "legal"}#${seed} records ${harness.lifecycle.recordCount}`);
  }
  if (relay.fatal.length > 0) stats.unanswered.push(`${reuseIds ? "reuse" : "legal"}#${seed} relay fatal ${relay.fatal.join(",")}`);
}

function runChaos(seed: number, stats: Stats): void {
  const random = lcg(seed + 777);
  const harness = new Harness(stats, `chaos#${seed}`);
  const connectionIds = ["a", "b", "c", "d", "e", "f"];
  const eventTypes = ["accepted", "call", "cancel", "public_shutdown", "public_unparseable", "control_invalid", "relay_closed", "node_response_written", "node_close"] as const;
  let requestNumber = 0;
  for (let step = 0; step < 300; step += 1) {
    const value = random();
    const connectionId = connectionIds[Math.floor(random() * connectionIds.length)];
    if (value < 0.75) {
      const type = random() < 0.3 ? (random() < 0.5 ? "accepted" : "relay_closed") : eventTypes[Math.floor(random() * eventTypes.length)];
      let event: HermesLifecycleEvent;
      switch (type) {
        case "call":
          event = { type: "call", connectionId, requestId: `r${requestNumber++}`, kind: "tools_call", valid: random() < 0.85 };
          break;
        case "cancel":
          event = { type: "cancel", connectionId, mcpRequestId: `r${Math.max(0, requestNumber - 1 - Math.floor(random() * 3))}` };
          break;
        case "node_response_written":
          event = { type: "node_response_written", connectionId, recordId: `call-${1 + Math.floor(random() * (requestNumber + 2))}` };
          break;
        case "node_close":
          event = { type: "node_close", connectionId, reason: "unparseable_call" };
          break;
        default:
          event = { type, connectionId } as HermesLifecycleEvent;
      }
      harness.apply(event);
    } else if (value < 0.97) {
      const records = harness.lifecycle.recordsSnapshot();
      const recordId = random() < 0.8 ? records[Math.floor(random() * Math.max(1, harness.lifecycle.recordCount))]?.id : `call-${1 + Math.floor(random() * (requestNumber + 2))}`;
      if (recordId !== undefined) harness.release(recordId);
    } else if (value < 0.975) {
      harness.apply({ type: "relay_shutdown_or_eof" });
    }
  }
}

function runHeavyChaos(seed: number, stats: Stats): void {
  const random = lcg(seed + 99991);
  const harness = new Harness(stats, `heavy#${seed}`);
  const connectionIds = ["a", "b", "c", "d", "e", "f", "g"];
  let requestNumber = 0;
  for (let step = 0; step < 300; step += 1) {
    const connectionId = connectionIds[Math.floor(random() * connectionIds.length)];
    const value = random();
    if (value < 0.25) harness.apply({ type: "accepted", connectionId });
    else if (value < 0.55) harness.apply({ type: "call", connectionId, requestId: `r${requestNumber++}`, kind: "hello", valid: random() < 0.9 });
    else if (value < 0.75) harness.apply({ type: "relay_closed", connectionId });
    else if (value < 0.8) harness.apply({ type: "node_close", connectionId, reason: "private_cap_overflow" });
    else if (value < 0.85) harness.apply({ type: "public_unparseable", connectionId });
    else if (value < 0.88) harness.apply({ type: "public_shutdown", connectionId });
    else if (value < 0.9) harness.apply({ type: "cancel", connectionId, mcpRequestId: `r${requestNumber - 1}` });
    else if (value < 0.94) {
      const records = harness.lifecycle.recordsSnapshot();
      const recordId = records.length > 0 ? records[Math.floor(random() * records.length)].id : undefined;
      if (recordId !== undefined) harness.settle(recordId, random() < 0.5);
    } else if (value < 0.96) {
      const records = harness.lifecycle.recordsSnapshot();
      const recordId = records.length > 0 ? records[Math.floor(random() * records.length)].id : `call-${requestNumber}`;
      harness.apply({ type: "node_response_written", connectionId, recordId });
    } else if (value < 0.962) {
      harness.apply({ type: "relay_shutdown_or_eof" });
    }
  }
}

function expectClean(stats: Stats, nodeFatalAllowed: boolean): void {
  expect(stats.throws).toEqual([]);
  expect(stats.boundViolations).toBe(0);
  expect(stats.liveViolations).toBe(0);
  if (!nodeFatalAllowed) expect(stats.nodeFatal).toEqual([]);
  expect(stats.sendFromBadState).toEqual([]);
  expect(stats.sendAfterStop).toBe(0);
  expect(stats.doubleAnswer).toEqual([]);
  expect(stats.unanswered).toEqual([]);
  expect(stats.adoptedRecord).toBe(0);
  expect(stats.actionAfterStop).toBe(0);
  expect(stats.payloadViolations).toEqual([]);
  expect(stats.duplicateClose).toBe(0);
  expect(stats.relayShutdownMissed).toBe(0);
}

describe("Hermes connection lifecycle exact-payload fuzz", () => {
  it("holds under legal relay schedules", () => {
    const stats = newStats();
    for (let seed = 1; seed <= 3000; seed += 1) runRelay(seed, false, seed % 3 === 0, stats);
    expectClean(stats, false);
  });

  it("holds under relay schedules that reuse connection ids", () => {
    const stats = newStats();
    for (let seed = 1; seed <= 3000; seed += 1) runRelay(seed, true, seed % 3 === 0, stats);
    expectClean(stats, false);
  });

  it("holds under arbitrary per-connection event schedules", () => {
    const stats = newStats();
    for (let seed = 1; seed <= 3000; seed += 1) runChaos(seed, stats);
    expectClean(stats, true);
  });

  it("holds under dense id-cycling schedules at the total record cap", () => {
    const stats = newStats();
    let schedulesAtCap = 0;
    for (let seed = 1; seed <= 3000; seed += 1) {
      const previousMax = stats.boundMax;
      stats.boundMax = 0;
      runHeavyChaos(seed, stats);
      if (stats.boundMax === HERMES_MAX_CALL_RECORDS) schedulesAtCap += 1;
      stats.boundMax = Math.max(previousMax, stats.boundMax);
    }
    expect(schedulesAtCap).toBeGreaterThan(0);
    expectClean(stats, true);
  });
});
