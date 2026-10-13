import { Buffer } from "node:buffer";
import { describe, expect, it } from "vitest";

import {
  HERMES_APPROVAL_DEADLINE_MS,
  HermesBridgeCore,
  type HermesBridgeAuditRecord,
  type HermesBridgeCorePorts,
  type HermesTimerHandle,
  parsePublicFrame,
  type NodeToRelayInput,
  type RelayToNodeFrame,
} from "../../src/hermes-memory-bridge/index.js";
import type { MemoryPassage, MemoryPassageInput, MemorySearchResult } from "../../src/sdw/adapters/memory-backend.js";
import { hermesBridgePassageTextDigest } from "../../src/sdw/adapters/sdw-memory-backend.js";
import { SdwValidationError } from "../../src/sdw/errors.js";
import { memoryGetSuccessFrameUtf8Bytes } from "../../src/sdw/memory-tool-projection.js";

const encoder = new TextEncoder();
const SCHEDULE_COUNT = 3_000;
const MAX_STEPS_PER_SCHEDULE = 80;

type ConnectionState = "open" | "busy" | "shutting" | "nodeclosed" | "closed";
type StopCause = "relay_shutdown" | "relay_eof" | "relay_fatal" | "write_failure";
type AdapterOutcome = "success" | "partial" | "throw_after_allow";
type AuditOutcome = "fulfilled" | "deferred" | "rejected";

interface ConnectionModel {
  readonly id: string;
  state: ConnectionState;
  requestId?: string;
  readonly answered: Set<string>;
}

interface Deferred<T> {
  readonly promise: Promise<T>;
  resolve(value: T): void;
  reject(error: unknown): void;
  done: boolean;
}

interface Coverage {
  readonly terminals: Set<string>;
  readonly dispatchRows: Set<string>;
  readonly stopCauses: Set<StopCause>;
  readonly auditOutcomes: Set<AuditOutcome>;
  readonly adapterOutcomes: Set<AdapterOutcome>;
  readonly interleavings: Set<"shutdown_while_lock_parked" | "shutdown_while_durability_wait">;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const cell = {
    promise: new Promise<T>((res, rej) => {
      resolve = (value) => {
        cell.done = true;
        res(value);
      };
      reject = (error) => {
        cell.done = true;
        rej(error);
      };
    }),
    resolve,
    reject,
    done: false,
  };
  return cell;
}

function rng(seed: number): () => number {
  let state = (seed * 2_654_435_761) >>> 0 || 1;
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

function publicFrame(connectionId: string, frame: Record<string, unknown> | string): RelayToNodeFrame {
  const publicBytes = encoder.encode(typeof frame === "string" ? frame : JSON.stringify(frame));
  return { kind: "frame", connectionId, publicBytes, publicFrame: parsePublicFrame(publicBytes) };
}

async function flush(turns: number): Promise<void> {
  for (let index = 0; index < turns; index += 1) await Promise.resolve();
}

function responsePayload(input: NodeToRelayInput): Record<string, unknown> {
  if (input.type !== "response") throw new Error("expected response");
  return JSON.parse(Buffer.from(input.publicPayloadBytes).toString("utf8")) as Record<string, unknown>;
}

async function runSchedule(seed: number): Promise<{ readonly violations: readonly string[]; readonly coverage: Coverage }> {
  const random = rng(seed);
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)]!;
  const adapterOutcomeOrder: readonly AdapterOutcome[] = ["partial", "throw_after_allow", "success"];
  let adapterOutcomeCursor = seed % adapterOutcomeOrder.length;
  const violations: string[] = [];
  const coverage: Coverage = {
    terminals: new Set(),
    dispatchRows: new Set(),
    stopCauses: new Set(),
    auditOutcomes: new Set(),
    adapterOutcomes: new Set(),
    interleavings: new Set(),
  };
  const timers = new Map<HermesTimerHandle, { readonly ms: number; readonly fire: () => void; readonly entryId?: string }>();
  const store = new Map<string, MemoryPassage>();
  const connections = new Map<string, ConnectionModel>();
  const probes: Array<{ readonly connectionId: string; readonly nonce: string; readonly drop: boolean }> = [];
  const reads: Array<Deferred<MemoryPassage | null>> = [];
  const locks: Array<Deferred<void>> = [];
  const audits: Array<{
    readonly kind: HermesBridgeAuditRecord["kind"];
    readonly entryId?: string;
    readonly cell: Deferred<void>;
    state: "pending" | "fulfilled" | "rejected";
  }> = [];
  const entryRequests = new Map<string, { readonly connectionId: string; readonly requestId: string }>();
  const dispatchedRefusals = new Map<string, Set<string>>();
  const abort = new AbortController();
  let core!: HermesBridgeCore;
  let nextConnection = 0;
  let nextRequest = 0;
  let stopped = false;
  let now = 1_000;

  const observeStop = (): void => {
    const snapshot = core.snapshot();
    if (snapshot.stopped && !stopped) {
      stopped = true;
      if (snapshot.stopCause !== undefined) coverage.stopCauses.add(snapshot.stopCause as StopCause);
      markRefusal(snapshot.slot?.entryId, "stop");
    }
  };

  const markRefusal = (entryId: string | undefined, reason: string): void => {
    if (entryId === undefined) return;
    const set = dispatchedRefusals.get(entryId) ?? new Set<string>();
    set.add(reason);
    dispatchedRefusals.set(entryId, set);
  };
  const markConnectionRefusal = (connectionId: string, reason: string, requestId?: string): void => {
    const entry = core.snapshot().ledger.entry;
    if (entry === undefined) return;
    const request = entryRequests.get(entry.id);
    if (request?.connectionId !== connectionId) return;
    if (requestId !== undefined && request.requestId !== requestId) return;
    if (reason === "peer_shutdown") {
      if (locks.some((lock) => !lock.done)) coverage.interleavings.add("shutdown_while_lock_parked");
      if (audits.some((audit) => audit.kind === "commit_intent" && audit.entryId === entry.id && !audit.cell.done)) {
        coverage.interleavings.add("shutdown_while_durability_wait");
      }
    }
    markRefusal(entry.id, reason);
  };

  const ports: HermesBridgeCorePorts = {
    writeFrame(input) {
      if (input.type === "probe") {
        coverage.dispatchRows.add("send_probe");
        if (random() < 0.02) {
          throw new Error("probe write stopped");
        }
        probes.push({ connectionId: input.connectionId, nonce: input.nonce, drop: random() < 0.1 });
        return;
      }
      if (input.type === "ready") return;
      const connection = connections.get(input.connectionId);
      if (connection === undefined) {
        violations.push(`write to unknown connection ${input.connectionId}`);
        return;
      }
      if (input.type === "close") {
        coverage.dispatchRows.add("write_close");
        connection.state = "nodeclosed";
        delete connection.requestId;
        return;
      }
      coverage.dispatchRows.add("write_response");
      const payload = responsePayload(input);
      if (payload.request_id !== input.requestId) violations.push("response request id mismatch");
      if (connection.state === "closed") violations.push("response after relay closed");
      if (connection.requestId !== input.requestId) violations.push(`response without matching request ${input.requestId}`);
      if (connection.answered.has(input.requestId)) violations.push(`duplicate response ${input.requestId}`);
      connection.answered.add(input.requestId);
      if (connection.requestId === input.requestId) {
        delete connection.requestId;
        if (connection.state === "busy") connection.state = "open";
      }
    },
    appendAudit(record: HermesBridgeAuditRecord) {
      coverage.dispatchRows.add("audit");
      if (record.kind === "terminal" && record.state !== undefined) coverage.terminals.add(record.state);
      const cell = deferred<void>();
      const audit: {
        readonly kind: HermesBridgeAuditRecord["kind"];
        readonly entryId?: string;
        readonly cell: Deferred<void>;
        state: "pending" | "fulfilled" | "rejected";
      } = {
        kind: record.kind,
        entryId: record.entryId,
        cell,
        state: "pending",
      };
      audits.push(audit);
      const draw = random();
      if (draw < 0.80) {
        coverage.auditOutcomes.add("fulfilled");
        cell.resolve();
      } else if (draw < 0.97) {
        coverage.auditOutcomes.add("deferred");
      } else {
        coverage.auditOutcomes.add("rejected");
        cell.reject(new Error("audit rejected"));
      }
      cell.promise.then(
        () => {
          audit.state = "fulfilled";
        },
        () => {
          audit.state = "rejected";
          markRefusal(record.entryId, "audit");
        },
      );
      return cell.promise;
    },
    nowMs: () => {
      now += 17;
      return now;
    },
    setTimer(ms, fire) {
      const handle = {};
      timers.set(handle, {
        ms,
        fire,
        ...(ms === HERMES_APPROVAL_DEADLINE_MS && core !== undefined && core.snapshot().slot?.entryId !== undefined
          ? { entryId: core.snapshot().slot?.entryId }
          : {}),
      });
      coverage.dispatchRows.add(ms === HERMES_APPROVAL_DEADLINE_MS ? "approval_timer_armed" : "probe_timer_armed");
      return handle;
    },
    clearTimer(handle) {
      timers.delete(handle);
    },
    adapter: {
      async insertPassage(input: MemoryPassageInput): Promise<MemoryPassage> {
        coverage.dispatchRows.add("adapter_insert");
        const lock = deferred<void>();
        locks.push(lock);
        const onAbort = () => lock.reject(new SdwValidationError("operation_aborted", "aborted"));
        if (abort.signal.aborted) onAbort();
        else abort.signal.addEventListener("abort", onAbort, { once: true });
        await lock.promise;
        abort.signal.removeEventListener("abort", onAbort);
        const id = input.passage_id ?? `p-${store.size + 1}`;
        const inserted = passage(id, input.text);
        await core.commitCheck.assertAllowedToCommit({
          passageId: id,
          documentId: `mem.${id}`,
          passageTextUtf8: Buffer.from(input.text),
          passageTextSha256: hermesBridgePassageTextDigest(input.text),
          getFrameUtf8Bytes: memoryGetSuccessFrameUtf8Bytes(inserted),
        });
        const outcome = adapterOutcomeOrder[adapterOutcomeCursor]!;
        adapterOutcomeCursor = (adapterOutcomeCursor + 1) % adapterOutcomeOrder.length;
        coverage.adapterOutcomes.add(outcome);
        if (outcome === "partial") {
          throw new SdwValidationError("partial_scope", "partial");
        }
        if (outcome === "throw_after_allow") {
          throw new Error("after allow");
        }
        store.set(id, inserted);
        return inserted;
      },
      getPassage(passageId) {
        coverage.dispatchRows.add("adapter_get");
        const read = deferred<MemoryPassage | null>();
        reads.push(read);
        return read.promise.then((value) => value ?? store.get(passageId) ?? null);
      },
      async searchPassages(query): Promise<readonly MemorySearchResult[]> {
        coverage.dispatchRows.add("adapter_search");
        return [...store.values()]
          .filter((entry) => entry.text.includes(query.text))
          .map((entry) => ({ passage: entry, match_count: 1 }));
      },
    },
    ownerSurface: { promptOwner: () => {
      coverage.dispatchRows.add("prompt_owner");
    } },
    abort,
  };
  core = new HermesBridgeCore(ports);
  const ledger = (core as unknown as {
    ledger: {
      commitCheck: (entryId: string, input: {
        readonly nowMs: number;
        readonly recordCurrent: boolean;
      }) => { readonly decision?: string };
    };
  }).ledger;
  const originalCommitCheck = ledger.commitCheck.bind(ledger);
  ledger.commitCheck = (entryId, input) => {
    const before = core.snapshot();
    const entry = before.ledger.entry?.id === entryId ? before.ledger.entry : undefined;
    const dispatched = dispatchedRefusals.get(entryId) ?? new Set<string>();
    const pendingAudit = audits.some((audit) => audit.entryId === entryId && audit.state !== "fulfilled");
    const allowedNow = entry !== undefined &&
      entry.state === "APPROVED" &&
      entry.started &&
      !entry.seen.cancel &&
      !entry.seen.deadline &&
      !entry.seen.deny &&
      !entry.seen.gone &&
      !entry.seen.stop &&
      !entry.seen.latch &&
      !before.ledger.latched &&
      !before.ledger.stopped &&
      !before.stopped &&
      input.recordCurrent &&
      input.nowMs < entry.deadlineAt &&
      dispatched.size === 0 &&
      !pendingAudit;
    const result = originalCommitCheck(entryId, input);
    if (result.decision === "allow" && !allowedNow) {
      violations.push(`allow outside semantic predicate ${entryId} ${JSON.stringify({
        entryState: entry?.state,
        started: entry?.started,
        seen: entry?.seen,
        latched: before.ledger.latched,
        ledgerStopped: before.ledger.stopped,
        stopped: before.stopped,
        recordCurrent: input.recordCurrent,
        nowMs: input.nowMs,
        deadlineAt: entry?.deadlineAt,
        dispatched: [...dispatched],
        pendingAudit,
      })}`);
    }
    return result;
  };

  const liveConnections = (): ConnectionModel[] => [...connections.values()].filter((connection) => connection.state !== "closed");
  const send = (frame: RelayToNodeFrame): void => {
    if (!stopped) {
      core.relayFrame(frame);
      observeStop();
    }
  };
  const randomAwait = async (): Promise<void> => flush(Math.floor(random() * 9));

  const step = (): void => {
    const actions: Array<() => void> = [];
    if (liveConnections().length < 4) {
      actions.push(() => {
        const id = `c${++nextConnection}`;
        connections.set(id, { id, state: "open", answered: new Set() });
        send({ kind: "accepted", connectionId: id });
      });
    }
    for (const connection of liveConnections()) {
      if (connection.state === "open") {
        actions.push(() => {
          const requestId = `r${++nextRequest}`;
          connection.state = "busy";
          connection.requestId = requestId;
          const draw = random();
          let payload: Record<string, unknown>;
          if (draw < 0.10) {
            payload = { type: "hello", request_id: requestId, protocol_version: "2026-10-12", client_name: "client" };
          } else if (draw < 0.15) {
            payload = { type: "tools_list", request_id: requestId };
          } else if (draw < 0.55) {
            payload = {
              type: "tools_call",
              request_id: requestId,
              name: "memory_insert",
              arguments: { text: `bridge text ${seed} ${requestId}`, taint: "user_content", passage_id: `p-${seed}-${requestId}` },
            };
          } else if (draw < 0.78) {
            payload = { type: "tools_call", request_id: requestId, name: "memory_get", arguments: { passage_id: pick([...store.keys(), "missing"]) } };
          } else {
            payload = { type: "tools_call", request_id: requestId, name: "memory_search", arguments: { query: "bridge" } };
          }
          send(publicFrame(connection.id, payload));
          const entry = core.snapshot().ledger.entry;
          if (payload.name === "memory_insert" && entry !== undefined && !entryRequests.has(entry.id)) {
            entryRequests.set(entry.id, { connectionId: connection.id, requestId });
          }
        });
      }
      if (connection.state === "busy") {
        actions.push(() => {
          markConnectionRefusal(connection.id, "cancel", connection.requestId);
          send(publicFrame(connection.id, { type: "cancel", mcp_request_id: connection.requestId }));
        });
      }
      if (connection.state === "open" || connection.state === "busy") {
        actions.push(() => {
          markConnectionRefusal(connection.id, "closed");
          connection.state = "closed";
          send({ kind: "closed", connectionId: connection.id });
        });
        actions.push(() => {
          markConnectionRefusal(connection.id, "peer_shutdown");
          connection.state = "shutting";
          send(publicFrame(connection.id, { type: "shutdown" }));
        });
        actions.push(() => {
          markConnectionRefusal(connection.id, "unparseable");
          send(publicFrame(connection.id, "{bad"));
        });
      }
      if (connection.state === "shutting" || connection.state === "nodeclosed") {
        actions.push(() => {
          connection.state = "closed";
          send({ kind: "closed", connectionId: connection.id });
        });
      }
    }
    if (probes.length > 0) {
      actions.push(() => {
        const probe = probes.shift()!;
        if (!probe.drop) {
          send({ kind: "probe_reply", connectionId: probe.connectionId, nonce: probe.nonce });
        }
      });
    }
    const entry = core.snapshot().ledger.entry;
    if (entry !== undefined && !stopped) {
      actions.push(() => {
        core.ownerApprove(entry.id, entry.textSha256);
        observeStop();
      });
      actions.push(() => {
        markRefusal(entry.id, "deny");
        core.ownerDeny(entry.id);
        observeStop();
      });
    }
    if (timers.size > 0) {
      actions.push(() => {
        const [handle, timer] = pick([...timers.entries()]);
        timers.delete(handle);
        if (timer.ms === HERMES_APPROVAL_DEADLINE_MS) {
          if (random() < 0.8) now += HERMES_APPROVAL_DEADLINE_MS + 1;
          coverage.dispatchRows.add("approval_timer_fire");
          markRefusal(timer.entryId, "deadline");
        } else {
          coverage.dispatchRows.add("probe_timer_fire");
        }
        timer.fire();
        observeStop();
      });
    }
    if (reads.some((read) => !read.done)) {
      actions.push(() => {
        const read = pick(reads.filter((item) => !item.done));
        if (random() < 0.1) read.reject(new Error("read failed"));
        else read.resolve(null);
      });
    }
    if (locks.some((lock) => !lock.done)) {
      actions.push(() => pick(locks.filter((item) => !item.done)).resolve());
    }
    if (audits.some((audit) => !audit.cell.done)) {
      actions.push(() => pick(audits.filter((audit) => !audit.cell.done)).cell.resolve());
    }
    if (random() < 0.03) {
      actions.push(() => {
        const cause = random() < 0.34 ? "relay_shutdown" : random() < 0.67 ? "relay_eof" : "relay_fatal";
        markRefusal(core.snapshot().slot?.entryId, "stop");
        if (cause === "relay_shutdown") send({ kind: "relay_shutdown" });
        else if (cause === "relay_eof") {
          core.relayEof();
          observeStop();
        } else {
          core.relayFatal("fatal");
          observeStop();
        }
        stopped = true;
      });
    }
    if (actions.length > 0) pick(actions)();
  };

  for (let index = 0; index < MAX_STEPS_PER_SCHEDULE; index += 1) {
    await randomAwait();
    observeStop();
    step();
  }

  for (let quiescencePass = 0; quiescencePass < 40; quiescencePass += 1) {
    await flush(12);
    observeStop();
    let changed = false;
    while (probes.length > 0) {
      const probe = probes.shift()!;
      send({ kind: "probe_reply", connectionId: probe.connectionId, nonce: probe.nonce });
      changed = true;
      await flush(4);
    }
    for (const audit of audits) {
      if (!audit.cell.done) {
        audit.cell.resolve();
        changed = true;
      }
    }
    for (const read of reads) {
      if (!read.done) {
        read.resolve(null);
        changed = true;
      }
    }
    for (const lock of locks) {
      if (!lock.done) {
        lock.resolve();
        changed = true;
      }
    }
    const entry = core.snapshot().ledger.entry;
    if (entry !== undefined && entry.state === "PENDING" && !stopped) {
      markRefusal(entry.id, "deny");
      core.ownerDeny(entry.id);
      changed = true;
    }
    for (const [handle, timer] of [...timers.entries()]) {
      timers.delete(handle);
      if (timer.ms === HERMES_APPROVAL_DEADLINE_MS) {
        if (random() < 0.8) now += HERMES_APPROVAL_DEADLINE_MS + 1;
        coverage.dispatchRows.add("approval_timer_fire");
        markRefusal(timer.entryId, "deadline");
      } else {
        coverage.dispatchRows.add("probe_timer_fire");
      }
      timer.fire();
      observeStop();
      changed = true;
      await flush(4);
    }
    if (!changed) break;
  }

  await flush(30);
  for (const connection of connections.values()) {
    if (connection.state === "busy" && connection.requestId !== undefined && !stopped) {
      violations.push(`unanswered request ${connection.requestId}`);
    }
  }
  if (!stopped) {
    for (const connection of connections.values()) {
      if (connection.state !== "closed") {
        connection.state = "closed";
        send({ kind: "closed", connectionId: connection.id });
      }
    }
    await flush(20);
    if (core.snapshot().lifecycle.recordCount !== 0) violations.push(`records retained ${core.snapshot().lifecycle.recordCount}`);
    core.relayFrame({ kind: "relay_shutdown" });
    observeStop();
  }
  await flush(40);
  observeStop();
  for (const [, timer] of [...timers.entries()]) {
    if (timer.ms === HERMES_APPROVAL_DEADLINE_MS) {
      if (random() < 0.8) now += HERMES_APPROVAL_DEADLINE_MS + 1;
      coverage.dispatchRows.add("approval_timer_fire");
      markRefusal(timer.entryId, "deadline");
    } else {
      coverage.dispatchRows.add("probe_timer_fire");
    }
    timer.fire();
    observeStop();
  }
  timers.clear();
  await flush(40);
  observeStop();
  const snapshot = core.snapshot();
  if (!snapshot.drained) violations.push("not drained");
  if (snapshot.slot !== undefined) violations.push("slot retained");
  if (snapshot.waiter.live !== undefined) violations.push("probe retained");
  if (snapshot.lifecycle.recordCount !== 0) violations.push(`records retained after stop ${snapshot.lifecycle.recordCount}`);
  return { violations, coverage };
}

describe("HermesBridgeCore schedule fuzz", () => {
  it("preserves response, commit and cleanup invariants across generated schedules", async () => {
    const coverage: Coverage = {
      terminals: new Set(),
      dispatchRows: new Set(),
      stopCauses: new Set(),
      auditOutcomes: new Set(),
      adapterOutcomes: new Set(),
      interleavings: new Set(),
    };
    const failures: string[] = [];
    for (let seed = 1; seed <= SCHEDULE_COUNT; seed += 1) {
      const result = await runSchedule(seed);
      for (const terminal of result.coverage.terminals) coverage.terminals.add(terminal);
      for (const row of result.coverage.dispatchRows) coverage.dispatchRows.add(row);
      for (const cause of result.coverage.stopCauses) coverage.stopCauses.add(cause);
      for (const outcome of result.coverage.auditOutcomes) coverage.auditOutcomes.add(outcome);
      for (const outcome of result.coverage.adapterOutcomes) coverage.adapterOutcomes.add(outcome);
      for (const interleaving of result.coverage.interleavings) coverage.interleavings.add(interleaving);
      if (result.violations.length > 0) failures.push(`seed ${seed}: ${result.violations.join(", ")}`);
    }

    expect(failures).toEqual([]);
    expect(coverage.terminals).toEqual(new Set(["CANCELED", "COMMITTED", "DENIED", "DISCONNECTED", "INDETERMINATE", "REFUSED", "TIMED_OUT"]));
    expect(coverage.stopCauses).toEqual(new Set(["relay_eof", "relay_fatal", "relay_shutdown", "write_failure"]));
    expect(coverage.auditOutcomes).toEqual(new Set(["deferred", "fulfilled", "rejected"]));
    expect(coverage.adapterOutcomes).toEqual(new Set(["partial", "success", "throw_after_allow"]));
    expect(coverage.dispatchRows).toEqual(new Set([
      "adapter_get",
      "adapter_insert",
      "adapter_search",
      "approval_timer_armed",
      "approval_timer_fire",
      "audit",
      "prompt_owner",
      "probe_timer_armed",
      "probe_timer_fire",
      "send_probe",
      "write_close",
      "write_response",
    ]));
    expect(coverage.interleavings).toEqual(new Set(["shutdown_while_lock_parked", "shutdown_while_durability_wait"]));
  }, 600_000);
});
