import {
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  type HermesApprovalAction,
  type HermesApprovalLedger,
  type HermesApprovalCommitCheckInput,
  type HermesApprovalDecision,
  type HermesApprovalEntryState,
  type HermesApprovalFatalReason,
  type HermesApprovalLateEvent,
  type HermesApprovalRefusalReason,
  type HermesApprovalResponseClass,
  type HermesApprovalTerminalState,
  type HermesApprovalWriteOutcome,
} from "../../src/hermes-memory-bridge/index.js";

interface ModelEntry {
  id: string;
  connectionId: string;
  recordId: string;
  textSha256: string;
  state: HermesApprovalEntryState;
  started: boolean;
  settled: boolean;
  responded: boolean;
  deadlineAt: number;
  seen: Record<HermesApprovalLateEvent, boolean>;
  responseClass?: HermesApprovalResponseClass;
  terminalReason?: string;
  latchReason?: string;
  lateEvents: Set<HermesApprovalLateEvent>;
}

export interface ModelResult {
  readonly actions: readonly HermesApprovalAction[];
  readonly refusal?: HermesApprovalRefusalReason;
  readonly fatal?: HermesApprovalFatalReason;
  readonly decision?: HermesApprovalDecision;
}

const TERMINAL = new Set<HermesApprovalEntryState>([
  "COMMITTED",
  "CANCELED",
  "TIMED_OUT",
  "DISCONNECTED",
  "REFUSED",
  "INDETERMINATE",
]);

export class ApprovalLedgerModel {
  private entry: ModelEntry | undefined;
  private stopped = false;
  private latched = false;
  private largestNowMs = Number.NEGATIVE_INFINITY;

  constructor(
    private readonly deadlineMs: number,
    private readonly resultCapBytes: number,
  ) {}

  admit(entryId: string, connectionId: string, recordId: string, textSha256: string, nowMs: number): ModelResult {
    if (!Number.isFinite(nowMs)) return { actions: [], refusal: "invalid_clock" };
    const now = this.clampNow(nowMs);
    if (this.stopped) return { actions: [], refusal: "stopped" };
    if (this.latched) return { actions: [], refusal: "latched" };
    if (this.entry !== undefined) return { actions: [], refusal: "busy" };
    this.entry = {
      id: entryId,
      connectionId,
      recordId,
      textSha256,
      state: "INSERT_STARTED",
      started: false,
      settled: false,
      responded: false,
      deadlineAt: now + this.deadlineMs,
      seen: this.emptySeen(),
      lateEvents: new Set(),
    };
    return { actions: [] };
  }

  deadline(entryId: string): ModelResult {
    return this.control(entryId, "deadline", "TIMED_OUT", "deadline", "unavailable");
  }

  cancel(entryId: string): ModelResult {
    return this.control(entryId, "cancel", "CANCELED", "cancel", "unavailable");
  }

  peerShutdown(entryId: string): ModelResult {
    return this.control(entryId, "cancel", "CANCELED", "peer_shutdown", "unavailable");
  }

  connectionGone(entryId: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return { actions: [] };
    if (entry.state === "INSERT_STARTED" && !entry.started) {
      entry.seen.gone = true;
      return this.finish(entry, "DISCONNECTED", "connection_gone", undefined, true, false);
    }
    if (entry.state === "INSERT_STARTED" || entry.state === "COMMITTING") {
      this.recordSeen(entry, "gone");
      return { actions: [] };
    }
    if (TERMINAL.has(entry.state) && !entry.settled) entry.seen.gone = true;
    return { actions: [] };
  }

  stop(): ModelResult {
    if (this.stopped) return { actions: [] };
    const result = this.applyGlobal("stop", "stopped", "unavailable");
    this.stopped = true;
    return result;
  }

  latch(reason: string): ModelResult {
    if (this.latched) return { actions: [] };
    const result = this.applyGlobal("latch", reason, "unavailable");
    this.latched = true;
    return result;
  }

  insertStarted(entryId: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return { actions: [], refusal: "unknown_entry" };
    if (entry.state === "INSERT_STARTED" && !entry.started) {
      entry.started = true;
      return { actions: [] };
    }
    return this.fatal();
  }

  commitCheck(entryId: string, input: HermesApprovalCommitCheckInput): ModelResult & { readonly decision: HermesApprovalDecision } {
    const entry = this.find(entryId);
    if (entry === undefined || entry.state !== "INSERT_STARTED" || !entry.started) return this.fatal("refuse");
    if (!Number.isFinite(input.nowMs)) return this.fatal("refuse");
    const terminal = this.decideCommit(entry, input, this.clampNow(input.nowMs));
    if (terminal === undefined) {
      entry.state = "COMMITTING";
      return { actions: [], decision: "allow" };
    }
    return {
      ...this.finish(entry, terminal.state, terminal.reason, terminal.responseClass, false, false),
      decision: "refuse",
    };
  }

  writeFinished(entryId: string, outcome: HermesApprovalWriteOutcome): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined || entry.state !== "COMMITTING") return this.fatal();
    if (outcome === "committed") return this.finish(entry, "COMMITTED", "write_committed", "success", false, false);
    if (outcome === "indeterminate") {
      this.latched = true;
      return this.finish(entry, "INDETERMINATE", "write_indeterminate", "unavailable", false, false);
    }
    return this.finish(entry, "REFUSED", "write_failed", "unavailable", false, false);
  }

  settled(entryId: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return this.fatal();
    if (entry.state === "INSERT_STARTED" && entry.started) {
      const terminal = this.decideCommit(entry, {
        probe: "resolved",
        admitDurable: false,
        nowMs: this.largestNowMs,
        recordCurrent: true,
        passageTextSha256: entry.textSha256,
        getFrameUtf8Bytes: 0,
      }, this.largestNowMs);
      if (terminal === undefined) {
        return this.finish(entry, "REFUSED", "insert_returned_before_commit_check", "unavailable", true, true);
      }
      return this.finish(entry, terminal.state, terminal.reason, terminal.responseClass, true, true);
    }
    if (!TERMINAL.has(entry.state)) return this.fatal();
    entry.settled = true;
    const actions = this.respond(entry);
    this.deleteIfComplete(entry);
    return { actions };
  }

  snapshot() {
    return {
      stopped: this.stopped,
      latched: this.latched,
      largestNowMs: this.largestNowMs,
      entry: this.entry === undefined ? undefined : {
        id: this.entry.id,
        connectionId: this.entry.connectionId,
        recordId: this.entry.recordId,
        textSha256: this.entry.textSha256,
        state: this.entry.state,
        started: this.entry.started,
        settled: this.entry.settled,
        responded: this.entry.responded,
        deadlineAt: this.entry.deadlineAt,
        seen: { ...this.entry.seen },
        responseClass: this.entry.responseClass,
        terminalReason: this.entry.terminalReason,
        lateEvents: [...this.entry.lateEvents],
      },
    };
  }

  private control(
    entryId: string,
    flag: HermesApprovalLateEvent,
    terminalState: HermesApprovalTerminalState,
    reason: string,
    responseClass: HermesApprovalResponseClass,
  ): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return { actions: [] };
    if (entry.state === "INSERT_STARTED" && !entry.started) {
      return this.finish(entry, terminalState, reason, responseClass, true, true);
    }
    if (entry.state === "INSERT_STARTED" && entry.started) {
      this.recordSeen(entry, flag);
      return { actions: [] };
    }
    if (entry.state === "COMMITTING") {
      this.recordSeen(entry, flag);
      return { actions: [] };
    }
    return { actions: [] };
  }

  private applyGlobal(
    flag: "stop" | "latch",
    reason: string,
    responseClass: HermesApprovalResponseClass,
  ): ModelResult {
    const entry = this.entry;
    if (entry === undefined) return { actions: [] };
    if (entry.state === "INSERT_STARTED" && !entry.started) {
      return this.finish(entry, "REFUSED", reason, responseClass, true, true);
    }
    if (entry.state === "INSERT_STARTED" || entry.state === "COMMITTING") {
      this.recordSeen(entry, flag, flag === "latch" ? reason : undefined);
    }
    return { actions: [] };
  }

  private decideCommit(
    entry: ModelEntry,
    input: HermesApprovalCommitCheckInput,
    nowMs: number,
  ): { readonly state: HermesApprovalTerminalState; readonly reason: string; readonly responseClass?: HermesApprovalResponseClass } | undefined {
    if (entry.seen.gone || !input.recordCurrent) return { state: "DISCONNECTED", reason: "connection_gone" };
    if (
      input.passageTextSha256 !== entry.textSha256 ||
      !Number.isFinite(input.getFrameUtf8Bytes) ||
      input.getFrameUtf8Bytes < 0 ||
      !(input.getFrameUtf8Bytes <= this.resultCapBytes)
    ) {
      return { state: "REFUSED", reason: "commit_binding_mismatch", responseClass: "unavailable" };
    }
    if (entry.seen.stop || entry.seen.latch || this.stopped || this.latched) {
      return { state: "REFUSED", reason: entry.latchReason ?? "service_unavailable", responseClass: "unavailable" };
    }
    if (entry.seen.cancel) return { state: "CANCELED", reason: "cancel", responseClass: "unavailable" };
    if (entry.seen.deadline || nowMs >= entry.deadlineAt) return { state: "TIMED_OUT", reason: "deadline", responseClass: "unavailable" };
    if (input.probe === "refused") return { state: "REFUSED", reason: "probe_refused", responseClass: "unavailable" };
    if (!input.admitDurable) return { state: "REFUSED", reason: "audit_unavailable", responseClass: "unavailable" };
    return undefined;
  }

  private finish(
    entry: ModelEntry,
    state: HermesApprovalTerminalState,
    reason: string,
    responseClass: HermesApprovalResponseClass | undefined,
    settle: boolean,
    respondNow: boolean,
  ): ModelResult {
    entry.state = state;
    entry.terminalReason = reason;
    entry.responseClass = state === "DISCONNECTED" ? undefined : responseClass;
    if (settle) entry.settled = true;
    const actions: HermesApprovalAction[] = [];
    if (respondNow) actions.push(...this.respond(entry));
    this.deleteIfComplete(entry);
    return { actions };
  }

  private respond(entry: ModelEntry): HermesApprovalAction[] {
    if (entry.responded || entry.seen.gone || entry.state === "DISCONNECTED" || entry.responseClass === undefined) return [];
    entry.responded = true;
    if (entry.responseClass === "success") return [{ kind: "respond", entryId: entry.id, response: "success" }];
    return [{
      kind: "respond",
      entryId: entry.id,
      response: entry.responseClass,
      message: entry.responseClass === "unavailable" ? HERMES_MEMORY_UNAVAILABLE : HERMES_MEMORY_DENIAL,
    }];
  }

  private recordSeen(entry: ModelEntry, flag: HermesApprovalLateEvent, reason?: string): void {
    entry.seen[flag] = true;
    if (flag === "latch" && reason !== undefined) entry.latchReason = reason;
    if (entry.state === "COMMITTING") entry.lateEvents.add(flag);
  }

  private deleteIfComplete(entry: ModelEntry): void {
    if (this.entry === entry && TERMINAL.has(entry.state) && entry.settled) this.entry = undefined;
  }

  private fatal(): ModelResult;
  private fatal(decision: HermesApprovalDecision): ModelResult & { readonly decision: HermesApprovalDecision };
  private fatal(decision?: HermesApprovalDecision): ModelResult {
    return decision === undefined ? { actions: [], fatal: "ledger_order" } : { actions: [], fatal: "ledger_order", decision };
  }

  private find(entryId: string): ModelEntry | undefined {
    return this.entry?.id === entryId ? this.entry : undefined;
  }

  private clampNow(nowMs: number): number {
    this.largestNowMs = Math.max(this.largestNowMs, nowMs);
    return this.largestNowMs;
  }


  private emptySeen(): Record<HermesApprovalLateEvent, boolean> {
    return { deadline: false, cancel: false, gone: false, stop: false, latch: false };
  }
}
