import {
  HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE,
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  HERMES_RATE_WINDOW_MS,
  type HermesApprovalAction,
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
  "DENIED",
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
  private readonly promptTimes: number[] = [];

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
    this.prunePrompts(now);
    if (this.promptTimes.length >= HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE) {
      return { actions: [], refusal: "prompt_rate" };
    }
    this.promptTimes.push(now);
    this.entry = {
      id: entryId,
      connectionId,
      recordId,
      textSha256,
      state: "PENDING",
      started: false,
      settled: false,
      responded: false,
      deadlineAt: now + this.deadlineMs,
      seen: this.emptySeen(),
      lateEvents: new Set(),
    };
    return {
      actions: [
        { kind: "audit", entryId, event: "created" },
        { kind: "prompt_owner", entryId },
      ],
    };
  }

  ownerApprove(entryId: string, textSha256: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return { actions: [], refusal: "unknown_entry" };
    if (entry.state !== "PENDING") return { actions: [], refusal: "not_pending" };
    if (entry.textSha256 !== textSha256) return { actions: [], refusal: "hash_mismatch" };
    entry.state = "APPROVED";
    return { actions: [{ kind: "audit", entryId, event: "approved" }] };
  }

  ownerDeny(entryId: string): ModelResult {
    return this.control(entryId, "deny", "DENIED", "owner_denied", "denial");
  }

  deadline(entryId: string): ModelResult {
    return this.control(entryId, "deadline", "TIMED_OUT", "deadline", "denial");
  }

  cancel(entryId: string): ModelResult {
    return this.control(entryId, "cancel", "CANCELED", "cancel", "denial");
  }

  peerShutdown(entryId: string): ModelResult {
    return this.control(entryId, "cancel", "CANCELED", "peer_shutdown", "denial");
  }

  connectionGone(entryId: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return { actions: [] };
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      entry.seen.gone = true;
      return this.finish(entry, "DISCONNECTED", "connection_gone", undefined, true, false);
    }
    if (entry.state === "APPROVED" || entry.state === "COMMITTING") {
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
    if (entry.state === "PENDING") return { actions: [], refusal: "not_approved" };
    if (entry.state === "APPROVED" && !entry.started) {
      entry.started = true;
      return { actions: [] };
    }
    return this.fatal();
  }

  commitCheck(entryId: string, input: HermesApprovalCommitCheckInput): ModelResult & { readonly decision: HermesApprovalDecision } {
    const entry = this.find(entryId);
    if (entry === undefined || entry.state !== "APPROVED" || !entry.started) return this.fatal("refuse");
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
    return this.finish(entry, "REFUSED", "write_failed", "denial", false, false);
  }

  settled(entryId: string): ModelResult {
    const entry = this.find(entryId);
    if (entry === undefined) return this.fatal();
    if (entry.state === "APPROVED" && entry.started) {
      const terminal = this.decideCommit(entry, {
        probe: "resolved",
        nowMs: this.largestNowMs,
        recordCurrent: true,
        passageTextSha256: entry.textSha256,
        getFrameUtf8Bytes: 0,
      }, this.largestNowMs);
      if (terminal === undefined) {
        return this.finish(entry, "REFUSED", "insert_returned_before_commit_check", "denial", true, true);
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
      promptWindowCount: this.promptTimes.length,
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
    if (entry === undefined) return flag === "deny" ? { actions: [], refusal: "unknown_entry" } : { actions: [] };
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      return this.finish(entry, terminalState, reason, responseClass, true, true);
    }
    if (entry.state === "APPROVED" && entry.started) {
      this.recordSeen(entry, flag);
      return { actions: [] };
    }
    if (entry.state === "COMMITTING") {
      this.recordSeen(entry, flag);
      return { actions: [] };
    }
    return flag === "deny" ? { actions: [], refusal: "not_pending" } : { actions: [] };
  }

  private applyGlobal(
    flag: "stop" | "latch",
    reason: string,
    responseClass: HermesApprovalResponseClass,
  ): ModelResult {
    const entry = this.entry;
    if (entry === undefined) return { actions: [] };
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      return this.finish(entry, "REFUSED", reason, responseClass, true, true);
    }
    if (entry.state === "APPROVED" || entry.state === "COMMITTING") {
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
      return { state: "REFUSED", reason: "commit_binding_mismatch", responseClass: "denial" };
    }
    if (input.probe === "refused") return { state: "REFUSED", reason: "probe_refused", responseClass: "denial" };
    if (entry.seen.stop || entry.seen.latch || this.stopped || this.latched) {
      return { state: "REFUSED", reason: entry.latchReason ?? "service_unavailable", responseClass: "unavailable" };
    }
    if (entry.seen.cancel) return { state: "CANCELED", reason: "cancel", responseClass: "denial" };
    if (entry.seen.deny) return { state: "DENIED", reason: "owner_denied", responseClass: "denial" };
    if (entry.seen.deadline || nowMs >= entry.deadlineAt) return { state: "TIMED_OUT", reason: "deadline", responseClass: "denial" };
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
    const actions: HermesApprovalAction[] = [{
      kind: "audit",
      entryId: entry.id,
      event: "terminal",
      state,
      reason,
      lateEvents: [...entry.lateEvents],
    }];
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

  private prunePrompts(nowMs: number): void {
    if (!Number.isFinite(nowMs)) return;
    while (this.promptTimes.length > 0 && nowMs - this.promptTimes[0]! >= HERMES_RATE_WINDOW_MS) {
      this.promptTimes.shift();
    }
  }

  private emptySeen(): Record<HermesApprovalLateEvent, boolean> {
    return { deny: false, deadline: false, cancel: false, gone: false, stop: false, latch: false };
  }
}
