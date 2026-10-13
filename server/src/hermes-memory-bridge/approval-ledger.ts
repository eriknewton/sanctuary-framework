import {
  HERMES_APPROVAL_DEADLINE_MS,
  HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE,
  HERMES_MAX_PENDING_APPROVALS,
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  HERMES_RATE_WINDOW_MS,
  MAX_RESULT_FRAME_BYTES,
} from "./constants.js";
import { HermesRateWindow } from "./rate-window.js";

export type HermesApprovalEntryState =
  | "PENDING"
  | "APPROVED"
  | "COMMITTING"
  | "COMMITTED"
  | "DENIED"
  | "CANCELED"
  | "TIMED_OUT"
  | "DISCONNECTED"
  | "REFUSED"
  | "INDETERMINATE";

export type HermesApprovalTerminalState = Exclude<HermesApprovalEntryState, "PENDING" | "APPROVED" | "COMMITTING">;
export type HermesApprovalResponseClass = "success" | "denial" | "unavailable";
export type HermesApprovalDecision = "allow" | "refuse";
export type HermesApprovalProbeVerdict = "resolved" | "refused";
export type HermesApprovalWriteOutcome = "committed" | "failed" | "indeterminate";
export type HermesApprovalRefusalReason =
  | "stopped"
  | "latched"
  | "busy"
  | "prompt_rate"
  | "hash_mismatch"
  | "not_pending"
  | "not_approved"
  | "unknown_entry";
export type HermesApprovalFatalReason = "ledger_order";
export type HermesApprovalLateEvent = "deny" | "deadline" | "cancel" | "gone" | "stop" | "latch";

export type HermesApprovalAction =
  | {
      readonly kind: "audit";
      readonly entryId: string;
      readonly event: "created" | "approved" | "terminal";
      readonly state?: HermesApprovalTerminalState;
      readonly reason?: string;
      readonly lateEvents?: readonly HermesApprovalLateEvent[];
    }
  | { readonly kind: "prompt_owner"; readonly entryId: string }
  | {
      readonly kind: "respond";
      readonly entryId: string;
      readonly response: HermesApprovalResponseClass;
      readonly message: typeof HERMES_MEMORY_DENIAL | typeof HERMES_MEMORY_UNAVAILABLE;
    };

export interface HermesApprovalLedgerResult {
  readonly actions: readonly HermesApprovalAction[];
  readonly refusal?: HermesApprovalRefusalReason;
  readonly fatal?: HermesApprovalFatalReason;
  readonly decision?: HermesApprovalDecision;
}

export interface HermesApprovalCommitCheckInput {
  readonly probe: HermesApprovalProbeVerdict;
  readonly nowMs: number;
  readonly recordCurrent: boolean;
  readonly passageTextSha256: string;
  readonly getFrameUtf8Bytes: number;
}

export interface HermesApprovalEntrySnapshot {
  readonly id: string;
  readonly connectionId: string;
  readonly recordId: string;
  readonly textSha256: string;
  readonly state: HermesApprovalEntryState;
  readonly started: boolean;
  readonly settled: boolean;
  readonly responded: boolean;
  readonly deadlineAt: number;
  readonly seen: Readonly<Record<HermesApprovalLateEvent, boolean>>;
  readonly responseClass?: HermesApprovalResponseClass;
  readonly terminalReason?: string;
  readonly lateEvents: readonly HermesApprovalLateEvent[];
}

export interface HermesApprovalLedgerSnapshot {
  readonly stopped: boolean;
  readonly latched: boolean;
  readonly largestNowMs: number;
  readonly entry?: HermesApprovalEntrySnapshot;
  readonly promptWindowCount: number;
}

interface HermesApprovalEntry {
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
  lateEvents: Set<HermesApprovalLateEvent>;
}

const TERMINAL_STATES = new Set<HermesApprovalEntryState>([
  "COMMITTED",
  "DENIED",
  "CANCELED",
  "TIMED_OUT",
  "DISCONNECTED",
  "REFUSED",
  "INDETERMINATE",
]);

const EMPTY_RESULT: HermesApprovalLedgerResult = Object.freeze({ actions: [] });

export class HermesApprovalLedger {
  private entry: HermesApprovalEntry | undefined;
  private stopped = false;
  private latched = false;
  private largestNowMs = Number.NEGATIVE_INFINITY;
  private readonly promptWindow = new HermesRateWindow(
    HERMES_MAX_APPROVAL_PROMPTS_PER_MINUTE,
    HERMES_RATE_WINDOW_MS,
  );

  admit(
    entryId: string,
    connectionId: string,
    recordId: string,
    textSha256: string,
    nowMs: number,
  ): HermesApprovalLedgerResult {
    const now = this.clampNow(nowMs);
    if (this.stopped) return { actions: [], refusal: "stopped" };
    if (this.latched) return { actions: [], refusal: "latched" };
    if (this.entry !== undefined || HERMES_MAX_PENDING_APPROVALS < 1) {
      return { actions: [], refusal: "busy" };
    }
    const promptAdmission = this.promptWindow.check(now);
    if (!promptAdmission.allowed) return { actions: [], refusal: "prompt_rate" };
    this.promptWindow.record(now);
    this.entry = {
      id: entryId,
      connectionId,
      recordId,
      textSha256,
      state: "PENDING",
      started: false,
      settled: false,
      responded: false,
      deadlineAt: now + HERMES_APPROVAL_DEADLINE_MS,
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

  ownerApprove(entryId: string, textSha256: string): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined) return { actions: [], refusal: "unknown_entry" };
    if (entry.state !== "PENDING") return { actions: [], refusal: "not_pending" };
    if (textSha256 !== entry.textSha256) return { actions: [], refusal: "hash_mismatch" };
    entry.state = "APPROVED";
    return { actions: [{ kind: "audit", entryId, event: "approved" }] };
  }

  ownerDeny(entryId: string): HermesApprovalLedgerResult {
    return this.control(entryId, "deny", "DENIED", "owner_denied", "denial");
  }

  deadline(entryId: string): HermesApprovalLedgerResult {
    return this.control(entryId, "deadline", "TIMED_OUT", "deadline", "denial");
  }

  cancel(entryId: string): HermesApprovalLedgerResult {
    return this.control(entryId, "cancel", "CANCELED", "cancel", "denial");
  }

  peerShutdown(entryId: string): HermesApprovalLedgerResult {
    return this.control(entryId, "cancel", "CANCELED", "peer_shutdown", "denial");
  }

  connectionGone(entryId: string): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined) return EMPTY_RESULT;
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      return this.finish(entry, "DISCONNECTED", "connection_gone", undefined, { settle: true, respondNow: false });
    }
    if (entry.state === "APPROVED" || entry.state === "COMMITTING") {
      this.recordSeen(entry, "gone");
      return EMPTY_RESULT;
    }
    return EMPTY_RESULT;
  }

  stop(): HermesApprovalLedgerResult {
    if (this.stopped) return EMPTY_RESULT;
    const result = this.applyGlobalRefusal("stop", "stopped", "unavailable");
    this.stopped = true;
    return result;
  }

  latch(_reason: string): HermesApprovalLedgerResult {
    if (this.latched) return EMPTY_RESULT;
    const result = this.applyGlobalRefusal("latch", "latched", "unavailable");
    this.latched = true;
    return result;
  }

  insertStarted(entryId: string): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined) return { actions: [], refusal: "unknown_entry" };
    if (entry.state === "PENDING") return { actions: [], refusal: "not_approved" };
    if (entry.state === "APPROVED" && !entry.started) {
      entry.started = true;
      return EMPTY_RESULT;
    }
    return this.fatal();
  }

  commitCheck(entryId: string, input: HermesApprovalCommitCheckInput): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    const now = this.clampNow(input.nowMs);
    if (entry === undefined) return this.fatal("refuse");
    if (entry.state !== "APPROVED" || !entry.started) return this.fatal("refuse");

    const terminal = this.decideCommit(entry, input, now);
    if (terminal === undefined) {
      entry.state = "COMMITTING";
      return { actions: [], decision: "allow" };
    }
    return this.finish(entry, terminal.state, terminal.reason, terminal.responseClass, {
      settle: false,
      respondNow: false,
      decision: "refuse",
    });
  }

  writeFinished(entryId: string, outcome: HermesApprovalWriteOutcome): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined || entry.state !== "COMMITTING") return this.fatal();
    if (outcome === "committed") {
      return this.finish(entry, "COMMITTED", "write_committed", "success", { settle: false, respondNow: false });
    }
    if (outcome === "indeterminate") {
      this.latched = true;
      return this.finish(entry, "INDETERMINATE", "write_indeterminate", "unavailable", {
        settle: false,
        respondNow: false,
      });
    }
    return this.finish(entry, "REFUSED", "write_failed", "denial", { settle: false, respondNow: false });
  }

  settled(entryId: string): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined) return this.fatal();
    if (entry.state === "APPROVED" && entry.started) return this.startedTerminalFromFlags(entry);
    if (!TERMINAL_STATES.has(entry.state)) return this.fatal();
    entry.settled = true;
    const actions = this.respondAtSettle(entry);
    this.deleteIfComplete(entry);
    return { actions };
  }

  snapshot(): HermesApprovalLedgerSnapshot {
    return {
      stopped: this.stopped,
      latched: this.latched,
      largestNowMs: this.largestNowMs,
      promptWindowCount: this.promptWindow.retainedCount,
      entry: this.entry === undefined ? undefined : this.snapshotEntry(this.entry),
    };
  }

  private control(
    entryId: string,
    flag: HermesApprovalLateEvent,
    terminalState: HermesApprovalTerminalState,
    reason: string,
    responseClass: HermesApprovalResponseClass,
  ): HermesApprovalLedgerResult {
    const entry = this.findEntry(entryId);
    if (entry === undefined) return flag === "deny" ? { actions: [], refusal: "unknown_entry" } : EMPTY_RESULT;
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      return this.finish(entry, terminalState, reason, responseClass, { settle: true, respondNow: true });
    }
    if (entry.state === "APPROVED" && entry.started) {
      this.recordSeen(entry, flag);
      return EMPTY_RESULT;
    }
    if (entry.state === "COMMITTING") {
      this.recordSeen(entry, flag);
      return EMPTY_RESULT;
    }
    return flag === "deny" ? { actions: [], refusal: "not_pending" } : EMPTY_RESULT;
  }

  private applyGlobalRefusal(
    flag: "stop" | "latch",
    reason: string,
    responseClass: HermesApprovalResponseClass,
  ): HermesApprovalLedgerResult {
    const entry = this.entry;
    if (entry === undefined) return EMPTY_RESULT;
    if (entry.state === "PENDING" || (entry.state === "APPROVED" && !entry.started)) {
      return this.finish(entry, "REFUSED", reason, responseClass, { settle: true, respondNow: true });
    }
    if (entry.state === "APPROVED" || entry.state === "COMMITTING") {
      this.recordSeen(entry, flag);
    }
    return EMPTY_RESULT;
  }

  private decideCommit(
    entry: HermesApprovalEntry,
    input: HermesApprovalCommitCheckInput,
    nowMs: number,
  ): { readonly state: HermesApprovalTerminalState; readonly reason: string; readonly responseClass?: HermesApprovalResponseClass } | undefined {
    if (entry.seen.gone || !input.recordCurrent) {
      return { state: "DISCONNECTED", reason: "connection_gone" };
    }
    // The hook digest must match the owner-approved UTF-8 passage digest from the storage adapter.
    if (input.passageTextSha256 !== entry.textSha256 || input.getFrameUtf8Bytes > MAX_RESULT_FRAME_BYTES) {
      return { state: "REFUSED", reason: "commit_binding_mismatch", responseClass: "denial" };
    }
    if (input.probe === "refused") return { state: "REFUSED", reason: "probe_refused", responseClass: "denial" };
    if (entry.seen.stop || entry.seen.latch || this.stopped || this.latched) {
      return { state: "REFUSED", reason: "service_unavailable", responseClass: "unavailable" };
    }
    if (entry.seen.cancel) return { state: "CANCELED", reason: "cancel", responseClass: "denial" };
    if (entry.seen.deny) return { state: "DENIED", reason: "owner_denied", responseClass: "denial" };
    if (entry.seen.deadline || nowMs >= entry.deadlineAt) {
      return { state: "TIMED_OUT", reason: "deadline", responseClass: "denial" };
    }
    return undefined;
  }

  private startedTerminalFromFlags(entry: HermesApprovalEntry): HermesApprovalLedgerResult {
    const terminal = this.decideCommit(entry, {
      probe: "resolved",
      nowMs: this.largestNowMs,
      recordCurrent: true,
      passageTextSha256: entry.textSha256,
      getFrameUtf8Bytes: 0,
    }, this.largestNowMs);
    if (terminal === undefined) {
      return this.finish(entry, "REFUSED", "insert_returned_before_commit_check", "denial", {
        settle: true,
        respondNow: true,
      });
    }
    return this.finish(entry, terminal.state, terminal.reason, terminal.responseClass, {
      settle: true,
      respondNow: true,
    });
  }

  private finish(
    entry: HermesApprovalEntry,
    state: HermesApprovalTerminalState,
    reason: string,
    responseClass: HermesApprovalResponseClass | undefined,
    options: { readonly settle: boolean; readonly respondNow: boolean; readonly decision?: HermesApprovalDecision },
  ): HermesApprovalLedgerResult {
    entry.state = state;
    entry.terminalReason = reason;
    entry.responseClass = state === "DISCONNECTED" ? undefined : responseClass;
    if (options.settle) entry.settled = true;
    const actions: HermesApprovalAction[] = [
      {
        kind: "audit",
        entryId: entry.id,
        event: "terminal",
        state,
        reason,
        lateEvents: [...entry.lateEvents],
      },
    ];
    if (options.respondNow) actions.unshift(...this.respondAtSettle(entry));
    this.deleteIfComplete(entry);
    return options.decision === undefined ? { actions } : { actions, decision: options.decision };
  }

  private respondAtSettle(entry: HermesApprovalEntry): HermesApprovalAction[] {
    if (entry.responded || entry.seen.gone || entry.state === "DISCONNECTED") return [];
    if (entry.responseClass === undefined) return [];
    entry.responded = true;
    return [{
      kind: "respond",
      entryId: entry.id,
      response: entry.responseClass,
      message: entry.responseClass === "unavailable" ? HERMES_MEMORY_UNAVAILABLE : HERMES_MEMORY_DENIAL,
    }];
  }

  private recordSeen(entry: HermesApprovalEntry, flag: HermesApprovalLateEvent): void {
    entry.seen[flag] = true;
    if (entry.state === "COMMITTING") entry.lateEvents.add(flag);
  }

  private findEntry(entryId: string): HermesApprovalEntry | undefined {
    return this.entry?.id === entryId ? this.entry : undefined;
  }

  private deleteIfComplete(entry: HermesApprovalEntry): void {
    // The global slot is released only after terminal state and settle are both observed.
    if (this.entry === entry && TERMINAL_STATES.has(entry.state) && entry.settled) {
      this.entry = undefined;
    }
  }

  private fatal(decision?: HermesApprovalDecision): HermesApprovalLedgerResult {
    return decision === undefined ? { actions: [], fatal: "ledger_order" } : { actions: [], fatal: "ledger_order", decision };
  }

  private clampNow(nowMs: number): number {
    // Every ledger clock input is monotonic-clamped so a backward step cannot reopen a deadline.
    const finiteNow = Number.isFinite(nowMs) ? nowMs : this.largestNowMs;
    this.largestNowMs = Math.max(this.largestNowMs, finiteNow);
    return this.largestNowMs;
  }

  private emptySeen(): Record<HermesApprovalLateEvent, boolean> {
    return {
      deny: false,
      deadline: false,
      cancel: false,
      gone: false,
      stop: false,
      latch: false,
    };
  }

  private snapshotEntry(entry: HermesApprovalEntry): HermesApprovalEntrySnapshot {
    return {
      id: entry.id,
      connectionId: entry.connectionId,
      recordId: entry.recordId,
      textSha256: entry.textSha256,
      state: entry.state,
      started: entry.started,
      settled: entry.settled,
      responded: entry.responded,
      deadlineAt: entry.deadlineAt,
      seen: { ...entry.seen },
      responseClass: entry.responseClass,
      terminalReason: entry.terminalReason,
      lateEvents: [...entry.lateEvents],
    };
  }
}
