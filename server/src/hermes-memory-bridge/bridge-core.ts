import { AsyncLocalStorage } from "node:async_hooks";

import type {
  MemoryPassage,
  MemoryPassageInput,
  MemorySearchQuery,
  MemorySearchResult,
} from "../sdw/adapters/memory-backend.js";
import {
  type HermesBridgeCommitCheck,
  type HermesBridgeCommitContext,
  hermesBridgePassageTextDigest,
} from "../sdw/adapters/sdw-memory-backend.js";
import { SdwValidationError } from "../sdw/errors.js";
import { isSdwIdentifier } from "../sdw/grammar.js";
import { memoryInsertIngress } from "../sdw/memory-provenance-ingress.js";
import type { PersistableTaint } from "../sdw/provenance.js";
import {
  HERMES_APPROVAL_DEADLINE_MS,
  HERMES_MAX_CALLS_PER_MINUTE,
  HERMES_MEMORY_DENIAL,
  HERMES_MEMORY_UNAVAILABLE,
  HERMES_RATE_WINDOW_MS,
  PROBE_REPLY_BOUND_MS,
} from "./constants.js";
import {
  HermesApprovalLedger,
  type HermesApprovalAction,
  type HermesApprovalLedgerResult,
  type HermesApprovalProbeVerdict,
  type HermesApprovalRefusalReason,
  type HermesApprovalTerminalState,
} from "./approval-ledger.js";
import {
  classifyHermesPublicFrameSummary,
  HermesConnectionLifecycle,
  type HermesCallRecordSnapshot,
  type HermesLifecycleAction,
  type HermesLifecycleResult,
  type HermesPublicFrameSummary,
} from "./connection-lifecycle.js";
import type {
  HermesMemoryToolArguments,
  NodeToRelayInput,
  PublicFrameParseResult,
  RelayToNodeFrame,
} from "./envelopes.js";
import {
  buildDeniedPublicResponseBytes,
} from "./envelopes.js";
import {
  createNodeCryptoHermesProbeNonceSource,
  HermesProbeWaiter,
  type HermesProbeWaiterAction,
  type HermesProbeWaiterResult,
} from "./probe-waiter.js";
import { HermesRateWindow } from "./rate-window.js";
import {
  PUBLIC_RESULT_ENVELOPE_MAX_BYTES,
  buildHelloResultBytes,
  buildMemoryGetResultBytes,
  buildMemoryInsertSuccessBytes,
  buildMemorySearchResultBytes,
  buildToolsListResultBytes,
  checkedError,
  type HermesPublicResultBuild,
} from "./public-results.js";

export type HermesTimerHandle = object;

export interface HermesApprovalPromptSummary {
  readonly entryId: string;
  readonly connectionId: string;
  readonly recordId: string;
  readonly textSha256: string;
  readonly passageText: string;
  readonly passageId?: string;
  readonly tags: readonly string[];
}

export interface HermesBridgeAuditRecord {
  readonly kind: "created" | "approved" | "terminal" | "commit_intent" | "latch";
  readonly entryId?: string;
  readonly connectionId?: string;
  readonly recordId?: string;
  readonly state?: HermesApprovalTerminalState;
  readonly reason?: string;
  readonly textSha256?: string;
  readonly lateEvents?: readonly string[];
}

export interface HermesBridgeCorePorts {
  readonly writeFrame: (input: NodeToRelayInput) => void;
  /**
   * The audit port is awaited inside the storage commit hook; it must never call
   * the memory adapter or take the corpus lock that the hook already holds.
   */
  readonly appendAudit: (record: HermesBridgeAuditRecord) => Promise<void>;
  readonly nowMs: () => number;
  readonly setTimer: (ms: number, fire: () => void) => HermesTimerHandle;
  readonly clearTimer: (handle: HermesTimerHandle) => void;
  readonly adapter: Pick<HermesBridgeMemoryAdapter, "insertPassage" | "getPassage" | "searchPassages">;
  readonly ownerSurface: { readonly promptOwner: (entryId: string, summary: HermesApprovalPromptSummary) => void };
  readonly abort: AbortController;
}

export interface HermesBridgeMemoryAdapter {
  insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage>;
  getPassage(passageId: string): Promise<MemoryPassage | null>;
  searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]>;
}

export type HermesBridgeStopCause = "relay_shutdown" | "relay_eof" | "relay_fatal" | "write_failure";

interface CommitContextSlot {
  readonly entryId: string;
}

interface DurableAudit {
  state: "pending" | "fulfilled" | "rejected";
  readonly promise: Promise<void>;
}

interface InsertSlot {
  readonly entryId: string;
  readonly connectionId: string;
  readonly recordId: string;
  readonly requestId: string;
  readonly text: string;
  readonly textSha256: string;
  readonly taint: PersistableTaint;
  readonly tags: readonly string[];
  readonly passageId?: string;
  deadlineTimer?: HermesTimerHandle;
  probeTimer?: HermesTimerHandle;
  readonly durability: Set<DurableAudit>;
  readonly verdictWaiters: Set<(verdict: HermesApprovalProbeVerdict) => void>;
  readonly hookWaiters: Set<() => void>;
  verdict?: HermesApprovalProbeVerdict;
  insertInFlight: boolean;
  hookAllowed: boolean;
  commitIds?: { readonly passageId: string; readonly documentId: string };
  successBytes?: Uint8Array;
  released: boolean;
}

interface ReadOperation {
  readonly connectionId: string;
  readonly recordId: string;
  readonly requestId: string;
}

export class HermesBridgeCommitRefusedError extends Error {
  constructor(message = "Hermes bridge commit refused") {
    super(message);
    this.name = "HermesBridgeCommitRefusedError";
  }
}

/**
 * Pure Hermes memory bridge integrator. It composes the wire, lifecycle,
 * probe-waiter, approval-ledger and slice-1 storage hook; it performs no fd,
 * child-process, startup, policy-gate or durable storage work itself.
 */
export class HermesBridgeCore {
  private readonly lifecycle = new HermesConnectionLifecycle();
  private readonly waiter = new HermesProbeWaiter(createNodeCryptoHermesProbeNonceSource());
  private readonly ledger = new HermesApprovalLedger();
  private readonly callWindow = new HermesRateWindow(HERMES_MAX_CALLS_PER_MINUTE, HERMES_RATE_WINDOW_MS);
  private readonly asyncContext = new AsyncLocalStorage<CommitContextSlot>();
  private readonly commitCheckObject: HermesBridgeCommitCheck;
  private readonly drainedListeners = new Set<(outcome: { readonly fatalBridge: boolean }) => void>();
  private slot: InsertSlot | undefined;
  private nextEntryNumber = 1;
  private stopped = false;
  private fatalBridgeFlag = false;
  private drainedFlag = false;
  private drainQueued = false;

  constructor(private readonly ports: HermesBridgeCorePorts) {
    if (ports.abort === undefined || ports.adapter === undefined) {
      throw new TypeError("HermesBridgeCore requires abort and adapter ports");
    }
    this.commitCheckObject = {
      abortSignal: ports.abort.signal,
      assertAllowedToCommit: (context) => this.assertAllowedToCommit(context),
    };
  }

  get commitCheck(): HermesBridgeCommitCheck {
    return this.commitCheckObject;
  }

  get fatalBridge(): boolean {
    return this.fatalBridgeFlag;
  }

  get drained(): boolean {
    return this.drainedFlag;
  }

  onDrained(listener: (outcome: { readonly fatalBridge: boolean }) => void): () => void {
    this.drainedListeners.add(listener);
    if (this.drainedFlag) queueMicrotask(() => listener({ fatalBridge: this.fatalBridgeFlag }));
    return () => this.drainedListeners.delete(listener);
  }

  relayFrame(frame: RelayToNodeFrame): void {
    if (this.stopped) return;
    switch (frame.kind) {
      case "accepted":
        this.applyLifecycle({ type: "accepted", connectionId: frame.connectionId });
        return this.endStep();
      case "frame":
        this.dispatchPublicFrame(frame);
        return this.endStep();
      case "closed":
        this.applyClosed(frame.connectionId);
        return this.endStep();
      case "probe_reply":
        this.performWaiterResult(this.waiter.reply(frame));
        return this.endStep();
      case "relay_shutdown":
        this.stop("relay_shutdown");
        return this.endStep();
    }
  }

  relayFatal(_reason: string): void {
    if (this.stopped) return;
    this.fatalBridgeFlag = true;
    this.stop("relay_fatal");
    this.endStep();
  }

  relayEof(): void {
    if (this.stopped) return;
    this.stop("relay_eof");
    this.endStep();
  }

  ownerApprove(entryId: string, textSha256: string): HermesApprovalRefusalReason | undefined {
    if (this.stopped) return undefined;
    const result = this.ledger.ownerApprove(entryId, textSha256);
    if (result.refusal !== undefined) return result.refusal;
    this.performLedgerResult(result);
    const entry = this.ledger.snapshot().entry;
    if (entry?.id === entryId && entry.state === "APPROVED" && !entry.started) {
      this.startInsert(entryId);
    }
    this.endStep();
    return undefined;
  }

  ownerDeny(entryId: string): HermesApprovalRefusalReason | undefined {
    if (this.stopped) return undefined;
    const result = this.ledger.ownerDeny(entryId);
    if (result.refusal !== undefined) return result.refusal;
    this.performLedgerResult(result);
    this.notifyHookWaiters();
    this.endStep();
    return undefined;
  }

  snapshot() {
    return {
      stopped: this.stopped,
      fatalBridge: this.fatalBridgeFlag,
      drained: this.drainedFlag,
      lifecycle: {
        liveCount: this.lifecycle.liveCount,
        recordCount: this.lifecycle.recordCount,
        records: this.lifecycle.recordsSnapshot(),
      },
      ledger: this.ledger.snapshot(),
      waiter: this.waiter.snapshot(),
      slot: this.slot === undefined ? undefined : {
        entryId: this.slot.entryId,
        recordId: this.slot.recordId,
        insertInFlight: this.slot.insertInFlight,
        hasDeadlineTimer: this.slot.deadlineTimer !== undefined,
        hasProbeTimer: this.slot.probeTimer !== undefined,
        durabilityPending: [...this.slot.durability].filter((audit) => audit.state === "pending").length,
        hasText: this.slot.text.length > 0,
      },
    };
  }

  private dispatchPublicFrame(frame: Extract<RelayToNodeFrame, { readonly kind: "frame" }>): void {
    const classified = classifyHermesPublicFrameSummary(publicSummary(frame.publicFrame));
    const lifecycleEvent = classified.type === "call"
      ? {
          type: "call" as const,
          connectionId: frame.connectionId,
          requestId: classified.requestId,
          kind: classified.kind,
          valid: classified.valid,
        }
      : classified.type === "cancel"
        ? { type: "cancel" as const, connectionId: frame.connectionId, mcpRequestId: classified.mcpRequestId }
        : { type: classified.type, connectionId: frame.connectionId };
    const result = this.lifecycle.apply(lifecycleEvent);
    if (this.handleLifecycleFatal(result)) return;
    this.performLifecycleActions(result.actions, frame.publicFrame);
    this.recordExits();
  }

  private applyClosed(connectionId: string): void {
    const result = this.lifecycle.apply({ type: "relay_closed", connectionId });
    if (this.handleLifecycleFatal(result)) return;
    this.performWaiterResult(this.waiter.connectionClosed(connectionId));
    this.performLifecycleActions(result.actions);
    this.recordExits();
  }

  private applyLifecycle(event: Parameters<HermesConnectionLifecycle["apply"]>[0]): void {
    const result = this.lifecycle.apply(event);
    if (this.handleLifecycleFatal(result)) return;
    this.performLifecycleActions(result.actions);
    this.recordExits();
  }

  private performLifecycleActions(actions: readonly HermesLifecycleAction[], publicFrame?: PublicFrameParseResult): void {
    for (const action of actions) {
      switch (action.type) {
        case "route_call":
          this.routeCall(action, publicFrame);
          break;
        case "deliver_control":
          this.deliverControl(action);
          break;
        case "send_fixed_denial":
          this.writeDirectResponse(action.connectionId, action.requestId, buildDeniedPublicResponseBytes(action.requestId));
          break;
        case "send_close":
          this.writeOrStop({ type: "close", connectionId: action.connectionId });
          break;
      }
    }
  }

  private routeCall(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    parsed: PublicFrameParseResult | undefined,
  ): void {
    const admission = this.callWindow.admit(this.ports.nowMs());
    if (!admission.allowed) {
      this.writeResponse(action.connectionId, action.recordId, checkedError(action.requestId, HERMES_MEMORY_DENIAL));
      this.releaseRecord(action.recordId);
      return;
    }
    const frame = parsed?.kind === "ok" ? parsed.frame : undefined;
    if (action.kind === "hello") {
      this.writeResultOrDenial(action.connectionId, action.recordId, action.requestId, buildHelloResultBytes(action.requestId));
      this.releaseRecord(action.recordId);
      return;
    }
    if (action.kind === "tools_list") {
      this.writeResultOrDenial(action.connectionId, action.recordId, action.requestId, buildToolsListResultBytes(action.requestId));
      this.releaseRecord(action.recordId);
      return;
    }
    if (frame?.kind !== "tools_call") {
      this.writeResponse(action.connectionId, action.recordId, checkedError(action.requestId, HERMES_MEMORY_DENIAL));
      this.releaseRecord(action.recordId);
      return;
    }
    switch (frame.name) {
      case "memory_get":
        this.startRead(action, () => this.ports.adapter.getPassage((frame.arguments as { readonly passage_id: string }).passage_id));
        return;
      case "memory_search":
        this.startSearch(action, frame.arguments);
        return;
      case "memory_insert":
        this.admitInsert(action, frame.arguments);
        return;
    }
  }

  private startRead(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    run: () => Promise<MemoryPassage | null>,
  ): void {
    const operation: ReadOperation = { connectionId: action.connectionId, recordId: action.recordId, requestId: action.requestId };
    run()
      .then((passage) => {
        this.writeResultOrDenial(
          operation.connectionId,
          operation.recordId,
          operation.requestId,
          buildMemoryGetResultBytes(operation.requestId, passage),
        );
      })
      .catch(() => {
        this.writeResponse(operation.connectionId, operation.recordId, checkedError(operation.requestId, HERMES_MEMORY_DENIAL));
      })
      .finally(() => {
        this.releaseRecord(operation.recordId);
        this.endStep();
      });
  }

  private startSearch(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    args: HermesMemoryToolArguments,
  ): void {
    const operation: ReadOperation = { connectionId: action.connectionId, recordId: action.recordId, requestId: action.requestId };
    const query = normalizeSearchQuery(args);
    if (query === null) {
      this.writeResponse(operation.connectionId, operation.recordId, checkedError(operation.requestId, HERMES_MEMORY_DENIAL));
      this.releaseRecord(operation.recordId);
      return;
    }
    this.ports.adapter.searchPassages(query)
      .then((results) => {
        this.writeResultOrDenial(
          operation.connectionId,
          operation.recordId,
          operation.requestId,
          buildMemorySearchResultBytes(operation.requestId, results),
        );
      })
      .catch(() => {
        this.writeResponse(operation.connectionId, operation.recordId, checkedError(operation.requestId, HERMES_MEMORY_DENIAL));
      })
      .finally(() => {
        this.releaseRecord(operation.recordId);
        this.endStep();
      });
  }

  private admitInsert(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    args: HermesMemoryToolArguments,
  ): void {
    const insert = normalizeInsertArgs(args);
    if (insert === null) {
      this.writeResponse(action.connectionId, action.recordId, checkedError(action.requestId, HERMES_MEMORY_DENIAL));
      this.releaseRecord(action.recordId);
      return;
    }
    const entryId = `hermes-entry-${this.nextEntryNumber++}`;
    const textSha256 = hermesBridgePassageTextDigest(insert.text);
    const slot: InsertSlot = {
      entryId,
      connectionId: action.connectionId,
      recordId: action.recordId,
      requestId: action.requestId,
      text: insert.text,
      textSha256,
      taint: insert.taint,
      tags: insert.tags,
      ...(insert.passageId === undefined ? {} : { passageId: insert.passageId }),
      durability: new Set(),
      verdictWaiters: new Set(),
      hookWaiters: new Set(),
      insertInFlight: false,
      hookAllowed: false,
      released: false,
    };
    const timer = this.ports.setTimer(HERMES_APPROVAL_DEADLINE_MS, () => this.fireApprovalDeadline(entryId));
    slot.deadlineTimer = timer;
    this.slot = slot;
    const admitted = this.ledger.admit(entryId, action.connectionId, action.recordId, textSha256, this.ports.nowMs());
    if (admitted.refusal !== undefined) {
      this.clearSlotTimers(slot);
      this.slot = undefined;
      const message = admitted.refusal === "latched" || admitted.refusal === "stopped"
        ? HERMES_MEMORY_UNAVAILABLE
        : HERMES_MEMORY_DENIAL;
      this.writeResponse(action.connectionId, action.recordId, checkedError(action.requestId, message));
      this.releaseRecord(action.recordId);
      return;
    }
    this.performLedgerResult(admitted);
  }

  private fireApprovalDeadline(entryId: string): void {
    const slot = this.slot;
    if (slot?.entryId !== entryId) return;
    slot.deadlineTimer = undefined;
    this.performLedgerResult(this.ledger.deadline(entryId));
    this.notifyHookWaiters();
    this.endStep();
  }

  private startInsert(entryId: string): void {
    const slot = this.slot;
    if (slot?.entryId !== entryId) return;
    const started = this.ledger.insertStarted(entryId);
    if (started.refusal !== undefined) return;
    this.performLedgerResult(started);
    slot.insertInFlight = true;
    const input: MemoryPassageInput = {
      text: slot.text,
      tags: slot.tags,
      ...(slot.passageId === undefined ? {} : { passage_id: slot.passageId }),
      provenanceContext: memoryInsertIngress(() => undefined, slot.taint),
    };
    const insertPromise = this.asyncContext.run(
      { entryId },
      () => this.ports.adapter.insertPassage(input, slot.taint),
    );
    insertPromise
      .then(() => this.finishInsert(slot, "committed"))
      .catch((error: unknown) => this.finishInsert(slot, "threw", error));
  }

  private finishInsert(slot: InsertSlot, outcome: "committed" | "threw", error?: unknown): void {
    slot.insertInFlight = false;
    if (outcome === "committed" && slot.hookAllowed) {
      this.performLedgerResult(this.ledger.writeFinished(slot.entryId, "committed"));
      if (slot.commitIds !== undefined) {
        const success = buildMemoryInsertSuccessBytes(slot.requestId, slot.commitIds);
        slot.successBytes = success.ok ? success.bytes : checkedError(slot.requestId, HERMES_MEMORY_UNAVAILABLE);
      }
    } else if (slot.hookAllowed) {
      if (isPartialScopeError(error)) this.performLedgerResult(this.ledger.latch("partial_scope"));
      this.performLedgerResult(this.ledger.writeFinished(slot.entryId, "indeterminate"));
    }
    this.performLedgerResult(this.ledger.settled(slot.entryId));
    this.endStep();
  }

  private async assertAllowedToCommit(context: HermesBridgeCommitContext): Promise<void> {
    const asyncEntry = this.asyncContext.getStore()?.entryId;
    if (asyncEntry === undefined) throw new HermesBridgeCommitRefusedError("missing bridge commit context");
    const slot = this.slot;
    if (slot?.entryId !== asyncEntry) throw new HermesBridgeCommitRefusedError("stale bridge commit context");
    slot.commitIds = { passageId: context.passageId, documentId: context.documentId };
    const probe = this.startProbeOrRefuse(slot);
    const verdict = probe === "pending" ? await this.awaitProbeVerdict(slot) : probe;
    const durable = verdict === "resolved" ? await this.awaitDurabilityForAllow(slot) : false;
    const finalVerdict: HermesApprovalProbeVerdict = durable ? verdict : "refused";
    const entry = this.ledger.snapshot().entry;
    const record = this.recordSnapshot(slot.recordId);
    const recordCurrent = entry?.id === slot.entryId && record?.state === "IN_FLIGHT";
    // No await is allowed between this record snapshot and commitCheck; queued controls must already be reflected in ledger state.
    const checked = this.ledger.commitCheck(slot.entryId, {
      probe: finalVerdict,
      nowMs: this.ports.nowMs(),
      recordCurrent,
      passageTextSha256: context.passageTextSha256,
      getFrameUtf8Bytes: context.getFrameUtf8Bytes + PUBLIC_RESULT_ENVELOPE_MAX_BYTES,
    });
    this.performLedgerResult(checked);
    if (checked.decision === "allow") {
      slot.hookAllowed = true;
      return;
    }
    throw new HermesBridgeCommitRefusedError();
  }

  private startProbeOrRefuse(slot: InsertSlot): HermesApprovalProbeVerdict | "pending" {
    const record = this.recordSnapshot(slot.recordId);
    const state = this.lifecycle.stateOf(slot.connectionId);
    const canProbe = state === "OPEN_BUSY" && record?.state === "IN_FLIGHT" && !this.lifecycle.stopped;
    if (!canProbe) return "refused";
    const result = this.waiter.start(slot.entryId, slot.connectionId);
    if (result.refusal !== undefined) return "refused";
    for (const action of result.actions) {
      if (action.kind !== "send_probe") continue;
      try {
        this.ports.writeFrame({ type: "probe", connectionId: action.connectionId, nonce: action.nonce });
      } catch {
        this.stop("write_failure");
        return "refused";
      }
      slot.probeTimer = this.ports.setTimer(PROBE_REPLY_BOUND_MS, () => {
        if (this.slot?.entryId !== slot.entryId || slot.probeTimer === undefined) return;
        slot.probeTimer = undefined;
        this.performWaiterResult(this.waiter.timeout(slot.entryId, action.nonce));
        this.endStep();
      });
    }
    return slot.verdict ?? "pending";
  }

  private awaitProbeVerdict(slot: InsertSlot): Promise<HermesApprovalProbeVerdict> {
    if (slot.verdict !== undefined) return Promise.resolve(slot.verdict);
    return new Promise((resolve) => {
      slot.verdictWaiters.add(resolve);
    });
  }

  private async awaitDurabilityForAllow(slot: InsertSlot): Promise<boolean> {
    this.addAuditDurability({ kind: "commit_intent", entryId: slot.entryId, connectionId: slot.connectionId, recordId: slot.recordId });
    for (;;) {
      if (this.shouldRefuseDurabilityWait(slot)) return false;
      const pending = [...slot.durability].filter((audit) => audit.state === "pending");
      if (pending.length === 0) return true;
      // Durability is required only for allow, so refusal state resumes this wait instead of holding the corpus lock.
      await Promise.race([
        Promise.all(pending.map((audit) => audit.promise.catch(() => undefined))),
        new Promise<void>((resolve) => slot.hookWaiters.add(resolve)),
      ]);
    }
  }

  private shouldRefuseDurabilityWait(slot: InsertSlot): boolean {
    const entry = this.ledger.snapshot().entry;
    return entry?.id !== slot.entryId ||
      entry.seen.cancel ||
      entry.seen.deadline ||
      entry.seen.deny ||
      entry.seen.gone ||
      entry.seen.stop ||
      entry.seen.latch ||
      this.ledger.snapshot().latched ||
      this.ledger.snapshot().stopped ||
      [...slot.durability].some((audit) => audit.state === "rejected");
  }

  private deliverControl(action: Extract<HermesLifecycleAction, { readonly type: "deliver_control" }>): void {
    const entry = this.ledger.snapshot().entry;
    if (entry === undefined || entry.recordId !== action.recordId) return;
    const result = action.control === "cancel"
      ? this.ledger.cancel(entry.id)
      : this.ledger.peerShutdown(entry.id);
    this.performLedgerResult(result);
    this.notifyHookWaiters();
  }

  private performLedgerResult(result: HermesApprovalLedgerResult): void {
    if (result.fatal !== undefined) {
      this.fatalBridgeFlag = true;
      this.stop("relay_fatal");
      return;
    }
    this.performLedgerActions(result.actions);
    this.reconcileEntrySlot();
  }

  private performLedgerActions(actions: readonly HermesApprovalAction[]): void {
    for (const action of actions) {
      switch (action.kind) {
        case "audit":
          this.addAuditDurability(auditRecordFromAction(action, this.slot));
          break;
        case "prompt_owner":
          this.promptOwnerLater(action.entryId);
          break;
        case "respond":
          this.respondFromLedger(action);
          break;
      }
    }
  }

  private addAuditDurability(record: HermesBridgeAuditRecord): void {
    let promise: Promise<void>;
    try {
      promise = Promise.resolve(this.ports.appendAudit(record));
    } catch (error) {
      promise = Promise.reject(error);
    }
    const audit: DurableAudit = { state: "pending", promise };
    const slot = record.entryId === this.slot?.entryId ? this.slot : undefined;
    if (slot !== undefined) slot.durability.add(audit);
    promise.then(
      () => {
        audit.state = "fulfilled";
        this.notifyHookWaiters();
      },
      () => {
        audit.state = "rejected";
        this.performLedgerResult(this.ledger.latch("audit"));
        this.notifyHookWaiters();
        this.endStep();
      },
    );
  }

  private promptOwnerLater(entryId: string): void {
    const slot = this.slot;
    if (slot?.entryId !== entryId) return;
    const summary: HermesApprovalPromptSummary = {
      entryId,
      connectionId: slot.connectionId,
      recordId: slot.recordId,
      textSha256: slot.textSha256,
      passageText: slot.text,
      ...(slot.passageId === undefined ? {} : { passageId: slot.passageId }),
      tags: slot.tags,
    };
    queueMicrotask(() => {
      try {
        this.ports.ownerSurface.promptOwner(entryId, summary);
      } catch {
        // Owner notification is bounded by the approval deadline, not by the prompt transport.
      }
    });
  }

  private respondFromLedger(action: Extract<HermesApprovalAction, { readonly kind: "respond" }>): void {
    const slot = this.slot;
    if (slot?.entryId !== action.entryId) return;
    if (action.response === "success") {
      this.writeResponse(
        slot.connectionId,
        slot.recordId,
        slot.successBytes ?? checkedError(slot.requestId, HERMES_MEMORY_UNAVAILABLE),
      );
      return;
    }
    this.writeResponse(slot.connectionId, slot.recordId, checkedError(slot.requestId, action.message));
  }

  private performWaiterResult(result: HermesProbeWaiterResult): void {
    if (result.fatal !== undefined) {
      this.fatalBridgeFlag = true;
      this.stop("relay_fatal");
      return;
    }
    for (const action of result.actions) this.performWaiterAction(action);
  }

  private performWaiterAction(action: HermesProbeWaiterAction): void {
    if (action.kind !== "resolved" && action.kind !== "refused") return;
    const slot = this.slot;
    if (slot?.entryId !== action.entryRef) return;
    if (slot.probeTimer !== undefined) {
      this.ports.clearTimer(slot.probeTimer);
      slot.probeTimer = undefined;
    }
    if (slot.verdict === undefined) {
      slot.verdict = action.kind === "resolved" ? "resolved" : "refused";
      for (const resolve of slot.verdictWaiters) resolve(slot.verdict);
      slot.verdictWaiters.clear();
    }
  }

  private recordExits(): void {
    const entry = this.ledger.snapshot().entry;
    if (entry === undefined) return;
    const record = this.recordSnapshot(entry.recordId);
    if (record?.state === "CLOSED_BY_NODE" || record?.state === "CONNECTION_GONE") {
      this.performLedgerResult(this.ledger.connectionGone(entry.id));
      this.notifyHookWaiters();
    } else if (record?.state === "SHUT_DOWN") {
      this.performLedgerResult(this.ledger.stop());
      this.notifyHookWaiters();
    }
  }

  private stop(_cause: HermesBridgeStopCause): void {
    if (this.stopped) return;
    this.stopped = true;
    const lifecycleResult = this.lifecycle.apply({ type: "relay_shutdown_or_eof" });
    this.performWaiterResult(this.waiter.stop());
    this.ports.abort.abort();
    this.recordExits();
    this.performLifecycleActions(lifecycleResult.actions);
    this.notifyHookWaiters();
    this.reconcileEntrySlot();
  }

  private handleLifecycleFatal(result: HermesLifecycleResult): boolean {
    if (result.fatal === undefined) return false;
    this.fatalBridgeFlag = true;
    this.stop("relay_fatal");
    return true;
  }

  private writeResultOrDenial(
    connectionId: string,
    recordId: string,
    requestId: string,
    result: HermesPublicResultBuild,
  ): void {
    this.writeResponse(connectionId, recordId, result.ok ? result.bytes : checkedError(requestId, HERMES_MEMORY_DENIAL));
  }

  private writeResponse(connectionId: string, recordId: string, publicPayloadBytes: Uint8Array): void {
    const record = this.recordSnapshot(recordId);
    const result = this.lifecycle.apply({ type: "node_response_written", connectionId, recordId });
    if (this.handleLifecycleFatal(result)) return;
    if (result.refusal === undefined && record?.requestId !== undefined) {
      this.writeOrStop({ type: "response", connectionId, requestId: record.requestId, publicPayloadBytes });
    }
    this.recordExits();
  }

  private writeDirectResponse(connectionId: string, requestId: string, publicPayloadBytes: Uint8Array): void {
    this.writeOrStop({ type: "response", connectionId, requestId, publicPayloadBytes });
  }

  private writeOrStop(input: NodeToRelayInput): void {
    try {
      this.ports.writeFrame(input);
    } catch {
      this.stop("write_failure");
    }
  }

  private releaseRecord(recordId: string): void {
    const result = this.lifecycle.release(recordId);
    for (const action of result.actions) {
      if (action.type === "send_fixed_denial") {
        this.writeDirectResponse(action.connectionId, action.requestId, buildDeniedPublicResponseBytes(action.requestId));
      }
    }
  }

  private reconcileEntrySlot(): void {
    const slot = this.slot;
    if (slot === undefined) return;
    const liveEntryId = this.ledger.snapshot().entry?.id;
    if (liveEntryId === slot.entryId || slot.insertInFlight) return;
    this.clearSlotTimers(slot);
    slot.durability.clear();
    if (!slot.released) {
      slot.released = true;
      this.releaseRecord(slot.recordId);
    }
    this.slot = undefined;
    this.maybeQueueDrained();
  }

  private clearSlotTimers(slot: InsertSlot): void {
    if (slot.deadlineTimer !== undefined) {
      this.ports.clearTimer(slot.deadlineTimer);
      slot.deadlineTimer = undefined;
    }
    if (slot.probeTimer !== undefined) {
      this.ports.clearTimer(slot.probeTimer);
      slot.probeTimer = undefined;
    }
  }

  private notifyHookWaiters(): void {
    const slot = this.slot;
    if (slot === undefined) return;
    for (const notify of slot.hookWaiters) notify();
    slot.hookWaiters.clear();
  }

  private recordSnapshot(recordId: string): HermesCallRecordSnapshot | undefined {
    return this.lifecycle.recordsSnapshot().find((record) => record.id === recordId);
  }

  private endStep(): void {
    this.reconcileEntrySlot();
    this.maybeQueueDrained();
  }

  private maybeQueueDrained(): void {
    if (!this.stopped || this.drainedFlag || this.drainQueued) return;
    if (this.ledger.snapshot().entry !== undefined || this.slot?.insertInFlight === true) return;
    this.drainQueued = true;
    queueMicrotask(() => {
      this.drainQueued = false;
      if (this.drainedFlag || this.ledger.snapshot().entry !== undefined || this.slot?.insertInFlight === true) return;
      this.drainedFlag = true;
      for (const listener of this.drainedListeners) listener({ fatalBridge: this.fatalBridgeFlag });
    });
  }
}

function publicSummary(result: PublicFrameParseResult): HermesPublicFrameSummary {
  if (result.kind === "ok") {
    const frame = result.frame;
    switch (frame.kind) {
      case "hello":
      case "tools_list":
        return { topLevelType: frame.kind, requestId: frame.requestId, strictValid: true };
      case "tools_call":
        return { topLevelType: "tools_call", requestId: frame.requestId, strictValid: true };
      case "cancel":
        return { topLevelType: "cancel", mcpRequestId: frame.mcpRequestId, strictValid: true };
      case "shutdown":
        return { topLevelType: "shutdown", strictValid: true };
    }
  }
  if (
    result.frameType === "hello" ||
    result.frameType === "tools_list" ||
    result.frameType === "tools_call"
  ) {
    return { topLevelType: result.frameType, requestId: result.requestId, strictValid: false };
  }
  return { topLevelType: result.frameType, strictValid: false };
}

function normalizeInsertArgs(args: HermesMemoryToolArguments): {
  readonly text: string;
  readonly taint: PersistableTaint;
  readonly tags: readonly string[];
  readonly passageId?: string;
} | null {
  if (!("text" in args) || !("taint" in args)) return null;
  if (args.text.length === 0 || !isTaint(args.taint)) return null;
  if (args.tags !== undefined && !args.tags.every((tag) => isSdwIdentifier(tag))) return null;
  if (args.passage_id !== undefined && !isSdwIdentifier(args.passage_id)) return null;
  return {
    text: args.text,
    taint: args.taint,
    tags: args.tags ?? [],
    ...(args.passage_id === undefined ? {} : { passageId: args.passage_id }),
  };
}

function normalizeSearchQuery(args: HermesMemoryToolArguments): MemorySearchQuery | null {
  const text = "text" in args && typeof args.text === "string"
    ? args.text
    : "query" in args && typeof args.query === "string"
      ? args.query
      : undefined;
  if (text === undefined || text.length === 0) return null;
  if ("tag" in args && args.tag !== undefined && !isSdwIdentifier(args.tag)) return null;
  if ("limit" in args && args.limit !== undefined && (!Number.isSafeInteger(args.limit) || args.limit < 1)) return null;
  return {
    text,
    ...("tag" in args && args.tag !== undefined ? { tag: args.tag } : {}),
    ...("limit" in args && args.limit !== undefined ? { limit: args.limit } : {}),
  };
}

function isTaint(value: string): value is PersistableTaint {
  return value === "user_content" || value === "agent_derived_clean" || value === "system_generated";
}

function auditRecordFromAction(action: Extract<HermesApprovalAction, { readonly kind: "audit" }>, slot: InsertSlot | undefined): HermesBridgeAuditRecord {
  return {
    kind: action.event,
    entryId: action.entryId,
    connectionId: slot?.entryId === action.entryId ? slot.connectionId : undefined,
    recordId: slot?.entryId === action.entryId ? slot.recordId : undefined,
    state: action.state,
    reason: action.reason,
    textSha256: slot?.entryId === action.entryId ? slot.textSha256 : undefined,
    lateEvents: action.lateEvents,
  };
}

function isPartialScopeError(error: unknown): boolean {
  return error instanceof SdwValidationError && error.category === "partial_scope";
}
