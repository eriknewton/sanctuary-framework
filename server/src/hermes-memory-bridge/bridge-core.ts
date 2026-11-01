// must match OWN_SCOPE_MEMORY_SAVES in server/src/principal-policy/gate.ts.
import { OWN_SCOPE_MEMORY_SAVES } from "../principal-policy/gate.js";
import { HermesRecallBudget, type HermesRecallResult } from "./recall.js";
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
  HERMES_INSERT_DEADLINE_MS,
  HermesAuditBackpressureError,
  MAX_RESULT_FRAME_BYTES,
  HERMES_MAX_CALLS_PER_MINUTE,
  HERMES_MEMORY_DENIAL,
  HERMES_RATE_WINDOW_MS,
  PROBE_REPLY_BOUND_MS,
} from "./constants.js";
import {
  HermesApprovalLedger,
  type HermesApprovalAction,
  type HermesApprovalLedgerResult,
  type HermesApprovalProbeVerdict,
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
  buildToolOutcomeBytes,
  buildMemoryRecallResultBytes,
  buildMemoryGetResultBytes,
  buildMemoryInsertSuccessBytes,
  buildMemorySearchResultBytes,
  buildToolsListResultBytes,
  checkedError,
  type HermesPublicResultBuild,
} from "./public-results.js";

export type HermesTimerHandle = object;

// The bridge pins the class because the client is the untrusted agent; the client taint field is validated at the wire and never forwarded to the adapter.
const BRIDGE_PINNED_MEMORY_TAINT: PersistableTaint = "user_content";
const TIMER_CLEAR_STOP_RETRY_ATTEMPTS = 2; // Two stop-path retries cover the cleanup pass and one retained-handle confirmation after the first clear failure.

export interface HermesBridgeAuditRecord {
  readonly kind: "insert_admitted" | "insert_unconfirmed" | "memory_recall" | "latch";
  readonly entryId?: string;
  readonly operation?: string;
  readonly tier?: number;
  readonly agent_id?: string;
  readonly requester_verified?: false;
  readonly passage_id?: string;
  readonly document_id?: string;
  readonly text_sha256?: string;
  readonly bytes?: number;
  readonly term_count?: number;
  readonly passage_ids?: readonly string[];
  readonly query_sha256?: string;
  readonly truncated?: boolean;
  readonly reason?: string;
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
  readonly adapter: Pick<HermesBridgeMemoryAdapter, "insertPassage" | "getPassage" | "searchPassages" | "recallPassages">;
  readonly agentId: string;
  readonly abort: AbortController;
}

export interface HermesBridgeMemoryAdapter {
  insertPassage(input: MemoryPassageInput, taint: PersistableTaint): Promise<MemoryPassage>;
  getPassage(passageId: string): Promise<MemoryPassage | null>;
  searchPassages(query: MemorySearchQuery): Promise<readonly MemorySearchResult[]>;
  recallPassages(budget: HermesRecallBudget): Promise<HermesRecallResult>;
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
  unconfirmedAudited: boolean;
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
 * probe-waiter, approval-ledger and storage commit hook; it performs no fd,
 * child-process, startup, policy-gate or durable storage work itself.
 *
 * The bridge core calls the memory adapter directly rather than the router or
 * CallToolRequestSchema path, so each tool has a local argument allowlist here.
 * Continuing path: a read still quarantining at stop can leave a batch lock
 * marker; the later bridge shell refuses readiness on that leftover marker.
 * Storage residuals: kernel-backed locks are unreachable here, document-lock
 * contention can only come from same-document quarantine, the hook keys on
 * allow rather than backend error type, metadata abort cannot happen after lock
 * acquisition, and the later shell builds exactly one bridge adapter.
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
  private stopCause: HermesBridgeStopCause | undefined;
  private fatalBridgeFlag = false;
  private drainedFlag = false;
  private drainQueued = false;

  constructor(private readonly ports: HermesBridgeCorePorts) {
    if (ports.abort === undefined || ports.adapter === undefined || !ports.agentId) {
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

  snapshot() {
    return {
      stopped: this.stopped,
      stopCause: this.stopCause,
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
          toolName: classified.toolName,
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
          this.writeDirectResponse(action.connectionId, action.requestId, this.lifecycleRefusalBytes(action));
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
    const nowMs = this.nowMsOrStop();
    if (nowMs === undefined) {
      this.releaseRecord(action.recordId);
      return;
    }
    const admission = this.callWindow.admit(nowMs);
    if (!admission.allowed) {
      this.writeResponse(action.connectionId, action.recordId, action.kind === "tools_call"
        ? buildToolOutcomeBytes(action.requestId, "denied") : checkedError(action.requestId, HERMES_MEMORY_DENIAL));
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
      this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "denied"));
      this.releaseRecord(action.recordId);
      return;
    }
    switch (frame.name) {
      case "sign_statement":
      case "export_memory":
      case "protection_rules":
        // No hold protocol is reachable from this slice; a later reviewed slice owns signing and export.
        this.writeResponse(action.connectionId, action.recordId,
          buildToolOutcomeBytes(action.requestId, frame.name === "protection_rules" ? "denied" : "unavailable_not_built"));
        this.releaseRecord(action.recordId);
        return;
      case "memory_recall":
        this.startRecall(action, frame.arguments);
        return;
      case "memory_get":
        this.startGet(action, frame.arguments);
        return;
      case "memory_search":
        this.startSearch(action, frame.arguments);
        return;
      case "memory_insert":
        this.admitInsert(action, frame.arguments);
        return;
      default:
        frame.name satisfies never;
        this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "denied"));
        this.releaseRecord(action.recordId);
        return;
    }
  }

  private startGet(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    args: HermesMemoryToolArguments,
  ): void {
    const passageId = normalizeGetArgs(args);
    if (passageId === null) {
      this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "denied"));
      this.releaseRecord(action.recordId);
      return;
    }
    this.startRead(action, () => this.ports.adapter.getPassage(passageId));
  }

  private startRead(
    action: Extract<HermesLifecycleAction, { readonly type: "route_call" }>,
    run: () => Promise<MemoryPassage | null>,
  ): void {
    const operation: ReadOperation = { connectionId: action.connectionId, recordId: action.recordId, requestId: action.requestId };
    let readPromise: Promise<MemoryPassage | null>;
    try {
      readPromise = run();
    } catch {
      this.writeResponse(operation.connectionId, operation.recordId, buildToolOutcomeBytes(operation.requestId, "denied"));
      this.releaseRecord(operation.recordId);
      this.endStep();
      return;
    }
    readPromise
      .then((passage) => {
        this.writeResultOrDenial(
          operation.connectionId,
          operation.recordId,
          operation.requestId,
          buildMemoryGetResultBytes(operation.requestId, passage),
        );
      })
      .catch(() => {
        this.writeResponse(operation.connectionId, operation.recordId, buildToolOutcomeBytes(operation.requestId, "denied"));
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
      this.writeResponse(operation.connectionId, operation.recordId, buildToolOutcomeBytes(operation.requestId, "denied"));
      this.releaseRecord(operation.recordId);
      return;
    }
    let searchPromise: Promise<readonly MemorySearchResult[]>;
    try {
      searchPromise = this.ports.adapter.searchPassages(query);
    } catch {
      this.writeResponse(operation.connectionId, operation.recordId, buildToolOutcomeBytes(operation.requestId, "denied"));
      this.releaseRecord(operation.recordId);
      this.endStep();
      return;
    }
    searchPromise
      .then((results) => {
        this.writeResultOrDenial(
          operation.connectionId,
          operation.recordId,
          operation.requestId,
          buildMemorySearchResultBytes(operation.requestId, results),
        );
      })
      .catch(() => {
        this.writeResponse(operation.connectionId, operation.recordId, buildToolOutcomeBytes(operation.requestId, "denied"));
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
      this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "denied"));
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
      tags: insert.tags,
      ...(insert.passageId === undefined ? {} : { passageId: insert.passageId }),
      durability: new Set(),
      verdictWaiters: new Set(),
      hookWaiters: new Set(),
      insertInFlight: false,
      hookAllowed: false,
      unconfirmedAudited: false,
      released: false,
    };
    const nowMs = this.nowMsOrStop();
    if (nowMs === undefined) {
      this.releaseRecord(action.recordId);
      return;
    }
    const admitted = this.ledger.admit(entryId, action.connectionId, action.recordId, textSha256, nowMs);
    if (admitted.refusal !== undefined) {
      this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "unavailable"));
      this.releaseRecord(action.recordId);
      return;
    }
    this.slot = slot;
    this.performLedgerResult(admitted);
    const timer = this.setTimerOrStop(HERMES_INSERT_DEADLINE_MS, () => this.fireInsertDeadline(entryId));
    if (timer === undefined) return;
    slot.deadlineTimer = timer;
    this.startInsert(entryId);
  }

  private fireInsertDeadline(entryId: string): void {
    const slot = this.slot;
    if (slot?.entryId !== entryId) return;
    slot.deadlineTimer = undefined;
    this.performLedgerResult(this.ledger.deadline(entryId));
    this.refuseLiveProbe(entryId);
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
      provenanceContext: memoryInsertIngress(() => undefined, BRIDGE_PINNED_MEMORY_TAINT),
    };
    let insertPromise: Promise<MemoryPassage>;
    try {
      insertPromise = this.asyncContext.run(
        { entryId },
        () => this.ports.adapter.insertPassage(input, BRIDGE_PINNED_MEMORY_TAINT),
      );
    } catch (error) {
      this.stop("write_failure");
      this.finishInsert(slot, "threw", error);
      return;
    }
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
        slot.successBytes = success.ok ? success.bytes : buildToolOutcomeBytes(slot.requestId, slot.hookAllowed ? "unconfirmed" : "unavailable");
      }
    } else if (slot.hookAllowed) {
      this.auditUnconfirmed(slot);
      // Every throw after allow is indeterminate; this core never reports the storage layer's failed outcome.
      if (isPartialScopeError(error)) this.latch("partial_scope");
      this.latch("indeterminate");
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
    // Live call, no partial-scope latch, then durable admission: none of these checks may follow a chunk write.
    if (verdict === "resolved" && !this.shouldRefuseDurabilityWait(slot)) {
      const beforeAppend = this.nowMsOrStop();
      const entry = this.ledger.snapshot().entry;
      if (beforeAppend !== undefined && entry !== undefined && beforeAppend < entry.deadlineAt &&
          this.recordSnapshot(slot.recordId)?.state === "IN_FLIGHT" &&
          context.passageTextSha256 === slot.textSha256 &&
          context.getFrameUtf8Bytes + PUBLIC_RESULT_ENVELOPE_MAX_BYTES <= MAX_RESULT_FRAME_BYTES) {
        // The fortress is single-owner (ownerRef = HERMES_MEMORY_AGENT_ID); every insert saves into the agent's own memory.
        // An own-scope save never waits for a human, per the operator's 10-29 decision carried by M1.
        this.addAuditDurability({ kind: "insert_admitted", entryId: slot.entryId,
          operation: OWN_SCOPE_MEMORY_SAVES.memory_insert, tier: 3, // Tier 3 is M1's own-scope save tier.
          ...this.auditPrincipal(), passage_id: context.passageId, document_id: context.documentId,
          text_sha256: context.passageTextSha256, bytes: context.passageTextUtf8.byteLength });
        await this.awaitDurabilityForAllow(slot);
      }
    }
    const entry = this.ledger.snapshot().entry;
    const record = this.recordSnapshot(slot.recordId);
    // A bridge stop exits the lifecycle record, so the commit check records connection_gone rather than trusting a stale row.
    const recordCurrent = entry?.id === slot.entryId && record?.state === "IN_FLIGHT";
    // No await is allowed between this record snapshot and commitCheck; queued controls must already be reflected in ledger state.
    const nowMs = this.nowMsOrStop();
    if (nowMs === undefined) throw new HermesBridgeCommitRefusedError();
    const checked = this.ledger.commitCheck(slot.entryId, {
      probe: verdict,
      admitDurable: slot.durability.size === 1 && [...slot.durability].every(audit => audit.state === "fulfilled"),
      nowMs,
      recordCurrent,
      passageTextSha256: context.passageTextSha256,
      getFrameUtf8Bytes: context.getFrameUtf8Bytes + PUBLIC_RESULT_ENVELOPE_MAX_BYTES,
    });
    this.performLedgerResult(checked);
    if (checked.decision === "allow" && slot.durability.size === 1 && [...slot.durability].every(audit => audit.state === "fulfilled")) {
      slot.hookAllowed = true;
      return;
    }
    throw new HermesBridgeCommitRefusedError();
  }

  private startProbeOrRefuse(slot: InsertSlot): HermesApprovalProbeVerdict | "pending" {
    if (this.shouldRefuseDurabilityWait(slot)) return "refused";
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
      const probeTimer = this.setTimerOrStop(PROBE_REPLY_BOUND_MS, () => {
        if (this.slot?.entryId !== slot.entryId || slot.probeTimer === undefined) return;
        slot.probeTimer = undefined;
        this.performWaiterResult(this.waiter.timeout(slot.entryId, action.nonce));
        this.endStep();
      });
      if (probeTimer === undefined) return "refused";
      slot.probeTimer = probeTimer;
    }
    return slot.verdict ?? "pending";
  }

  private refuseLiveProbe(entryId: string): void {
    const live = this.waiter.snapshot().live;
    if (live?.entryRef === entryId) this.performWaiterResult(this.waiter.timeout(entryId, live.nonce));
  }

  private awaitProbeVerdict(slot: InsertSlot): Promise<HermesApprovalProbeVerdict> {
    if (slot.verdict !== undefined) return Promise.resolve(slot.verdict);
    return new Promise((resolve) => {
      slot.verdictWaiters.add(resolve);
    });
  }

  private async awaitDurabilityForAllow(slot: InsertSlot): Promise<boolean> {
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
    // The commit decision must see a client's shutdown as a refusal flag, because the lifecycle keeps the record IN_FLIGHT until closed.
    const result = action.control === "shutdown"
      ? this.ledger.peerShutdown(entry.id)
      : this.ledger.cancel(entry.id);
    this.performLedgerResult(result);
    this.refuseLiveProbe(entry.id);
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
      this.respondFromLedger(action);
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
      (reason: unknown) => {
        audit.state = "rejected";
        // Backpressure refuses before effect; it is capacity exhaustion, not a failed durable audit append, so it does not latch.
        if (!(reason instanceof HermesAuditBackpressureError)) this.latch("audit");
        this.notifyHookWaiters();
        this.endStep();
      },
    );
  }

  private auditUnconfirmed(slot: InsertSlot): void {
    if (slot.unconfirmedAudited) return;
    slot.unconfirmedAudited = true;
    this.addAuditDurability({ kind: "insert_unconfirmed", entryId: slot.entryId,
      passage_id: slot.commitIds?.passageId, ...this.auditPrincipal() });
  }

  private auditPrincipal(): { agent_id: string; requester_verified: false } {
    return {
      // Must match the agent: form of callerIdentity in server/src/router.ts.
      agent_id: `agent:${this.ports.agentId}`,
      // The agent id is relay-pinned and uid-checked; the calling process, session and turn are not verified.
      requester_verified: false,
    };
  }

  private latch(reason: string): void {
    if (this.ledger.snapshot().latched) return;
    this.performLedgerResult(this.ledger.latch(reason));
    this.addAuditDurability({ kind: "latch", reason });
  }

  private startRecall(action: Extract<HermesLifecycleAction, { type: "route_call" }>, args: HermesMemoryToolArguments): void {
    if (!("query" in args) || typeof args.query !== "string") {
      this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "denied"));
      this.releaseRecord(action.recordId);
      return;
    }
    const query = args.query;
    const budget = new HermesRecallBudget(query, this.ports.nowMs, this.ports.abort.signal);
    void (async () => {
      let appendingAudit = false;
      try {
        const result = budget.terms.length === 0 ? budget.result() : await this.ports.adapter.recallPassages(budget);
        appendingAudit = true;
        await this.ports.appendAudit({ kind: "memory_recall", term_count: budget.terms.length,
          passage_ids: result.passages.map(p => p.passage_id), query_sha256: hermesBridgePassageTextDigest(query),
          truncated: result.truncated, ...this.auditPrincipal() });
        this.writeResultOrDenial(action.connectionId, action.recordId, action.requestId, buildMemoryRecallResultBytes(action.requestId, result));
      } catch (reason) {
        // Backpressure is a capacity refusal and must not disable future admission.
        if (appendingAudit && !(reason instanceof HermesAuditBackpressureError)) this.latch("audit");
        this.writeResponse(action.connectionId, action.recordId, buildToolOutcomeBytes(action.requestId, "unavailable"));
      } finally {
        this.releaseRecord(action.recordId);
        this.endStep();
      }
    })();
  }

  private lifecycleRefusalBytes(action: Extract<HermesLifecycleAction, { type: "send_fixed_denial" }>): Uint8Array {
    if (action.toolName !== undefined) {
      // Only the record owning the allowed insert can have an unconfirmed write; another call cannot inherit its outcome.
      return buildToolOutcomeBytes(action.requestId, action.responseClass === "release" && this.slot?.recordId === action.recordId && this.slot.hookAllowed
        ? "unconfirmed" : action.responseClass === "release" || action.capacity ? "unavailable" : "denied");
    }
    // A non-catalogued name or hello/list fault is a protocol fault, not a tool refusal.
    return buildDeniedPublicResponseBytes(action.requestId);
  }

  private respondFromLedger(action: Extract<HermesApprovalAction, { readonly kind: "respond" }>): void {
    const slot = this.slot;
    if (slot?.entryId !== action.entryId) return;
    if (action.response === "success") {
      this.writeResponse(
        slot.connectionId,
        slot.recordId,
        slot.successBytes ?? buildToolOutcomeBytes(slot.requestId, slot.hookAllowed ? "unconfirmed" : "unavailable"),
      );
      return;
    }
    this.writeResponse(slot.connectionId, slot.recordId, buildToolOutcomeBytes(slot.requestId, slot.hookAllowed ? "unconfirmed" : "unavailable"));
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
      this.clearSlotTimer(slot, "probeTimer");
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
    this.stopCause = _cause;
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
    this.writeResponse(connectionId, recordId, result.ok ? result.bytes : buildToolOutcomeBytes(requestId, "denied"));
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
    if (this.slot?.recordId === recordId && this.slot.hookAllowed && result.actions.some(action => action.type === "send_fixed_denial")) {
      this.auditUnconfirmed(this.slot);
    }
    for (const action of result.actions) {
      if (action.type === "send_fixed_denial") {
        this.writeDirectResponse(action.connectionId, action.requestId, this.lifecycleRefusalBytes(action));
      }
    }
  }

  private reconcileEntrySlot(): void {
    const slot = this.slot;
    if (slot === undefined) return;
    const liveEntryId = this.ledger.snapshot().entry?.id;
    if (liveEntryId === slot.entryId || slot.insertInFlight) return;
    const timersCleared = this.clearSlotTimers(slot);
    slot.durability.clear();
    if (!slot.released) {
      slot.released = true;
      this.releaseRecord(slot.recordId);
    }
    if (!timersCleared) {
      this.maybeQueueDrained();
      return;
    }
    this.slot = undefined;
    this.maybeQueueDrained();
  }

  private clearSlotTimers(slot: InsertSlot): boolean {
    let cleared = true;
    if (slot.deadlineTimer !== undefined) {
      cleared = this.clearSlotTimer(slot, "deadlineTimer") && cleared;
    }
    if (slot.probeTimer !== undefined) {
      cleared = this.clearSlotTimer(slot, "probeTimer") && cleared;
    }
    return cleared;
  }

  private nowMsOrStop(): number | undefined {
    try {
      return this.ports.nowMs();
    } catch {
      this.stop("write_failure");
      this.endStep();
      return undefined;
    }
  }

  private setTimerOrStop(ms: number, fire: () => void): HermesTimerHandle | undefined {
    try {
      return this.ports.setTimer(ms, fire);
    } catch {
      this.stop("write_failure");
      this.endStep();
      return undefined;
    }
  }

  private clearSlotTimer(slot: InsertSlot, key: "deadlineTimer" | "probeTimer"): boolean {
    const handle = slot[key];
    if (handle === undefined) return true;
    const attempts = this.stopped ? TIMER_CLEAR_STOP_RETRY_ATTEMPTS : 1;
    for (let attempt = 0; attempt < attempts; attempt += 1) {
      try {
        this.ports.clearTimer(handle);
        slot[key] = undefined;
        return true;
      } catch {
        if (!this.stopped) {
          this.stop("write_failure");
          this.endStep();
          return slot[key] === undefined;
        }
      }
    }
    return false;
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
    if (this.ledger.snapshot().entry !== undefined || this.slot !== undefined) return;
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
        return { topLevelType: "tools_call", requestId: frame.requestId, strictValid: true, toolName: frame.name };
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
    return { topLevelType: result.frameType, requestId: result.requestId, strictValid: false, toolName: result.toolName };
  }
  return { topLevelType: result.frameType, strictValid: false };
}

function normalizeInsertArgs(args: HermesMemoryToolArguments): {
  readonly text: string;
  readonly tags: readonly string[];
  readonly passageId?: string;
} | null {
  if (!("text" in args) || !("taint" in args)) return null;
  if (args.text.length === 0 || !isTaint(args.taint)) return null;
  if (args.tags !== undefined && !args.tags.every((tag) => isSdwIdentifier(tag))) return null;
  if (args.passage_id !== undefined && !isSdwIdentifier(args.passage_id)) return null;
  return {
    text: args.text,
    tags: args.tags ?? [],
    ...(args.passage_id === undefined ? {} : { passageId: args.passage_id }),
  };
}

function normalizeGetArgs(args: HermesMemoryToolArguments): string | null {
  if (!("passage_id" in args) || typeof args.passage_id !== "string") return null;
  return isSdwIdentifier(args.passage_id) ? args.passage_id : null;
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

function isPartialScopeError(error: unknown): boolean {
  return error instanceof SdwValidationError && error.category === "partial_scope";
}
