export const HERMES_MEMORY_DENIAL_MESSAGE = "Memory request denied.";

// must match MAX_PUBLIC_CONNECTIONS in hermes-memory-relay/SEAM.md.
export const HERMES_MAX_PUBLIC_CONNECTIONS = 4;
// 4 = the settling reserve paired with the four relay-admitted public slots; no separate settling ceiling is enforced.
export const HERMES_SETTLING_RESERVE = HERMES_MAX_PUBLIC_CONNECTIONS;
// 8 = the single total cap enforced at call admission: four live slots plus the settling reserve of four.
export const HERMES_MAX_CALL_RECORDS = HERMES_MAX_PUBLIC_CONNECTIONS + HERMES_SETTLING_RESERVE;

export type HermesConnectionState =
  | "UNKNOWN"
  | "OPEN_IDLE"
  | "OPEN_BUSY"
  | "OPEN_IDLE_PEER_SHUTTING"
  | "OPEN_BUSY_PEER_SHUTTING"
  | "NODE_CLOSED";

export type HermesCallKind = "hello" | "tools_list" | "tools_call";
export type HermesControlKind = "cancel" | "shutdown";
export type HermesCallRecordState =
  | "IN_FLIGHT"
  | "RESPONDED"
  | "CLOSED_BY_NODE"
  | "CONNECTION_GONE"
  | "SHUT_DOWN";

export type HermesNodeCloseReason = "unparseable_call" | "private_cap_overflow";

export type HermesLifecycleEvent =
  | { type: "accepted"; connectionId: string }
  | { type: "call"; connectionId: string; requestId: string; kind: HermesCallKind; valid: boolean }
  | { type: "cancel"; connectionId: string; mcpRequestId: string }
  | { type: "public_shutdown"; connectionId: string }
  | { type: "public_unparseable"; connectionId: string }
  | { type: "control_invalid"; connectionId: string }
  | { type: "relay_closed"; connectionId: string }
  | { type: "node_response_written"; connectionId: string; recordId: string }
  | { type: "node_close"; connectionId: string; reason: HermesNodeCloseReason }
  | { type: "relay_shutdown_or_eof" };

/**
 * Actions are authorized only by the apply or release step that emitted them; callers write every emitted action in order and never re-check it against later state.
 */
export type HermesLifecycleAction =
  | { type: "send_close"; connectionId: string }
  | {
      type: "route_call";
      connectionId: string;
      recordId: string;
      requestId: string;
      kind: HermesCallKind;
    }
  | {
      type: "deliver_control";
      connectionId: string;
      recordId: string;
      requestId: string;
      control: HermesControlKind;
    }
  | {
      type: "send_fixed_denial";
      connectionId: string;
      recordId: string;
      requestId: string;
      message: typeof HERMES_MEMORY_DENIAL_MESSAGE;
      responseClass: "immediate" | "release";
    };

export type HermesFatalReason =
  | "too_many_live"
  | "unknown_connection"
  | "unknown"
  | "closed_for_unknown_or_duplicate"
  | "duplicate_accepted"
  | "second_call_forwarded"
  | "event_after_peer_shutdown";

export type HermesRefusalReason =
  | "call_record_capacity"
  | "call_validation_failed"
  | "no_current_record"
  | "record_not_current";

export interface HermesLifecycleResult {
  readonly actions: readonly HermesLifecycleAction[];
  readonly fatal?: { readonly connectionId: string; readonly reason: HermesFatalReason };
  readonly refusal?: { readonly connectionId: string; readonly reason: HermesRefusalReason };
}

export interface HermesReleaseResult {
  readonly actions: readonly HermesLifecycleAction[];
  readonly released: boolean;
}

export interface HermesCallRecordSnapshot {
  readonly id: string;
  readonly connectionId: string;
  readonly requestId: string;
  readonly kind: HermesCallKind;
  readonly state: HermesCallRecordState;
  readonly pendingCancel: boolean;
  readonly pendingShutdown: boolean;
}

export interface HermesPublicFrameSummary {
  readonly topLevelType?: string;
  readonly requestId?: string;
  readonly mcpRequestId?: string;
  readonly strictValid: boolean;
}

export type HermesClassifiedPublicFrame =
  | { type: "call"; requestId: string; kind: HermesCallKind; valid: boolean }
  | { type: "cancel"; mcpRequestId: string }
  | { type: "public_shutdown" }
  | { type: "public_unparseable" }
  | { type: "control_invalid" };

interface ConnectionRow {
  state: Exclude<HermesConnectionState, "UNKNOWN">;
  currentRecordId?: string;
}

interface CallRecord {
  id: string;
  connectionId: string;
  requestId: string;
  kind: HermesCallKind;
  state: HermesCallRecordState;
  pendingCancel: boolean;
  pendingShutdown: boolean;
}

const CALL_KINDS = new Set<string>(["hello", "tools_list", "tools_call"]);

export function classifyHermesPublicFrameSummary(summary: HermesPublicFrameSummary): HermesClassifiedPublicFrame {
  if (CALL_KINDS.has(summary.topLevelType ?? "") && summary.requestId !== undefined) {
    return {
      type: "call",
      requestId: summary.requestId,
      kind: summary.topLevelType as HermesCallKind,
      valid: summary.strictValid,
    };
  }
  if (summary.topLevelType === "cancel") {
    // Invalid control frames send nothing because the relay seam reserves fixed denials for recoverable calls.
    return summary.strictValid && summary.mcpRequestId !== undefined
      ? { type: "cancel", mcpRequestId: summary.mcpRequestId }
      : { type: "control_invalid" };
  }
  if (summary.topLevelType === "shutdown") {
    return summary.strictValid ? { type: "public_shutdown" } : { type: "control_invalid" };
  }
  return { type: "public_unparseable" };
}

export class HermesConnectionLifecycle {
  private readonly rows = new Map<string, ConnectionRow>();
  private readonly records = new Map<string, CallRecord>();
  private nextRecordNumber = 1;
  private stoppedFlag = false;

  get stopped(): boolean {
    return this.stoppedFlag;
  }

  get liveCount(): number {
    return this.rows.size;
  }

  get recordCount(): number {
    return this.records.size;
  }

  stateOf(connectionId: string): HermesConnectionState {
    return this.rows.get(connectionId)?.state ?? "UNKNOWN";
  }

  recordsSnapshot(): HermesCallRecordSnapshot[] {
    return [...this.records.values()].map((record) => ({ ...record }));
  }

  apply(event: HermesLifecycleEvent): HermesLifecycleResult {
    if (event.type === "relay_shutdown_or_eof") {
      return this.applyRelayShutdownOrEof();
    }
    // The stopped gate is the per-connection lifecycle boundary: after relay shutdown no later row event emits Node output.
    if (this.stoppedFlag) return { actions: [] };

    const state = this.stateOf(event.connectionId);
    switch (state) {
      case "UNKNOWN":
        return this.state_UNKNOWN(event);
      case "OPEN_IDLE":
        return this.state_OPEN_IDLE(event);
      case "OPEN_BUSY":
        return this.state_OPEN_BUSY(event);
      case "OPEN_IDLE_PEER_SHUTTING":
        return this.state_OPEN_IDLE_PEER_SHUTTING(event);
      case "OPEN_BUSY_PEER_SHUTTING":
        return this.state_OPEN_BUSY_PEER_SHUTTING(event);
      case "NODE_CLOSED":
        return this.state_NODE_CLOSED(event);
    }
  }

  release(recordId: string): HermesReleaseResult {
    const record = this.records.get(recordId);
    if (record === undefined) return { actions: [], released: false };
    const row = this.rows.get(record.connectionId);
    const actions: HermesLifecycleAction[] = [];
    if (record.state === "IN_FLIGHT" && this.isBusyState(row?.state) && row?.currentRecordId === recordId) {
      // Release cannot go silent: a current call that settles without a built response still owes the fixed denial.
      actions.push(this.fixedDenialAction(record, "release"));
      row.state = row.state === "OPEN_BUSY_PEER_SHUTTING" ? "OPEN_IDLE_PEER_SHUTTING" : "OPEN_IDLE";
      delete row.currentRecordId;
    }
    this.records.delete(recordId);
    return { actions, released: true };
  }

  private state_UNKNOWN(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        if (this.liveCount >= HERMES_MAX_PUBLIC_CONNECTIONS) {
          return this.fatal(event.connectionId, "too_many_live");
        }
        // NODE_CLOSED and peer-shutting rows count as live until relay_closed because the relay still owns their public slot.
        // Record ids are never reused, and only the admitting step sets a row's current record to the record it just minted.
        this.rows.set(event.connectionId, { state: "OPEN_IDLE" });
        return { actions: [] };
      case "relay_closed":
        return this.fatal(event.connectionId, "closed_for_unknown_or_duplicate");
      case "node_response_written":
        return this.refusal(event.connectionId, "record_not_current");
      case "node_close":
        return { actions: [] };
      case "call":
        return this.fatal(event.connectionId, "unknown_connection");
      case "cancel":
      case "public_shutdown":
      case "public_unparseable":
      case "control_invalid":
        return this.fatal(event.connectionId, "unknown");
    }
  }

  private state_OPEN_IDLE(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        return this.fatal(event.connectionId, "duplicate_accepted");
      case "call":
        return this.acceptCallFromIdle(event);
      case "cancel":
      case "control_invalid":
        return { actions: [] };
      case "public_shutdown":
        return this.updateRowState(event.connectionId, "OPEN_IDLE_PEER_SHUTTING");
      case "public_unparseable":
        return this.sendCloseFromIdle(event.connectionId);
      case "relay_closed":
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.refusal(event.connectionId, "no_current_record");
      case "node_close":
        return this.sendCloseFromIdle(event.connectionId);
    }
  }

  private state_OPEN_BUSY(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        return this.fatal(event.connectionId, "duplicate_accepted");
      case "call":
        return this.fatal(event.connectionId, "second_call_forwarded");
      case "cancel":
        return this.deliverCancel(event.connectionId, event.mcpRequestId);
      case "public_shutdown":
        return this.markBusyPeerShuttingAndDeliverShutdown(event.connectionId);
      case "public_unparseable":
        return this.closeBusyConnection(event.connectionId);
      case "control_invalid":
        return { actions: [] };
      case "relay_closed":
        this.finishCurrentRecord(event.connectionId, "CONNECTION_GONE");
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.responseWritten(event.connectionId, event.recordId);
      case "node_close":
        return this.closeBusyConnection(event.connectionId);
    }
  }

  private state_OPEN_IDLE_PEER_SHUTTING(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        return this.fatal(event.connectionId, "duplicate_accepted");
      case "call":
      case "cancel":
      case "public_shutdown":
      case "public_unparseable":
      case "control_invalid":
        // The relay promises closed next after a forwarded shutdown; any intervening public frame is outside the table.
        return this.fatal(event.connectionId, "event_after_peer_shutdown");
      case "relay_closed":
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.refusal(event.connectionId, "no_current_record");
      case "node_close":
        return this.sendCloseFromIdle(event.connectionId);
    }
  }

  private state_OPEN_BUSY_PEER_SHUTTING(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        return this.fatal(event.connectionId, "duplicate_accepted");
      case "call":
      case "cancel":
      case "public_shutdown":
      case "public_unparseable":
      case "control_invalid":
        // A call is never routed after peer shutdown because the relay has already chosen the closing path.
        return this.fatal(event.connectionId, "event_after_peer_shutdown");
      case "relay_closed":
        // This is the expected arrival after peer shutdown; the call remains only as detached settling work.
        this.finishCurrentRecord(event.connectionId, "CONNECTION_GONE");
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.responseWritten(event.connectionId, event.recordId);
      case "node_close":
        return this.closeBusyConnection(event.connectionId);
    }
  }

  private state_NODE_CLOSED(event: Exclude<HermesLifecycleEvent, { type: "relay_shutdown_or_eof" }>): HermesLifecycleResult {
    switch (event.type) {
      case "accepted":
        return this.fatal(event.connectionId, "duplicate_accepted");
      case "relay_closed":
        // Node close is followed by the relay closed frame; this row is live until that expected arrival.
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.refusal(event.connectionId, "record_not_current");
      case "call":
      case "cancel":
      case "public_shutdown":
      case "public_unparseable":
      case "control_invalid":
      case "node_close":
        // Nothing is sent from NODE_CLOSED because the one close has already been written.
        return { actions: [] };
    }
  }

  private acceptCallFromIdle(event: Extract<HermesLifecycleEvent, { type: "call" }>): HermesLifecycleResult {
    const row = this.rowForKnownConnection(event.connectionId);
    if (row === undefined) return this.fatal(event.connectionId, "unknown_connection");
    const record = this.newRecord(event);
    // The single total record cap is checked before row mutation, so an over-cap call gets exactly one denial and leaves no retained record.
    if (this.records.size >= HERMES_MAX_CALL_RECORDS) {
      return {
        actions: [this.fixedDenialAction(record, "immediate")],
        refusal: { connectionId: event.connectionId, reason: "call_record_capacity" },
      };
    }
    if (event.valid !== true) {
      return {
        actions: [this.fixedDenialAction(record, "immediate")],
        refusal: { connectionId: event.connectionId, reason: "call_validation_failed" },
      };
    }
    row.state = "OPEN_BUSY";
    // The admitting step is the only path that points a row at a current record, and it points only at the record it just minted.
    row.currentRecordId = record.id;
    this.records.set(record.id, record);
    return { actions: [{ type: "route_call", connectionId: record.connectionId, recordId: record.id, requestId: record.requestId, kind: record.kind }] };
  }

  private responseWritten(connectionId: string, recordId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return this.refusal(connectionId, "record_not_current");
    const currentRecordId = row.currentRecordId;
    if (currentRecordId === undefined) return this.refusal(connectionId, "no_current_record");
    if (recordId !== currentRecordId) return this.refusal(connectionId, "record_not_current");
    const record = this.records.get(currentRecordId);
    if (record?.state !== "IN_FLIGHT") return this.refusal(connectionId, "record_not_current");
    record.state = "RESPONDED";
    this.records.delete(currentRecordId);
    row.state = row.state === "OPEN_BUSY_PEER_SHUTTING" ? "OPEN_IDLE_PEER_SHUTTING" : "OPEN_IDLE";
    delete row.currentRecordId;
    return { actions: [] };
  }

  private deliverCancel(connectionId: string, mcpRequestId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return { actions: [] };
    const record = row.currentRecordId === undefined ? undefined : this.records.get(row.currentRecordId);
    // A cancel carries the caller's request id; mismatches are not authority over the current call.
    if (record?.state !== "IN_FLIGHT" || record.requestId !== mcpRequestId) return { actions: [] };
    return this.deliverCoalescedControl(record, "cancel", "pendingCancel");
  }

  private deliverShutdown(connectionId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return { actions: [] };
    const record = row.currentRecordId === undefined ? undefined : this.records.get(row.currentRecordId);
    if (record?.state !== "IN_FLIGHT") return { actions: [] };
    return this.deliverCoalescedControl(record, "shutdown", "pendingShutdown");
  }

  private deliverCoalescedControl(record: CallRecord, control: HermesControlKind, flag: "pendingCancel" | "pendingShutdown"): HermesLifecycleResult {
    if (record[flag]) return { actions: [] };
    record[flag] = true;
    return {
      actions: [
        {
          type: "deliver_control",
          connectionId: record.connectionId,
          recordId: record.id,
          requestId: record.requestId,
          control,
        },
      ],
    };
  }

  private closeBusyConnection(connectionId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return { actions: [] };
    this.finishCurrentRecord(connectionId, "CLOSED_BY_NODE");
    row.state = "NODE_CLOSED";
    return { actions: [{ type: "send_close", connectionId }] };
  }

  private applyRelayShutdownOrEof(): HermesLifecycleResult {
    // The stopped gate is the lifecycle boundary: after it flips, no per-connection event emits Node output.
    if (this.stoppedFlag) return { actions: [] };
    this.stoppedFlag = true;
    const actions: HermesLifecycleAction[] = [];
    for (const record of this.records.values()) {
      // Relay shutdown or EOF reaches current and detached records; a prior shutdown delivery is coalesced but the terminal state is unified.
      if (!record.pendingShutdown) {
        actions.push({
          type: "deliver_control",
          connectionId: record.connectionId,
          recordId: record.id,
          requestId: record.requestId,
          control: "shutdown",
        });
        record.pendingShutdown = true;
      }
      record.state = "SHUT_DOWN";
    }
    return { actions };
  }

  private finishCurrentRecord(connectionId: string, state: "CLOSED_BY_NODE" | "CONNECTION_GONE"): void {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return;
    const recordId = row.currentRecordId;
    if (recordId === undefined) return;
    const record = this.records.get(recordId);
    if (record?.state === "IN_FLIGHT") record.state = state;
    delete row.currentRecordId;
  }

  private newRecord(event: Extract<HermesLifecycleEvent, { type: "call" }>): CallRecord {
    const id = `call-${this.nextRecordNumber++}`;
    return {
      id,
      connectionId: event.connectionId,
      requestId: event.requestId,
      kind: event.kind,
      state: "IN_FLIGHT",
      pendingCancel: false,
      pendingShutdown: false,
    };
  }

  private fixedDenialAction(record: CallRecord, responseClass: "immediate" | "release"): Extract<HermesLifecycleAction, { type: "send_fixed_denial" }> {
    return {
      type: "send_fixed_denial",
      connectionId: record.connectionId,
      recordId: record.id,
      requestId: record.requestId,
      message: HERMES_MEMORY_DENIAL_MESSAGE,
      responseClass,
    };
  }

  private isBusyState(state: ConnectionRow["state"] | undefined): state is "OPEN_BUSY" | "OPEN_BUSY_PEER_SHUTTING" {
    return state === "OPEN_BUSY" || state === "OPEN_BUSY_PEER_SHUTTING";
  }

  private rowForKnownConnection(connectionId: string): ConnectionRow | undefined {
    return this.rows.get(connectionId);
  }

  private updateRowState(connectionId: string, state: ConnectionRow["state"]): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return this.fatal(connectionId, "unknown_connection");
    row.state = state;
    return { actions: [] };
  }

  private sendCloseFromIdle(connectionId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return { actions: [] };
    row.state = "NODE_CLOSED";
    return { actions: [{ type: "send_close", connectionId }] };
  }

  private markBusyPeerShuttingAndDeliverShutdown(connectionId: string): HermesLifecycleResult {
    const row = this.rowForKnownConnection(connectionId);
    if (row === undefined) return { actions: [] };
    row.state = "OPEN_BUSY_PEER_SHUTTING";
    return this.deliverShutdown(connectionId);
  }

  private fatal(connectionId: string, reason: HermesFatalReason): HermesLifecycleResult {
    return { actions: [], fatal: { connectionId, reason } };
  }

  private refusal(connectionId: string, reason: HermesRefusalReason): HermesLifecycleResult {
    return { actions: [], refusal: { connectionId, reason } };
  }

}
