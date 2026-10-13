export const HERMES_MEMORY_DENIAL_MESSAGE = "Memory request denied.";

// must match MAX_PUBLIC_CONNECTIONS in hermes-memory-relay/SEAM.md.
export const HERMES_MAX_PUBLIC_CONNECTIONS = 4;
// 4 = the settling reserve paired with the four relay-admitted public slots.
export const HERMES_MAX_SETTLING_CALLS = HERMES_MAX_PUBLIC_CONNECTIONS;
// 8 = four live connection call records plus four settling call records.
export const HERMES_MAX_CALL_RECORDS = HERMES_MAX_PUBLIC_CONNECTIONS + HERMES_MAX_SETTLING_CALLS;

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
  generation: number;
  currentRecordId?: string;
}

interface CallRecord {
  id: string;
  connectionId: string;
  generation: number;
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
  private nextRowGeneration = 1;
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

  canWriteResponse(recordId: string): boolean {
    if (this.stoppedFlag) return false;
    const record = this.records.get(recordId);
    if (record?.state !== "IN_FLIGHT") return false;
    const row = this.rows.get(record.connectionId);
    return this.isBusyState(row?.state) && row.currentRecordId === recordId && row.generation === record.generation;
  }

  canSendClose(connectionId: string): boolean {
    if (this.stoppedFlag) return false;
    const state = this.rows.get(connectionId)?.state;
    return state === "OPEN_IDLE" || state === "OPEN_BUSY" || state === "OPEN_IDLE_PEER_SHUTTING" || state === "OPEN_BUSY_PEER_SHUTTING";
  }

  canSendLifecycleAction(action: HermesLifecycleAction): boolean {
    if (this.stoppedFlag) return false;
    switch (action.type) {
      case "route_call": {
        const record = this.records.get(action.recordId);
        const row = record === undefined ? undefined : this.rows.get(record.connectionId);
        return (
          record?.state === "IN_FLIGHT" &&
          record.connectionId === action.connectionId &&
          record.requestId === action.requestId &&
          record.kind === action.kind &&
          this.isBusyState(row?.state) &&
          row.currentRecordId === record.id &&
          row.generation === record.generation
        );
      }
      case "deliver_control": {
        const record = this.records.get(action.recordId);
        return (
          record?.state === "IN_FLIGHT" &&
          record.connectionId === action.connectionId &&
          record.requestId === action.requestId &&
          ((action.control === "cancel" && record.pendingCancel) || (action.control === "shutdown" && record.pendingShutdown))
        );
      }
      case "send_fixed_denial": {
        const state = this.stateOf(action.connectionId);
        return !this.records.has(action.recordId) && (state === "OPEN_IDLE" || state === "OPEN_IDLE_PEER_SHUTTING");
      }
      case "send_close":
        return this.canSendClose(action.connectionId);
    }
  }

  apply(event: HermesLifecycleEvent): HermesLifecycleResult {
    if (event.type === "relay_shutdown_or_eof") {
      return this.applyRelayShutdownOrEof();
    }
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
        // A deleted row leaves no tombstone; generations keep any older call record from attaching to the new row.
        if (this.liveCount >= HERMES_MAX_PUBLIC_CONNECTIONS) {
          return this.fatal(event.connectionId, "too_many_live");
        }
        // NODE_CLOSED and peer-shutting rows count as live until relay_closed because the relay still owns their public slot.
        this.rows.set(event.connectionId, { state: "OPEN_IDLE", generation: this.nextRowGeneration++ });
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
        this.requireRow(event.connectionId).state = "OPEN_IDLE_PEER_SHUTTING";
        return { actions: [] };
      case "public_unparseable":
        this.requireRow(event.connectionId).state = "NODE_CLOSED";
        return { actions: [{ type: "send_close", connectionId: event.connectionId }] };
      case "relay_closed":
        this.rows.delete(event.connectionId);
        return { actions: [] };
      case "node_response_written":
        return this.refusal(event.connectionId, "no_current_record");
      case "node_close":
        this.requireRow(event.connectionId).state = "NODE_CLOSED";
        return { actions: [{ type: "send_close", connectionId: event.connectionId }] };
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
        this.requireRow(event.connectionId).state = "OPEN_BUSY_PEER_SHUTTING";
        return this.deliverShutdown(event.connectionId);
      case "public_unparseable":
        return this.closeBusyConnection(event.connectionId);
      case "control_invalid":
        return { actions: [] };
      case "relay_closed":
        this.finishCurrentRecord(this.requireRow(event.connectionId), "CONNECTION_GONE");
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
        this.requireRow(event.connectionId).state = "NODE_CLOSED";
        return { actions: [{ type: "send_close", connectionId: event.connectionId }] };
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
        this.finishCurrentRecord(this.requireRow(event.connectionId), "CONNECTION_GONE");
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
    const row = this.requireRow(event.connectionId);
    const record = this.newRecord(event);
    // The record cap is checked before row mutation, so an over-cap call gets exactly one denial and leaves no retained record.
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
    row.currentRecordId = record.id;
    this.records.set(record.id, record);
    return { actions: [{ type: "route_call", connectionId: record.connectionId, recordId: record.id, requestId: record.requestId, kind: record.kind }] };
  }

  private responseWritten(connectionId: string, recordId: string): HermesLifecycleResult {
    const row = this.requireRow(connectionId);
    const currentRecordId = row.currentRecordId;
    if (currentRecordId === undefined) return this.refusal(connectionId, "no_current_record");
    if (recordId !== currentRecordId) return this.refusal(connectionId, "record_not_current");
    const record = this.records.get(currentRecordId);
    if (record?.state !== "IN_FLIGHT" || record.generation !== row.generation) return this.refusal(connectionId, "record_not_current");
    record.state = "RESPONDED";
    this.records.delete(currentRecordId);
    row.state = row.state === "OPEN_BUSY_PEER_SHUTTING" ? "OPEN_IDLE_PEER_SHUTTING" : "OPEN_IDLE";
    delete row.currentRecordId;
    return { actions: [] };
  }

  private deliverCancel(connectionId: string, mcpRequestId: string): HermesLifecycleResult {
    const row = this.requireRow(connectionId);
    const record = row.currentRecordId === undefined ? undefined : this.records.get(row.currentRecordId);
    // A cancel carries the caller's request id; mismatches are not authority over the current call.
    if (record?.state !== "IN_FLIGHT" || record.requestId !== mcpRequestId || record.generation !== row.generation) return { actions: [] };
    return this.deliverCoalescedControl(record, "cancel", "pendingCancel");
  }

  private deliverShutdown(connectionId: string): HermesLifecycleResult {
    const row = this.requireRow(connectionId);
    const record = row.currentRecordId === undefined ? undefined : this.records.get(row.currentRecordId);
    if (record?.state !== "IN_FLIGHT" || record.generation !== row.generation) return { actions: [] };
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
    const row = this.requireRow(connectionId);
    this.finishCurrentRecord(row, "CLOSED_BY_NODE");
    row.state = "NODE_CLOSED";
    return { actions: [{ type: "send_close", connectionId }] };
  }

  private applyRelayShutdownOrEof(): HermesLifecycleResult {
    // The stopped gate is the lifecycle boundary: after it flips, no per-connection event emits Node output.
    if (this.stoppedFlag) return { actions: [] };
    this.stoppedFlag = true;
    const actions: HermesLifecycleAction[] = [];
    for (const record of this.records.values()) {
      // E9 reaches current and detached records; a prior shutdown delivery is coalesced but the terminal state is unified.
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

  private finishCurrentRecord(row: ConnectionRow, state: "CLOSED_BY_NODE" | "CONNECTION_GONE"): void {
    const recordId = row.currentRecordId;
    if (recordId === undefined) return;
    const record = this.records.get(recordId);
    if (record?.state === "IN_FLIGHT" && record.generation === row.generation) record.state = state;
    delete row.currentRecordId;
  }

  private newRecord(event: Extract<HermesLifecycleEvent, { type: "call" }>): CallRecord {
    const id = `call-${this.nextRecordNumber++}`;
    const row = this.requireRow(event.connectionId);
    return {
      id,
      connectionId: event.connectionId,
      generation: row.generation,
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

  private requireRow(connectionId: string): ConnectionRow {
    const row = this.rows.get(connectionId);
    if (row === undefined) throw new Error(`missing Hermes lifecycle row for ${connectionId}`);
    return row;
  }

  private fatal(connectionId: string, reason: HermesFatalReason): HermesLifecycleResult {
    return { actions: [], fatal: { connectionId, reason } };
  }

  private refusal(connectionId: string, reason: HermesRefusalReason): HermesLifecycleResult {
    return { actions: [], refusal: { connectionId, reason } };
  }

}
