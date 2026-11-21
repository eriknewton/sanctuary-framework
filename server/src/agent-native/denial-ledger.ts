/**
 * Denial ledger: the operator-side record of why a tool call was refused.
 *
 * Every refusal leaves the MCP router as one fixed result, so the cause of a
 * refusal is never visible to the agent. The router hands the cause to this
 * ledger instead, and the ledger records it in the audit log.
 */

/**
 * The closed list of refusal causes. Must match the literals the router passes
 * at every recordDenial call site in router.ts, which
 * test/agent-native/denial-ledger.test.ts checks structurally. A value outside
 * this list is recorded as `other`.
 */
export const DENIAL_CAUSES = [
  "pre_gate_argument_refused",
  "export_capacity",
  "pre_gate_record_fault",
  "gate_fault",
  "gate_denied",
  "integrity_read_fault",
  "write_integrity_stop",
  "handler_error",
  "post_allow_refusal",
  "proxy_upstream_error",
  "session_not_bound",
  "origin_unresolved",
  "other",
] as const;

export type DenialCause = (typeof DENIAL_CAUSES)[number];

const DENIAL_CAUSE_SET: ReadonlySet<string> = new Set(DENIAL_CAUSES);

export function closedDenialCause(cause: string): DenialCause {
  return DENIAL_CAUSE_SET.has(cause) ? (cause as DenialCause) : "other";
}

/** What the router knows about one refusal; operator-side only. */
export interface DenialRecordInput {
  /** The registered tool name. */
  readonly tool: string;
  /** The router's server-set caller principal (`agent:<id>` or `agent:unknown`). */
  readonly origin: string;
  /** An audit id this refusal relates to (an approval audit id, a tool_error ref). */
  readonly linked_ref?: string;
  /** The first error's name, or the top-level verdict key of a refused body. */
  readonly error_name?: string;
  /** The first error's message, or the top-level verdict value of a refused body. */
  readonly error_message?: string;
  /** Boolean facts a handler reported about effects it already committed. */
  readonly facts?: Readonly<Record<string, boolean>>;
}

/** The router's view of the ledger: record and forget, never awaited. */
export interface DenialRecorder {
  record(cause: DenialCause, input: DenialRecordInput): void;
}

/**
 * A ledger with no audit sink, for router fixtures built without an audit log:
 * it counts refusals per cause and starts no I/O.
 */
export class CountingDenialRecorder implements DenialRecorder {
  private readonly counts = new Map<DenialCause, number>();

  record(cause: DenialCause, _input: DenialRecordInput): void {
    const closed = closedDenialCause(cause);
    this.counts.set(closed, (this.counts.get(closed) ?? 0) + 1);
  }

  count(cause: DenialCause): number {
    return this.counts.get(cause) ?? 0;
  }
}
