import { z } from "zod";
import { canonicalBytes, refuse, safeInteger } from "./contract.js";
import { parseStrict } from "../smb/parse-strict.js";
import { advancePersistence, persistenceComplete, preparePersistence, type PersistenceEvent, type PersistenceState } from "./durable-store.js";
import { ANCHOR_VERSION, anchorSchema, proposeAnchor, reconcile, recoveryPrepareBase, type ActivationAnchor, type ReconciliationInput } from "../linux-business/activation-anchor.js";

// Must match durable-store.ts and protocol-transitions.json: COMPLETE is a persistence phase, never authority.
export const TRANSACTION_VERSION = 2; // Revision two persists cuts, drain acknowledgments and recovery comparison.
export const TRANSACTION_MAX_BYTES = 65536;
export const TRANSACTION_PHASES = ["PREPARED", "STAGED", "D_PREPARE", "SELECTOR", "D_COMMIT", "COMPLETE"] as const;
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const revision = z.object({revision: safeInteger, digest}).strict();
const reconciliationSchema = z.object({custody: anchorSchema, drain: anchorSchema,
  outside_receipt_digest: digest, original_tail_digest: z.union([z.literal("GENESIS"), digest])}).strict();
const transactionSchema = z.object({version: z.literal(TRANSACTION_VERSION), transaction_id: z.string().regex(/^[a-f0-9]{32}$/),
  operation: z.enum(["PROVISION", "ROTATE", "RECOVER"]), old: revision, next: revision, phase: z.enum(TRANSACTION_PHASES), cut: z.boolean(),
  reconciliation: z.object({result: z.literal("CONSISTENT"), input: reconciliationSchema}).strict().nullable(),
  drain_ack: z.object({prepare: anchorSchema.nullable(), commit: anchorSchema.nullable()}).strict()}).strict();
export type CustodyTransaction = z.infer<typeof transactionSchema>;
/** Decode the journal format without opening any custody path or creating an installed signing capability. */
export function decodeTransaction(bytes: Uint8Array): CustodyTransaction {
  const value = transactionSchema.parse(parseStrict(bytes, TRANSACTION_MAX_BYTES));
  // A journal binds consecutive revisions and changed bytes, preventing a replay from becoming a new commit.
  if (value.next.revision !== value.old.revision + 1 || value.next.digest === value.old.digest || !Buffer.from(canonicalBytes(value)).equals(Buffer.from(bytes))) return refuse();
  return value;
}
export interface TransactionState {
  readonly journal: CustodyTransaction; readonly persistence: PersistenceState; readonly recovery_required: boolean;
  /** The drain anchor observed before PREPARE; the prepare acknowledgment is exactly one PREPARE step from it, carrying the reconciled drained tuple for a recovery. */
  readonly prior_anchor: ActivationAnchor;
}
function equal(a: unknown, b: unknown): boolean { return Buffer.from(canonicalBytes(a)).equals(Buffer.from(canonicalBytes(b))); }
function priorBound(journal: CustodyTransaction, prior: ActivationAnchor): boolean {
  return prior.enrollment_revision === journal.old.revision && prior.custody_envelope_digest === journal.old.digest;
}
/** Begin a pure transcript; an installed caller must separately prove closed effects and exclusive custody. */
export function beginTransaction(journal: CustodyTransaction, priorAnchor: ActivationAnchor): TransactionState {
  const checked = decodeTransaction(canonicalBytes(journal)), prior = anchorSchema.parse(priorAnchor);
  // A persisted cut cannot be erased by replaying the journal through the initial phase.
  if (checked.cut || checked.phase !== "PREPARED") return refuse();
  // Evidence fields start empty, so acknowledgments and reconciliation can only enter through their own checked events.
  if (checked.reconciliation !== null || checked.drain_ack.prepare !== null || checked.drain_ack.commit !== null) return refuse();
  // The pre-transaction anchor names the journal's old custody revision, so a foreign anchor cannot seed the acknowledgment check.
  if (!priorBound(checked, prior)) return refuse();
  return {journal: checked, persistence: preparePersistence(checked), recovery_required: false, prior_anchor: prior};
}
/** Must match the D_ACK arm and transactionComplete: one predicate admits a prepare acknowledgment wherever it is checked. */
function prepareAckValid(state: TransactionState, ack: ActivationAnchor | null): boolean {
  const j = state.journal;
  if (ack === null || !priorBound(j, state.prior_anchor)) return false;
  // Drain acknowledgment names this transaction and its new custody bytes before either phase can settle.
  if (ack.recovery_required || ack.retired || ack.enrollment_revision !== j.next.revision ||
      ack.custody_envelope_digest !== j.next.digest || ack.transaction_id !== j.transaction_id) return false;
  // Must match PREPARE_CHANGED_FIELDS in activation-anchor.ts: the anchor reducer admits the acknowledgment as exactly one PREPARE step.
  const preparedFrom = (before: ActivationAnchor) => {
    try { proposeAnchor(before, {version: ANCHOR_VERSION, op: "PREPARE", request_id: j.transaction_id, expected: before, next: ack}); return true; }
    catch { return false; }
  };
  // Must match recoveryPrepareBase in activation-anchor.ts: a recovery steps from the prior anchor carrying the reconciled drained tuple, any other transaction from the prior anchor itself.
  const base = j.operation !== "RECOVER" ? state.prior_anchor : j.reconciliation === null ? null : recoveryPrepareBase(state.prior_anchor, j.reconciliation.input.drain);
  return base !== null && preparedFrom(base);
}
function commitAckValid(prepare: ActivationAnchor | null, commit: ActivationAnchor | null): boolean {
  // The commit acknowledgment may only clear the transaction in the exact prepared drain tuple.
  return prepare !== null && commit !== null && equal({...prepare, transaction_id: null}, commit);
}
/** A cut journal is durable once its own bytes completed file sync, directory sync and exact readback. */
export function cutDurable(state: TransactionState): boolean {
  return state.journal.cut && persistenceComplete(state.persistence);
}
export type TransactionEvent = PersistenceEvent | {op: "NEXT" | "CUT"} |
  {op: "RECONCILE"; input: ReconciliationInput} | {op: "D_ACK"; anchor: ActivationAnchor};
export function advanceTransaction(state: TransactionState, event: TransactionEvent): TransactionState {
  if (event.op === "CUT") {
    const journal = {...state.journal, cut: true};
    return {...state, journal, persistence: preparePersistence(journal), recovery_required: true};
  }
  if (state.recovery_required || state.journal.cut) {
    // A cut remains sticky in the transcript, so a later success acknowledgment cannot erase uncertainty.
    if (event.op === "NEXT" || event.op === "RECONCILE" || event.op === "D_ACK") return refuse();
    // The cut journal itself may still be written, synced and read back, so a replay of the persisted bytes refuses at begin.
    return {...state, persistence: advancePersistence(state.persistence, event as PersistenceEvent)};
  }
  if (event.op === "RECONCILE") {
    // Only an exact outside receipt and fully drained old custody revision can support same-epoch completion.
    // A recorded reconciliation is write-once, so the drain tuple an acknowledgment must name cannot be replaced.
    // A drain that disagrees with the prior anchor outside the drained tuple is inconsistent with it, so it refuses here where that is detected.
    if (state.journal.operation !== "RECOVER" || state.journal.phase !== "PREPARED" || state.journal.reconciliation !== null ||
        reconcile(event.input) !== "CONSISTENT" || recoveryPrepareBase(state.prior_anchor, event.input.drain) === null ||
        event.input.custody.enrollment_revision !== state.journal.old.revision ||
        event.input.custody.custody_envelope_digest !== state.journal.old.digest) return refuse();
    const journal = {...state.journal, reconciliation: {result: "CONSISTENT" as const, input: reconciliationSchema.parse(event.input)}};
    return {...state, journal, persistence: preparePersistence(journal)};
  }
  if (event.op === "D_ACK") {
    const anchor = anchorSchema.parse(event.anchor), j = state.journal;
    if (j.phase !== "D_PREPARE" && j.phase !== "D_COMMIT") return refuse();
    const slot = j.phase === "D_PREPARE" ? "prepare" : "commit";
    // Each acknowledgment is write-once, so a later reply cannot replace the tuple already journaled.
    if (j.drain_ack[slot] !== null) return refuse();
    if (slot === "prepare" ? !prepareAckValid(state, anchor) : !commitAckValid(j.drain_ack.prepare, anchor)) return refuse();
    const journal = {...j, drain_ack: {...j.drain_ack, [slot]: anchor}};
    return {...state, journal, persistence: preparePersistence(journal)};
  }
  if (event.op !== "NEXT") return {...state, persistence: advancePersistence(state.persistence, event as PersistenceEvent)};
  const index = TRANSACTION_PHASES.indexOf(state.journal.phase);
  // Must match durable-store.ts: each phase waits for file fsync, directory fsync and exact readback before continuing.
  if (!persistenceComplete(state.persistence) || index === TRANSACTION_PHASES.length - 1) return refuse();
  const journal = {...state.journal, phase: TRANSACTION_PHASES[index + 1]};
  return {...state, journal, persistence: preparePersistence(journal), recovery_required: false};
}
export function transactionComplete(state: TransactionState): boolean {
  const j = state.journal;
  // Must match the D_ACK arm: completion re-runs both acknowledgment predicates, so seeded or later-changed acknowledgments cannot settle.
  if (!prepareAckValid(state, j.drain_ack.prepare) || !commitAckValid(j.drain_ack.prepare, j.drain_ack.commit)) return false;
  // The final readback was of this exact journal, so a journal changed after persistence cannot complete.
  if (state.persistence.bytes !== preparePersistence(j).bytes) return false;
  // Must match activation-anchor.ts reconcile: a local COMPLETE phase cannot invent outside recovery evidence.
  if (j.operation === "RECOVER" && (!j.reconciliation || j.reconciliation.result !== "CONSISTENT" || reconcile(j.reconciliation.input) !== "CONSISTENT" ||
      j.reconciliation.input.custody.enrollment_revision !== j.old.revision || j.reconciliation.input.custody.custody_envelope_digest !== j.old.digest)) return false;
  // Completion includes durable readback of the drain acknowledgment, not merely the local phase name.
  return !state.recovery_required && !j.cut && j.phase === "COMPLETE" && persistenceComplete(state.persistence);
}
export function recover_same_epoch(input: ReconciliationInput): boolean {
  // a custody-only rollback refuses; no total-host rollback protection is claimed.
  // Same-epoch recovery requires comparison with the last exported receipt from outside the restored failure domain; without that comparison it refuses and a new epoch is required.
  return reconcile(input) === "CONSISTENT";
}
/** Pure outcome classification has no reference to a live supervisor or latch. */
export function classifyCustodyOutcome(expectedEnvelopeDigest: string, actualEnvelopeDigest: string, factor: "ACCEPTED" | "REFUSED" | "CANCELLED"): "CLEAN" | "FACTOR_REFUSED" | "INTEGRITY_REFUSED" {
  // Envelope integrity precedes factor classification because changed custody bytes are not a bad password.
  if (!digest.safeParse(expectedEnvelopeDigest).success || !digest.safeParse(actualEnvelopeDigest).success || expectedEnvelopeDigest !== actualEnvelopeDigest) return "INTEGRITY_REFUSED";
  return factor === "ACCEPTED" ? "CLEAN" : "FACTOR_REFUSED";
}
