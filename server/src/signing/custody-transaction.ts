import { z } from "zod";
import { canonicalBytes, refuse, safeInteger } from "./contract.js";
import { parseStrict } from "../smb/parse-strict.js";
import { advancePersistence, persistenceComplete, preparePersistence, type PersistenceEvent, type PersistenceState } from "./durable-store.js";
import { anchorSchema, reconcile, type ActivationAnchor, type ReconciliationInput } from "../linux-business/activation-anchor.js";

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
export interface TransactionState { readonly journal: CustodyTransaction; readonly persistence: PersistenceState; readonly recovery_required: boolean; }
/** Begin a pure transcript; an installed caller must separately prove closed effects and exclusive custody. */
export function beginTransaction(journal: CustodyTransaction): TransactionState {
  const checked = decodeTransaction(canonicalBytes(journal));
  // A persisted cut cannot be erased by replaying the journal through the initial phase.
  if (checked.cut || checked.phase !== "PREPARED") return refuse();
  return {journal: checked, persistence: preparePersistence(checked), recovery_required: false};
}
export type TransactionEvent = PersistenceEvent | {op: "NEXT" | "CUT"} |
  {op: "RECONCILE"; input: ReconciliationInput} | {op: "D_ACK"; anchor: ActivationAnchor};
export function advanceTransaction(state: TransactionState, event: TransactionEvent): TransactionState {
  if (event.op === "CUT") {
    const journal = {...state.journal, cut: true};
    return {journal, persistence: preparePersistence(journal), recovery_required: true};
  }
  // A cut remains sticky in the transcript, so a later success acknowledgment cannot erase uncertainty.
  if (state.recovery_required || state.journal.cut) return refuse();
  if (event.op === "RECONCILE") {
    // Only an exact outside receipt and fully drained old custody revision can support same-epoch completion.
    if (state.journal.operation !== "RECOVER" || state.journal.phase !== "PREPARED" ||
        reconcile(event.input) !== "CONSISTENT" || event.input.custody.enrollment_revision !== state.journal.old.revision ||
        event.input.custody.custody_envelope_digest !== state.journal.old.digest) return refuse();
    const journal = {...state.journal, reconciliation: {result: "CONSISTENT" as const, input: reconciliationSchema.parse(event.input)}};
    return {...state, journal, persistence: preparePersistence(journal)};
  }
  if (event.op === "D_ACK") {
    const anchor = anchorSchema.parse(event.anchor), j = state.journal;
    // Drain acknowledgment names this transaction and its new custody bytes before either phase can settle.
    if (anchor.recovery_required || anchor.retired || anchor.enrollment_revision !== j.next.revision ||
        anchor.custody_envelope_digest !== j.next.digest ||
        (j.phase !== "D_PREPARE" && j.phase !== "D_COMMIT") ||
        (j.phase === "D_PREPARE" ? anchor.transaction_id !== j.transaction_id : anchor.transaction_id !== null)) return refuse();
    // The commit acknowledgment may only clear the transaction in the exact prepared drain tuple.
    if (j.phase === "D_COMMIT" && (!j.drain_ack.prepare ||
        !Buffer.from(canonicalBytes({...j.drain_ack.prepare, transaction_id: null})).equals(Buffer.from(canonicalBytes(anchor))))) return refuse();
    const journal = {...j, drain_ack: {...j.drain_ack, [j.phase === "D_PREPARE" ? "prepare" : "commit"]: anchor}};
    return {...state, journal, persistence: preparePersistence(journal)};
  }
  if (event.op !== "NEXT") return {...state, persistence: advancePersistence(state.persistence, event as PersistenceEvent)};
  const index = TRANSACTION_PHASES.indexOf(state.journal.phase);
  // Must match durable-store.ts: each phase waits for file fsync, directory fsync and exact readback before continuing.
  if (!persistenceComplete(state.persistence) || index === TRANSACTION_PHASES.length - 1) return refuse();
  const journal = {...state.journal, phase: TRANSACTION_PHASES[index + 1]};
  return {journal, persistence: preparePersistence(journal), recovery_required: false};
}
export function transactionComplete(state: TransactionState): boolean {
  const j = state.journal;
  // Must match activation-anchor.ts reconcile: a local COMPLETE phase cannot invent outside recovery evidence.
  if (j.operation === "RECOVER" && (!j.reconciliation || j.reconciliation.result !== "CONSISTENT" || reconcile(j.reconciliation.input) !== "CONSISTENT" ||
      j.reconciliation.input.custody.enrollment_revision !== j.old.revision || j.reconciliation.input.custody.custody_envelope_digest !== j.old.digest)) return false;
  // Completion includes durable readback of the drain acknowledgment, not merely the local phase name.
  return !state.recovery_required && !j.cut && j.drain_ack.prepare !== null && j.drain_ack.commit !== null &&
    j.phase === "COMPLETE" && persistenceComplete(state.persistence);
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
