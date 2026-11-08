import { z } from "zod";
import { canonicalBytes, refuse, safeInteger } from "./contract.js";
import { parseStrict } from "../smb/parse-strict.js";
import { advancePersistence, persistenceComplete, preparePersistence, type PersistenceEvent, type PersistenceState } from "./durable-store.js";
import { reconcile, type ReconciliationInput } from "../linux-business/activation-anchor.js";

// Must match durable-store.ts and protocol-transitions.json: COMPLETE is a persistence phase, never authority.
export const TRANSACTION_VERSION = 1;
export const TRANSACTION_MAX_BYTES = 65536;
export const TRANSACTION_PHASES = ["PREPARED", "STAGED", "D_PREPARE", "SELECTOR", "D_COMMIT", "COMPLETE"] as const;
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const revision = z.object({revision: safeInteger, digest}).strict();
const transactionSchema = z.object({version: z.literal(TRANSACTION_VERSION), transaction_id: z.string().regex(/^[a-f0-9]{32}$/),
  operation: z.enum(["PROVISION", "ROTATE", "RECOVER"]), old: revision, next: revision, phase: z.enum(TRANSACTION_PHASES)}).strict();
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
  if (checked.phase !== "PREPARED") return refuse();
  return {journal: checked, persistence: preparePersistence(checked), recovery_required: false};
}
export function advanceTransaction(state: TransactionState, event: PersistenceEvent | {op: "NEXT" | "CUT"}): TransactionState {
  if (event.op === "CUT") return {...state, recovery_required: true};
  // A cut remains sticky in the transcript, so a later success acknowledgment cannot erase uncertainty.
  if (state.recovery_required) return refuse();
  if (event.op !== "NEXT") return {...state, persistence: advancePersistence(state.persistence, event as PersistenceEvent)};
  const index = TRANSACTION_PHASES.indexOf(state.journal.phase);
  // Must match durable-store.ts: each phase waits for file fsync, directory fsync and exact readback before continuing.
  if (!persistenceComplete(state.persistence) || index === TRANSACTION_PHASES.length - 1) return refuse();
  const journal = {...state.journal, phase: TRANSACTION_PHASES[index + 1]};
  return {journal, persistence: preparePersistence(journal), recovery_required: false};
}
export function transactionComplete(state: TransactionState): boolean {
  return !state.recovery_required && state.journal.phase === "COMPLETE" && persistenceComplete(state.persistence);
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
