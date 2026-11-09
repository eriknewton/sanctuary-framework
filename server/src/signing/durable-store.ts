import { canonicalBytes, refuse } from "./contract.js";

// Must match custody-transaction.ts: every persistence phase requires both fsyncs and exact readback.
export const DURABILITY_STEPS = ["WRITE", "FILE_SYNC", "DIRECTORY_SYNC", "READBACK"] as const;
export interface PersistenceState { readonly bytes: string; readonly step: number; }
export type PersistenceEvent = {op: "WRITE" | "FILE_SYNC" | "DIRECTORY_SYNC"} | {op: "READBACK"; bytes: Uint8Array};
/** A pure transcript reducer for injected persistence ports; this is not a filesystem implementation. */
export function preparePersistence(value: unknown): PersistenceState {
  return Object.freeze({bytes: Buffer.from(canonicalBytes(value)).toString("base64url"), step: 0});
}
export function advancePersistence(state: PersistenceState, event: PersistenceEvent): PersistenceState {
  // Ordered file and directory acknowledgments cannot substitute for readback of the exact proposed bytes.
  if (event.op !== DURABILITY_STEPS[state.step] || (event.op === "READBACK" && Buffer.from(event.bytes).toString("base64url") !== state.bytes)) return refuse();
  return Object.freeze({...state, step: state.step + 1});
}
export function persistenceComplete(state: PersistenceState): boolean { return state.step === DURABILITY_STEPS.length; }
