import { refuse } from "./contract.js";
import protocol from "./protocol-transitions.json";

// Must match protocol-transitions.json and generated business_profile/protocol_transitions.rs in their entirety.
export const CUSTODY_STATES = Object.freeze(protocol.states);
export type CustodyState = typeof CUSTODY_STATES[number];
/** Pure relation only; these guard names are not installed evidence or signing authority. */
export const ALLOWED_TRANSITIONS = Object.freeze(protocol.rows.map(row => Object.freeze(row)));
/** A granted transition: the next state and, for a LOCKING entry, the named state cleanup must settle into. */
export interface TransitionResult { readonly to: CustodyState; readonly cleanup_destination: CustodyState | null; }
export function transition(from: string, event: string, guard = "ALWAYS"): TransitionResult {
  const row: {to: CustodyState; cleanup_destination?: CustodyState} | undefined =
    ALLOWED_TRANSITIONS.find(entry => entry.from === from && entry.event === event && entry.guard === guard);
  // A named guard must establish the continuing path before the relation grants a destination state.
  if (!row) return refuse();
  // The cleanup destination is returned with the next state so a settled lock (LOCKED) and an uncertain one
  // (RECOVERY_REQUIRED) stay distinguishable; the supervisor must carry it into the WIPED exit's DESTINATION_* guard.
  return Object.freeze({to: row.to, cleanup_destination: row.cleanup_destination ?? null});
}
