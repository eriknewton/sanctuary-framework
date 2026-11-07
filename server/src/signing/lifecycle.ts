import { refuse } from "./contract.js";

export const CUSTODY_STATES = ["UNPROVISIONED", "PROVISIONING", "ROTATING", "RECOVERING", "RECOVERY_REQUIRED", "RETIRED", "LOCKED", "UNLOCKING", "UNLOCKED", "LOCKING", "WIPED", "WIPE_UNCONFIRMED"] as const;
export type CustodyState = typeof CUSTODY_STATES[number];
/** Normative event conditions are facts the future supervisor must establish, not caller assertions. */
export const ALLOWED_TRANSITIONS = [
  {
    "from": "LOCKED",
    "event": "Intact enrolled custody and no recovery/retirement marker",
    "to": "LOCKED",
    "guard": "BOOT"
  },
  {
    "from": "LOCKED",
    "event": "No enrollment AND independently proven fresh root",
    "to": "UNPROVISIONED",
    "guard": "BOOT"
  },
  {
    "from": "LOCKED",
    "event": "Interrupted transaction, missing/corrupt enrolled data, rollback or raw-file evidence",
    "to": "RECOVERY_REQUIRED",
    "guard": "BOOT"
  },
  {
    "from": "LOCKED",
    "event": "Durable retired epoch",
    "to": "RETIRED",
    "guard": "BOOT"
  },
  {
    "from": "UNPROVISIONED",
    "event": "Explicit bounded owner provision",
    "to": "PROVISIONING",
    "guard": "ALWAYS"
  },
  {
    "from": "PROVISIONING",
    "event": "Complete durable enrollment, buffers cleared and worker reaped",
    "to": "WIPED",
    "guard": "ALWAYS"
  },
  {
    "from": "PROVISIONING",
    "event": "Failure/timeout",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKED",
    "event": "Valid owner ceremony and exclusive lifecycle slot",
    "to": "UNLOCKING",
    "guard": "ALWAYS"
  },
  {
    "from": "UNLOCKING",
    "event": "All read-only custody, public pin, WAL and internal self-test checks within both deadlines",
    "to": "UNLOCKED",
    "guard": "ALWAYS"
  },
  {
    "from": "UNLOCKING",
    "event": "Bad factor/cancel/deadline",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "LOCKED"
  },
  {
    "from": "UNLOCKING",
    "event": "Integrity/rollback/raw-file mismatch",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "RECOVERY_REQUIRED"
  },
  {
    "from": "UNLOCKED",
    "event": "Authorized D8 append/control/seal within lease; admission latch respected",
    "to": "UNLOCKED",
    "guard": "ALWAYS"
  },
  {
    "from": "UNLOCKED",
    "event": "Owner lock, margin reached after finalization, expiry, peer death, policy fault or shutdown",
    "to": "LOCKING",
    "guard": "SETTLED",
    "cleanup_destination": "LOCKED"
  },
  {
    "from": "UNLOCKED",
    "event": "Owner lock, margin reached after finalization, expiry, peer death, policy fault or shutdown",
    "to": "LOCKING",
    "guard": "UNCERTAIN",
    "cleanup_destination": "RECOVERY_REQUIRED"
  },
  {
    "from": "UNLOCKED",
    "event": "Owner rotation while effects CLOSED and old worker settled",
    "to": "ROTATING",
    "guard": "ALWAYS"
  },
  {
    "from": "ROTATING",
    "event": "Durable dual-signature transaction and new binding committed",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "LOCKED"
  },
  {
    "from": "ROTATING",
    "event": "Any cut/error/deadline",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKING",
    "event": "Cooperative owned-buffer cleanup AND worker reaped",
    "to": "WIPED",
    "guard": "ALWAYS"
  },
  {
    "from": "LOCKING",
    "event": "Forced termination confirmed reaped, no cleanup proof",
    "to": "WIPE_UNCONFIRMED",
    "guard": "ALWAYS"
  },
  {
    "from": "LOCKING",
    "event": "Worker not reaped or IO unsettled",
    "to": "LOCKING",
    "guard": "ALWAYS"
  },
  {
    "from": "WIPED",
    "event": "Recorded destination intact",
    "to": "LOCKED",
    "guard": "DESTINATION_LOCKED"
  },
  {
    "from": "WIPED",
    "event": "Recorded destination intact",
    "to": "RECOVERY_REQUIRED",
    "guard": "DESTINATION_RECOVERY_REQUIRED"
  },
  {
    "from": "WIPE_UNCONFIRMED",
    "event": "Attended old-process absence plus storage reconciliation",
    "to": "RECOVERY_REQUIRED",
    "guard": "ALWAYS"
  },
  {
    "from": "RECOVERY_REQUIRED",
    "event": "Owner selects D8 C14/C15/C16 transaction",
    "to": "RECOVERING",
    "guard": "ALWAYS"
  },
  {
    "from": "RECOVERING",
    "event": "Validated durable reconciliation, worker gone",
    "to": "LOCKED",
    "guard": "ALWAYS"
  },
  {
    "from": "RECOVERING",
    "event": "Replacement commits old retirement and independent new enrollment",
    "to": "RETIRED",
    "guard": "ALWAYS"
  },
  {
    "from": "LOCKED",
    "event": "C17 exact nonsecret orphan cleanup",
    "to": "LOCKED",
    "guard": "ALWAYS"
  },
  {
    "from": "RECOVERING",
    "event": "Error/cut/deadline",
    "to": "LOCKING",
    "guard": "ALWAYS",
    "cleanup_destination": "RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKED",
    "event": "Explicit owner retirement, signed boundary already prepared or declared gap",
    "to": "RETIRED",
    "guard": "ALWAYS"
  },
  {
    "from": "RETIRED",
    "event": "Historical read only",
    "to": "RETIRED",
    "guard": "ALWAYS"
  }
] as const satisfies readonly {from: CustodyState; event: string; guard: string; to: CustodyState; cleanup_destination?: CustodyState}[];
export function transition(from: string, event: string, guard = "ALWAYS"): CustodyState {
  const row = ALLOWED_TRANSITIONS.find(entry => entry.from === from && entry.event === event && entry.guard === guard);
  // A named guard must establish the continuing path before the relation grants a destination state.
  if (!row) return refuse();
  return row.to;
}
