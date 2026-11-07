import { refuse } from "./contract.js";

export const CUSTODY_STATES = ["UNPROVISIONED", "PROVISIONING", "ROTATING", "RECOVERING", "RECOVERY_REQUIRED", "RETIRED", "LOCKED", "UNLOCKING", "UNLOCKED", "LOCKING", "WIPED", "WIPE_UNCONFIRMED"] as const;
export type CustodyState = typeof CUSTODY_STATES[number];
/** Normative event conditions are facts the future supervisor must establish, not caller assertions. */
export const ALLOWED_TRANSITIONS = [
  {
    "from": "LOCKED at boot",
    "event": "Intact enrolled custody and no recovery/retirement marker",
    "to": "LOCKED"
  },
  {
    "from": "LOCKED at boot",
    "event": "No enrollment AND independently proven fresh root",
    "to": "UNPROVISIONED"
  },
  {
    "from": "LOCKED at boot",
    "event": "Interrupted transaction, missing/corrupt enrolled data, rollback or raw-file evidence",
    "to": "RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKED at boot",
    "event": "Durable retired epoch",
    "to": "RETIRED"
  },
  {
    "from": "UNPROVISIONED",
    "event": "Explicit bounded owner provision",
    "to": "PROVISIONING"
  },
  {
    "from": "PROVISIONING",
    "event": "Complete durable enrollment, buffers cleared and worker reaped",
    "to": "WIPED"
  },
  {
    "from": "PROVISIONING",
    "event": "Failure/timeout",
    "to": "LOCKING with destination RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKED",
    "event": "Valid owner ceremony and exclusive lifecycle slot",
    "to": "UNLOCKING"
  },
  {
    "from": "UNLOCKING",
    "event": "All read-only custody, public pin, WAL and internal self-test checks within both deadlines",
    "to": "UNLOCKED"
  },
  {
    "from": "UNLOCKING",
    "event": "Bad factor/cancel/deadline",
    "to": "LOCKING with destination LOCKED"
  },
  {
    "from": "UNLOCKING",
    "event": "Integrity/rollback/raw-file mismatch",
    "to": "LOCKING with destination RECOVERY_REQUIRED"
  },
  {
    "from": "UNLOCKED",
    "event": "Authorized D8 append/control/seal within lease; admission latch respected",
    "to": "UNLOCKED"
  },
  {
    "from": "UNLOCKED",
    "event": "Owner lock, margin reached after finalization, expiry, peer death, policy fault or shutdown",
    "to": "LOCKING with destination LOCKED or RECOVERY_REQUIRED if uncertain"
  },
  {
    "from": "UNLOCKED",
    "event": "Owner rotation while effects CLOSED and old worker settled",
    "to": "ROTATING"
  },
  {
    "from": "ROTATING",
    "event": "Durable dual-signature transaction and new binding committed",
    "to": "LOCKING with destination LOCKED"
  },
  {
    "from": "ROTATING",
    "event": "Any cut/error/deadline",
    "to": "LOCKING with destination RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKING",
    "event": "Cooperative owned-buffer cleanup AND worker reaped",
    "to": "WIPED"
  },
  {
    "from": "LOCKING",
    "event": "Forced termination confirmed reaped, no cleanup proof",
    "to": "WIPE_UNCONFIRMED"
  },
  {
    "from": "LOCKING",
    "event": "Worker not reaped or IO unsettled",
    "to": "LOCKING, no released reservation or replacement"
  },
  {
    "from": "WIPED",
    "event": "Recorded destination intact",
    "to": "LOCKED or RECOVERY_REQUIRED"
  },
  {
    "from": "WIPE_UNCONFIRMED",
    "event": "Attended old-process absence plus storage reconciliation",
    "to": "RECOVERY_REQUIRED, then explicit recovery"
  },
  {
    "from": "RECOVERY_REQUIRED",
    "event": "Owner selects D8 C14/C15/C16 transaction",
    "to": "RECOVERING"
  },
  {
    "from": "RECOVERING",
    "event": "Validated durable reconciliation, worker gone",
    "to": "LOCKED, never directly UNLOCKED"
  },
  {
    "from": "RECOVERING",
    "event": "Replacement commits old retirement and independent new enrollment",
    "to": "RETIRED for old enrollment; new enrollment follows provision to LOCKED"
  },
  {
    "from": "LOCKED",
    "event": "C17 exact nonsecret orphan cleanup",
    "to": "LOCKED"
  },
  {
    "from": "RECOVERING",
    "event": "Error/cut/deadline",
    "to": "LOCKING with destination RECOVERY_REQUIRED"
  },
  {
    "from": "LOCKED",
    "event": "Explicit owner retirement, signed boundary already prepared or declared gap",
    "to": "RETIRED"
  },
  {
    "from": "RETIRED",
    "event": "Historical read only",
    "to": "RETIRED"
  }
] as const;
export function transition(from: string, event: string): string {
  const row = ALLOWED_TRANSITIONS.find(entry => entry.from === from && entry.event === event);
  // Unlisted transitions deny because absence from the relation grants no lifecycle authority.
  if (!row) return refuse();
  return row.to;
}
