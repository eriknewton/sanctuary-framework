/**
 * Phase S1 — Supervisor rotation safety (review finding M3).
 *
 * A supervised agent must NOT launch while a master rotation is in flight.
 * Rotation (#501, `core/master-rotation.ts`) is a journaled two-phase re-key:
 * while the journal exists the fortress is split between the old and new
 * master, and `establishMaster` itself refuses to boot then
 * (`CustodyRotationInProgressError`). A supervisor holding the OLD master in
 * memory that launches a child mid-rotation would write under a retired key —
 * split-state, the exact corruption the custody work exists to prevent.
 *
 * So before launching ANY supervised child — and at supervisor boot — we check
 * for the rotation journal and refuse-to-launch / park-all if it is present.
 * This mirrors `establishMaster`'s guard but is reachable from the supervisor
 * without going through a full establishment (the supervisor already holds a
 * transient master and only needs to know "is a rotation in progress?").
 *
 * For S1 the rule is the simplest safe one the brief recommends: a supervised
 * agent refuses to launch during rotation, and (symmetrically) the rotate
 * preflight already refuses while a rotation journal exists. Stopping all
 * supervised agents before a rotation is operator procedure in S1; a
 * drain→re-establish handshake is deferred (design §M3 (b), follow-on).
 */

import { ROTATION_JOURNAL_KEY } from "../core/master-custody.js";
import type { StorageBackend } from "../storage/interface.js";

/**
 * True iff a master-rotation journal is present on the fortress storage —
 * i.e. a rotation is in flight (or crashed mid-flight and needs `--resume`).
 * The supervisor treats `true` as "refuse to launch, park agents needs-unlock
 * until the rotation finishes."
 *
 * Reads the `_meta`/`rotation-journal` entry directly (the same key
 * `establishMaster` and `rotateMaster` guard on). A storage read failure is
 * treated as "in progress" — fail closed: if we cannot prove rotation is NOT
 * happening, we do not launch.
 */
export async function isRotationInProgress(
  storage: StorageBackend,
): Promise<boolean> {
  try {
    const raw = await storage.read("_meta", ROTATION_JOURNAL_KEY);
    return raw !== null;
  } catch {
    // Cannot read the journal marker ⇒ cannot prove safety ⇒ refuse.
    return true;
  }
}
