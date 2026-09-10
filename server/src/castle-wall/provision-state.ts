/**
 * The fortress's own Castle Wall provisioning state: the ONE named answer to
 * "is THIS vault on the wall that is running on THIS machine?"
 *
 * Why a named state exists at all: before this module every surface inferred
 * wall state from something else (the system-extension list, the machine-wide
 * pin file, audit-derived arm evidence), and none of those is a claim ABOUT A
 * VAULT. On a machine that carries a leftover activated extension from an
 * earlier install, "the extension is enabled" is true and says nothing about
 * the vault the operator just created; reporting it as protection is the
 * fail-open this module closes.
 *
 * TWO STATES, ONE WRITER, ONE DERIVATION:
 *
 *  - `not_yet_walled` is the ONLY value ever persisted, and `wrap/init.ts` is
 *    its only writer. It records that a vault was created before the wall was
 *    turned on for it.
 *  - `walled` is DERIVED at read time and is never written by anything. A
 *    surface may report it only from BOTH halves of the pair: the
 *    helper-authoritative trust-anchor verdict is CONSISTENT (the machine-wide
 *    anchor holds the root signer helper's key) AND this fortress's own
 *    enforcement-evidenced arm state is armed.
 *
 * STATED CAPABILITY BOUND (AGENTS.md rule 1: absent, indeterminate, and
 * unproven all read as not-proven, never as passing). A surface that cannot
 * observe both halves reports `not_yet_walled`. That is a deliberate
 * false-negative: under-claiming protection is safe, over-claiming it is the
 * defect. Callers that can observe only one half must pass the honest
 * `"unknown"` rather than inventing the other.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";

/**
 * At-rest `_meta` key carrying the persisted provisioning claim.
 *
 * Cross-file contract, three sides, all of which must agree:
 *  - must match the `case` in `classifyMetaKey` (`core/master-rotation.ts`);
 *    an unrecognized `_meta` key makes master rotation refuse EVERY fortress
 *    that carries it, so a rename without that case bricks rotation.
 *  - must match the hand-typed inventory row in
 *    `test/core/master-rotation-meta-key-parity.test.ts`.
 *  - must match the at-rest row in `server/reorg-surface-manifest.md`.
 *
 * The record is plaintext (the classification is `plaintext-keep`): the value
 * is a product state token, never operator data and never a secret, and
 * diagnostic surfaces that cannot open the fortress must still be able to read
 * it.
 */
export const CASTLE_WALL_PROVISION_META_KEY = "castle-wall-provision-v1";

/** The named states. `walled` is derived only; nothing writes it. */
export type CastleWallProvisionState = "not_yet_walled" | "walled";

/** The only value `wrap/init.ts` ever persists. */
export const CASTLE_WALL_NOT_YET_WALLED = "not_yet_walled";

/**
 * The helper-authoritative trust-anchor verdict, as the relying surface saw
 * it. `unknown` is the honest reading whenever the authoritative comparison
 * (machine-wide pin vs the live signer-helper key) was not made; it never
 * stands in for `consistent`.
 *
 * Must match the `TrustAnchorObservation` vocabulary in `cli/install.ts`
 * (`consistent` / `broken` / `unprovisioned` / `unknown`), which parses the
 * three authoritative verdict lines `cli/castle-wall.ts` prints.
 */
export type TrustAnchorVerdictObservation =
  | "consistent"
  | "broken"
  | "unprovisioned"
  | "unknown";

export interface DeriveCastleWallProvisionInput {
  /** Helper-authoritative anchor verdict; `unknown` when unobservable here. */
  trustAnchor: TrustAnchorVerdictObservation;
  /**
   * This fortress's OWN enforcement-evidenced arm state (the `arm_state ===
   * "armed"` derivation in `principal-policy/posture.ts`), or `"unknown"` when
   * this surface cannot observe it. Host-wide facts (an activated system
   * extension, an enabled content filter) are NOT this observation and must
   * never be passed here: they are true of the machine, not of the vault.
   */
  armed: boolean | "unknown";
}

/**
 * THE derivation chokepoint. Both halves must be positively observed for
 * `walled`; everything else, including every unobservable half, is
 * `not_yet_walled`.
 *
 * Failure mode this shape exists for: a hand-written `if` at each consumer
 * drifts, and a drifted copy that greens on one half is invisible (the surface
 * keeps printing a plausible token). One function, called by every consumer.
 */
export function deriveCastleWallProvision(
  input: DeriveCastleWallProvisionInput,
): CastleWallProvisionState {
  return input.trustAnchor === "consistent" && input.armed === true
    ? "walled"
    : "not_yet_walled";
}

/**
 * Read-only observation of the persisted claim. Three states, because a caller
 * that reads "could not tell" as "no claim" is the same fail-open the
 * machine-wide anchor reader closes.
 */
export type PersistedCastleWallProvisionObservation =
  | { state: "absent" }
  | { state: "not-yet-walled" }
  | { state: "unreadable" };

/**
 * On-disk location of the plaintext `_meta` record.
 *
 * Must match the layout in `storage/filesystem.ts`
 * (`{basePath}/{namespace}/{key}.enc`, with `basePath` = `<fortress>/state`);
 * the key needs no `!`-escaping because every character in it is in that
 * encoder's safe set (`[A-Za-z0-9_.-]`).
 */
export function castleWallProvisionRecordPath(fortressPath: string): string {
  return join(
    fortressPath,
    "state",
    "_meta",
    `${CASTLE_WALL_PROVISION_META_KEY}.enc`,
  );
}

/**
 * Read the persisted claim without opening the fortress.
 *
 * Deliberately tolerant of every read failure: this is consumed by read-only
 * diagnostics (`doctor`, `castle-wall status`) whose whole job is to run on a
 * fortress that may already be broken. `unreadable` and `absent` are distinct
 * so a caller can say which it saw; neither is ever reported as `walled`.
 */
export async function readPersistedCastleWallProvision(
  fortressPath: string,
): Promise<PersistedCastleWallProvisionObservation> {
  try {
    const raw = await readFile(castleWallProvisionRecordPath(fortressPath), "utf8");
    return raw.trim() === CASTLE_WALL_NOT_YET_WALLED
      ? { state: "not-yet-walled" }
      : { state: "unreadable" };
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "ENOENT"
      ? { state: "absent" }
      : { state: "unreadable" };
  }
}

/**
 * The one operator-facing sentence for a record that exists at the claim's path
 * and does not parse (empty, truncated, some token this version does not know).
 *
 * Shared so `doctor` and any later diagnostic cannot drift into two different
 * descriptions of the same state, and deliberately phrased as a statement about
 * the CLAIM rather than about the wall: the honest reading is "this vault's own
 * wall claim is unreadable", never "the wall is broken" and never, as the code
 * did before, silence that a machine-level OK then filled in.
 */
export const CASTLE_WALL_PROVISION_UNREADABLE_MESSAGE =
  "this vault's wall provisioning state is unreadable, so it is not read as " +
  "being on the wall";

/**
 * The one operator-facing sentence for a vault that is not yet on the wall.
 * Shared so `init`, `wrap`, `castle-wall status`, and `doctor` cannot drift
 * into four different descriptions of the same state.
 *
 * Deliberately free of trust-anchor vocabulary: it is read on a first run, by
 * someone who has not yet met the word "pin".
 */
export const CASTLE_WALL_NOT_YET_WALLED_SENTENCE =
  "This vault is not yet on the Castle Wall of this Mac. Turning the wall on " +
  "for this vault is the installer's next step; until then this vault's " +
  "agents are not filtered by this vault's policy.";
