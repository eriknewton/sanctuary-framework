/**
 * Closed pre-mutation authorization predicate shared by every P1 path.
 *
 * The adapter (`wrap/local-intelligence.ts`) and the sequencer
 * (`intelligence/provisioning.ts`) both consume THIS function, so the decision
 * whether a run is authorized, unrequested, or refused exists once. A second
 * hand-mirrored copy of the truth table is how "not requested" and "asked for
 * and impossible" drifted apart in the first place.
 */

/**
 * The operator-facing hint naming the one flag that opts a headless run into
 * the ceremony. Must match the `--provision-local-intelligence` case in
 * `wrap/cli.ts` and `wrap/init.ts`; the flag name travels with the hint so a
 * rename cannot leave the advice pointing at a flag that no longer parses.
 */
export const LOCAL_INTELLIGENCE_OPT_IN_HINT =
  "re-run with --provision-local-intelligence on an interactive terminal to set it up";

export type LocalProvisioningPreflight =
  /** The operator opted in, or a terminal is present to ask. */
  | { kind: "proceed" }
  /**
   * Nobody asked for local intelligence on this run: no flag, and no terminal
   * that could be asked. This is NOT a refusal. It records nothing, degrades
   * nothing, and leaves the fortress exactly as it was.
   */
  | { kind: "not-requested" }
  /** The operator asked (or declined) and the answer is a refusal. */
  | { kind: "refused"; reason: "declined" | "non_tty" };

export function localProvisioningPreflight(
  isTty: boolean,
  preAnswered: boolean | undefined,
): LocalProvisioningPreflight {
  // An explicit `--no-provision-local-intelligence` is a decision about local
  // intelligence, so it stays an audited, recorded decline.
  if (preAnswered === false) return { kind: "refused", reason: "declined" };
  // INVARIANT: an absent flag on a headless run is silence, not a request. A
  // refusal row and a persisted provisioning failure here would degrade a
  // fortress on behalf of an operator who never mentioned local intelligence.
  if (!isTty && preAnswered === undefined) return { kind: "not-requested" };
  // A positive flag enters the ceremony but never grants headless mutation:
  // the operator asked for something this run cannot honestly do, so it is
  // refused out loud rather than skipped.
  if (!isTty) return { kind: "refused", reason: "non_tty" };
  return { kind: "proceed" };
}
