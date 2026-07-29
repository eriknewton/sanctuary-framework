/**
 * The SINGLE construction site for every causal claim the evidence pack makes
 * about WHY the retained audit log's history begins where it does.
 *
 * D11-1 (dry-bar round 11), the finding this module exists to make
 * unrepresentable: the zero-coverage arm of {@link detectShortfall} told a law
 * firm "This almost always means earlier entries were pruned by size/count
 * (FIFO) retention" while the pack held `ever_pruned === false` -- the field
 * whose own doc-comment calls it "the definitive discriminator" for exactly
 * that question, and which the sibling start-shortfall arm forty lines away
 * consulted correctly. Two packs generated seconds apart from the SAME fortress
 * therefore gave the firm directly contradictory causal diagnoses of the SAME
 * timestamp, in a SIGNED document. The harm direction is self-incriminating:
 * it tells a firm audit records were destroyed by retention when they never
 * existed, which in a discovery or malpractice context is spoliation-adjacent
 * language.
 *
 * The defect was not arithmetic. It was a causal diagnosis stated without
 * consulting the field that settles it. Ten rounds of point-fixes had each
 * moved that shape to a neighbouring surface, so the fix here is structural
 * rather than a second `ever_pruned` check at the old call site:
 *
 *  1. **One constructor.** {@link diagnoseHistoryGap} is the only function in
 *     the evidence pack that may produce a sentence attributing (or declining
 *     to attribute) the gap to pruning. Every arm composes its prose from the
 *     {@link HistoryGapDiagnosis} this returns.
 *  2. **It cannot be called without the discriminator.** The parameter object
 *     requires `ever_pruned` plus the at-cap determinability pair, so there is
 *     no route to a causal clause that skips them.
 *
 *     HONEST BOUND on what (2) does and does not buy (gate finding F1,
 *     2026-07-18, established by a 12-cell brute force of the fact space, not
 *     by code read): requiring the discriminator as a parameter forces it to be
 *     PASSED, not to be DECISIVE. `buildDiagnosis` orders the `at_cap` arm
 *     ABOVE `ever_pruned`, so with `ever_pruned === false` and the log at a
 *     retention cap, 3 of 4 cells still emit the hedged "may have been pruned
 *     by size/count (FIFO) retention" into the SIGNED artifact. That is NOT the
 *     definitive false verdict D11-1 was (the language is hedged, so it does
 *     not breach the stated bar, and it is not a regression), but this module
 *     must not be read as guaranteeing that `ever_pruned === false` suppresses
 *     every pruning clause. It does not. Reordering `at_cap` below the
 *     discriminator is a semantic change and is queued for round 12, NOT done
 *     here. Do not restate property (2) more strongly than this paragraph.
 *  3. **The vocabulary is confined here.** The pruning-assertion phrases exist
 *     as constants in this file only; `history-attribution-chokepoint.test.ts`
 *     fails if any other evidence-pack module reintroduces them, which is what
 *     stops the class from reappearing on the next neighbouring surface.
 *  4. **Fail-closed construction guard.** {@link diagnoseHistoryGap} asserts its
 *     own output before returning: a diagnosis that asserts pruning while the
 *     facts say the log never pruned throws rather than ships. A future edit
 *     that reintroduces the contradiction cannot produce a signed artifact.
 *
 * D11-3 (round 11), fixed here too because it lives in the same sentences: the
 * advice half used to say "raise the retention cap". The shipped server
 * constructs `new AuditLog(storage, masterKey)` with no config (`index.ts`), and
 * `AuditLogConfig.maxEntries` is set only by tests -- there is no config file
 * field, environment variable, or CLI flag that raises it. Advising a firm's
 * operator to do something the product exposes no way to do fails the same
 * honesty bar as a false figure, so the advice now names only the remediation
 * that actually ships: `sanctuary audit-chain export`.
 */

/**
 * What the pack can honestly say about the log's pruning history. Ordered by
 * how much the facts settle, most-settled first.
 *
 * - `never_pruned`: DEFINITIVE. The log never pruned AND is definitively below
 *   both caps, so its true earliest entry is still retained: any gap before it
 *   is genuine inactivity, not destroyed records.
 * - `at_cap`: the log sits at a retention cap, so FIFO pruning of earlier
 *   entries is actively expected.
 * - `has_pruned`: the log has pruned at least once. Pruning is a fact; whether
 *   THIS gap is that pruning still is not.
 * - `undetermined`: the discriminator could not be read, or at-cap position is
 *   not determinable. Assert neither cause.
 */
export type HistoryGapAttribution =
  | "never_pruned"
  | "at_cap"
  | "has_pruned"
  | "undetermined";

/**
 * The retention facts that settle {@link HistoryGapAttribution}. Required, not
 * optional: a caller cannot reach a causal clause without supplying the
 * discriminator, which is the structural half of the D11-1 fix.
 */
export interface HistoryGapFacts {
  /**
   * `RetentionFacts.ever_pruned` -- the definitive discriminator between
   * genuine inactivity and destroyed records. `null` when it could not be read.
   */
  readonly ever_pruned: boolean | null;
  /**
   * Whether "at a retention cap" is computable at all from the facts read (the
   * `retentionDeterminability` chokepoint's verdict). When false, the
   * flattering `never_pruned` reassurance must not fire: `!at_cap` is then true
   * only because at-cap was never asserted, NOT because below-cap was proven.
   */
  readonly at_cap_determinable: boolean;
  /** Whether any contributing store is at its own entry or size cap. */
  readonly at_cap: boolean;
}

/**
 * A settled causal diagnosis. `cause` states what the pack knows about pruning;
 * `advice` states remediation and is the EMPTY string when no remediation is
 * honest (nothing was pruned) -- callers append it unconditionally.
 */
export interface HistoryGapDiagnosis {
  readonly attribution: HistoryGapAttribution;
  /** Sentence attributing, or declining to attribute, the gap. Never empty. */
  readonly cause: string;
  /** Remediation sentence, or "" when none applies. */
  readonly advice: string;
}

/**
 * The pruning-assertion vocabulary, confined to this module. Any evidence-pack
 * module that reintroduces these phrases is asserting a cause outside the one
 * constructor, which is the D11-1 defect; the chokepoint test enforces that.
 */
const PRUNED_ASSERTION = "entries were pruned";
const FIFO_ASSERTION = "pruned by size/count (FIFO) retention";

/**
 * Affirmative pruning claims, for the fail-closed guard below. A `never_pruned`
 * diagnosis rendering any of these would be the D11-1 defect exactly. The
 * negated form ("not that entries were pruned") is correct prose for that arm
 * and is deliberately absent from this list.
 */
const AFFIRMATIVE_PRUNING_CLAIMS: readonly string[] = [
  FIFO_ASSERTION,
  "means earlier " + PRUNED_ASSERTION,
  "may have been pruned",
  "has pruned entries",
  "at a retention cap",
];

/**
 * The only actionable remediation the product ships. See the D11-3 note in the
 * module header for why the retention cap is deliberately not mentioned.
 */
const SNAPSHOT_ADVICE =
  " Export periodic snapshots (`sanctuary audit-chain export`) so a later " +
  "report can cover periods this one cannot.";

/**
 * The single place any causal claim about the log's history is constructed.
 *
 * Consults `ever_pruned` -- the definitive discriminator -- on EVERY path, so a
 * never-pruned log can never be told its entries were pruned, and an unread
 * discriminator can never produce a definitive cause in either direction.
 *
 * @throws if the diagnosis it built contradicts the facts it was given. This is
 * a fail-closed construction guard, not input validation: it fires only on a
 * programming error in this module, and it fires BEFORE a contradictory
 * sentence can be signed into an artifact a law firm relies on.
 */
export function diagnoseHistoryGap(
  facts: HistoryGapFacts
): HistoryGapDiagnosis {
  const diagnosis = buildDiagnosis(facts);

  // Fail-closed guard. `never_pruned` is the arm where a contradiction would be
  // actively harmful (telling a firm records were destroyed when none were), so
  // prove the rendered text makes no AFFIRMATIVE pruning claim before returning
  // it. Negated forms ("not that entries were pruned") are the correct prose for
  // this arm and are deliberately not matched.
  if (diagnosis.attribution === "never_pruned") {
    const rendered = diagnosis.cause + diagnosis.advice;
    const affirmsPruning = AFFIRMATIVE_PRUNING_CLAIMS.some((claim) =>
      rendered.includes(claim)
    );
    if (affirmsPruning) {
      throw new Error(
        "evidence-pack history attribution: built a diagnosis asserting that " +
          "entries were pruned from a log whose ever_pruned discriminator says " +
          "nothing was ever pruned. Refusing to render a causal claim the facts " +
          "contradict."
      );
    }
  }
  // A definitive claim about the PRUNING HISTORY -- in either direction --
  // requires the discriminator to have been read.
  //
  // `at_cap` is deliberately NOT in this list: it is a claim about the log's
  // CAP POSITION, read independently of `ever_pruned`, and its prose asserts no
  // definitive cause ("may have been ... cannot be affirmed here"). An earlier
  // draft of this guard rejected `at_cap` under an unread discriminator, which
  // made an honest and reachable fortress state (cap position known, rotation
  // anchor unreadable) throw at generation time and emit NO pack at all. Failing
  // closed on a claim the pack is entitled to make is its own defect.
  const claimsPruningHistory =
    diagnosis.attribution === "never_pruned" ||
    diagnosis.attribution === "has_pruned";
  if (facts.ever_pruned === null && claimsPruningHistory) {
    throw new Error(
      "evidence-pack history attribution: built a definitive '" +
        diagnosis.attribution +
        "' diagnosis while the ever_pruned discriminator could not be read."
    );
  }
  return diagnosis;
}

function buildDiagnosis(facts: HistoryGapFacts): HistoryGapDiagnosis {
  // DEFINITIVE never-pruned. Requires the discriminator to say so AND the
  // at-cap position to be definitively below both caps: `ever_pruned === false`
  // alone does not exclude sitting exactly AT a cap with the next append about
  // to prune, and an undeterminable cap position cannot prove below-cap.
  if (
    facts.ever_pruned === false &&
    facts.at_cap_determinable &&
    !facts.at_cap
  ) {
    return {
      attribution: "never_pruned",
      cause:
        "The log has never pruned entries (it is below both its entry and " +
        "size retention caps), so this reflects that the fortress had no " +
        "recorded activity in that period, not that " +
        PRUNED_ASSERTION +
        ".",
      advice: "",
    };
  }

  // At a cap: pruning of earlier entries is actively expected. Checked before
  // `has_pruned` so the more actionable state is the one reported.
  if (facts.at_cap_determinable && facts.at_cap) {
    return {
      attribution: "at_cap",
      cause:
        "The log is at a retention cap (entries or size), so earlier entries " +
        "may have been " +
        FIFO_ASSERTION +
        "; whether this gap is pruning or genuine inactivity cannot be " +
        "affirmed here.",
      advice: SNAPSHOT_ADVICE,
    };
  }

  // The log HAS pruned at some point. That is a fact; that THIS gap is that
  // pruning is not, and the pack says so rather than asserting the cause.
  if (facts.ever_pruned === true) {
    return {
      attribution: "has_pruned",
      cause:
        "The log has pruned entries at least once, so earlier entries may " +
        "have been " +
        FIFO_ASSERTION +
        "; whether this gap is pruning or genuine inactivity cannot be " +
        "affirmed here.",
      advice: SNAPSHOT_ADVICE,
    };
  }

  // Discriminator unread, or at-cap position not determinable. Assert neither
  // cause. This is the arm a merged census with no per-store breakdown lands
  // in, and the arm an unread `ever_pruned` lands in.
  return {
    attribution: "undetermined",
    cause:
      "Whether earlier entries were " +
      FIFO_ASSERTION +
      " or the fortress simply had no earlier recorded activity cannot be " +
      "determined from this report: size-based pruning of large early entries " +
      "cannot be ruled out.",
    advice: SNAPSHOT_ADVICE,
  };
}
