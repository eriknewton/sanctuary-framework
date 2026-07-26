/**
 * The ONE place every pack artifact declares the window it was actually taken
 * over.
 *
 * D11-2 (Claude lens, dry-bar round 11): the pack is a quarter-scoped signed
 * document -- its cover states `Reporting quarter: 2026-Q1` -- but several of
 * the things it ships are not quarter-scoped at all, and nothing said so. The
 * sharpest observed case: a Q1 pack asserted, signed, "Total recorded audit
 * operations in the quarter: 0" and "NONE of this quarter is covered", and
 * shipped beside it an `audit-chain.jsonl` holding 17 timestamped audit records,
 * ZERO of which fell in the reporting quarter. Both lenses grepped the rendered
 * reports for any scope disclosure and found none.
 *
 * A reader is then left with two available conclusions, both wrong: "the report
 * says 0 but the evidence file has 17 records, so the report is understating",
 * or "these 17 records are the Q1 evidence". There is also a secondary
 * over-disclosure consequence: a firm asked for Q1 hands its carrier a signed
 * record set covering Q2 and Q3 activity nobody asked about.
 *
 * The whole-log export is technically NECESSARY -- a hash chain must be
 * contiguous to verify, and a quarter-sliced subset would break at the boundary
 * -- so the defect is the missing declaration, not the behaviour. The fix is
 * therefore a declaration that cannot be forgotten:
 *
 * {@link ARTIFACT_SCOPES} is a total `Record` over {@link PackArtifactId}, so
 * adding an artifact to the pack without declaring the window it covers is a
 * COMPILE error, not a review miss. Rendering surfaces call
 * {@link declareArtifactScope} rather than writing scope prose inline, so the
 * declaration cannot drift from the registry either.
 */

/** Every artifact the pack ships or summarises whose scope a reader could misread. */
export type PackArtifactId =
  | "transparency_bundle"
  | "audit_chain"
  | "anchor_evidence"
  | "tool_inventory";

/**
 * The window an artifact's contents actually cover, as distinct from the
 * reporting quarter printed on the pack's cover.
 */
export type ArtifactScope =
  /** Contents are confined to the reporting quarter. Needs no disclosure. */
  | { readonly kind: "reporting_quarter" }
  /**
   * Contents span the fortress's entire retained history, across all quarters.
   * `why` states the technical reason, so the disclosure explains rather than
   * merely warns.
   */
  | { readonly kind: "whole_retained_history"; readonly why: string }
  /**
   * Contents are a snapshot read at generation time, so they describe the
   * fortress as of the moment the pack was made, NOT as of the quarter.
   */
  | { readonly kind: "generation_time_snapshot" };

/**
 * Total registry: every {@link PackArtifactId} must appear. TypeScript enforces
 * that, which is the anti-drift property this module exists for.
 */
const ARTIFACT_SCOPES: Record<PackArtifactId, ArtifactScope> = {
  audit_chain: {
    kind: "whole_retained_history",
    why:
      "a hash chain must be contiguous to verify, so slicing it to one quarter " +
      "would break the chain at the boundary and make it unverifiable",
  },
  transparency_bundle: {
    kind: "whole_retained_history",
    why:
      "the checkpoint chain is verified from its genesis root, so a " +
      "quarter-sliced bundle could not be checked",
  },
  anchor_evidence: {
    kind: "whole_retained_history",
    why: "the receipts are recorded per checkpoint counter, not per quarter",
  },
  tool_inventory: { kind: "generation_time_snapshot" },
};

/**
 * The disclosure sentence for an artifact whose scope differs from the pack's
 * reporting quarter, or "" when it does not differ.
 *
 * Callers append the result unconditionally: an artifact that IS quarter-scoped
 * contributes nothing, and one that is not cannot be rendered without its
 * declaration, because this is the only function that produces the prose.
 */
export function declareArtifactScope(
  id: PackArtifactId,
  context: { readonly quarterLabel: string; readonly generatedAt?: string }
): string {
  const scope = ARTIFACT_SCOPES[id];
  switch (scope.kind) {
    case "reporting_quarter":
      return "";
    case "whole_retained_history":
      return (
        ` SCOPE: this file is NOT limited to ${context.quarterLabel}. It spans ` +
        "the fortress's ENTIRE retained history across all quarters, because " +
        scope.why +
        ". Records in it may pre-date or post-date the reporting quarter, and " +
        "its record count is therefore NOT comparable with the in-quarter " +
        "counts stated elsewhere in this report."
      );
    case "generation_time_snapshot":
      return (
        ` SCOPE: this reflects the fortress as of the moment this pack was ` +
        (context.generatedAt !== undefined
          ? `generated (${context.generatedAt})`
          : "generated") +
        `, NOT as of ${context.quarterLabel}. Tools added or removed since the ` +
        "quarter ended are reflected here; tools present during the quarter but " +
        "removed before generation are not."
      );
  }
}
