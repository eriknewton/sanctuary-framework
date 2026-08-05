/**
 * The ONE shape-check for a bundle's `source_custody` block.
 *
 * Two callers need the identical rule and must never drift:
 *
 *  - the import path (`bundle.ts` `resolveSourceMasterKey`), which REFUSES a
 *    malformed block with `SOURCE_CUSTODY_MALFORMED` rather than demoting the
 *    import to the legacy derivation path (a downgrade);
 *  - the verifier (`verifier.ts` `summarizeEncryptedState`), which CLASSIFIES
 *    the block so `sanctuary exit inspect` can name the credential that opens
 *    the bundle.
 *
 * They lived apart once, and the verifier's copy was "is it object-shaped?".
 * A signed-but-malformed bundle therefore inspected as `bundle-rekey-key`,
 * printed the re-key import command, and exited 0, while the import it named
 * refused the block outright. An affordance that confidently names an unusable
 * credential is worse than no affordance, because the operator trusts it while
 * leaving and the source fortress may already be gone. One predicate, two
 * callers, no second copy of the rules to fall behind.
 *
 * This file lives outside `bundle.ts` because `bundle.ts` imports
 * `verifier.ts`; putting the predicate in `bundle.ts` would make the verifier's
 * import of it a cycle. It deliberately has no imports of its own: it is a pure
 * structural check over untrusted parsed JSON, which is the only thing either
 * caller actually holds.
 */

/** The only `source_custody.format` token that has ever been minted. */
export const SOURCE_CUSTODY_FORMAT = "SANCTUARY_EXIT_SOURCE_CUSTODY_V1";

/**
 * Maximum wraps accepted in a bundle's source_custody block. Export emits
 * exactly one; the cap bounds work on crafted bundles (codex round-1 LOW).
 */
export const SOURCE_CUSTODY_MAX_WRAPS = 4;

/**
 * Three-state read of the block, mirroring how import treats it:
 * `absent` (no block: import takes a different path entirely), `valid` (the
 * bundle re-key path is live), `malformed` (import refuses).
 */
export type SourceCustodyState = "absent" | "valid" | "malformed";

/**
 * True when `candidate` is a `source_custody` block the import path will
 * accept. Total over `unknown`: a crafted, truncated, or null block returns
 * false rather than throwing.
 *
 * The `recovery-key`-only wrap restriction is a security rule, not a schema
 * nicety: a passphrase-type wrap here would reintroduce the offline passphrase
 * oracle and feed bundle-controlled Argon2id parameters into the unwrap path
 * (codex round-1 findings 1 and 2). The HKDF unwrap for recovery-key wraps
 * carries no attacker-tunable cost parameters.
 */
export function isValidSourceCustody(candidate: unknown): boolean {
  if (
    candidate === null ||
    typeof candidate !== "object" ||
    Array.isArray(candidate)
  ) {
    return false;
  }
  const custody = candidate as { format?: unknown; wraps?: unknown };
  if (custody.format !== SOURCE_CUSTODY_FORMAT) return false;
  if (!Array.isArray(custody.wraps)) return false;
  if (custody.wraps.length === 0) return false;
  if (custody.wraps.length > SOURCE_CUSTODY_MAX_WRAPS) return false;
  return custody.wraps.every((wrap: unknown) => {
    if (wrap === null || typeof wrap !== "object") return false;
    const candidateWrap = wrap as {
      id?: unknown;
      type?: unknown;
      payload?: unknown;
    };
    return (
      typeof candidateWrap.id === "string" &&
      candidateWrap.type === "recovery-key" &&
      typeof candidateWrap.payload === "object"
    );
  });
}

/**
 * Classify a bundle's `source_custody` field. `undefined` means the artifact
 * carried no block at all; anything else (including `null`) is run through
 * {@link isValidSourceCustody}, exactly as the import path does.
 */
export function readSourceCustodyState(candidate: unknown): SourceCustodyState {
  if (candidate === undefined) return "absent";
  return isValidSourceCustody(candidate) ? "valid" : "malformed";
}
