import type { ClaimSiteId } from "./egress-gate/claim-basis.js";

declare const OBSERVED: unique symbol;
declare const VERIFIED_EMPTY: unique symbol;

/**
 * Claim ids whose structural-honesty proof is local to this build slice.
 * Existing ids still live in `egress-gate/claim-basis.ts`; the observe and
 * inventory ids are scoped witnesses for non-egress-gate surfaces.
 */
export const STRUCTURAL_HONESTY_CLAIM_IDS = [
  "provision-orchestrate.armed",
  "provision-orchestrate.disarmed",
  "provision-exclusive-arm.exclusive-armed",
  "provision-exclusive-arm.coarse-composition-restored",
  "observe.source-state",
  "observe.candidate-census",
  "evidence-pack.inventory.empty-verified",
] as const;

export type StructuralHonestyClaimId = typeof STRUCTURAL_HONESTY_CLAIM_IDS[number];
export type ClaimId = ClaimSiteId | StructuralHonestyClaimId;

/** A value produced inside a named observation boundary. */
export type Observed<T> = T & { readonly [OBSERVED]: true };

/** The only constructor for `Observed<T>` values. */
export async function observing<T>(
  label: ClaimId,
  op: () => T | Promise<T>,
): Promise<Observed<Awaited<T>>> {
  void label;
  return (await op()) as Observed<Awaited<T>>;
}

export type SourceReadOutcome =
  | {
      status: "read-and-verified";
      source_id: string;
      record_count: number;
    }
  | {
      status: "read-failed";
      source_id: string;
      reason: string;
    }
  | {
      status: "not-read";
      source_id: string;
      reason: string;
    };

/** Witness that every named source was read and every one produced zero rows. */
export type VerifiedEmpty = { readonly [VERIFIED_EMPTY]: true };

/** Mint a verified-empty witness only from completed zero-row source reads. */
export function verifiedEmptyFrom(
  label: ClaimId,
  sources: readonly SourceReadOutcome[],
): VerifiedEmpty | undefined {
  void label;
  if (sources.length === 0) return undefined;
  const allEmpty = sources.every(
    (source) => source.status === "read-and-verified" && source.record_count === 0,
  );
  return allEmpty ? ({} as VerifiedEmpty) : undefined;
}

/** Render or return a definitive-empty claim only when a verified-empty witness exists. */
export function claimFromVerifiedEmpty<T>(witness: VerifiedEmpty, value: T): T {
  void witness;
  return value;
}
