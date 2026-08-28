/**
 * Fleet entitlement plan catalog (Slice 1 of the fleet billing build).
 *
 * A "plan" is a named, pre-ratified bundle of entitlement-claim defaults an
 * operator can reach with `sanctuary license issue --plan <name>` instead of
 * assembling the raw `--tier`/`--nodes`/`--features`/`--pricing-unit` flags
 * by hand (Slice 2, `cli/license.ts`). This module is PURE DATA + a PURE
 * FUNCTION: no I/O, no crypto, no custody, no signed artifact. It maps a
 * plan name onto the EXISTING v2 claim shape (`entitlement/token.ts`) — no
 * new tier token, no schema change. `token.ts`, `tier.ts`, the entitlement
 * domain labels, and every surface in `reorg-surface-manifest.md` are FROZEN
 * for this slice and this file does not touch any of them.
 *
 * NO DOLLAR AMOUNTS ANYWHERE in this file (code, comments, tests, help
 * text): this is a public repo and pricing wording is owner-gated
 * (AGENTS.md WHAT THESE TOOLS MUST NEVER DO #9, non-disclosure). "Flat to N
 * nodes, then metered per extra node" is a BILLING-side statement; this
 * catalog only ever expresses the resulting NODE COUNT the entitlement layer
 * enforces — deploy-time billing config carries amounts later, out of scope
 * here.
 *
 * Design basis: Review/Sanctuary/Fleet_Billing_Slice0_Packaging_Mapping_2026-08-28.md
 * (decisions D1-D5), which resolves the ratified packaging in
 * Review/Strategy/Fleet_Pricing_Decision_Note_2026-08-03.md onto this shipped
 * schema. Only the Team plan ships in this slice (D1); Pro is deferred (D4)
 * — its shape is recorded there so adding it later needs no new tier token,
 * only a new catalog entry.
 */

import type { EntitlementTier } from "./tier.js";
import type {
  EntitlementFeatureFlag,
  PricingUnit,
} from "./token.js";

/**
 * The full known feature-flag set a v2 license may unlock, in canonical
 * order. MUST MATCH the `EntitlementFeatureFlag` union in `token.ts` —
 * `token.ts` is FROZEN for this slice (no edits permitted), so this array
 * cannot carry a reciprocal "must match" pin comment on that side; the
 * exhaustiveness assertion in `plan-catalog.test.ts` is the enforcement
 * mechanism instead. This ALSO replaces the CLI's own hand-mirrored
 * `KNOWN_FEATURES` set in `cli/license.ts` (previously a second, independent
 * copy of this exact list) so there is ONE source of the known-features set,
 * not two that can silently drift apart (AGENTS.md prose hygiene: cross-file
 * registries are shared, not hand-mirrored).
 */
export const ALL_ENTITLEMENT_FEATURE_FLAGS: readonly EntitlementFeatureFlag[] =
  Object.freeze(["roster", "policy-dist", "kill-safety", "console"]);

/**
 * Nodes included in the Team plan before any `--extra-nodes` purchase.
 * 10 = the ratified Team base node count (Slice-0 note D1: "entitledCount:
 * 10 + extraNodes purchased"). Billing states this to customers as "flat to
 * 10 nodes, then metered per extra node" — a BILLING-side fact; this
 * constant is the entitlement-side node count only, never a dollar amount.
 */
export const TEAM_INCLUDED_NODES = 10;

/**
 * The largest `--extra-nodes` purchase the Team plan will accept. DERIVED,
 * not a bare literal: the resulting `entitledCount` is signed into a v2
 * license claim (`entitlement/token.ts`) and persisted in the tamper-evident
 * issuance ledger, so `TEAM_INCLUDED_NODES + extraNodes` must never exceed
 * `Number.MAX_SAFE_INTEGER` -- past that boundary a double can represent an
 * integer VALUE that is not the unique representable integer any more (two
 * different mathematical counts can round to the same float64, or a value
 * can round-trip differently through JSON on a different engine), which
 * would let an operator-supplied `--extra-nodes` produce a claim whose
 * signed node count is not the count the operator actually typed.
 */
export const TEAM_MAX_EXTRA_NODES = Number.MAX_SAFE_INTEGER - TEAM_INCLUDED_NODES;

/**
 * Default grace-period length in days when neither `--grace-days` nor a plan
 * fills it. 14 = the shipped grace default, UNCHANGED by this slice (Slice-0
 * note D1: "grace default stays the shipped 14-day default"). Single-sourced
 * here (not re-declared in `cli/license.ts`) so the CLI's raw `--grace-days`
 * default and every plan's `defaultGraceDays` cannot drift apart — a single
 * constant, not a mirrored pair.
 */
export const DEFAULT_GRACE_DAYS = 14;

/**
 * The closed set of purchasable plan names this catalog knows. Team is the
 * only plan that ships in this slice (Slice-0 D1); Pro is deferred (D4) and
 * intentionally absent here until its own slice-0 lands.
 */
export const PLAN_NAMES = Object.freeze(["team"] as const);

/** A single purchasable plan name. */
export type PlanName = (typeof PLAN_NAMES)[number];

/** True when `value` is a known plan name. */
export function isPlanName(value: unknown): value is PlanName {
  return (
    typeof value === "string" && (PLAN_NAMES as readonly string[]).includes(value)
  );
}

/**
 * A plan's claim template: everything a caller needs to fill an
 * `EntitlementClaimsV2` from a plan name plus an overage count, EXCEPT the
 * per-issuance fields a plan cannot know ahead of time (subject,
 * notBefore/notAfter, licenseId, issuer). The billing `period` also stays an
 * explicit per-issuance operator choice, not catalog data — every plan
 * supports the full `monthly | annual` set today, so there is nothing for
 * the catalog to constrain (see `cli/license.ts`).
 */
export interface PlanClaimTemplate {
  readonly tier: EntitlementTier;
  readonly pricingUnit: PricingUnit;
  readonly featureFlags: readonly EntitlementFeatureFlag[];
  readonly defaultGraceDays: number;
  /** The largest `--extra-nodes` this plan will accept (see
   * `TEAM_MAX_EXTRA_NODES`'s derivation comment for why this bound exists).
   * A caller (the CLI) validates against this BEFORE calling
   * `entitledCount`, so the operator sees the bound in the refusal message
   * rather than a generic overflow error. */
  readonly maxExtraNodes: number;
  /**
   * Overage math: the total entitled node count for a given `--extra-nodes`
   * purchase past the plan's included floor. Throws on a non-safe-integer,
   * negative, or over-`maxExtraNodes` input — a caller (the CLI) validates
   * `extraNodes` first, so reaching this with a bad value is a caller bug
   * that must fail loud, never silently coerce to a wrong (or unsafely
   * rounded) node count that then gets SIGNED into a license claim.
   */
  entitledCount(extraNodes: number): number;
}

function teamEntitledCount(extraNodes: number): number {
  if (
    !Number.isSafeInteger(extraNodes) ||
    extraNodes < 0 ||
    extraNodes > TEAM_MAX_EXTRA_NODES
  ) {
    throw new RangeError(
      `extraNodes must be a safe non-negative integer no greater than ` +
        `${TEAM_MAX_EXTRA_NODES}, got ${extraNodes}`,
    );
  }
  return TEAM_INCLUDED_NODES + extraNodes;
}

/**
 * The plan catalog: plan name -> claim template. FROZEN (the outer record
 * AND the one template object it holds) so a consumer cannot mutate a shared
 * template in place and corrupt every future `--plan team` issuance that
 * reads the same frozen object.
 */
export const PLAN_CATALOG: Readonly<Record<PlanName, PlanClaimTemplate>> =
  Object.freeze({
    team: Object.freeze({
      tier: "team",
      pricingUnit: "node",
      featureFlags: ALL_ENTITLEMENT_FEATURE_FLAGS,
      defaultGraceDays: DEFAULT_GRACE_DAYS,
      maxExtraNodes: TEAM_MAX_EXTRA_NODES,
      entitledCount: teamEntitledCount,
    }),
  });

/**
 * Plan name -> claim template. The pure lookup `cli/license.ts` calls after
 * validating the name with `isPlanName`. Throws on an unknown plan name
 * (rather than returning `undefined`) so a caller that skips the
 * `isPlanName` guard fails loud instead of a filled claim silently carrying
 * `undefined` fields into signing.
 */
export function getPlanClaimTemplate(plan: PlanName): PlanClaimTemplate {
  const template = PLAN_CATALOG[plan];
  if (!template) {
    throw new RangeError(`unknown plan '${plan}'`);
  }
  return template;
}
