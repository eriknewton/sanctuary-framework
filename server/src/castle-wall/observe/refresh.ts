/**
 * THE refresh chokepoint: recorded denied-flow audit history -> candidate
 * store, IDEMPOTENTLY and ALLOWLIST-AWARE (sweep finding R3-1, 2026-07-14).
 *
 * The pre-watermark engine (`cli/castle-wall-observe.ts` calling
 * `foldObservations` + `mergeObservations` directly) re-folded the FULL
 * retained `egress_blocked` history on every `observe candidates` run and
 * merged ADDITIVELY, so:
 *   (a) `times_seen` multiplied ~N-fold across N refreshes (a wrong number
 *       everywhere it renders, including the signed evidence pack), and
 *   (b) a candidate the operator PROMOTED (now allowed) or DISCARDED was
 *       re-minted from the already-folded history on the next refresh.
 *
 * This module fixes both at ONE chokepoint (the whack-a-mole -> chokepoint
 * rule; do not re-fix per surface):
 *
 * 1. FOLD WATERMARK (idempotency). Every audit-chain event is folded exactly
 *    once, ever: the store persists the highest authenticated chain sequence
 *    already folded (`FoldWatermark`), and a refresh folds only entries with
 *    a HIGHER sequence. Sequences come from `AuditLog.streamVerifiedChain`,
 *    the same strict-verified, append-monotonic, prune-stable hash-chain
 *    position the workload registry replays by -- never a skewable
 *    wall-clock timestamp. Chosen over replace-only recompute because it
 *    also gives discard/promote the semantics the operator (and the
 *    evidence pack's legend) expects: a removed candidate is re-minted only
 *    by a genuinely NEW observation, with its count restarted -- never
 *    resurrected from stale history.
 *
 *    Crash ordering: the watermark is advanced BEFORE the fold is merged.
 *    A crash between the two loses that delta batch (an undercount -- and a
 *    still-denied destination re-mints itself on the agent's next attempt),
 *    but can never double-count. Fail toward NOT promoting / NOT inflating,
 *    never toward an overstated Seen count in a signed artifact.
 *
 * 2. RECOMPUTE HEAL (bootstrap + anomaly). With no valid watermark (fresh
 *    store, a store written by the pre-watermark engine, or a watermark
 *    ahead of the chain head after an audit-store reset), the refresh
 *    replays the full retained history and REPLACE-writes each folded key
 *    (`replaceObservations`): re-running converges to the true
 *    retained-history counts instead of accumulating. This is the one-time
 *    heal for stores the old engine inflated.
 *
 * 3. ALLOWLIST-AWARE FOLD + PRUNE. A folded row whose destination the
 *    CURRENT cryptographically verified manifest already allows is never
 *    minted (suppressed), and a persisted row that is now allowed is
 *    removed -- so after a clean refresh, no pending candidate names a
 *    destination the operator's policy permits (the invariant the evidence
 *    pack's "Destinations permitted by the operator's policy do NOT appear
 *    here" legend asserts). Matching goes through the enforcing evaluator's
 *    OWN matcher (`../allowlist/match.ts` -- the parity chokepoint shared
 *    with `egress-proxy.ts`; observe/ still never imports the evaluator
 *    module, preserving THE RED-LINE structural pin). An allowlist that is
 *    present but does NOT verify aborts the refresh loud -- never silently
 *    skips the filter (WHAT THESE TOOLS MUST NEVER DO #5). Pruning is
 *    safe-direction (removes candidate rows, exactly like `observe
 *    discard`; never adds a rule) and fail-closed on doubt: a destination
 *    that cannot be canonicalized cannot be allowed by the wall, so its row
 *    is KEPT, and suppression happens only on a positive verified match.
 *
 * RED-LINE (unchanged): nothing here writes the live signed allowlist. This
 * module READS the verified manifest and writes only the reserved,
 * agent-invisible candidate namespace. The enforcing evaluator still never
 * reads the candidate store.
 */

import type { AllowlistRule } from "../allowlist/schema.js";
import {
  allowlistAllowsFlow,
  canonicalizeConnectAuthority,
  type CanonicalConnectAuthority,
} from "../allowlist/match.js";
import type { VerifiedChainConsumer } from "../../operational/audit-log.js";
import { flowEventFromAuditEntry } from "./adapter.js";
import { foldObservations } from "./fold.js";
import type { CandidateObservation, FlowObservationEvent, FoldWatermark } from "./types.js";

/** Narrow audit surface the refresh needs; `AuditLog` satisfies it. Strict verification is the contract: the stream throws on a chain-integrity failure, so a refresh never folds over an unverified chain. */
export interface RefreshAuditSource {
  streamVerifiedChain(consumer: VerifiedChainConsumer): Promise<void>;
}

/** Narrow candidate-store surface the refresh needs; `ObserveStore` satisfies it. */
export interface RefreshCandidateStore {
  getFoldWatermark(): Promise<FoldWatermark | null>;
  setFoldWatermark(watermark: FoldWatermark): Promise<void>;
  listCandidates(): Promise<Map<string, CandidateObservation>>;
  mergeObservations(observations: readonly CandidateObservation[]): Promise<void>;
  replaceObservations(observations: readonly CandidateObservation[]): Promise<void>;
  removeCandidate(key: string): Promise<void>;
}

/**
 * The current live allowlist, as the CALLER read + verified it.
 *   - `ok`: `rules` is the cryptographically verified ruleset (empty on a
 *     fresh install with no manifest -- the filter is then vacuous).
 *   - `unverified`: a manifest exists but could not be verified (bad
 *     signature, corrupt file, missing pinned key, ...). The refresh ABORTS
 *     without folding or writing anything -- never silently proceeds with an
 *     unfiltered fold.
 */
export type RefreshAllowlistRead =
  | { status: "ok"; rules: AllowlistRule[] }
  | { status: "unverified"; reason: string };

export interface RefreshDeps {
  auditLog: RefreshAuditSource;
  store: RefreshCandidateStore;
  readAllowlist: () => Promise<RefreshAllowlistRead>;
  now: Date;
}

export type RefreshOutcome =
  | {
      status: "refreshed";
      /** `incremental`: folded only entries past the watermark, merged additively. `recompute`: no valid watermark -- replayed full retained history with replace semantics (the heal path). */
      mode: "incremental" | "recompute";
      /** Denied-flow events this pass actually folded (post-watermark in incremental mode). */
      folded_events: number;
      /** Folded candidate rows suppressed because the verified allowlist already permits them (never minted). */
      suppressed_allowed: number;
      /** Persisted candidate rows removed because the verified allowlist now permits them. */
      removed_now_allowed: number;
    }
  | { status: "allowlist_unverified"; reason: string };

/**
 * Is this candidate's destination allowed by the CURRENT verified ruleset,
 * per the enforcing evaluator's own matcher? Fail-closed toward KEEPING the
 * candidate: a destination that cannot canonicalize can never be allowed by
 * the wall (the proxy denies `canonicalization_failed`), so it stays a
 * candidate; only a positive verified match suppresses/prunes.
 */
export function candidateCurrentlyAllowed(
  rules: readonly AllowlistRule[],
  row: Pick<CandidateObservation, "host" | "ip" | "port" | "protocol">,
): boolean {
  if (rules.length === 0) return false;
  const dest = row.host ?? row.ip;
  let target: CanonicalConnectAuthority;
  try {
    // A raw IPv6 literal needs brackets to form a canonical authority.
    const authorityHost = dest.includes(":") && !dest.startsWith("[") ? `[${dest}]` : dest;
    target = canonicalizeConnectAuthority(`${authorityHost}:${row.port}`);
  } catch {
    return false;
  }
  return allowlistAllowsFlow([...rules], target, row.protocol);
}

/**
 * Refresh the candidate store from the verified audit chain. See the module
 * header for the three guarantees (fold watermark, recompute heal,
 * allowlist-aware fold + prune). Throws if the audit chain fails strict
 * verification (`streamVerifiedChain`'s contract) -- the caller surfaces
 * that loud and writes nothing, because all writes happen only after the
 * stream returns clean.
 */
export async function refreshCandidatesFromAudit(deps: RefreshDeps): Promise<RefreshOutcome> {
  const allowlist = await deps.readAllowlist();
  if (allowlist.status === "unverified") {
    return { status: "allowlist_unverified", reason: allowlist.reason };
  }

  // ── Single verified pass over the chain (buffered writes: nothing below
  // touches the store until the stream has returned clean). ──
  let events: Array<{ sequence: number; event: FlowObservationEvent }> = [];
  let headSequence: number | null = null;
  await deps.auditLog.streamVerifiedChain({
    onEntry: ({ sequence, entry }) => {
      if (headSequence === null || sequence > headSequence) headSequence = sequence;
      const event = flowEventFromAuditEntry(entry);
      if (event) events.push({ sequence, event });
    },
    reset: () => {
      events = [];
      headSequence = null;
    },
  });

  const watermark = await deps.store.getFoldWatermark();
  const chainHead: number | null = headSequence;

  // Recompute when there is no watermark to trust: never seen one (fresh
  // store, or a store written by the pre-watermark engine -- the heal), or
  // the persisted watermark is AHEAD of the surviving chain head (the audit
  // store was reset/rebuilt underneath us; the old positions are meaningless
  // against the new chain, and replaying with replace semantics converges).
  const recompute = watermark === null || (chainHead !== null && watermark.folded_through_sequence > chainHead);
  const foldableEvents = recompute
    ? events.map((item) => item.event)
    : events.filter((item) => item.sequence > watermark!.folded_through_sequence).map((item) => item.event);

  const folded = foldObservations(foldableEvents);
  const kept: CandidateObservation[] = [];
  let suppressedAllowed = 0;
  for (const row of folded) {
    if (candidateCurrentlyAllowed(allowlist.rules, row)) {
      suppressedAllowed += 1;
      continue;
    }
    kept.push(row);
  }

  // Crash-ordering, per mode (neither write pair is atomic, so pick the
  // order whose crash window can never double-count):
  //   - INCREMENTAL (additive merge): watermark FIRST. A crash between the
  //     two loses the delta batch -- an undercount that a still-denied
  //     destination re-mints on the agent's next attempt -- and can never
  //     re-add already-merged events.
  //   - RECOMPUTE (idempotent replace): replace FIRST. A crash before the
  //     watermark lands just recomputes again next run (replace converges);
  //     writing the watermark first would strand the heal as a permanently
  //     un-applied "incremental with nothing new".
  const advanceWatermark = async (): Promise<void> => {
    if (chainHead === null) return;
    if (watermark !== null && watermark.folded_through_sequence === chainHead) return;
    await deps.store.setFoldWatermark({
      folded_through_sequence: chainHead,
      updated_at: deps.now.toISOString(),
    });
  };

  if (recompute) {
    await deps.store.replaceObservations(kept);
    await advanceWatermark();
  } else {
    await advanceWatermark();
    await deps.store.mergeObservations(kept);
  }

  // ── Allowlist prune over the PERSISTED set: a pending candidate whose
  // destination the operator's verified policy now permits is removed (the
  // same safe direction as `observe discard`; never adds a rule). Runs even
  // when nothing new folded, so a promote in another template/session is
  // reconciled on the very next refresh. ──
  let removedNowAllowed = 0;
  const persisted = await deps.store.listCandidates();
  for (const [key, candidate] of persisted) {
    if (candidateCurrentlyAllowed(allowlist.rules, candidate)) {
      await deps.store.removeCandidate(key);
      removedNowAllowed += 1;
    }
  }

  return {
    status: "refreshed",
    mode: recompute ? "recompute" : "incremental",
    folded_events: foldableEvents.length,
    suppressed_allowed: suppressedAllowed,
    removed_now_allowed: removedNowAllowed,
  };
}
