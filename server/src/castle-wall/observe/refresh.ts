/**
 * THE refresh chokepoint: recorded denied-flow audit history -> candidate
 * store, IDEMPOTENTLY and ALLOWLIST-AWARE (sweep finding R3-1, 2026-07-14;
 * hardened per the two-family Codex gate's fix round, same date).
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
 * 1. FOLD WATERMARK (idempotency), CHAIN-IDENTITY-BOUND. Every audit-chain
 *    event is folded exactly once, ever: the store persists the highest
 *    authenticated chain sequence already folded PLUS the `entry_hash` of
 *    the chained entry at that sequence (`FoldWatermark`), and a refresh
 *    folds only entries with a HIGHER sequence. Sequences and hashes come
 *    from `AuditLog.streamVerifiedChain`, the same strict-verified,
 *    append-monotonic, prune-stable hash-chain position the workload
 *    registry replays by -- never a skewable wall-clock timestamp. The hash
 *    binding (Codex gate HIGH-2) means a watermark is honored ONLY against
 *    the chain that minted it: if the audit store was reset/rebuilt and the
 *    new chain regrew past the old watermark's sequence, the entry at that
 *    sequence carries a different hash, the watermark is invalid, and the
 *    refresh RECOMPUTES instead of silently skipping the new chain's prefix.
 *    (A watermark whose sequence has been FIFO-pruned off the surviving
 *    chain is still honored: the stream's own anchor verification attests
 *    the surviving chain is the same chain's suffix.)
 *
 * 2. CROSS-RUN MUTUAL EXCLUSION (Codex gate BLOCKER). Two concurrent
 *    refreshes would read the same watermark, fold the same suffix, and
 *    additively merge it twice. Every refresh therefore runs under
 *    `deps.lock`: acquire returns null when another refresh holds it, and
 *    the refresh ABORTS (`refresh_in_progress`) without reading or writing
 *    anything. The CLI supplies an O_EXCL lockfile with stale-holder
 *    breaking (see `cli/castle-wall-observe.ts`); in-process callers/tests
 *    use `inProcessRefreshLock()`.
 *
 * 3. RECOMPUTE HEAL (bootstrap + anomaly), REVIEW-MARKER-AWARE. With no
 *    valid watermark (fresh store, a store written by the pre-watermark
 *    engine, or an invalid/mismatched watermark), the refresh replays the
 *    full retained history and REPLACE-writes each folded key that is
 *    ALREADY in the store (`replaceObservations`): re-running converges to
 *    the true retained-history counts instead of accumulating -- the heal
 *    for stores the old engine inflated. A key NOT in the store is minted
 *    only from events recorded AFTER the chain's last observe review action
 *    (`castle_wall_observe_discard` / `castle_wall_observe_promote` audit
 *    entries, which ride the same verified chain): any candidate the
 *    operator discarded under the old engine was folded from events BEFORE
 *    that review, so those events must not resurrect it (Codex gate
 *    HIGH-1). A chain with no review action ever recorded is a fresh
 *    bootstrap and mints from the full retained history (the documented
 *    "observe start -> run agent -> review candidates" flow). The
 *    suppressed direction is conservative and self-healing: a still-denied
 *    destination re-mints itself from its next NEW denial.
 *
 * 4. ALLOWLIST-AWARE FOLD + PRUNE. A folded row whose destination the
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
 * Crash ordering, per mode (neither write pair is atomic; pick the order
 * whose crash window can never double-count):
 *   - INCREMENTAL (additive merge): watermark FIRST. A crash between the two
 *     loses that delta batch -- an undercount that a still-denied destination
 *     re-mints on the agent's next attempt -- and can never re-add
 *     already-merged events.
 *   - RECOMPUTE (idempotent replace): replace FIRST. A crash before the
 *     watermark lands just recomputes again next run (replace converges);
 *     writing the watermark first would strand the heal as a permanently
 *     un-applied "incremental with nothing new".
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
import { candidateKey, type CandidateObservation, type FlowObservationEvent, type FoldWatermark } from "./types.js";

/** The observe review-action audit operations (written by the CLI's discard/promote verbs onto the SAME verified chain the fold streams). Their chain position bounds what a recompute may MINT (module doc, guarantee 3). */
const OBSERVE_REVIEW_OPERATIONS: ReadonlySet<string> = new Set([
  "castle_wall_observe_discard",
  "castle_wall_observe_promote",
]);

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
 * Mutual exclusion for the whole refresh (module doc, guarantee 2).
 * `acquire` returns a release function on success, or `null` when another
 * refresh currently holds the lock -- the refresh then aborts WITHOUT
 * reading or writing anything (fail toward not folding, never toward
 * folding twice). Implementations must be safe to release exactly once.
 */
export interface RefreshLock {
  acquire(): Promise<(() => Promise<void>) | null>;
}

/**
 * A single-process `RefreshLock` (module-level mutual exclusion within one
 * Node process). Sufficient for in-process callers and tests; the CLI uses
 * an O_EXCL lockfile instead because two `observe candidates` INVOCATIONS
 * are separate processes.
 */
export function inProcessRefreshLock(): RefreshLock {
  let held = false;
  return {
    async acquire() {
      if (held) return null;
      held = true;
      return async () => {
        held = false;
      };
    },
  };
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
  /** Mutual exclusion across concurrent refreshes (Codex gate BLOCKER; see {@link RefreshLock}). */
  lock: RefreshLock;
  now: Date;
}

export type RefreshOutcome =
  | {
      status: "refreshed";
      /** `incremental`: folded only entries past the valid watermark, merged additively. `recompute`: no valid watermark -- replayed retained history with replace-existing/mint-post-review semantics (the heal path). */
      mode: "incremental" | "recompute";
      /** Denied-flow events this pass actually folded. */
      folded_events: number;
      /** Folded candidate rows suppressed because the verified allowlist already permits them (never minted). */
      suppressed_allowed: number;
      /** Persisted candidate rows removed because the verified allowlist now permits them. */
      removed_now_allowed: number;
    }
  | { status: "allowlist_unverified"; reason: string }
  | { status: "refresh_in_progress" };

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
 * header for the four guarantees (chain-bound fold watermark, mutual
 * exclusion, review-marker-aware recompute heal, allowlist-aware fold +
 * prune). Throws if the audit chain fails strict verification
 * (`streamVerifiedChain`'s contract) -- the caller surfaces that loud and
 * nothing has been written, because all store writes happen only after the
 * stream returns clean.
 */
export async function refreshCandidatesFromAudit(deps: RefreshDeps): Promise<RefreshOutcome> {
  const release = await deps.lock.acquire();
  if (release === null) {
    return { status: "refresh_in_progress" };
  }
  try {
    return await runRefresh(deps);
  } finally {
    await release();
  }
}

async function runRefresh(deps: RefreshDeps): Promise<RefreshOutcome> {
  const allowlist = await deps.readAllowlist();
  if (allowlist.status === "unverified") {
    return { status: "allowlist_unverified", reason: allowlist.reason };
  }

  const watermark = await deps.store.getFoldWatermark();

  // ── Single verified pass over the chain (buffered writes: nothing below
  // touches the store until the stream has returned clean). ──
  let events: Array<{ sequence: number; event: FlowObservationEvent }> = [];
  let headSequence: number | null = null;
  let headHash: string | null = null;
  let lowestSequence: number | null = null;
  let hashAtWatermark: string | null = null;
  let lastReviewSequence: number | null = null;
  await deps.auditLog.streamVerifiedChain({
    onEntry: ({ sequence, entry_hash, entry }) => {
      if (headSequence === null || sequence > headSequence) {
        headSequence = sequence;
        headHash = entry_hash;
      }
      if (lowestSequence === null || sequence < lowestSequence) lowestSequence = sequence;
      if (watermark !== null && sequence === watermark.folded_through_sequence) {
        hashAtWatermark = entry_hash;
      }
      if (
        OBSERVE_REVIEW_OPERATIONS.has(entry.operation) &&
        (lastReviewSequence === null || sequence > lastReviewSequence)
      ) {
        lastReviewSequence = sequence;
      }
      const event = flowEventFromAuditEntry(entry);
      if (event) events.push({ sequence, event });
    },
    reset: () => {
      events = [];
      headSequence = null;
      headHash = null;
      lowestSequence = null;
      hashAtWatermark = null;
      lastReviewSequence = null;
    },
  });

  const chainHead: number | null = headSequence;
  const chainLowest: number | null = lowestSequence;

  // A watermark is honored ONLY against the chain that minted it (module
  // doc, guarantee 1):
  //   - none persisted -> recompute (fresh store, or a pre-watermark store);
  //   - sequence beyond the surviving head -> the chain shrank/reset under
  //     us -> recompute;
  //   - the surviving entry at the watermark's sequence carries a DIFFERENT
  //     hash -> a reset/rebuilt chain regrew past the old position -> the
  //     old position is meaningless here -> recompute (never silently skip
  //     the new chain's prefix);
  //   - the watermark's sequence has been pruned off the surviving chain
  //     (below the lowest survivor) -> honored: the stream's own rotation-
  //     anchor verification attests the surviving chain is the same chain's
  //     suffix.
  const watermarkValid =
    watermark !== null &&
    chainHead !== null &&
    watermark.folded_through_sequence <= chainHead &&
    (chainLowest === null ||
      watermark.folded_through_sequence < chainLowest ||
      hashAtWatermark === watermark.entry_hash);
  const recompute = !(watermark !== null && (chainHead === null ? true : watermarkValid));
  // (An empty chain with a persisted watermark folds nothing and keeps the
  // watermark: `chainHead === null` yields recompute=false and an empty fold.)

  const kept: CandidateObservation[] = [];
  let suppressedAllowed = 0;
  let foldedCount: number;

  const keepFiltered = (folded: readonly CandidateObservation[], into: CandidateObservation[]): void => {
    for (const row of folded) {
      if (candidateCurrentlyAllowed(allowlist.rules, row)) {
        suppressedAllowed += 1;
        continue;
      }
      into.push(row);
    }
  };

  const advanceWatermark = async (): Promise<void> => {
    if (chainHead === null || headHash === null) return;
    if (
      watermark !== null &&
      watermark.folded_through_sequence === chainHead &&
      watermark.entry_hash === headHash
    ) {
      return;
    }
    await deps.store.setFoldWatermark({
      folded_through_sequence: chainHead,
      entry_hash: headHash,
      updated_at: deps.now.toISOString(),
    });
  };

  if (recompute) {
    // Heal existing rows from the FULL retained history; mint new rows only
    // from post-review events (module doc, guarantee 3).
    const allEvents = events.map((item) => item.event);
    const postReviewEvents =
      lastReviewSequence === null
        ? allEvents
        : events.filter((item) => item.sequence > lastReviewSequence!).map((item) => item.event);
    foldedCount = allEvents.length;

    const persistedBefore = await deps.store.listCandidates();
    const replacements: CandidateObservation[] = [];
    keepFiltered(
      foldObservations(allEvents).filter((row) => persistedBefore.has(candidateKey(row))),
      replacements,
    );
    const mints: CandidateObservation[] = [];
    keepFiltered(
      foldObservations(postReviewEvents).filter((row) => !persistedBefore.has(candidateKey(row))),
      mints,
    );
    kept.push(...replacements, ...mints);

    // RECOMPUTE crash order: replace/mint FIRST, then the watermark (see
    // module doc). Both writes are replace-semantics here: a re-run of this
    // same recompute converges.
    await deps.store.replaceObservations(kept);
    await advanceWatermark();
  } else {
    const newEvents = events
      .filter((item) => watermark === null || item.sequence > watermark.folded_through_sequence)
      .map((item) => item.event);
    foldedCount = newEvents.length;
    keepFiltered(foldObservations(newEvents), kept);

    // INCREMENTAL crash order: watermark FIRST, then the additive merge (see
    // module doc): a crash between the two undercounts, never double-counts.
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
    folded_events: foldedCount,
    suppressed_allowed: suppressedAllowed,
    removed_now_allowed: removedNowAllowed,
  };
}
