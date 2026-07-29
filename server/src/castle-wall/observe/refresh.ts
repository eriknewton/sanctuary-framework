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
 * 1. SOURCE-ENUMERATED SNAPSHOT RECOMPUTE (idempotency). Every refresh reads
 *    every registered audit source to completion and folds the full retained
 *    history into one aggregate candidate snapshot. There is no per-source
 *    contribution schema in Option A and no additive merge in the refresh
 *    path: persisted aggregate rows are replaced from the snapshot, so
 *    re-reading the same source history is idempotent.
 *
 * 2. CROSS-RUN MUTUAL EXCLUSION (Codex gate BLOCKER). Two concurrent
 *    refreshes would compute and replace the same shared candidate rows with
 *    no transactional boundary between the encrypted state entries. Every
 *    refresh therefore runs under
 *    `deps.lock`: acquire returns null when another refresh holds it, and
 *    the refresh ABORTS (`refresh_in_progress`) without reading or writing
 *    anything. The CLI supplies an O_EXCL lockfile that is NEVER
 *    auto-broken (Codex round-2 HIGH: any same-call break-and-retry scheme
 *    has a TOCTOU where a slow breaker unlinks a fresh lock; a stale lock
 *    from a crashed run is surfaced to the operator with exact guidance
 *    instead -- see `cli/castle-wall-observe.ts`); in-process callers/tests
 *    use `inProcessRefreshLock()`.
 *
 * 3. REVIEW-LEDGER-AWARE MINTING. The refresh replays the full retained
 *    history every time. Candidate removals now write a per-candidate review
 *    tombstone in the observe StateStore BEFORE the row is deleted; this is
 *    the durable guarantee, independent of any audit chain's retention or
 *    reset history. A reviewed key is folded only from events recorded AFTER
 *    its tombstone `reviewed_at`, even after a later post-review denial
 *    re-mints it, so historical pre-resolution events never refill its
 *    count. Chain review markers (`castle_wall_observe_discard` /
 *    `castle_wall_observe_promote`) remain as a secondary migration horizon
 *    for older rows with no tombstone: absent keys are minted only from
 *    events after the latest retained marker. A chain with no review action
 *    and no tombstone is a fresh bootstrap and mints from retained history.
 *
 * 4. ALLOWLIST-AWARE FOLD + PRUNE, SCOPE-AWARE. A folded row whose flow the
 *    CURRENT cryptographically verified manifest already allows FOR THAT
 *    ROW'S AGENT is never minted (suppressed), and a persisted row that is
 *    now allowed for its agent is removed -- so after a clean refresh, no
 *    pending candidate names a flow the operator's policy permits (the
 *    invariant the evidence pack's egress-table legend asserts). The
 *    verdict never reconstructs any single enforcer (Codex rounds 3-6:
 *    the three shipped enforcers diverge on precedence, scope handling,
 *    and pattern syntax); it is the conservative CROSS-ENFORCER
 *    DISCIPLINE documented on `candidateCurrentlyAllowed`: a generous
 *    union deny/prompt veto plus an exact unconditional scope-covering
 *    allow on the axes every enforcer agrees on (catch-all destination,
 *    exact host, or exact ip -- exactly the shape promote synthesizes).
 *    A rule scoped to template A never suppresses template B's identical
 *    destination; a matching deny/prompt anywhere vetoes (macOS
 *    deny-wins); pattern/cidr allows leave rows pending (disclosed
 *    conservative staleness). observe/ still never imports the evaluator
 *    module (THE RED-LINE structural pin). An allowlist that is
 *    present but does NOT verify aborts the refresh loud -- never silently
 *    skips the filter (WHAT THESE TOOLS MUST NEVER DO #5). Pruning is
 *    safe-direction (removes candidate rows, exactly like `observe
 *    discard`; never adds a rule) and fail-closed on doubt: a destination
 *    that cannot be canonicalized cannot be allowed by the wall, so its row
 *    is KEPT, and suppression happens only on a positive verified match.
 *
 * Crash ordering: Option A deliberately chooses idempotent snapshot
 * replacement, not the old watermark-first undercount contract. Source
 * contribution markers are written before the snapshot so a crash can only
 * make a later missing source block definitive-empty output; then the
 * candidate snapshot is replace-written. A retry folds the same retained
 * history and converges to the same aggregate counts -- no crash window can
 * double-add a source's events.
 *
 * RED-LINE (unchanged): nothing here writes the live signed allowlist. This
 * module READS the verified manifest and writes only the reserved,
 * agent-invisible candidate namespace. The enforcing evaluator still never
 * reads the candidate store.
 */

import type { AllowlistRule } from "../allowlist/schema.js";
import { ruleProtocolMatches, ruleScopeCoversAgent } from "../allowlist/match.js";
import { OBSERVE_PROMOTED_RULE_ID_PREFIX } from "../constants.js";
import { ipMatches, cidrMatches } from "../allowlist/ip-cidr.js";
import type { RuleMatch } from "../allowlist/schema.js";
import type { VerifiedChainConsumer } from "../../operational/audit-log.js";
import { flowEventFromAuditEntry } from "./adapter.js";
import { foldObservations } from "./fold.js";
import {
  OBSERVE_AUDIT_SOURCE_IDS,
  candidateKey,
  isObserveAuditSourceId,
  type CandidateObservation,
  type FlowObservationEvent,
  type FoldWatermark,
  type ObserveCandidateReviewRecord,
  type ObserveAuditSourceId,
} from "./types.js";
import type {
  ObserveCandidateReviewSnapshot,
  ObserveLastRefreshOutcome,
  ObserveSourceState,
  ObserveSourceStateSnapshot,
} from "./store.js";

/** The observe review-action audit operations (written by the CLI's discard/promote verbs onto the SAME verified chain the fold streams). Their chain position bounds what a recompute may MINT (module doc, guarantee 3). */
const OBSERVE_REVIEW_OPERATIONS: ReadonlySet<string> = new Set([
  "castle_wall_observe_discard",
  "castle_wall_observe_promote",
]);

/** Narrow audit surface the refresh needs; `AuditLog` satisfies it. Strict verification is the contract: the stream throws on a chain-integrity failure, so a refresh never folds over an unverified chain. */
export interface RefreshAuditSource {
  streamVerifiedChain(consumer: VerifiedChainConsumer): Promise<void>;
}

export type RefreshAuditSourceDescriptor =
  | {
      source_id: ObserveAuditSourceId;
      status: "present";
      auditLog: RefreshAuditSource;
      /** Stable physical segment identity for reset/missing detection, e.g. the boot-token fingerprint. */
      instance_id?: string;
    }
  | {
      source_id: ObserveAuditSourceId;
      status: "absent";
      reason: string;
      instance_id?: string;
    }
  | {
      source_id: ObserveAuditSourceId;
      status: "read_failed";
      reason: string;
      instance_id?: string;
    };

export type ObserveAuditSourceReadOutcome =
  | {
      source_id: ObserveAuditSourceId;
      status: "read_ok";
      entries_read: number;
      flow_events: number;
      candidate_rows: number;
      head_sequence: number | null;
      head_hash: string | null;
      instance_id?: string;
    }
  | {
      source_id: ObserveAuditSourceId;
      status: "absent";
      reason: string;
      instance_id?: string;
    }
  | {
      source_id: ObserveAuditSourceId;
      status: "read_failed";
      reason: string;
      failure:
        | "source_unreadable"
        | "missing_after_contribution"
        | "instance_changed_after_contribution";
      instance_id?: string;
    };

export interface ObserveQuarantinedSourceState {
  key: string;
  reason: string;
  source_id?: string;
}

/** Narrow candidate-store surface the refresh needs; `ObserveStore` satisfies it. */
export interface RefreshCandidateStore {
  getFoldWatermark(): Promise<FoldWatermark | null>;
  setFoldWatermark(watermark: FoldWatermark): Promise<void>;
  listCandidates(): Promise<Map<string, CandidateObservation>>;
  mergeObservations(observations: readonly CandidateObservation[]): Promise<void>;
  replaceObservations(observations: readonly CandidateObservation[]): Promise<void>;
  replaceCandidateSnapshot(observations: readonly CandidateObservation[]): Promise<void>;
  listSourceStates(): Promise<ObserveSourceStateSnapshot>;
  putSourceState(state: ObserveSourceState): Promise<void>;
  listCandidateReviews(): Promise<ObserveCandidateReviewSnapshot>;
  putLastRefreshOutcome(outcome: ObserveLastRefreshOutcome): Promise<void>;
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
  /**
   * Legacy single-source input. Production callers should pass
   * `auditSources`; when this is used, it is treated as the registered
   * `master-audit` source for older in-process tests/callers.
   */
  auditLog: RefreshAuditSource;
  auditSources?: readonly RefreshAuditSourceDescriptor[];
  store: RefreshCandidateStore;
  readAllowlist: () => Promise<RefreshAllowlistRead>;
  /** Mutual exclusion across concurrent refreshes (Codex gate BLOCKER; see {@link RefreshLock}). */
  lock: RefreshLock;
  now: Date;
  /**
   * Pinned Castle Wall audit-producer key for read-side attribution. Without a
   * key, attribution-sensitive rows do not fold into observe candidates.
   */
  pinnedProducerKeyB64url?: string | null;
  /** Local fortress id needed to resolve macOS signed audit-token subjects. */
  subjectFortressId?: string | null;
}

export type RefreshOutcome =
  | {
      status: "refreshed";
      /** Option A always recomputes the aggregate from retained source history and replace-writes the snapshot. */
      mode: "recompute";
      /** Denied-flow events this pass actually folded. */
      folded_events: number;
      /** Folded candidate rows suppressed because the verified allowlist already permits them (never minted). */
      suppressed_allowed: number;
      /** Persisted candidate rows removed because the verified allowlist now permits them. */
      removed_now_allowed: number;
      /** Per-source read witnesses. Definitive empty output requires every enumerated source to be read_ok or valid absent. */
      source_reads: ObserveAuditSourceReadOutcome[];
      quarantined_sources: ObserveQuarantinedSourceState[];
      definitive_empty: boolean;
    }
  | {
      status: "source_read_incomplete";
      source_reads: ObserveAuditSourceReadOutcome[];
      quarantined_sources: ObserveQuarantinedSourceState[];
      reason: string;
    }
  | { status: "allowlist_unverified"; reason: string }
  | { status: "refresh_in_progress" };

/**
 * Is this candidate's flow allowed by the CURRENT verified ruleset FOR THIS
 * CANDIDATE'S AGENT, per the enforcing daemon's own semantics? The verdict
 * comes from `evaluateFlowFirstMatch` (`../allowlist/match.ts`), which
 * mirrors the Rust daemon's `PolicySnapshot::evaluate` exactly:
 *   - SCOPE applies first (Codex round-3 HIGH: a rule promoted for
 *     template A does not make template B's identical destination
 *     "allowed" -- the daemon still denies B, so B's candidate must stay
 *     pending review and keep re-minting);
 *   - FIRST MATCH WINS in manifest order (Codex round-4 HIGH: a leading
 *     matching deny/prompt beats a later matching allow -- the daemon
 *     denies/prompts that flow and keeps recording egress_blocked, so the
 *     candidate must NOT be suppressed just because SOME allow rule also
 *     matches).
 * THE CROSS-ENFORCER DISCIPLINE (Codex rounds 3-6: three shipped enforcers,
 * three divergent semantics -- Rust daemon: first-match-wins, scope-aware,
 * `.suffix` patterns only; macOS filter: deny-ANYWHERE-wins over allow,
 * scope-aware, `*.suffix` patterns; TS CONNECT proxy: some-allow,
 * scope-blind, deny-blind, `*.suffix` patterns. Reconstructing any single
 * enforcer's verdict here suppressed candidates another enforcer still
 * denies and records). Suppression therefore never models one enforcer; it
 * requires BOTH of:
 *   1. NO DENY/PROMPT COULD FIRE (a generous UNION veto): any deny or
 *      prompt rule whose destination/port/protocol could match this flow
 *      under ANY shipped enforcer's syntax -- either pattern form, exact
 *      pattern, host, ip, cidr, ignoring scope -- vetoes suppression.
 *      Over-vetoing only KEEPS a candidate (conservative).
 *   2. AN EXACT UNCONDITIONAL ALLOW EXISTS: an allow rule with no
 *      time_window (conditional allowance never suppresses; the Linux
 *      daemon refuses such manifests outright), whose scope covers this
 *      row's agent (`ruleScopeCoversAgent` -- shared-axis parity with the
 *      daemon and the macOS filter, and CONSERVATIVE on the macOS-only
 *      `uids` axis: a uids-only rule, e.g. an exclusive-routing GATE-scoped
 *      promoted rule the gate daemon only loads at re-arm, NEVER suppresses
 *      -- 2026-07-27 fix-round F2, the third recurrence of the self-masking
 *      shape), and whose destination matches on the axes EVERY enforcer
 *      agrees on: a catch-all destination (no destination axes), an exact
 *      (ASCII-case-insensitive) `host` entry for a hostname-bearing row,
 *      or an exact `ip` entry for an IP-only row. host_pattern and cidr
 *      NEVER satisfy the allow leg (their semantics differ or are
 *      unshared across enforcers) -- such rules leave the row pending, a
 *      disclosed conservative staleness, never a hidden denied flow.
 * This is exactly the shape the promote flow synthesizes
 * (host-or-ip + port + protocol + template/agent scope), so the product's
 * own promote-then-refresh path always suppresses; anything less exact
 * stays visible for review.
 */
export function candidateCurrentlyAllowed(
  rules: readonly AllowlistRule[],
  row: Pick<
    CandidateObservation,
    "agent_id" | "agent_template" | "host" | "ip" | "port" | "protocol" | "provenance"
  >,
): boolean {
  if (rules.length === 0) return false;

  // macOS UNATTRIBUTED bucket (Codex round-7 HIGH), NOW PROVENANCE-SCOPED
  // (#897 finding 2): the macOS filter fail-closed-drops every uid-mode flow
  // whose audit token cannot be decoded, REGARDLESS of allow rules
  // (AllowlistEvaluator suppressAllowMatches), and keeps recording those
  // drops -- but the recorded event cannot tell an unattributed drop from an
  // attributed default-deny. Every flow the current macOS build reports
  // carries the default resolver's `templateId: "unknown"`
  // (FlowEvaluatorEngine.defaultAgentResolver; macos-flow-events.ts uses the
  // same fallback identity), so a macOS "unknown" row may contain flows NO
  // allow rule can ever permit and must NEVER be suppressed or pruned.
  //
  // The Linux daemon ALSO stamps `agent_template: "unknown"` -- NFQUEUE
  // hardcodes it (`nfqueue.rs`) -- but there "unknown" is a REAL, enforceable
  // template: an allow rule scoped to it genuinely flips the daemon's verdict,
  // so a daemon "unknown" row IS a legitimate suppression candidate and must
  // NOT get this exemption (else finding 1's newly-folded Linux rows would be
  // blanket-pinned pending forever, breaking the evidence-pack legend
  // "permitted destinations do NOT appear here"). The two are told apart by
  // the row's PROVENANCE (adapter.ts): the exemption applies to every row we
  // cannot POSITIVELY attribute to the Linux daemon -- macOS rows AND any
  // undefined-origin (legacy/hand-built) row -- the conservative direction.
  // When the macOS registry resolver lands, that build must forward the real
  // template before its rows lose the exemption.
  if (row.agent_template === "unknown" && row.provenance !== "linux_daemon") return false;

  for (const rule of rules) {
    if (rule.disposition === "allow") continue;
    if (denyOrPromptCouldMatch(rule.match, row)) return false;
  }

  const agent = { agent_id: row.agent_id, agent_template: row.agent_template };
  return rules.some(
    (rule) =>
      rule.disposition === "allow" &&
      rule.time_window === undefined &&
      ruleScopeCoversAgent(rule.scope, agent) &&
      ruleProtocolMatches(rule.match.protocol, row.protocol) &&
      portAxisAdmits(rule.match.port, row.port) &&
      allowDestinationExact(rule.match, row),
  );
}

/**
 * Round-3 R2(b): true iff this row's destination is covered by an
 * OBSERVE-PROMOTED, gate-scoped, unconditional allow in the verified ruleset
 * -- i.e. the row was promoted on THIS exclusive-routing fortress and is
 * awaiting the re-arm that loads the gate daemon's destination snapshot.
 * Such a rule NEVER suppresses the row (F2: uids-only does not cover the
 * agent), so without this marker the candidates listing could not tell
 * "promoted, awaiting re-arm" from "never promoted".
 *
 * Round-3 L2 tightening (the over-marking direction): the covering rule must
 * (a) carry the `derived-observe-` id prefix -- a provisioned gate-uid
 * endpoint rule covering the same destination is NOT a promotion and must
 * not mark a never-promoted row -- and (b) be scoped to exactly the CURRENT
 * marker's gate uid (`gateUid`): a rule bound to a STALE gate uid is one the
 * next re-arm will not serve, so claiming "awaiting re-arm" for it would be
 * false. Destination legs are the SAME exact-match helpers
 * `candidateCurrentlyAllowed` uses, so the two verdicts cannot drift.
 * Purely informational: no suppression, no pruning.
 */
export function candidatePromotedAwaitingRearm(
  rules: readonly AllowlistRule[],
  row: Pick<CandidateObservation, "host" | "ip" | "port" | "protocol">,
  gateUid: number,
): boolean {
  return rules.some(
    (rule) =>
      rule.disposition === "allow" &&
      rule.id.startsWith(OBSERVE_PROMOTED_RULE_ID_PREFIX) &&
      rule.time_window === undefined &&
      rule.scope?.uids?.length === 1 &&
      rule.scope.uids[0] === gateUid &&
      (rule.scope.agent_ids?.length ?? 0) === 0 &&
      (rule.scope.template_ids?.length ?? 0) === 0 &&
      ruleProtocolMatches(rule.match.protocol, row.protocol) &&
      portAxisAdmits(rule.match.port, row.port) &&
      allowDestinationExact(rule.match, row),
  );
}

/** ASCII-only lowercase (parity with the Rust daemon's `to_ascii_lowercase`; JS `toLowerCase` also folds non-ASCII, which the daemon does not). */
function asciiLower(value: string): string {
  return value.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function portAxisAdmits(spec: number | number[] | undefined, port: number): boolean {
  if (spec === undefined) return true;
  return Array.isArray(spec) ? spec.includes(port) : spec === port;
}

function asArray<T>(value: T | T[]): T[] {
  return Array.isArray(value) ? value : [value];
}

/** The allow leg's destination test: ONLY the axes every shipped enforcer agrees on (see candidateCurrentlyAllowed doc). */
function allowDestinationExact(
  match: RuleMatch,
  row: Pick<CandidateObservation, "host" | "ip">,
): boolean {
  const hasHost = match.host !== undefined;
  const hasPattern = match.host_pattern !== undefined && match.host_pattern.length > 0;
  const hasIp = match.ip !== undefined;
  const hasCidr = match.cidr !== undefined;
  if (!hasHost && !hasPattern && !hasIp && !hasCidr) {
    // No destination axes: every enforcer treats the destination as
    // non-constraining (port/protocol alone decide).
    return true;
  }
  if (row.host !== null) {
    const hostLower = asciiLower(row.host);
    return hasHost && asArray(match.host!).some((h) => asciiLower(h) === hostLower);
  }
  return hasIp && row.ip.length > 0 && ipMatches(match.ip!, row.ip);
}

/** The veto leg: could this deny/prompt rule's match-clause fire for this flow under ANY shipped enforcer's syntax? Generous by design (scope ignored; both pattern forms honored; exact-pattern form honored; host treated as IP literal for ip/cidr axes). Over-matching only KEEPS a candidate. */
function denyOrPromptCouldMatch(
  match: RuleMatch,
  row: Pick<CandidateObservation, "host" | "ip" | "port" | "protocol">,
): boolean {
  if (!ruleProtocolMatches(match.protocol, row.protocol)) return false;
  if (!portAxisAdmits(match.port, row.port)) return false;

  const hasHost = match.host !== undefined;
  const hasPattern = match.host_pattern !== undefined && match.host_pattern.length > 0;
  const hasIp = match.ip !== undefined;
  const hasCidr = match.cidr !== undefined;
  if (!hasHost && !hasPattern && !hasIp && !hasCidr) return true;

  if (row.host !== null) {
    // FULL-Unicode folding on the VETO side (Codex round-7 HIGH): the macOS
    // filter compares exact hosts with Unicode-aware caseInsensitiveCompare,
    // so an ASCII-only fold here would miss a deny that macOS enforces
    // (e.g. deny "é.example" vs row "É.example"). Unicode folding
    // matches a strict SUPERSET of what ASCII folding matches, so using it
    // on the veto only ever KEEPS more rows (conservative); the ALLOW leg
    // stays ASCII-only (the Rust daemon's strictest interpretation).
    const hostLower = row.host.toLowerCase();
    if (hasHost && asArray(match.host!).some((h) => h.toLowerCase() === hostLower)) return true;
    if (hasPattern && patternCouldMatch(match.host_pattern!, hostLower)) return true;
  }
  for (const literal of [row.ip, row.host ?? ""]) {
    if (literal.length === 0) continue;
    if (hasIp && ipMatches(match.ip!, literal)) return true;
    if (hasCidr && cidrMatches(match.cidr!, literal)) return true;
  }
  return false;
}

/** Union of every shipped enforcer's host_pattern syntax: `*.suffix` (proxy/macOS), `.suffix` (Rust daemon), and the exact-pattern fallback (macOS compares a non-wildcard pattern as an exact host). Full-Unicode folding (veto side; see denyOrPromptCouldMatch). */
function patternCouldMatch(pattern: string, hostLower: string): boolean {
  const patternLower = pattern.toLowerCase();
  if (patternLower.startsWith("*.")) {
    const dotSuffix = patternLower.slice(1); // ".suffix"
    return hostLower.endsWith(dotSuffix) && hostLower.length > dotSuffix.length;
  }
  if (patternLower.startsWith(".")) {
    return hostLower.endsWith(patternLower) && hostLower.length > patternLower.length;
  }
  return patternLower === hostLower;
}

/**
 * Refresh the candidate store from the registered verified audit sources. See
 * the module header for the source-enumerated recompute, mutual exclusion,
 * review-marker-aware minting, source read witnesses, and allowlist-aware
 * fold/prune guarantees. Throws if an audit chain fails strict verification
 * (`streamVerifiedChain`'s contract) -- the caller surfaces that loud and
 * nothing has been written, because all store writes happen only after the
 * stream returns clean.
 */
export async function refreshCandidatesFromAudit(deps: RefreshDeps): Promise<RefreshOutcome> {
  const release = await deps.lock.acquire();
  if (release === null) {
    return { status: "refresh_in_progress" };
  }
  let outcome: RefreshOutcome;
  try {
    outcome = await runRefresh(deps);
  } finally {
    // Releasing is best-effort: a release failure must never mask the real
    // refresh result (Codex round-2 LOW -- a completed refresh reported as
    // "failed, nothing changed" would be false). A stranded lock surfaces on
    // the next run as refresh_in_progress with operator guidance.
    try {
      await release();
    } catch {
      // Deliberately swallowed; see above.
    }
  }
  return outcome;
}

async function runRefresh(deps: RefreshDeps): Promise<RefreshOutcome> {
  const allowlist = await deps.readAllowlist();
  if (allowlist.status === "unverified") {
    return recordLastRefreshOutcome(deps, {
      status: "allowlist_unverified",
      reason: allowlist.reason,
    });
  }

  const sourceStateSnapshot = await deps.store.listSourceStates();
  const candidateReviewSnapshot = await deps.store.listCandidateReviews();
  const sources = normalizeAuditSources(deps);
  const sourceReads: ObserveAuditSourceReadOutcome[] = [];
  const readOk: SourceReadOk[] = [];

  for (const source of sources) {
    const prior = sourceStateSnapshot.known.get(source.source_id);
    const gated = sourceCompletenessGate(source, prior);
    if (gated !== null) {
      sourceReads.push(gated);
      continue;
    }
    if (source.status === "absent") {
      sourceReads.push({
        source_id: source.source_id,
        status: "absent",
        reason: source.reason,
        ...(source.instance_id !== undefined ? { instance_id: source.instance_id } : {}),
      });
      continue;
    }
    if (source.status === "read_failed") {
      sourceReads.push({
        source_id: source.source_id,
        status: "read_failed",
        reason: source.reason,
        failure: "source_unreadable",
        ...(source.instance_id !== undefined ? { instance_id: source.instance_id } : {}),
      });
      continue;
    }

    const outcome = await readPresentSource(source, deps, allowlist.rules);
    sourceReads.push(outcome.outcome);
    if ("events" in outcome) readOk.push(outcome);
  }

  const quarantinedSources = sourceStateSnapshot.quarantined.map((q) => ({
    key: q.key,
    reason: q.reason,
    ...(q.source_id !== undefined ? { source_id: q.source_id } : {}),
  }));
  const incomplete = sourceReads.find((source) => source.status === "read_failed");
  if (incomplete || quarantinedSources.length > 0 || candidateReviewSnapshot.quarantined.length > 0) {
    return recordLastRefreshOutcome(deps, {
      status: "source_read_incomplete",
      source_reads: sourceReads,
      quarantined_sources: quarantinedSources,
      reason: incomplete
        ? `${incomplete.source_id}: ${incomplete.reason}`
        : quarantinedSources.length > 0
          ? "unknown persisted observe source state is quarantined"
          : "persisted observe candidate review state is quarantined",
    });
  }

  const persistedBefore = await deps.store.listCandidates();
  const reviewHorizon = latestReviewHorizon(readOk);
  const allEvents = readOk.flatMap((source) => source.events.map((item) => item.event));
  const foldableEvents = allEvents.filter((event) =>
    eventSurvivesReviewLedger(
      event,
      persistedBefore,
      candidateReviewSnapshot.known,
      reviewHorizon,
    ),
  );

  const snapshot = new Map<string, CandidateObservation>();
  const suppressedAllowedKeys = new Set<string>();
  const keepIfNotAllowed = (row: CandidateObservation): void => {
    const key = candidateKey(row);
    if (candidateCurrentlyAllowed(allowlist.rules, row)) {
      suppressedAllowedKeys.add(key);
      return;
    }
    snapshot.set(key, row);
  };

  for (const row of foldObservations(foldableEvents)) keepIfNotAllowed(row);

  let removedNowAllowed = 0;
  for (const candidate of persistedBefore.values()) {
    if (candidateCurrentlyAllowed(allowlist.rules, candidate)) removedNowAllowed += 1;
  }

  const nowIso = deps.now.toISOString();
  for (const source of sourceReads) {
    if (source.status === "read_ok" || source.status === "absent") {
      const prior = sourceStateSnapshot.known.get(source.source_id);
      const contributed = source.status === "read_ok" && source.candidate_rows > 0;
      await deps.store.putSourceState({
        source_id: source.source_id,
        ever_contributed: (prior?.ever_contributed ?? false) || contributed,
        last_read_status: source.status,
        last_read_at: nowIso,
        ...(source.instance_id !== undefined
          ? { last_instance_id: source.instance_id }
          : prior?.last_instance_id !== undefined
            ? { last_instance_id: prior.last_instance_id }
            : {}),
        ...(contributed
          ? { last_contributed_at: nowIso }
          : prior?.last_contributed_at !== undefined
            ? { last_contributed_at: prior.last_contributed_at }
            : {}),
      });
    }
  }

  await deps.store.replaceCandidateSnapshot([...snapshot.values()]);

  return recordLastRefreshOutcome(deps, {
    status: "refreshed",
    mode: "recompute",
    folded_events: foldableEvents.length,
    suppressed_allowed: suppressedAllowedKeys.size,
    removed_now_allowed: removedNowAllowed,
    source_reads: sourceReads,
    quarantined_sources: quarantinedSources,
    definitive_empty: snapshot.size === 0,
  });
}

interface SourceReadOk {
  outcome: Extract<ObserveAuditSourceReadOutcome, { status: "read_ok" }>;
  events: Array<{ sequence: number; event: FlowObservationEvent }>;
  reviewTimestamps: string[];
}

interface ReviewHorizon {
  timestamp: string;
  epochMs: number;
}

function normalizeAuditSources(deps: RefreshDeps): RefreshAuditSourceDescriptor[] {
  const raw = deps.auditSources ?? [
    {
      source_id: "master-audit" as const,
      status: "present" as const,
      auditLog: deps.auditLog,
      instance_id: "operator-master",
    },
  ];

  const sources: RefreshAuditSourceDescriptor[] = [];
  const seen = new Set<ObserveAuditSourceId>();
  for (const source of raw) {
    if (!isObserveAuditSourceId(source.source_id) || seen.has(source.source_id)) continue;
    seen.add(source.source_id);
    sources.push(source);
  }
  return sources.sort(
    (a, b) =>
      OBSERVE_AUDIT_SOURCE_IDS.indexOf(a.source_id) -
      OBSERVE_AUDIT_SOURCE_IDS.indexOf(b.source_id),
  );
}

function sourceCompletenessGate(
  source: RefreshAuditSourceDescriptor,
  prior: ObserveSourceState | undefined,
): ObserveAuditSourceReadOutcome | null {
  if (!prior?.ever_contributed) return null;

  if (source.status === "absent") {
    return {
      source_id: source.source_id,
      status: "read_failed",
      reason: "source is missing after previously contributing to this observe store",
      failure: "missing_after_contribution",
      ...(source.instance_id !== undefined ? { instance_id: source.instance_id } : {}),
    };
  }
  if (
    source.status === "present" &&
    prior.last_instance_id !== undefined &&
    source.instance_id !== undefined &&
    prior.last_instance_id !== source.instance_id
  ) {
    return {
      source_id: source.source_id,
      status: "read_failed",
      reason: "source segment changed after previously contributing to this observe store",
      failure: "instance_changed_after_contribution",
      instance_id: source.instance_id,
    };
  }
  return null;
}

async function readPresentSource(
  source: Extract<RefreshAuditSourceDescriptor, { status: "present" }>,
  deps: RefreshDeps,
  rules: readonly AllowlistRule[],
): Promise<SourceReadOk | { outcome: Extract<ObserveAuditSourceReadOutcome, { status: "read_failed" }> }> {
  let entriesRead = 0;
  let events: Array<{ sequence: number; event: FlowObservationEvent }> = [];
  let reviewTimestamps: string[] = [];
  let headSequence: number | null = null;
  let headHash: string | null = null;
  try {
    await source.auditLog.streamVerifiedChain({
      onEntry: ({ sequence, entry_hash, entry }) => {
        entriesRead += 1;
        if (headSequence === null || sequence > headSequence) {
          headSequence = sequence;
          headHash = entry_hash;
        }
        if (OBSERVE_REVIEW_OPERATIONS.has(entry.operation)) {
          reviewTimestamps.push(entry.timestamp);
        }
        const event = flowEventFromAuditEntry(entry, {
          pinnedProducerKeyB64url: deps.pinnedProducerKeyB64url ?? null,
          subjectFortressId: deps.subjectFortressId ?? null,
        });
        if (event) events.push({ sequence, event });
      },
      reset: () => {
        entriesRead = 0;
        events = [];
        reviewTimestamps = [];
        headSequence = null;
        headHash = null;
      },
    });
  } catch (error) {
    return {
      outcome: {
        source_id: source.source_id,
        status: "read_failed",
        reason: (error as Error).message,
        failure: "source_unreadable",
        ...(source.instance_id !== undefined ? { instance_id: source.instance_id } : {}),
      },
    };
  }

  const candidateRows = foldObservations(events.map((item) => item.event)).filter(
    (row) => !candidateCurrentlyAllowed(rules, row),
  ).length;
  return {
    outcome: {
      source_id: source.source_id,
      status: "read_ok",
      entries_read: entriesRead,
      flow_events: events.length,
      candidate_rows: candidateRows,
      head_sequence: headSequence,
      head_hash: headHash,
      ...(source.instance_id !== undefined ? { instance_id: source.instance_id } : {}),
    },
    events,
    reviewTimestamps,
  };
}

function latestReviewHorizon(reads: readonly SourceReadOk[]): ReviewHorizon | null {
  let latest: ReviewHorizon | null = null;
  for (const read of reads) {
    for (const timestamp of read.reviewTimestamps) {
      const epochMs = Date.parse(timestamp);
      if (Number.isNaN(epochMs)) continue;
      if (latest === null || epochMs > latest.epochMs) {
        latest = { timestamp, epochMs };
      }
    }
  }
  return latest;
}

function eventAfterReviewHorizon(
  event: FlowObservationEvent,
  horizon: ReviewHorizon,
): boolean {
  const epochMs = Date.parse(event.timestamp);
  if (Number.isNaN(epochMs)) return event.timestamp > horizon.timestamp;
  return epochMs > horizon.epochMs;
}

function reviewHorizonFromRecord(record: ObserveCandidateReviewRecord): ReviewHorizon {
  return { timestamp: record.reviewed_at, epochMs: Date.parse(record.reviewed_at) };
}

function candidateKeyForEvent(event: FlowObservationEvent): string {
  return candidateKey({
    agent_template: event.agent.template,
    host: event.destination.host,
    ip: event.destination.ip,
    port: event.destination.port,
    protocol: event.destination.protocol,
  });
}

function eventSurvivesReviewLedger(
  event: FlowObservationEvent,
  persistedBefore: ReadonlyMap<string, CandidateObservation>,
  candidateReviews: ReadonlyMap<string, ObserveCandidateReviewRecord>,
  chainReviewHorizon: ReviewHorizon | null,
): boolean {
  const key = candidateKeyForEvent(event);
  const candidateReview = candidateReviews.get(key);
  if (candidateReview) {
    return eventAfterReviewHorizon(event, reviewHorizonFromRecord(candidateReview));
  }
  if (persistedBefore.has(key) || chainReviewHorizon === null) return true;
  return eventAfterReviewHorizon(event, chainReviewHorizon);
}

async function recordLastRefreshOutcome<T extends RefreshOutcome>(
  deps: RefreshDeps,
  outcome: T,
): Promise<T> {
  if (outcome.status === "refresh_in_progress") return outcome;
  const refreshedAt = deps.now.toISOString();
  const sourceReads = "source_reads" in outcome ? outcome.source_reads : [];
  const quarantinedSources =
    "quarantined_sources" in outcome ? outcome.quarantined_sources : [];
  const record: ObserveLastRefreshOutcome = {
    schema_version: "1.0",
    refreshed_at: refreshedAt,
    status: outcome.status,
    source_reads: sourceReads,
    quarantined_sources: quarantinedSources,
    ...("definitive_empty" in outcome ? { definitive_empty: outcome.definitive_empty } : {}),
    ...("reason" in outcome ? { reason: outcome.reason } : {}),
  };
  try {
    await deps.store.putLastRefreshOutcome(record);
  } catch {
    // The candidate snapshot is already the source of truth. A missing
    // witness makes later store-only zero claims UNDETERMINED, which is the
    // safe direction; do not report a successful refresh as failed here.
  }
  return outcome;
}
