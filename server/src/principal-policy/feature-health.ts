/**
 * Feature-usage health — Slice 1 (generalize the `posture.ts` evidence model).
 *
 * The CISO who turns on Sanctuary is paying for a set of security features
 * (the Castle Wall egress firewall, the secret broker, the human-approval
 * gates, the unified inbox, the privacy strippers). Today they can confirm
 * those features are *configured*. This module answers a blunt second question:
 * **which of those features actually DID something in the window, and is any of
 * them silently dead?** — as a pure, read-only projection over the existing
 * encrypted audit chain. There is NO new event stream and NO new write path;
 * the only new artifact is the (configuration, not telemetry) feature registry
 * below.
 *
 * Design discipline baked in (the ratified must-fixes from the 2026-06-13
 * adversarial review):
 *
 *  - ONE color model, lifted verbatim from `posture.ts`'s G4 arm-state. `armed`
 *    / green is earned ONLY by fresh enforcement evidence. Evidence-absent does
 *    NOT render green; it renders a distinct non-green chip. We never ship a
 *    second, more-permissive color model than the one `posture.ts` already
 *    enforces (HIGH-2).
 *
 *  - "unknown is never green" + "broken-zero is undetectable for purely
 *    event-driven features." Self-reporting features (Castle Wall) can prove
 *    their own liveness via fresh enforcement evidence, so they earn `armed`;
 *    a fault op flips them to `fault`/red; stale or absent evidence is
 *    `unknown` (NOT green) — the "daemon silently died" case stays `unknown`
 *    because the periodic heartbeat *producer* is deliberately out of this
 *    slice (Slice 2). Event-driven features have NO liveness signal by
 *    construction: activity in the window renders `active`/green; quiet renders
 *    a distinct non-green `unconfirmed` chip ("armed — activity-only, not
 *    independently confirmed"), NEVER the same green as evidence-backed active.
 *    The config-vs-activity cross-check is *vacuous* for event-driven features
 *    (configured-ON + zero activity is indistinguishable from healthy-quiet),
 *    and we say so plainly rather than papering over it (HIGH-3).
 *
 *  - Integrity-tainted read → forced `unknown`, never green, for EVERY feature
 *    (the "never fake green" invariant applied to the read path).
 *
 *  - Provenance gate for Castle Wall evidence: an L1 entry only counts as
 *    Castle Wall enforcement evidence if it carries the audit consumer's
 *    `cw_source` provenance marker — a different producer reusing an operation
 *    name like `egress_blocked` can never arm the wall. Same teeth as
 *    `posture.ts`. (The known in-process-writer boundary documented there
 *    applies here unchanged.)
 *
 *  - Cache-invalidation: health is recomputed on audit chain-head advance, so a
 *    post-fault refresh can never show stale green. The pure evaluator is
 *    recomputed by the route layer keyed on the chain head (see
 *    `posture-routes.ts`).
 *
 *  - `policy_loaded` is NOT treated as liveness OR as strong live-adjudication
 *    evidence here. It fires only inside the reload path; a daemon that loaded
 *    policy once but stopped enforcing would otherwise read green for the
 *    freshness window. Only `egress_allowed` / `egress_blocked` /
 *    `operator_decision` prove live adjudication. (`posture.ts:74` currently
 *    still lists `policy_loaded` in `CASTLE_WALL_ENFORCEMENT_OPERATIONS` — a
 *    latent honesty seam tracked for coordinator triage; this slice does not
 *    rely on it and leaves the shipped constant untouched.)
 *
 * These functions are pure over their injected dependencies so they unit-test
 * without a live HTTP server or a running daemon.
 */

import type { AuditLog, AuditEntry } from "../operational/audit-log.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../castle-wall/constants.js";
import {
  CASTLE_WALL_NOT_ENFORCING_OPERATIONS,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  DEFAULT_DIGEST_WINDOW_MS,
  ENFORCEMENT_FUTURE_SKEW_MS,
} from "./posture.js";
import {
  reverifyEntryProducerSignature,
  enforcementEntryCounts,
  producerSignedDedupKey,
  type VerifyProducerSignatureFn,
} from "./producer-reverify.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Live-adjudication evidence for Castle Wall. Deliberately a STRICTER set than
 * `posture.ts:CASTLE_WALL_ENFORCEMENT_OPERATIONS`: only operations that prove
 * the filter adjudicated real traffic. `policy_loaded` is excluded (it proves a
 * manifest was accepted once, not that the wall is still enforcing — see the
 * module header's honesty-seam note).
 */
export const CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS: ReadonlySet<string> =
  Object.freeze(
    new Set<string>(["egress_allowed", "egress_blocked", "operator_decision"]),
  );

/**
 * How a feature proves it is alive.
 *
 *  - `self_reporting`: emits evidence that could only come from the enforcing
 *    component acting on a real flow/policy, so fresh evidence earns `armed`
 *    and a fault op earns `fault`. Castle Wall is the only such feature in
 *    Slice 1.
 *  - `event_driven`: only ever writes to the audit log when something actually
 *    triggered it. A zero count is genuinely ambiguous (healthy-quiet vs
 *    silently-disabled are indistinguishable from counts alone), so quiet is
 *    rendered as a distinct non-green `unconfirmed` chip — never green, never
 *    red. Broken-zero is UNDETECTABLE for these features in Slice 1.
 */
export type FeatureLivenessClass = "self_reporting" | "event_driven";

/**
 * Health verdict for one feature. The color model is lifted from `posture.ts`:
 *
 *  - `active`   → GREEN. Earned ONLY by fresh, provenance-gated evidence
 *                 (self-reporting features) or by real activity in the window
 *                 (event-driven features). The single green value.
 *  - `fault`    → RED. A fresh fault/not-enforcing event was observed.
 *  - `unconfirmed` → distinct NON-GREEN chip. An event-driven feature with no
 *                 activity in the window: armed, but its working state cannot be
 *                 independently confirmed. NEVER the same chip as `active`.
 *  - `unknown`  → NON-GREEN. We cannot prove the state either way: a
 *                 self-reporting feature with stale/absent evidence (incl. the
 *                 "daemon silently died" case, pending the Slice-2 heartbeat),
 *                 or any feature whose backing audit read was integrity-tainted.
 */
export type FeatureHealthStatus = "active" | "fault" | "unconfirmed" | "unknown";

/**
 * Stable enum form of *why* a feature reads as it does. The UI renders human
 * copy from this; the field never leaks rule internals.
 */
export type FeatureHealthBasis =
  | "fresh_enforcement_evidence"
  | "activity_in_window"
  | "fault_evidence"
  | "stale_evidence"
  | "no_evidence_self_reporting"
  | "no_activity_event_driven"
  | "integrity_tainted"
  // The freshness-window scan could not be proven complete (it returned a full
  // page, so an older fault inside the window may have been dropped). We cannot
  // prove the absence of a fault, so a self-reporting feature can never render
  // green on this basis — it fails closed to `unknown`. See codex MEDIUM
  // 2026-06-13.
  | "freshness_scan_incomplete";

/**
 * A feature's matcher + liveness declaration. This is configuration, not
 * telemetry. Matchers are operation-string-keyed wherever possible to stay on
 * the cheap query path (the `details` post-filter is only used for the Castle
 * Wall provenance gate, which is mandatory for correctness).
 */
export interface FeatureRegistryEntry {
  /** Stable feature id (used as the row key and for drill-down routing). */
  id: string;
  /** Plain-English feature name for the row label. */
  label: string;
  /** Audit layer the feature writes to (narrows the query). */
  layer: AuditEntry["layer"];
  /** How the feature proves liveness. */
  liveness: FeatureLivenessClass;
  /**
   * Operation strings that count as an INVOCATION of this feature. For a
   * self-reporting feature these are its live-adjudication ops; for an
   * event-driven feature these are the ops it emits when triggered.
   */
  invocationOps: ReadonlySet<string>;
  /**
   * Operation strings that prove the feature is present but NOT enforcing
   * (fault). Only meaningful for self-reporting features; empty for
   * event-driven ones (they have no fault-event vocabulary in Slice 1).
   */
  faultOps?: ReadonlySet<string>;
  /**
   * When true, an invocation only counts if the entry carries the Castle Wall
   * `cw_source` provenance marker. Defends against a different L1 producer
   * reusing an operation name. Castle Wall only.
   */
  requireCastleWallProvenance?: boolean;
  /**
   * Whether broken-zero is even detectable for this feature. Surfaced verbatim
   * so the UI never implies "confirmed working" for a feature it cannot
   * independently confirm. Self-reporting → true; event-driven → false.
   */
  brokenZeroDetectable: boolean;
}

/**
 * One health row in the panel. `/v1`-compatible via `origin_machine`, matching
 * the rest of the posture surface.
 */
export interface FeatureHealthRow {
  origin_machine: string;
  feature_id: string;
  label: string;
  liveness: FeatureLivenessClass;
  /** The single non-green-unless-earned color model. */
  status: FeatureHealthStatus;
  /** Stable reason enum; UI renders copy from this. */
  basis: FeatureHealthBasis;
  /** Count of invocations matched in the window. */
  invocation_count: number;
  /** ISO8601 of the most recent invocation evidence, if any. */
  last_evidence_at: string | null;
  /**
   * Whether broken-zero is detectable for this feature. False for purely
   * event-driven features (the config-vs-activity cross-check is vacuous for
   * them). The UI uses this to phrase the `unconfirmed` chip honestly.
   */
  broken_zero_detectable: boolean;
  /** True when the backing audit read was integrity-clean. */
  audit_integrity_ok: boolean;
  /** Freshness window (ms) used to judge "recent" for self-reporting features. */
  freshness_window_ms: number;
}

/**
 * The Slice-1 feature registry. Only features whose audit operations are
 * already emitted + queryable today (verified against the tree on 2026-06-13).
 * Mutually exclusive by construction: no operation string appears in two
 * entries, so an event is never double-counted across features.
 */
export const SLICE1_FEATURE_REGISTRY: ReadonlyArray<FeatureRegistryEntry> =
  Object.freeze([
    {
      id: "castle_wall_egress",
      label: "Castle Wall egress firewall",
      layer: "l1",
      liveness: "self_reporting",
      // Only live-adjudication ops prove enforcement; NOT policy_loaded.
      invocationOps: CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS,
      faultOps: CASTLE_WALL_NOT_ENFORCING_OPERATIONS,
      requireCastleWallProvenance: true,
      brokenZeroDetectable: true,
    },
    {
      id: "secret_broker",
      label: "Secret broker (selective disclosure)",
      layer: "l3",
      liveness: "event_driven",
      invocationOps: Object.freeze(
        new Set<string>(["broker_token_issued", "broker_token_denied"]),
      ),
      brokenZeroDetectable: false,
    },
    {
      id: "approval_gates",
      label: "Human-approval gates",
      layer: "l2",
      liveness: "event_driven",
      // The cross-harness approval resolver emits a single exact operation; the
      // per-tool gate ops are dynamic (`gate_allow:<op>`), so we key on the
      // stable resolved op + the broker-independent approval signal.
      invocationOps: Object.freeze(
        new Set<string>(["cross_harness_approval_resolved"]),
      ),
      brokenZeroDetectable: false,
    },
    {
      id: "unified_inbox",
      label: "Unified approval inbox",
      layer: "l2",
      liveness: "event_driven",
      invocationOps: Object.freeze(
        new Set<string>([
          "unified_inbox_entry_aggregated",
          "unified_inbox_entry_resolved",
          "unified_inbox_entry_deduped",
        ]),
      ),
      brokenZeroDetectable: false,
    },
    {
      id: "privacy_strips",
      label: "Query-privacy strips",
      layer: "l2",
      liveness: "event_driven",
      // ONLY the actual rewrite proves the privacy stripper DID something. A
      // config update or a consent record is administrative housekeeping, not a
      // strip — counting them as activity would render the feature green without
      // a single query ever having been stripped (codex HIGH 2026-06-13).
      invocationOps: Object.freeze(
        new Set<string>(["query_anonymity_pii_rewritten"]),
      ),
      brokenZeroDetectable: false,
    },
  ]);

export interface BuildFeatureHealthInput {
  auditLog: AuditLog;
  originMachine: string;
  /** Registry to evaluate. Defaults to the Slice-1 registry; injectable for tests. */
  registry?: ReadonlyArray<FeatureRegistryEntry>;
  now?: number;
  /** Freshness window for self-reporting evidence. */
  freshnessWindowMs?: number;
  /** Window over which invocations are counted. */
  windowMs?: number;
  /**
   * The reader's pinned producer public key (see `BuildCastleWallPostureInput`).
   * Threaded into every per-feature evaluation so provenance-gated Castle Wall
   * invocations re-verify their producer signature. Null on macOS / pre-provision.
   */
  pinnedProducerKeyB64url?: string | null;
  /**
   * Slice P fail-honest signal: a producer key is EXPECTED (the daemon published
   * one) but the reader could NOT load it. The read-side authenticity basis is
   * therefore unavailable, so NO feature may render green — falling back to the
   * channel basis would be a weaker basis than the key-bearing consumer's. When
   * true, the panel is computed with `integrityOk=false`, which the existing
   * "tainted read → unknown" lever maps to `unknown` for every row (never green).
   * Set only when `pinnedProducerKeyB64url` is null.
   */
  producerKeyExpectedButUnavailable?: boolean;
  /** Injectable verify fn for tests; defaults to the real Ed25519 verifier. */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}

/**
 * Evaluate one feature's health from a pre-read, integrity-judged slice of
 * audit entries. Pure: no I/O. Exposed for fine-grained unit tests.
 *
 * `integrityOk === false` forces `unknown` regardless of what the entries say —
 * a tainted read can NEVER render green (or even red, since the evidence we'd
 * judge a fault from is itself untrustworthy).
 */
export function evaluateFeatureHealth(args: {
  feature: FeatureRegistryEntry;
  /** The full digest window (e.g. 24h): used for invocation_count + staleness. */
  entries: ReadonlyArray<AuditEntry>;
  /**
   * The freshness window (e.g. 10m): the basis for the fault/green decision.
   * Defaults to `entries` for callers (and tests) that pass a single set. The
   * panel builder passes a dedicated, completeness-checked freshness read so a
   * fault inside the window can never be dropped by the digest read's page
   * limit (codex MEDIUM 2026-06-13).
   */
  freshnessEntries?: ReadonlyArray<AuditEntry>;
  /**
   * False when the freshness read could not be proven complete (it returned a
   * full page). A self-reporting feature then cannot render green — it fails
   * closed to `unknown` — because an older fault in the window may be unseen.
   * Defaults to true.
   */
  freshnessComplete?: boolean;
  originMachine: string;
  now: number;
  freshnessWindowMs: number;
  integrityOk: boolean;
  /**
   * The reader's pinned producer public key (see `BuildCastleWallPostureInput`).
   * When non-null, a provenance-gated Castle Wall INVOCATION only counts toward
   * green if its producer signature RE-verifies against this key; a forged
   * `producer_signed`-claiming invocation is dropped. When null, invocation
   * recognition rests on the channel basis (legacy / macOS). Fault recognition
   * is never gated by it (faults fail toward RED — see `classify`).
   */
  pinnedProducerKeyB64url?: string | null;
  /** Injectable verify fn for tests; defaults to the real Ed25519 verifier. */
  verifyProducerSignature?: VerifyProducerSignatureFn;
}): FeatureHealthRow {
  const { feature, entries, originMachine, now, freshnessWindowMs, integrityOk } =
    args;
  const pinnedProducerKey = args.pinnedProducerKeyB64url ?? null;
  const freshnessEntries = args.freshnessEntries ?? entries;
  const freshnessComplete = args.freshnessComplete ?? true;
  const freshnessFloor = now - freshnessWindowMs;

  // Shared per-entry guard: belongs to this feature's layer and is an invocation
  // or fault op for it. The Castle Wall provenance gate is ASYMMETRIC by design —
  // green is gated strictly, faults are recognized loosely:
  //
  //  - GREEN-EARNING invocation ops MUST carry the consumer's `cw_source` marker.
  //    A foreign producer reusing an op name like `egress_blocked` therefore
  //    cannot ARM (green) the wall. (A forged wire-level `cw_source` cannot
  //    survive into the persisted entry because the consumer stamps the marker
  //    AFTER spreading the event's own details.)
  //  - FAULT ops are NOT gated: some real Castle Wall not-enforcing writes (e.g.
  //    `policy_validation_failed` from the daemon) are appended WITHOUT the
  //    marker. Gating faults on it would DROP real faults and leave the wall
  //    green-while-faulted (codex MEDIUM 2026-06-13). We fail toward RED: a
  //    foreign fake fault is only a false alarm (availability), never a hidden
  //    fault.
  //
  // NOTE (codex HIGH 2026-06-13, accepted as shipped-parity): the green gate is a
  // string-equality check on a mutable `details` field, so any IN-PROCESS writer
  // holding `AuditLog.append` could forge a green. This is the EXACT trust
  // boundary the shipped `posture.ts` already lives with (in-process writers are
  // trusted; the wall's real anti-forgery anchor is the signed manifest, not this
  // read-side projection). This slice is no MORE permissive than posture.ts;
  // cryptographic per-entry provenance is out of scope for a read projection.
  // Returns the classification, or null to skip.
  const classify = (
    entry: AuditEntry,
  ):
    | {
        ts: number;
        tsValid: boolean;
        isInvocation: boolean;
        isFault: boolean;
        /** Dedup key for a re-verified producer-signed invocation, else null. */
        signedDedupKey: string | null;
      }
    | null => {
    if (entry.layer !== feature.layer) return null;
    const op = entry.operation;
    const isInvocation = feature.invocationOps.has(op);
    const isFault = feature.faultOps !== undefined && feature.faultOps.has(op);
    if (!isInvocation && !isFault) return null;
    // Gate ONLY green-earning invocation evidence; never gate fault recognition.
    // (For Castle Wall, invocationOps and faultOps are disjoint, so a fault entry
    // is never dropped here.)
    let signedTs: number | null = null;
    let signedDedupKey: string | null = null;
    if (feature.requireCastleWallProvenance && isInvocation) {
      const hasProvenance =
        isRecord(entry.details) &&
        entry.details[CASTLE_WALL_AUDIT_PROVENANCE_KEY] ===
          CASTLE_WALL_AUDIT_PROVENANCE_VALUE;
      if (!hasProvenance) return null;
      // SIGNATURE GATE (Slice R): the marker is a forgeable pre-filter. The
      // authority for a green-earning invocation is the producer signature,
      // RE-verified here against the pinned key. When a key IS configured, only a
      // `producer_signed_verified` invocation counts — a channel/absent-basis or
      // forged entry is dropped (the consumer never persists genuine enforcement
      // evidence on the channel basis when a key is set; codex HIGH #1). When NO
      // key is configured, the channel basis counts (honest macOS floor). Fault
      // ops are NOT routed here (they fail toward RED), so this never drops a
      // real fault.
      const reResult = reverifyEntryProducerSignature(
        entry.details,
        pinnedProducerKey,
        args.verifyProducerSignature,
      );
      if (!enforcementEntryCounts(reResult.basis, pinnedProducerKey !== null)) {
        return null;
      }
      signedTs = reResult.signedCapturedAtMs;
      if (reResult.basis === "producer_signed_verified" && isRecord(entry.details)) {
        signedDedupKey = producerSignedDedupKey(entry.details);
      }
    }
    // Freshness uses the SIGNATURE-BOUND capture time for a verified producer
    // signature, defeating same-seq replay with a forged-fresh top-level
    // timestamp (codex HIGH #3). Channel-basis / fault entries use the top-level
    // timestamp (the honest no-key floor).
    const ts = signedTs !== null ? signedTs : Date.parse(entry.timestamp);
    // Reject future-dated evidence beyond a small clock-skew tolerance: a future
    // timestamp must not keep a self-reporting feature green past the real
    // freshness window.
    const tsValid = !Number.isNaN(ts) && ts <= now + ENFORCEMENT_FUTURE_SKEW_MS;
    return { ts, tsValid, isInvocation, isFault, signedDedupKey };
  };

  // Pass 1 — counts + staleness over the full digest window. A re-verified
  // producer-signed invocation counts at MOST ONCE: a copied genuine signed
  // entry (same seq + signature) must not inflate invocation_count (codex
  // round-4 HIGH). Pass 2 is max-based, so duplicates there are harmless and
  // need no dedup.
  const countedSignedKeys = new Set<string>();
  let invocationCount = 0;
  let latestInvocationMs: number | null = null;
  for (const entry of entries) {
    const c = classify(entry);
    if (c === null || !c.isInvocation) continue;
    if (c.signedDedupKey !== null) {
      if (countedSignedKeys.has(c.signedDedupKey)) continue; // duplicate replay
      countedSignedKeys.add(c.signedDedupKey);
    }
    invocationCount += 1;
    if (
      !Number.isNaN(c.ts) &&
      (latestInvocationMs === null || c.ts > latestInvocationMs)
    ) {
      latestInvocationMs = c.ts;
    }
  }

  // Pass 2 — the fault/green decision over the (completeness-checked) freshness
  // window. Fresh fault AND fresh invocation are both freshness-window facts.
  let latestFreshInvocationMs: number | null = null;
  let latestFreshFaultMs: number | null = null;
  for (const entry of freshnessEntries) {
    const c = classify(entry);
    if (c === null || !c.tsValid || c.ts < freshnessFloor) continue;
    if (
      c.isInvocation &&
      (latestFreshInvocationMs === null || c.ts > latestFreshInvocationMs)
    ) {
      latestFreshInvocationMs = c.ts;
    }
    if (
      c.isFault &&
      (latestFreshFaultMs === null || c.ts > latestFreshFaultMs)
    ) {
      latestFreshFaultMs = c.ts;
    }
  }

  let status: FeatureHealthStatus;
  let basis: FeatureHealthBasis;

  if (!integrityOk) {
    // The "never fake green" invariant applied to the read path: a tainted
    // read can never render green (or a trusted red). Fail closed to unknown.
    status = "unknown";
    basis = "integrity_tainted";
  } else if (feature.liveness === "self_reporting") {
    // Self-reporting: green ONLY on fresh live-adjudication evidence; a fresh
    // fault is red and takes precedence over green ALWAYS; stale or absent
    // evidence is unknown (NEVER green). The "daemon silently died" case lands
    // here as `unknown` — the periodic heartbeat producer that would distinguish
    // quiet-healthy from dead is Slice 2, by design.
    if (latestFreshFaultMs !== null) {
      // Fault precedence: a fresh fault renders the feature `fault` even when
      // fresh enforcement evidence co-occurs in the window (a wall that
      // crashed/unbound after adjudicating is degraded, not healthy). Ordering
      // this branch FIRST is the load-bearing "no green while faulted" guarantee
      // — codex HIGH 2026-06-13.
      status = "fault";
      basis = "fault_evidence";
    } else if (!freshnessComplete) {
      // The freshness scan was not provably complete, so an older fault in the
      // window may be unseen. We cannot prove fault-absence → never green.
      status = "unknown";
      basis = "freshness_scan_incomplete";
    } else if (latestFreshInvocationMs !== null) {
      status = "active";
      basis = "fresh_enforcement_evidence";
    } else if (latestInvocationMs !== null) {
      status = "unknown";
      basis = "stale_evidence";
    } else {
      status = "unknown";
      basis = "no_evidence_self_reporting";
    }
  } else {
    // Event-driven: activity in the window is green; quiet is a DISTINCT
    // non-green `unconfirmed` chip, never green and never red. Broken-zero is
    // undetectable for these features (the config-vs-activity cross-check is
    // vacuous — configured-ON + zero activity is indistinguishable from
    // healthy-quiet).
    if (invocationCount > 0) {
      status = "active";
      basis = "activity_in_window";
    } else {
      status = "unconfirmed";
      basis = "no_activity_event_driven";
    }
  }

  return {
    origin_machine: originMachine,
    feature_id: feature.id,
    label: feature.label,
    liveness: feature.liveness,
    status,
    basis,
    invocation_count: invocationCount,
    last_evidence_at:
      latestInvocationMs !== null
        ? new Date(latestInvocationMs).toISOString()
        : null,
    broken_zero_detectable: feature.brokenZeroDetectable,
    audit_integrity_ok: integrityOk,
    freshness_window_ms: freshnessWindowMs,
  };
}

export interface FeatureHealthPanel {
  origin_machine: string;
  window_start: string;
  window_end: string;
  /** One row per registry feature, in registry order. */
  rows: FeatureHealthRow[];
  /** True when the backing audit read was integrity-clean. */
  audit_integrity_ok: boolean;
  /**
   * Honest disclosure, surfaced to the UI: broken-zero (a silently-disabled
   * feature) is UNDETECTABLE for purely event-driven features in Slice 1, and
   * the periodic Castle Wall liveness heartbeat (which would catch the "daemon
   * silently died" case) is Slice 2. The panel never claims more than it can
   * prove.
   */
  disclosure: {
    broken_zero_undetectable_for_event_driven: true;
    castle_wall_silent_death_is_unknown_not_green: true;
  };
}

/**
 * Build the feature-health panel: one read over the audit window, judged for
 * integrity once, then folded per-feature through `evaluateFeatureHealth`.
 *
 * The read mirrors `posture.ts`'s cost profile: a single window-sized query
 * with `limit: 10_000` (matchers are operation-string-keyed, so we stay off the
 * `details` post-filter path except for the Castle Wall provenance gate). If
 * the read fails or is integrity-tainted, EVERY row fails closed to `unknown`
 * — never an empty-but-green panel.
 */
export async function buildFeatureHealthPanel(
  input: BuildFeatureHealthInput,
): Promise<FeatureHealthPanel> {
  const now = input.now ?? Date.now();
  const freshnessWindowMs =
    input.freshnessWindowMs ?? DEFAULT_ENFORCEMENT_FRESHNESS_MS;
  const windowMs = input.windowMs ?? DEFAULT_DIGEST_WINDOW_MS;
  const registry = input.registry ?? SLICE1_FEATURE_REGISTRY;
  const windowStart = new Date(now - windowMs).toISOString();
  const windowEnd = new Date(now).toISOString();

  // The audit query pages with a fixed limit and returns the most-recent slice;
  // a full page means older entries in the range were dropped (truncation).
  const AUDIT_PAGE_LIMIT = 10_000;

  let entries: AuditEntry[];
  let integrityOk: boolean;
  try {
    // One read over the whole digest window across all layers; per-feature
    // folding narrows by layer. A window-sized limit (not the default 50) so the
    // count reflects the full window, not a recent slice.
    const result = await input.auditLog.query({
      since: windowStart,
      limit: AUDIT_PAGE_LIMIT,
    });
    entries = result.entries;
    integrityOk = result.integrity_findings.length === 0;
  } catch {
    // A failed/tainted read must NOT render any feature green. Fail closed: an
    // empty entry set with integrityOk=false makes every row `unknown`.
    entries = [];
    integrityOk = false;
  }

  // Dedicated freshness-window read for the fault/green decision. The digest read
  // above can drop the OLDEST entries when the window is busier than one page,
  // which could mask a fault inside the (much shorter) freshness window and let a
  // feature read green while faulted — codex MEDIUM 2026-06-13. A scan scoped to
  // the freshness window is far less likely to truncate; if it DOES return a full
  // page we cannot prove fault-absence, so `freshnessComplete=false` forces every
  // self-reporting feature to fail closed to `unknown`.
  const freshnessFloorIso = new Date(now - freshnessWindowMs).toISOString();
  let freshnessEntries: AuditEntry[];
  let freshnessComplete: boolean;
  try {
    const fresh = await input.auditLog.query({
      since: freshnessFloorIso,
      limit: AUDIT_PAGE_LIMIT,
    });
    freshnessEntries = fresh.entries;
    freshnessComplete = fresh.entries.length < AUDIT_PAGE_LIMIT;
    if (fresh.integrity_findings.length > 0) integrityOk = false;
  } catch {
    freshnessEntries = [];
    freshnessComplete = false;
    integrityOk = false;
  }

  // Slice P fail-honest: a producer key is expected but the reader could not
  // load it, so the read-side authenticity basis is unavailable. Force the
  // tainted-read path (integrityOk=false, freshnessComplete=false): every row
  // renders `unknown`, never green on a weaker basis than the consumer wrote
  // with. This reuses the existing "untrustworthy read → unknown" invariant.
  if (input.producerKeyExpectedButUnavailable === true) {
    integrityOk = false;
    freshnessComplete = false;
  }

  // Bound each window's UPPER edge: the query only filters `since`, so skip any
  // entry timestamped past `now` (an unparseable timestamp is kept; the chain's
  // own integrity machinery owns malformed-entry detection).
  const upperBounded = (list: AuditEntry[]): AuditEntry[] =>
    list.filter((e) => {
      const ts = Date.parse(e.timestamp);
      return Number.isNaN(ts) || ts <= now;
    });
  const inWindow = upperBounded(entries);
  const inFreshness = upperBounded(freshnessEntries);

  const rows = registry.map((feature) =>
    evaluateFeatureHealth({
      feature,
      entries: inWindow,
      freshnessEntries: inFreshness,
      freshnessComplete,
      originMachine: input.originMachine,
      now,
      freshnessWindowMs,
      integrityOk,
      pinnedProducerKeyB64url: input.pinnedProducerKeyB64url ?? null,
      ...(input.verifyProducerSignature
        ? { verifyProducerSignature: input.verifyProducerSignature }
        : {}),
    }),
  );

  return {
    origin_machine: input.originMachine,
    window_start: windowStart,
    window_end: windowEnd,
    rows,
    audit_integrity_ok: integrityOk,
    disclosure: {
      broken_zero_undetectable_for_event_driven: true,
      castle_wall_silent_death_is_unknown_not_green: true,
    },
  };
}

// ── OS-notification fault rule set (the 3 fault classes ONLY) ─────────────────

/**
 * The TIGHT set of fault classes eligible for an OS notification (Erik-ratified
 * 2026-06-13). Everything else is dashboard-only. This module defines the rule
 * shape and the matcher; it does NOT itself raise notifications (the raise path
 * is the route/daemon layer's job and is rate-limited + deduped there).
 *
 *   (a) castle_wall_fault    — a fresh Castle Wall not-enforcing event
 *                              (filter_crashed / provider_unbound /
 *                              no_wall_engaged / external_firewall_clobber /
 *                              policy_validation_failed). Rides the existing
 *                              `CASTLE_WALL_NOT_ENFORCING_OPERATIONS` set.
 *   (b) feature_silently_off — a feature observed ON (active) in a prior
 *                              evaluation, then `unconfirmed`/`unknown` in a
 *                              later one (an ON→OFF state transition). State
 *                              comparison is the caller's; this enum names it.
 *   (c) plugin_failure_surge — DEFERRED behind #508 S4. No emission path exists
 *                              yet (`substrate/verdict.ts` is contract-only),
 *                              so this rule is wired but DORMANT: it can never
 *                              fire until a `plugin_error` producer lands. Do
 *                              NOT fabricate a producer to make it fire.
 */
export type FeatureFaultClass =
  | "castle_wall_fault"
  | "feature_silently_off"
  | "plugin_failure_surge";

export interface FeatureFaultClassRule {
  class: FeatureFaultClass;
  /** Human-facing description (the notification body source). */
  description: string;
  /**
   * Whether a producer exists for this class today. `plugin_failure_surge` is
   * dormant until #508 S4 lands an emission path; the route layer MUST skip any
   * rule whose `dormant` flag is true so a dormant rule can never fire on
   * fabricated data.
   */
  dormant: boolean;
}

export const FEATURE_FAULT_CLASS_RULES: ReadonlyArray<FeatureFaultClassRule> =
  Object.freeze([
    {
      class: "castle_wall_fault",
      description:
        "Castle Wall reported it is not enforcing (a fault event was observed).",
      dormant: false,
    },
    {
      class: "feature_silently_off",
      description:
        "A security feature was active and then went silent without an operator action.",
      dormant: false,
    },
    {
      class: "plugin_failure_surge",
      description:
        "A security plugin's failure rate crossed into sustained failure.",
      // DORMANT: no plugin_error emission path exists until #508 S4. Wired so
      // the rule shape is reviewable now; the route layer must not fire it.
      dormant: true,
    },
  ]);
