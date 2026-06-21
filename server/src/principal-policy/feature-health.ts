/**
 * Feature-usage health - Slice 1 (generalize the `posture.ts` evidence model).
 *
 * The CISO who turns on Sanctuary is paying for a set of security features
 * (the Castle Wall egress firewall, the secret broker, the human-approval
 * gates, the unified inbox, the privacy strippers). Today they can confirm
 * those features are *configured*. This module answers a blunt second question:
 * **which of those features actually DID something in the window, and is any of
 * them silently dead?** - as a pure, read-only projection over the existing
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
 *    a fault op flips them to `fault`/red. Slice 2 closes the "daemon silently
 *    died" gap: a periodic, producer-signed liveness heartbeat lets the
 *    absence-of-enforcement case split into an honest alive-but-idle (`unknown`,
 *    `alive_no_recent_enforcement`) vs a silently-dead wall (`fault`/red,
 *    `dead_no_heartbeat`) - the latter the alarm Slice 1 left as a silent
 *    `unknown`. The heartbeat NEVER earns green: green stays gated on fresh
 *    live-adjudication evidence only. Event-driven features have NO liveness
 *    signal by construction: activity in the window renders `active`/green;
 *    quiet renders a distinct non-green `unconfirmed` chip ("armed - activity-
 *    only, not independently confirmed"), NEVER the same green as evidence-backed
 *    active. The config-vs-activity cross-check is *vacuous* for event-driven
 *    features (configured-ON + zero activity is indistinguishable from
 *    healthy-quiet), and we say so plainly rather than papering over it (HIGH-3).
 *
 *  - Integrity-tainted read → forced `unknown`, never green, for EVERY feature
 *    (the "never fake green" invariant applied to the read path).
 *
 *  - Provenance gate for Castle Wall evidence: an L1 entry only counts as
 *    Castle Wall enforcement evidence if it carries the audit consumer's
 *    `cw_source` provenance marker - a different producer reusing an operation
 *    name like `egress_blocked` can never arm the wall. Same teeth as
 *    `posture.ts`. (The known in-process-writer boundary documented there
 *    applies here unchanged.)
 *
 *  - Cache-invalidation: health is recomputed on audit chain-head advance, so a
 *    post-fault refresh can never show stale green. The pure evaluator is
 *    recomputed by the route layer keyed on the chain head (see
 *    `posture-routes.ts`).
 *
 *  - `policy_loaded` is NOT treated as liveness OR as live-adjudication
 *    evidence here. It fires only inside the reload path; a daemon that loaded
 *    policy once but stopped enforcing would otherwise read green for the
 *    freshness window. Only `egress_allowed` / `egress_blocked` /
 *    `operator_decision` prove live adjudication. This live-adjudication set is
 *    now the SAME frozen object as
 *    `posture.ts:CASTLE_WALL_ENFORCEMENT_OPERATIONS` (imported below): the
 *    banner reader and this feature-health panel share one definition of
 *    "armed," so they can never disagree on whether a wall is green. The
 *    previously-tracked honesty seam (posture armed on `policy_loaded` alone on
 *    the no-key/channel basis) is now closed at the source.
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
  CASTLE_WALL_ENFORCEMENT_OPERATIONS,
  CASTLE_WALL_LIVENESS_OPERATIONS,
  CASTLE_WALL_NOT_ENFORCING_OPERATIONS,
  CASTLE_WALL_STAND_DOWN_OPERATIONS,
  DEFAULT_ENFORCEMENT_FRESHNESS_MS,
  DEFAULT_DIGEST_WINDOW_MS,
  ENFORCEMENT_FUTURE_SKEW_MS,
} from "./posture.js";
import {
  reverifyEntryProducerSignature,
  enforcementEntryCounts,
  livenessEntryCounts,
  producerSignedDedupKey,
  signedCanonicalOperation,
  type EntryReverifyBasis,
  type VerifyProducerSignatureFn,
} from "./producer-reverify.js";
import { CASTLE_WALL_HEARTBEAT_OPERATION } from "../castle-wall/constants.js";
import {
  BROKER_DAEMON_HEARTBEAT_OPERATION,
  BROKER_DAEMON_STAND_DOWN_OPERATION,
  BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
  BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
} from "../broker-mcp/liveness-constants.js";

/**
 * Liveness-op set for the broker daemon's process-liveness heartbeat (Option C).
 * A frozen single-element set, mirroring `CASTLE_WALL_LIVENESS_OPERATIONS`. Kept
 * DISJOINT from the event-driven `secret_broker` row's invocation ops
 * (`broker_token_issued` / `broker_token_denied`): a liveness beat proves the
 * PROCESS is up, NOT that a token decision happened.
 */
const BROKER_DAEMON_LIVENESS_OPERATIONS: ReadonlySet<string> = Object.freeze(
  new Set<string>([BROKER_DAEMON_HEARTBEAT_OPERATION]),
);

/**
 * Stand-down op set for the broker daemon (Option C false-RED parity with the
 * corrected Castle Wall Slice-2 pattern): a clean operator stop records this so a
 * deliberate shutdown is NOT misread as a silent death.
 */
const BROKER_DAEMON_STAND_DOWN_OPERATIONS: ReadonlySet<string> = Object.freeze(
  new Set<string>([BROKER_DAEMON_STAND_DOWN_OPERATION]),
);

/**
 * The broker daemon row's `invocationOps` is the EMPTY frozen set. A liveness
 * heartbeat is NOT request-correctness evidence, so this row can NEVER reach the
 * green `active` branch (which requires a fresh invocation) - green is
 * STRUCTURALLY impossible, not merely policy. Exported-by-reference as a single
 * frozen empty set to make that intent explicit and unforgeable.
 */
const BROKER_DAEMON_NO_INVOCATION_OPS: ReadonlySet<string> = Object.freeze(
  new Set<string>(),
);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function lifecycleQuerySpecs(
  registry: ReadonlyArray<FeatureRegistryEntry>,
): Array<{ layer: AuditEntry["layer"]; operation_type: string }> {
  const seen = new Set<string>();
  const specs: Array<{ layer: AuditEntry["layer"]; operation_type: string }> = [];
  for (const feature of registry) {
    for (const ops of [feature.livenessOps, feature.standDownOps]) {
      for (const op of ops ?? []) {
        const key = `${feature.layer}::${op}`;
        if (seen.has(key)) continue;
        seen.add(key);
        specs.push({ layer: feature.layer, operation_type: op });
      }
    }
  }
  return specs;
}

/**
 * Map from the daemon's SIGNED WAL `operation` vocabulary to the read-side
 * `entry.operation` this reader keys features on. Mirrors `WAL_OPERATION_TO_*`
 * in the audit consumer and `SIGNED_WAL_OP_TO_ENTRY_OP` in `posture.ts`, plus
 * the Slice-2 heartbeat (identity: the daemon signs and files the beat under the
 * same `castle_wall_heartbeat` op). Used to bind a re-verified signed body's
 * operation to the entry it is filed under, so a genuine signed tuple cannot be
 * relabeled into a different feature slot - e.g. a signed liveness heartbeat
 * stapled onto an `egress_blocked` entry to manufacture green (the sibling
 * posture reader binds the same way; feature-health must not be the weaker
 * surface).
 */
const SIGNED_WAL_OP_TO_FEATURE_OP: Readonly<Record<string, string>> =
  Object.freeze({
    egress_approved: "egress_allowed",
    egress_blocked: "egress_blocked",
    egress_pending: "operator_decision",
    [CASTLE_WALL_HEARTBEAT_OPERATION]: CASTLE_WALL_HEARTBEAT_OPERATION,
  });

/**
 * True iff a re-verified producer-signed entry's SIGNED canonical body attests
 * to the same read-side operation the entry is filed under. Fail closed on any
 * parse failure / unknown signed op / mismatch: a verified signature over one
 * operation must NOT count toward a DIFFERENT operation's tally.
 */
function signedOperationMatchesEntry(
  details: Record<string, unknown>,
  entryOperation: string,
): boolean {
  const signedOp = signedCanonicalOperation(details);
  if (signedOp === null) return false;
  return SIGNED_WAL_OP_TO_FEATURE_OP[signedOp] === entryOperation;
}

/**
 * A feature's per-feature producer-signature scheme: the bundle of read-side
 * re-verification primitives the green-gate uses for a feature whose producer
 * cryptographically signs its evidence. Factoring it out of a hardcoded Castle
 * Wall branch lets a future signing daemon declare the same teeth WITHOUT this
 * module growing a second `if (feature.id === ...)` ladder, while a feature with
 * NO scheme (a channel-marker-only heartbeat) skips the path entirely. The
 * Castle Wall scheme wires the EXISTING functions, so Castle Wall's behavior is
 * byte-for-byte unchanged.
 */
export interface ProducerSignatureScheme {
  /** Re-verify one entry's persisted producer signature against the pinned key. */
  reverify: (
    details: unknown,
    pinnedProducerKeyB64url: string | null,
    verify?: VerifyProducerSignatureFn,
  ) => { basis: EntryReverifyBasis; signedCapturedAtMs: number | null };
  /**
   * Does this basis let a GREEN-earning invocation count? (Key-present hosts
   * require a verified producer signature; no-key hosts accept channel basis.)
   */
  enforcementCounts: (basis: EntryReverifyBasis, keyPresent: boolean) => boolean;
  /**
   * Does this basis let a non-green LIVENESS / stand-down lifecycle signal
   * count? (Channel basis counts on every host; only a rejected forgery does
   * not, the heartbeat's inverse-asymmetry rule.)
   */
  livenessCounts: (basis: EntryReverifyBasis) => boolean;
  /**
   * For a verified producer signature, does the signed canonical body's
   * operation bind to the entry's filed operation? Closes the relabel/staple
   * attack. Channel-basis entries have no signed op to bind and skip this.
   */
  signedOperationMatches: (
    details: Record<string, unknown>,
    entryOperation: string,
  ) => boolean;
  /** Stable dedup key for a verified producer-signed entry (exact-replay guard). */
  dedupKey: (details: Record<string, unknown>) => string | null;
}

/**
 * The Castle Wall producer-signature scheme: the existing re-verify primitives
 * wired into the per-feature shape. Declaring this on the Castle Wall registry
 * row reproduces the prior hardcoded behavior EXACTLY (same re-verify, same
 * enforcement/liveness basis rules, same signed-op binding, same dedup).
 */
export const CASTLE_WALL_PRODUCER_SIGNATURE_SCHEME: ProducerSignatureScheme =
  Object.freeze({
    reverify: reverifyEntryProducerSignature,
    enforcementCounts: enforcementEntryCounts,
    livenessCounts: livenessEntryCounts,
    signedOperationMatches: signedOperationMatchesEntry,
    dedupKey: producerSignedDedupKey,
  });

/**
 * Live-adjudication evidence for Castle Wall: the operations that prove the
 * filter adjudicated real traffic (`egress_allowed` / `egress_blocked` /
 * `operator_decision`). `policy_loaded` is excluded (it proves a manifest was
 * accepted once, not that the wall is still enforcing).
 *
 * This is an ALIAS of `posture.ts:CASTLE_WALL_ENFORCEMENT_OPERATIONS`, not a
 * second copy: both readers consume the one frozen set, so no divergent color
 * model can drift back in (the convergence this slice landed). The
 * live-adjudication name is retained for the existing call sites and tests that
 * import it.
 */
export const CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS: ReadonlySet<string> =
  CASTLE_WALL_ENFORCEMENT_OPERATIONS;

/**
 * How a feature proves it is alive.
 *
 *  - `self_reporting`: emits evidence that could only come from the enforcing
 *    component acting on a real flow/policy, so fresh evidence earns `armed`
 *    and a fault op earns `fault`. Slice 2 adds a periodic, producer-signed
 *    liveness heartbeat so a silently-dead daemon (no fresh heartbeat) reads
 *    `fault`/red instead of `unknown`. Castle Wall is the only such feature.
 *  - `event_driven`: only ever writes to the audit log when something actually
 *    triggered it. A zero count is genuinely ambiguous (healthy-quiet vs
 *    silently-disabled are indistinguishable from counts alone), so quiet is
 *    rendered as a distinct non-green `unconfirmed` chip - never green, never
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
 *                 self-reporting feature that is alive-but-idle (a fresh
 *                 heartbeat, no fresh adjudication), or whose evidence is
 *                 stale/absent with no prior liveness signal, or any feature
 *                 whose backing audit read was integrity-tainted. Slice 2 moves
 *                 the genuinely-dead case (alive once, now no heartbeat) OUT of
 *                 `unknown` and into `fault`.
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
  // Observability Slice 2: NO fresh enforcement evidence AND a FRESH liveness
  // heartbeat. The daemon is alive but has not adjudicated a flow in the window,
  // so this is the honest "armed but idle" reading - `unknown` (never green),
  // but distinguished from a silently-dead wall. Closes the alive-vs-dead
  // ambiguity the old single `no_evidence_self_reporting` basis collapsed.
  | "alive_no_recent_enforcement"
  // Observability Slice 2: NO fresh enforcement evidence AND NO fresh heartbeat
  // within the freshness window. The periodic heartbeat producer should be
  // beating; its absence means the daemon silently died (process killed, sysext
  // unbound). Rendered as `fault`/red - the silent-death alarm Slice 1 left as
  // `unknown`.
  | "dead_no_heartbeat"
  // Observability Slice 2 (false-RED fix): NO fresh enforcement AND NO fresh
  // heartbeat, BUT the most-recent lifecycle signal is an INTENTIONAL stand-down
  // (a clean operator `filter_stopped` or an `arm_lease_revoked`). The wall is
  // off ON PURPOSE, not silently dead, so the honest reading is `unknown` (off,
  // not enforcing) - NOT the `dead_no_heartbeat` red alarm and NEVER green. A
  // genuine silent death (heartbeat stopped with NO subsequent stand-down)
  // still reads `dead_no_heartbeat`; the suppression rests on the SAME trust
  // basis as the heartbeat (see the stand-down trust note in `posture.ts`), so a
  // forger cannot use it to mute a real alarm into green - only into this
  // non-green `unknown`.
  | "intentionally_stopped"
  | "no_activity_event_driven"
  | "integrity_tainted"
  // The freshness-window scan could not be proven complete (it returned a full
  // page, so an older fault inside the window may have been dropped). We cannot
  // prove the absence of a fault, so a self-reporting feature can never render
  // green on this basis - it fails closed to `unknown`. See codex MEDIUM
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
   * Operation strings that prove the feature's daemon is ALIVE but do NOT prove
   * it adjudicated a real flow (the periodic liveness heartbeat, Slice 2). Only
   * meaningful for self-reporting features. A fresh liveness op moves the
   * absence-of-enforcement case from `unknown` toward an honest alive-but-idle
   * vs silently-dead distinction; it NEVER earns green on its own and is kept
   * DISJOINT from `invocationOps` (a heartbeat is liveness, not adjudication).
   * Absent/empty for features with no heartbeat producer.
   */
  livenessOps?: ReadonlySet<string>;
  /**
   * Operation strings that record an INTENTIONAL stand-down of this feature's
   * daemon (observability Slice 2 false-RED fix): a clean operator stop or an
   * arm-lease revoke. Only meaningful for self-reporting features with a
   * heartbeat producer. A RECENT stand-down (more recent than the last
   * heartbeat) means the daemon went quiet ON PURPOSE, so the reader relabels
   * what would otherwise be `dead_no_heartbeat`/red to an honest non-fault
   * `intentionally_stopped`/`unknown` (off, not dead). Gated on the SAME trust
   * basis as the heartbeat (`livenessEntryCounts`), so it can never mute a real
   * alarm into green - only into a non-green `unknown`. Kept DISJOINT from
   * `invocationOps` / `livenessOps` / `faultOps`. Absent for features with no
   * stand-down producer.
   */
  standDownOps?: ReadonlySet<string>;
  /**
   * Optional per-feature provenance marker. When present, an invocation /
   * liveness / stand-down entry only counts if its `details[key] === value`,
   * the cheap pre-filter that defends against a different producer on the same
   * layer reusing an operation name. Castle Wall declares its existing
   * `cw_source` marker here, so its provenance check is unchanged; a future
   * always-on daemon feature (the broker liveness heartbeat next) declares its
   * own `{ key, value }` pair to get the same gate WITHOUT inheriting Castle
   * Wall's signature machinery. A feature with no marker counts on the operation
   * string alone (the event-driven rows).
   */
  provenanceMarker?: { readonly key: string; readonly value: string };
  /**
   * Optional per-feature producer-signature scheme. When present, the
   * green-earning invocation evidence (and the liveness / stand-down lifecycle
   * signals) are RE-verified against the reader's pinned producer key through
   * this scheme, exactly as Castle Wall does today: a forged
   * `producer_signed`-claiming entry is dropped, a verified signed body's
   * operation is bound to the entry it is filed under, and exact replays are
   * deduped. Castle Wall declares the Castle Wall scheme, so its signed-basis
   * behavior is identical. A feature with a `provenanceMarker` but NO scheme
   * (the broker's channel-marker heartbeat) is recognized on the channel/marker
   * basis only (the signature re-verify path is never attempted for it), which
   * is the SAME basis a genuine Castle Wall heartbeat already uses on a
   * non-key-bearing host. Only meaningful alongside a `provenanceMarker`.
   */
  producerSignatureScheme?: ProducerSignatureScheme;
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
      // Slice 2: the periodic liveness heartbeat. Disjoint from invocationOps
      // (liveness, not adjudication), so it can distinguish alive-idle from
      // silently-dead WITHOUT ever earning green.
      livenessOps: CASTLE_WALL_LIVENESS_OPERATIONS,
      // Slice 2 false-RED fix: an intentional stand-down (clean stop or arm-lease
      // revoke) is the deliberate ABSENCE of enforcement, not a silent death.
      // A recent stand-down relabels `dead_no_heartbeat`/red to a non-fault
      // `intentionally_stopped`/`unknown`. Same trust basis as the heartbeat.
      standDownOps: CASTLE_WALL_STAND_DOWN_OPERATIONS,
      // Castle Wall declares its EXISTING `cw_source` provenance marker (the same
      // pre-filter) plus the Castle Wall producer-signature scheme, so its
      // provenance + signed-basis gate is byte-for-byte unchanged from the prior
      // `requireCastleWallProvenance: true`.
      provenanceMarker: {
        key: CASTLE_WALL_AUDIT_PROVENANCE_KEY,
        value: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
      },
      producerSignatureScheme: CASTLE_WALL_PRODUCER_SIGNATURE_SCHEME,
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
      // Observability (Option C, Erik-ratified): PROCESS-LIVENESS of the
      // long-running `sanctuary broker-server` MCP daemon. ADDITIVE on the
      // event-driven `secret_broker` row above (which stays UNCHANGED): that row
      // counts token decisions; THIS row answers only "is the broker daemon
      // process still alive, or did it silently die in a quiet window?".
      //
      // HONEST SCOPE (the multi-angle review hammers this): a heartbeat proves
      // ONLY that this daemon PROCESS is up. It does NOT prove the broker would
      // correctly mint or deny a token (no enforcement evidence exists for that),
      // NOT that the keychain backend is reachable, and says NOTHING about the
      // per-invocation `sanctuary secrets` CLI / in-server tool path. The UI copy
      // reads "broker daemon alive" / process liveness, NEVER "broker healthy" or
      // green.
      //
      // `invocationOps` is the EMPTY set, so green (`active`) is STRUCTURALLY
      // impossible: the `active` branch requires a fresh invocation, and there is
      // no invocation vocabulary here. A heartbeat can only move the
      // absence-of-evidence case from `unknown` toward an honest
      // daemon-alive-but-idle vs silently-dead split; it never earns green.
      //
      // CHANNEL/MARKER basis only (NO `producerSignatureScheme`): the broker has
      // no per-event producer-signing infra, so recognition rests on the broker
      // provenance marker via the generalized per-feature gate from #658 - the
      // SAME basis a genuine Castle Wall heartbeat uses on a non-key-bearing
      // host. The in-process-writer boundary the Castle Wall channel heartbeat
      // discloses applies here UNCHANGED: an L3 writer holding `AuditLog.append`
      // could forge a fresh beat to suppress the alarm red -> non-green
      // `unknown`, but NEVER manufacture green.
      id: "secret_broker_daemon",
      label: "Secret broker daemon (process liveness)",
      layer: "l3",
      liveness: "self_reporting",
      // EMPTY by design: a heartbeat never proves request-correctness, so this
      // row can never read `active`/green.
      invocationOps: BROKER_DAEMON_NO_INVOCATION_OPS,
      // The periodic process-liveness heartbeat.
      livenessOps: BROKER_DAEMON_LIVENESS_OPERATIONS,
      // A clean operator stop relabels the otherwise-silent quiet window as an
      // honest intentional stand-down (false-RED parity with Castle Wall #657).
      standDownOps: BROKER_DAEMON_STAND_DOWN_OPERATIONS,
      // Channel/marker basis: provenance marker, NO signature scheme.
      provenanceMarker: {
        key: BROKER_DAEMON_AUDIT_PROVENANCE_KEY,
        value: BROKER_DAEMON_AUDIT_PROVENANCE_VALUE,
      },
      // Silent death of the broker DAEMON process is now detectable from a
      // missing heartbeat (true). NOTE: this is detectable for the long-running
      // DAEMON only; the event-driven `secret_broker` row's broken-zero (a
      // silently-disabled broker that emits no token events) remains UNDETECTABLE
      // - both facts coexist and the disclosure block states both honestly.
      brokenZeroDetectable: true,
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
      // The ALWAYS-ON Tier A query-privacy feature: fingerprintable HTTP
      // headers are stripped from every outbound substrate call, structurally
      // unconditional (no operator opt-out), emitting
      // `query_anonymity_headers_stripped` on every wrapped fetch
      // (`query-anonymity/header-strip.ts`; wired in `intelligence/selector.ts`).
      //
      // HONESTY (do NOT relabel to "anonymity"): this is metadata hygiene, not
      // anonymity. Stripping fingerprintable headers reduces what the substrate
      // provider can correlate, but the provider still sees the query CONTENT
      // and the authenticated API key. The row label and any panel copy must say
      // "header strip" / "metadata", never imply the queries are anonymous. See
      // the Phase 2 design overclaim flag (2026-06-19 §2.1 C).
      //
      // It is `event_driven`: it only writes to the audit log when a call
      // actually went out, so a quiet window is genuinely ambiguous (no calls vs
      // silently bypassed are indistinguishable from counts alone). Quiet renders
      // the distinct non-green `unconfirmed` chip, NEVER green - the broker is
      // broken-zero-undetectable, so absence is not evidence of health.
      id: "header_strip",
      label: "Query-privacy header strip (metadata)",
      layer: "l2",
      liveness: "event_driven",
      invocationOps: Object.freeze(
        new Set<string>(["query_anonymity_headers_stripped"]),
      ),
      brokenZeroDetectable: false,
    },
    {
      // Tier B PII rewrite (OPT-IN, off by default). Distinct from the Tier A
      // `header_strip` row above: this row intentionally counts ONLY the actual
      // rewrite op (`query_anonymity_pii_rewritten`), so a config update or a
      // consent record (administrative housekeeping, not a strip) can never
      // render it green without a single query having been rewritten (codex HIGH
      // 2026-06-13).
      //
      // KNOWN STANDING (documentation only - do NOT change behavior to force
      // green): the PII-rewrite emitter is not yet wired into the live selector
      // path (the deferred Rho-2.5 boot-wiring), so `query_anonymity_pii_rewritten`
      // does not fire in production today. This row therefore reads `unconfirmed`
      // (amber) until that wiring lands. That is the honest state; the always-on
      // privacy feature that DOES fire on every call is the `header_strip` row.
      id: "privacy_strips",
      label: "Query-privacy PII rewrite (opt-in)",
      layer: "l2",
      liveness: "event_driven",
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
   * therefore unavailable, so NO feature may render green - falling back to the
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
 * `integrityOk === false` forces `unknown` regardless of what the entries say -
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
   * full page). A self-reporting feature then cannot render green - it fails
   * closed to `unknown` - because an older fault in the window may be unseen.
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
   * is never gated by it (faults fail toward RED - see `classify`).
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
  // or fault op for it. The Castle Wall provenance gate is ASYMMETRIC by design -
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
  const livenessOps = feature.livenessOps;
  const standDownOps = feature.standDownOps;
  const provenanceMarker = feature.provenanceMarker;
  const signatureScheme = feature.producerSignatureScheme;
  const classify = (
    entry: AuditEntry,
  ):
    | {
        ts: number;
        tsValid: boolean;
        isInvocation: boolean;
        isFault: boolean;
        /** A producer-gated liveness heartbeat (Slice 2). Never an invocation. */
        isLiveness: boolean;
        /**
         * An intentional stand-down marker (Slice 2 false-RED fix): a clean
         * operator stop or arm-lease revoke. Never an invocation, never a fault.
         */
        isStandDown: boolean;
        /** Dedup key for a re-verified producer-signed invocation, else null. */
        signedDedupKey: string | null;
      }
    | null => {
    if (entry.layer !== feature.layer) return null;
    const op = entry.operation;
    const isInvocation = feature.invocationOps.has(op);
    const isFault = feature.faultOps !== undefined && feature.faultOps.has(op);
    const isLiveness = livenessOps !== undefined && livenessOps.has(op);
    const isStandDown = standDownOps !== undefined && standDownOps.has(op);
    if (!isInvocation && !isFault && !isLiveness && !isStandDown) return null;
    // Gate ONLY green-earning invocation evidence AND liveness heartbeats; never
    // gate fault recognition. (For Castle Wall, invocationOps / faultOps /
    // livenessOps are mutually disjoint, so a fault entry is never dropped here.)
    //
    // INVOCATIONS and LIVENESS heartbeats both pass the provenance marker + the
    // producer-signature re-verify, but their COUNT rules differ because they are
    // different kinds of evidence:
    //
    //  - An INVOCATION is green-earning enforcement evidence: on a key-bearing
    //    host the audit consumer never persists a genuine one on the channel
    //    basis, so only `producer_signed_verified` counts (`enforcementEntryCounts`).
    //  - A LIVENESS heartbeat is NOT green-earning. The real producer
    //    (`macos-daemon.ts:emitAuditHeartbeat`) writes it as a DIRECT
    //    `auditLog.append`, never through the signing consumer, so a GENUINE beat
    //    is channel-basis on EVERY host (Linux included). Gating it with
    //    `enforcementEntryCounts` would drop every genuine beat on a key-bearing
    //    host and render the silent-death alarm inert on the platform that
    //    matters. It is gated with `livenessEntryCounts`: a genuine channel beat
    //    counts, but a forged `producer_signed`-CLAIMING beat with a bad signature
    //    (`producer_signed_rejected`) still does NOT - the one way an in-process
    //    forger could fake "I am alive" to suppress the alarm.
    //  - A STAND-DOWN marker (Slice 2 false-RED fix) is ALSO not green-earning.
    //    The producer (`macos-daemon.ts` stop()/onArmLeaseRevoke) writes it as a
    //    DIRECT channel-basis `auditLog.append`, so it shares the heartbeat's
    //    trust basis EXACTLY and is gated with `livenessEntryCounts` for the same
    //    reason: a genuine channel stand-down counts (so a real clean stop
    //    suppresses the false alarm on every host), but a forged
    //    `producer_signed`-CLAIMING stand-down with a bad signature does NOT. A
    //    forged CHANNEL-basis stand-down is accepted on the same forgeable basis
    //    a forged channel heartbeat already is - and like that heartbeat it can
    //    only relabel a RED alarm into a non-green `unknown`, NEVER manufacture
    //    green, so no weaker trust boundary than the alarm it relabels is added.
    const gatedAsLiveness = isLiveness || isStandDown;
    let signedTs: number | null = null;
    let signedDedupKey: string | null = null;
    if (provenanceMarker !== undefined && (isInvocation || isLiveness || isStandDown)) {
      // MARKER GATE (per-feature). The marker is a forgeable pre-filter that
      // defends against a different producer on the same layer reusing an
      // operation name. Universal to any feature that declares a `provenanceMarker`
      // (Castle Wall today, the broker heartbeat next); fault ops are NOT routed
      // here (they fail toward RED), so this never drops a real fault.
      const hasProvenance =
        isRecord(entry.details) &&
        entry.details[provenanceMarker.key] === provenanceMarker.value;
      if (!hasProvenance) return null;
      // SIGNATURE GATE (per-feature, scheme-conditional). When the feature
      // declares a producer-signature SCHEME (Castle Wall), the marker's
      // authority is the producer signature, RE-verified here against the pinned
      // key. A feature with a marker but NO scheme (the broker's channel-marker
      // heartbeat) is recognized on the channel/marker basis only (the same
      // basis a genuine Castle Wall heartbeat already uses on a non-key-bearing
      // host), so the re-verify path is never attempted for it.
      if (signatureScheme !== undefined) {
        const reResult = signatureScheme.reverify(
          entry.details,
          pinnedProducerKey,
          args.verifyProducerSignature,
        );
        const basisCounts = gatedAsLiveness
          ? signatureScheme.livenessCounts(reResult.basis)
          : signatureScheme.enforcementCounts(
              reResult.basis,
              pinnedProducerKey !== null,
            );
        if (!basisCounts) {
          return null;
        }
        // OPERATION BINDING (parity with `posture.ts`): for a verified producer
        // signature the signed canonical body's operation is authoritative, NOT
        // the forgeable top-level `entry.operation`. Require they match so a
        // genuine signed tuple cannot be relabeled into a different feature slot,
        // e.g. a signed liveness heartbeat re-appended as `egress_blocked` to
        // manufacture green when it only proved liveness. Channel-basis entries
        // have no signed op to bind, so they keep the honest no-key floor (the
        // entry op).
        if (
          reResult.basis === "producer_signed_verified" &&
          isRecord(entry.details) &&
          !signatureScheme.signedOperationMatches(entry.details, op)
        ) {
          return null;
        }
        signedTs = reResult.signedCapturedAtMs;
        if (
          reResult.basis === "producer_signed_verified" &&
          isRecord(entry.details)
        ) {
          signedDedupKey = signatureScheme.dedupKey(entry.details);
        }
      }
    }
    // Freshness uses the SIGNATURE-BOUND capture time for a verified producer
    // signature, defeating same-seq replay with a forged-fresh top-level
    // timestamp (codex HIGH #3). Channel-basis / fault entries use the top-level
    // timestamp (the honest no-key floor).
    const ts = signedTs !== null ? signedTs : Date.parse(entry.timestamp);
    // Reject future-dated evidence beyond a small clock-skew tolerance: a future
    // timestamp must not keep a self-reporting feature green past the real
    // freshness window, nor let a future-dated heartbeat read as a fresh
    // liveness signal.
    const tsValid = !Number.isNaN(ts) && ts <= now + ENFORCEMENT_FUTURE_SKEW_MS;
    return {
      ts,
      tsValid,
      isInvocation,
      isFault,
      isLiveness,
      isStandDown,
      signedDedupKey,
    };
  };

  // Pass 1 - counts + staleness over the full digest window. A re-verified
  // producer-signed invocation counts at MOST ONCE: a copied genuine signed
  // entry (same seq + signature) must not inflate invocation_count (codex
  // round-4 HIGH). Pass 2 is max-based, so duplicates there are harmless and
  // need no dedup.
  const countedSignedKeys = new Set<string>();
  let invocationCount = 0;
  let latestInvocationMs: number | null = null;
  // Slice 2: did we observe ANY producer-gated heartbeat anywhere in the digest
  // window (fresh or stale)? Used so the silent-death alarm fires ONLY when the
  // daemon was once provably alive (a heartbeat or an invocation exists) and has
  // since gone silent - NOT on a wall that was never installed/started (no
  // evidence of any kind), which stays the honest `unknown`. A fault alarm is a
  // claim; we never raise it without prior liveness evidence.
  let everSawHeartbeat = false;
  // Slice 2 false-RED fix: the most-recent heartbeat AND the most-recent
  // INTENTIONAL stand-down (clean stop / arm-lease revoke) anywhere in the
  // digest window. The silent-death branch suppresses the alarm iff the last
  // lifecycle signal was a stand-down (stand-down at least as recent as the last
  // heartbeat): the wall went quiet ON PURPOSE, not by dying. If a heartbeat is
  // MORE recent than the last stand-down, the daemon came back and beat after
  // the stand-down, then went silent with no further stand-down → a genuine
  // silent death, and the alarm still fires.
  let latestHeartbeatMs: number | null = null;
  let latestStandDownMs: number | null = null;
  for (const entry of entries) {
    const c = classify(entry);
    if (c === null) continue;
    if (c.isLiveness && c.tsValid) {
      everSawHeartbeat = true;
      if (latestHeartbeatMs === null || c.ts > latestHeartbeatMs) {
        latestHeartbeatMs = c.ts;
      }
    }
    if (c.isStandDown && c.tsValid) {
      if (latestStandDownMs === null || c.ts > latestStandDownMs) {
        latestStandDownMs = c.ts;
      }
    }
    if (!c.isInvocation) continue;
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

  // Pass 2 - the fault/green decision over the (completeness-checked) freshness
  // window. Fresh fault, fresh invocation, AND fresh heartbeat are all
  // freshness-window facts.
  let latestFreshInvocationMs: number | null = null;
  let latestFreshFaultMs: number | null = null;
  // Slice 2: the most recent FRESH, producer-gated liveness heartbeat. Only used
  // to split the absence-of-enforcement case into alive-idle vs silently-dead; it
  // NEVER promotes a feature to green.
  let latestFreshHeartbeatMs: number | null = null;
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
    if (
      c.isLiveness &&
      (latestFreshHeartbeatMs === null || c.ts > latestFreshHeartbeatMs)
    ) {
      latestFreshHeartbeatMs = c.ts;
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
    // fault is red and takes precedence over green ALWAYS. Slice 2 closes the
    // "daemon silently died" gap Slice 1 left: a periodic, producer-signed
    // liveness heartbeat lets the ABSENCE-of-enforcement case split into an
    // honest alive-but-idle (`unknown`) vs silently-dead (`fault`/red) reading.
    // The heartbeat NEVER moves the PRESENCE case to green - green stays gated on
    // fresh live-adjudication evidence only.
    const hasFreshHeartbeat = latestFreshHeartbeatMs !== null;
    // A feature with NO heartbeat producer wired (no livenessOps) cannot
    // distinguish dead from idle, so it keeps the Slice-1 `unknown` floor rather
    // than mislabeling a quiet feature as dead.
    const hasHeartbeatProducer =
      livenessOps !== undefined && livenessOps.size > 0;
    // The silent-death alarm requires that the HEARTBEAT PRODUCER was once
    // provably running: a heartbeat (fresh or stale) appears somewhere in the
    // digest window, and now none is fresh. The beating stopped → the daemon
    // silently died. We deliberately do NOT raise the alarm from stale
    // enforcement evidence alone (no heartbeat ever seen): that could be a wall
    // from an older build with no heartbeat producer, or a deliberately disarmed
    // wall, so the honest reading there stays `stale_evidence`/`unknown`. With no
    // heartbeat ever observed we cannot prove the producer was running, so we
    // never fabricate a silent-death claim (never overclaim).
    const heartbeatProducerWasRunning = everSawHeartbeat;
    // Slice 2 false-RED fix: was the wall INTENTIONALLY stood down (clean stop /
    // arm-lease revoke), making this quiet window expected rather than a silent
    // death? True iff a stand-down signal exists in the digest window AND it is
    // at least as recent as the most-recent heartbeat. If a heartbeat came AFTER
    // the last stand-down, the daemon came back and beat again, then went silent
    // with no further stand-down - that IS a genuine silent death, so we do NOT
    // suppress. The stand-down rests on the SAME trust basis as the heartbeat
    // (channel-basis, `livenessEntryCounts`-gated), so a forger cannot use it to
    // mute a real alarm into GREEN - only into a non-green `unknown`.
    const intentionallyStoodDown =
      latestStandDownMs !== null &&
      (latestHeartbeatMs === null || latestStandDownMs >= latestHeartbeatMs);
    if (latestFreshFaultMs !== null) {
      // Fault precedence: a fresh fault renders the feature `fault` even when
      // fresh enforcement evidence (or a fresh heartbeat) co-occurs in the window
      // (a wall that crashed/unbound after adjudicating is degraded, not
      // healthy). Ordering this branch FIRST is the load-bearing "no green/idle
      // while faulted" guarantee - codex HIGH 2026-06-13. A fresh fault still
      // beats a fresh heartbeat (Slice-2 invariant: fault precedence unchanged).
      status = "fault";
      basis = "fault_evidence";
    } else if (!freshnessComplete) {
      // The freshness scan was not provably complete, so an older fault in the
      // window may be unseen. We cannot prove fault-absence → never green, and
      // also never the dead-alarm (an unseen heartbeat could exist too). Fail
      // closed to `unknown`.
      status = "unknown";
      basis = "freshness_scan_incomplete";
    } else if (latestFreshInvocationMs !== null) {
      // PRESENCE case: fresh live-adjudication evidence. Green. A heartbeat never
      // changes this branch (it cannot upgrade or downgrade real adjudication).
      status = "active";
      basis = "fresh_enforcement_evidence";
    } else if (hasFreshHeartbeat) {
      // ABSENCE-of-enforcement + FRESH heartbeat: the daemon is alive but has not
      // adjudicated a flow in the window. Honest alive-but-idle - `unknown`
      // (never green), distinguished from a silently-dead wall.
      status = "unknown";
      basis = "alive_no_recent_enforcement";
    } else if (
      hasHeartbeatProducer &&
      heartbeatProducerWasRunning &&
      intentionallyStoodDown
    ) {
      // ABSENCE-of-enforcement + NO fresh heartbeat, BUT the most-recent
      // lifecycle signal is an INTENTIONAL stand-down (clean operator stop or
      // arm-lease revoke). The wall is off ON PURPOSE, not silently dead, so the
      // honest reading is `unknown` (`intentionally_stopped`) - NOT the
      // `dead_no_heartbeat` red alarm, and NEVER green. This is the false-RED fix:
      // without it a deliberately-stopped wall read red for the whole digest
      // window. Ordered BEFORE the silent-death branch so a recorded stand-down
      // always relabels the quiet window honestly.
      status = "unknown";
      basis = "intentionally_stopped";
    } else if (hasHeartbeatProducer && heartbeatProducerWasRunning) {
      // ABSENCE-of-enforcement + NO fresh heartbeat, on a feature whose daemon
      // SHOULD be beating AND whose heartbeat producer was provably running
      // earlier in the window, with NO intentional stand-down recorded: the
      // beating stopped on its own → the wall silently died (process killed,
      // sysext unbound). The Slice-2 silent-death alarm - `fault`/red, not the old
      // `unknown`. (Reaching here means freshnessComplete is true, so the absence
      // of a heartbeat in the freshness window is provable, not a truncated read.)
      status = "fault";
      basis = "dead_no_heartbeat";
    } else if (latestInvocationMs !== null) {
      // Stale enforcement evidence but no heartbeat ever observed (an older build
      // with no heartbeat producer, or a wall disarmed since): keep the Slice-1
      // reading - `unknown`, never green. We do not fabricate a silent-death
      // alarm without proof the heartbeat producer was running.
      status = "unknown";
      basis = "stale_evidence";
    } else {
      // No enforcement evidence and no heartbeat ever: we cannot tell a
      // never-started wall from one that died long ago. Honest `unknown`, never a
      // fabricated silent-death alarm.
      status = "unknown";
      basis = "no_evidence_self_reporting";
    }
  } else {
    // Event-driven: activity in the window is green; quiet is a DISTINCT
    // non-green `unconfirmed` chip, never green and never red. Broken-zero is
    // undetectable for these features (the config-vs-activity cross-check is
    // vacuous - configured-ON + zero activity is indistinguishable from
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
   * feature) is UNDETECTABLE for purely event-driven features in Slice 1.
   *
   * Slice 2 update: the Castle Wall "daemon silently died" case is DETECTED
   * when lifecycle history is complete. A periodic liveness heartbeat means a
   * wall that silently dies (process killed, sysext unbound) in a quiet window
   * reads `fault`/red (`dead_no_heartbeat`), NOT the old `unknown`. So
   * `castle_wall_silent_death_is_unknown_not_green` is `false` on complete
   * history. It flips back to `true` when a history/freshness read is incomplete,
   * because absence of a fresh beat is then not provable. The panel still never
   * claims more than it can prove - a heartbeat proves liveness only, never green.
   *
   * Slice 2 false-RED fix: the silent-death alarm is now DISTINGUISHED from an
   * INTENTIONAL stand-down. A clean operator stop or an arm-lease revoke records
   * a stand-down marker; the reader relabels what would otherwise be
   * `dead_no_heartbeat`/red to an honest `intentionally_stopped`/`unknown` (off
   * on purpose, not dead). Only a GENUINE silent death (the heartbeat stopped
   * with NO subsequent stand-down) still reads red when history is complete.
   * `silent_death_distinguished_from_intentional_stop` records this honestly.
   * CAVEAT (no overclaim): the
   * stand-down marker is on the heartbeat's channel-basis trust boundary, so an
   * in-process forger that can already forge a heartbeat could relabel a real red
   * alarm to this `unknown` - but NEVER to green (the suppression can only move
   * red -> non-green `unknown`). This is the same forgeable in-process-writer
   * boundary the heartbeat itself discloses; it adds no weaker trust path.
   *
   * Broker Option C update: the long-running `broker-server` DAEMON now emits the
   * same kind of process-liveness heartbeat + stand-down, so a broker daemon that
   * silently dies in a quiet window reads `dead_no_heartbeat`/red on complete
   * history. `broker_daemon_silent_death_detectable` is false when the
   * lifecycle/freshness history was truncated.
   * CRITICALLY, this does NOT make the EVENT-DRIVEN `secret_broker` row's
   * broken-zero detectable: a broker that is silently disabled but emits no token
   * events is still indistinguishable from one that is simply quiet
   * (`broken_zero_undetectable_for_event_driven` stays true). Both facts coexist:
   * DAEMON process-death is detectable; event-driven broken-zero is not. The
   * daemon heartbeat is channel/marker basis (no producer signature), so it
   * carries the SAME in-process-writer caveat as the Castle Wall channel
   * heartbeat - it can only move red -> non-green `unknown`, never to green.
   */
  disclosure: {
    broken_zero_undetectable_for_event_driven: true;
    castle_wall_silent_death_is_unknown_not_green: boolean;
    silent_death_distinguished_from_intentional_stop: boolean;
    /**
     * The long-running broker DAEMON process now emits a liveness heartbeat, so
     * its silent death (process killed / wedged) is detectable as
     * `dead_no_heartbeat`/red on the `secret_broker_daemon` row when
     * lifecycle/freshness history is complete. Process-liveness only: NOT
     * token-mint/deny correctness, NOT keychain-reachability. Coexists with
     * `broken_zero_undetectable_for_event_driven` (the event-driven
     * `secret_broker` row's broken-zero stays undetectable).
     */
    broker_daemon_silent_death_detectable: boolean;
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
 * - never an empty-but-green panel.
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
  let freshnessComplete = true;
  let lifecycleHistoryComplete = true;
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

    // Lifecycle evidence (heartbeat + intentional stand-down) must not be
    // crowded out by unrelated high-volume audit traffic. Query those exact
    // operation/layer pairs before folding so silent-death detection still sees
    // stale-but-in-window lifecycle signals.
    for (const spec of lifecycleQuerySpecs(registry)) {
      const lifecycle = await input.auditLog.query({
        since: windowStart,
        layer: spec.layer,
        operation_type: spec.operation_type,
        limit: AUDIT_PAGE_LIMIT,
      });
      entries.push(...lifecycle.entries);
      if (lifecycle.total > lifecycle.entries.length) {
        lifecycleHistoryComplete = false;
      }
      if (lifecycle.integrity_findings.length > 0) integrityOk = false;
    }
  } catch {
    // A failed/tainted read must NOT render any feature green. Fail closed: an
    // empty entry set with integrityOk=false makes every row `unknown`.
    entries = [];
    integrityOk = false;
    lifecycleHistoryComplete = false;
  }

  // Dedicated freshness-window read for the fault/green decision. The digest read
  // above can drop the OLDEST entries when the window is busier than one page,
  // which could mask a fault inside the (much shorter) freshness window and let a
  // feature read green while faulted - codex MEDIUM 2026-06-13. A scan scoped to
  // the freshness window is far less likely to truncate; if it DOES return a full
  // page we cannot prove fault-absence, so `freshnessComplete=false` forces every
  // self-reporting feature to fail closed to `unknown`.
  const freshnessFloorIso = new Date(now - freshnessWindowMs).toISOString();
  let freshnessEntries: AuditEntry[];
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
  const detectionEvidenceComplete = freshnessComplete && lifecycleHistoryComplete;

  return {
    origin_machine: input.originMachine,
    window_start: windowStart,
    window_end: windowEnd,
    rows,
    audit_integrity_ok: integrityOk,
    disclosure: {
      broken_zero_undetectable_for_event_driven: true,
      // Slice 2: silent death is now DETECTED (a missing heartbeat reads
      // `fault`/red, not `unknown`) when the lifecycle history is complete.
      // If any history/freshness read was truncated, keep the old caveat true:
      // absence of a fresh beat is not provable on an incomplete history.
      castle_wall_silent_death_is_unknown_not_green:
        !detectionEvidenceComplete,
      // Slice 2 false-RED fix: a clean stop / arm-lease revoke is relabeled
      // `intentionally_stopped`, so a deliberately-stopped wall no longer reads a
      // false red `dead_no_heartbeat` when lifecycle history is complete.
      silent_death_distinguished_from_intentional_stop:
        detectionEvidenceComplete,
      // Broker Option C: the long-running broker DAEMON process now emits a
      // liveness heartbeat, so its silent death is detectable on the
      // `secret_broker_daemon` row. Process-liveness only - this does NOT make
      // the event-driven `secret_broker` row's broken-zero detectable (that flag
      // above stays true). Both honest facts coexist.
      broker_daemon_silent_death_detectable: detectionEvidenceComplete,
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
 *   (a) castle_wall_fault    - a fresh Castle Wall not-enforcing event
 *                              (filter_crashed / provider_unbound /
 *                              no_wall_engaged / external_firewall_clobber /
 *                              policy_validation_failed). Rides the existing
 *                              `CASTLE_WALL_NOT_ENFORCING_OPERATIONS` set.
 *   (b) feature_silently_off - a feature observed ON (active) in a prior
 *                              evaluation, then `unconfirmed`/`unknown` in a
 *                              later one (an ON→OFF state transition). State
 *                              comparison is the caller's; this enum names it.
 *   (c) plugin_failure_surge - DEFERRED behind #508 S4. No emission path exists
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
