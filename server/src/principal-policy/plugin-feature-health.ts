/**
 * Per-plugin feature-health rows (read-only observability projection).
 *
 * The CISO who installs a third-party security plugin is paying for it the same
 * way they pay for a native feature, so a plugin earns its OWN feature-health
 * row, scored on the SAME color model as the native rows (`active` / `fault` /
 * `unconfirmed` / `unknown`, lifted verbatim from `feature-health.ts`). This
 * module derives those rows from the per-plugin attribution the host already
 * records on every adjudicated egress decision (design 2026-06-13, section 3).
 *
 * THIS IS A PURE READ-ONLY PROJECTION. It adds NO write path, NO new audit op,
 * and NO new storage. It folds the `contributors` array that the egress proxy
 * already staples onto the `egress_decision` audit entry
 * (`castle-wall/egress-proxy.ts:appendPluginAuditIfConfigured`). It changes
 * NOTHING about enforcement.
 *
 * The invariants below are load-bearing (design section 3.2 + section 7); they
 * are the adversarial-gate criteria for this surface:
 *
 *  1. Attribution fields are DISPLAY-ONLY and TAINTED. A contribution's
 *     `confidence` / `signals` / `rationale` come from third-party plugin code
 *     and are untrusted. They flow ONLY into the (length-bounded, inert) render
 *     payload on `PluginHealthRow.last_contribution`; they NEVER feed any status
 *     math, any threshold, or any enforcement decision. The status of a row is a
 *     pure function of COUNTS and the integrity flag, never of an attribution
 *     string or number. (The #508 combiner already takes only
 *     `EnforcementDecision`, never the attribution fields; this projection keeps
 *     that boundary by reading attribution strictly for rendering.)
 *
 *  2. Integrity-finding forces a row to `unknown`, NEVER green. A tainted audit
 *     read can never present a derived green: `integrityOk === false` maps every
 *     plugin row to `unknown` regardless of what the contributions say. Green
 *     must mean "verified active," never "could not check, assumed fine."
 *
 *  3. `plugin_error` is VISIBLE and drives the row to `fault`. When a plugin
 *     crashes, times out, or desyncs, the host mints a `plugin_error`-class
 *     contribution verdict (`fail_mode_applied` / `timeout` /
 *     `unhealthy_skipped`). A plugin cannot dodge a bad row by failing silently,
 *     because failing IS the signal: a sustained host-minted error rate ranks the
 *     row `fault`/red, never green-quiet.
 *
 *  4. The matcher keys ONLY on the host-owned `egress_decision` op + the host-
 *     stamped `contributors` array (never on an attribution field), so it does
 *     not double-count, mis-attribute across plugins, or collide with a native-
 *     feature row's op. Mutual exclusion against the native registry is validated
 *     at load by `assertPluginMatcherDisjoint`.
 *
 *  5. Monotonicity is honest. A plugin can only move an outcome toward
 *     deny/escalate (there is no "allow" verdict in the #508 algebra), so a row
 *     reports "raised N escalations to your inbox" and "caused N enforced denies"
 *     as DISTINCT counts (design section 3.3) and never shows a plugin loosening
 *     a decision.
 *
 * Plugin liveness is `event_driven`, NOT self-reporting: the supervisor tracks a
 * per-plugin heartbeat IN MEMORY only (`substrate/supervisor.ts` PluginHealth),
 * and emits NO periodic per-plugin liveness audit op to the chain. The only
 * per-plugin signal that reaches the audit log is a `contributors` entry, which
 * is written ONLY when a flow was actually adjudicated. A zero count is therefore
 * genuinely ambiguous (healthy-quiet vs silently-removed are indistinguishable
 * from counts alone), so a quiet plugin reads the DISTINCT non-green
 * `unconfirmed` chip, never green and never a false red. This is the conservative
 * default the soaks discipline demands. Broken-zero is UNDETECTABLE for a plugin
 * in this slice, and the panel says so plainly.
 */

import type { AuditEntry } from "../operational/audit-log.js";
import type {
  PluginContribution,
  PluginContributionVerdict,
} from "../substrate/attribution.js";

/**
 * The native feature-health status color model, re-declared here as the SAME
 * literal union the native rows use (`feature-health.ts:FeatureHealthStatus`).
 * It is re-declared rather than imported to keep this module free of any import
 * edge back to `feature-health.ts` (which imports the row builder below), so no
 * module cycle is introduced. A `FeatureHealthStatus` and this type are
 * structurally identical; a frozen test (`assertStatusModelMatchesNative`)
 * pins them together so they can never drift apart.
 */
export type PluginRowStatus = "active" | "fault" | "unconfirmed" | "unknown";

/**
 * The minimal structural shape of a native registry row that
 * `assertPluginMatcherDisjoint` needs. Kept structural (not an import of
 * `FeatureRegistryEntry`) to avoid a module cycle; any `FeatureRegistryEntry`
 * satisfies it.
 */
export interface NativeRegistryRowShape {
  id: string;
  layer: AuditEntry["layer"];
  invocationOps: ReadonlySet<string>;
  faultOps?: ReadonlySet<string>;
  livenessOps?: ReadonlySet<string>;
  standDownOps?: ReadonlySet<string>;
}

/**
 * The single host-owned audit operation a per-plugin row keys on. The egress
 * proxy appends ONE `egress_decision` L1 entry per adjudicated flow that ran
 * plugins, carrying the `contributors` array
 * (`castle-wall/egress-proxy.ts`). The per-plugin matcher reads that array; it
 * never keys on an attribution field. Frozen so the matcher op cannot drift.
 */
export const PLUGIN_CONTRIBUTION_AUDIT_OPERATION = "egress_decision" as const;

/** The audit layer the `egress_decision` entry is written on. */
export const PLUGIN_CONTRIBUTION_AUDIT_LAYER: AuditEntry["layer"] = "l1";

/**
 * Host-minted error verdicts (design section 3.2): the host stamps one of these
 * when a plugin crashes, times out, or is skipped while unhealthy. They are NOT
 * plugin-authored, so a plugin cannot suppress them by misbehaving. A sustained
 * rate of these drives the row to `fault`. Frozen.
 */
export const PLUGIN_ERROR_VERDICTS: ReadonlySet<PluginContributionVerdict> =
  Object.freeze(
    new Set<PluginContributionVerdict>([
      "fail_mode_applied",
      "timeout",
      "unhealthy_skipped",
    ]),
  );

/**
 * Minimum number of contributions before an error RATE is meaningful: below this
 * we have too little signal to call a row faulted (a single early timeout on a
 * fresh plugin is not a fault). Mirrors the supervisor's deny-flood
 * `minEvaluations` floor in spirit (a small-sample guard, not a wall-clock soak).
 */
export const DEFAULT_PLUGIN_ERROR_MIN_CONTRIBUTIONS = 5;

/**
 * Host-minted error rate (over the digest window) at or above which the row
 * reads `fault`. Set high so a plugin must be substantially degraded, not merely
 * occasionally slow, before the operator sees red. This is a COUNT ratio, never
 * derived from any attribution field.
 */
export const DEFAULT_PLUGIN_ERROR_FAULT_RATE = 0.5;

/**
 * Per-plugin invocation tally, split so the operator sees each plugin's REAL
 * agency (design section 3.3): an escalation goes to the inbox for human review;
 * an enforced deny actually blocked a flow. These are DISTINCT and never
 * conflated. Every field is a COUNT; none is derived from an attribution string.
 */
export interface PluginContributionTally {
  /** Total contributions this plugin weighed in on over the window. */
  total: number;
  /**
   * Contributions whose verdict was `deny`: the plugin moved the outcome to an
   * enforced block. "Caused N enforced denies."
   */
  enforced_denies: number;
  /**
   * Contributions whose verdict was `escalate`: routed to the operator's
   * approval inbox, NOT an automatic action. "Raised N escalations to your
   * inbox." Kept DISTINCT from `enforced_denies` (design section 3.3).
   */
  escalations_to_inbox: number;
  /**
   * Contributions whose verdict was `observe` or `no_objection`: the plugin
   * weighed in but did not move the outcome toward block/escalate. Non-acting.
   */
  observed: number;
  /**
   * Host-minted error contributions (`fail_mode_applied` / `timeout` /
   * `unhealthy_skipped`). Visible by design: failing silently is itself the
   * signal (design section 3.2).
   */
  plugin_errors: number;
}

/**
 * Inert, length-bounded, display-ONLY echo of a plugin's most recent
 * contribution. This is the ONLY place a tainted attribution field appears, and
 * it appears only on the render payload. The status of the row is computed
 * WITHOUT reading any field here. `rationale` is already length-bounded at the
 * source (`attribution.ts:boundContributionRationale`); we surface it verbatim
 * as inert text for the drill-down. NOTHING in this object is parsed into a
 * threshold or fed back to enforcement.
 */
export interface PluginContributionDisplay {
  /** The composed/contribution verdict (an enum, host-classified, not free text). */
  verdict: PluginContributionVerdict;
  /**
   * The plugin's self-reported confidence (0..1) if it provided one. TAINTED,
   * display-only: never compared to a threshold, never gates status.
   */
  confidence: number | null;
  /**
   * The plugin's self-reported rationale, length-bounded at the source. TAINTED,
   * display-only inert text: never parsed, never gates status.
   */
  rationale: string;
  /** ISO8601 timestamp of the audit entry this contribution rode on. */
  at: string;
}

/**
 * One per-plugin health row. Mirrors the native `FeatureHealthRow` shape so the
 * panel composes uniformly, with a per-plugin `tally` and a strictly
 * display-only `last_contribution`. `status` here is the SAME union as the
 * native rows.
 */
export interface PluginHealthRow {
  origin_machine: string;
  /** Row key: the plugin's id, namespaced so it never collides with a native id. */
  feature_id: string;
  /** Plain-English label for the row. */
  label: string;
  /** Always `event_driven` for plugins (no per-plugin liveness audit op exists). */
  liveness: "event_driven";
  /** SAME color model as the native rows. */
  status: PluginRowStatus;
  /** Stable reason enum; the UI renders copy from this. */
  basis: PluginHealthBasis;
  /** Total contributions matched in the window (the row's invocation count). */
  invocation_count: number;
  /** The split tally (inbox vs deny vs observed vs error). */
  tally: PluginContributionTally;
  /** ISO8601 of the most recent contribution, if any. */
  last_evidence_at: string | null;
  /**
   * DISPLAY-ONLY echo of the most recent contribution's tainted attribution.
   * Null when the plugin had no contribution in the window. NEVER read by status
   * math.
   */
  last_contribution: PluginContributionDisplay | null;
  /**
   * Always false for a plugin row: broken-zero (a silently-removed plugin) is
   * undetectable from counts alone, because there is no per-plugin liveness
   * heartbeat in the audit chain. Surfaced so the UI never implies "confirmed
   * working" for a quiet plugin.
   */
  broken_zero_detectable: false;
  /** True when the backing audit read was integrity-clean. */
  audit_integrity_ok: boolean;
}

/**
 * Why a plugin row reads as it does. The UI renders human copy from this enum;
 * it never leaks rule internals and is never an attribution string.
 */
export type PluginHealthBasis =
  // Contributions in the window with a tolerable (sub-threshold) error rate.
  | "activity_in_window"
  // Host-minted error rate at/above the fault threshold over a meaningful
  // sample: the plugin is substantially degraded (design section 3.2).
  | "plugin_error_rate"
  // No contributions in the window. Quiet is genuinely ambiguous for an
  // event-driven feature, so this is the DISTINCT non-green `unconfirmed` chip,
  // never green and never red.
  | "no_activity_event_driven"
  // The backing audit read was integrity-tainted; the row fails closed to
  // `unknown`, never green.
  | "integrity_tainted";

/**
 * Classify a single contribution verdict into its tally bucket. Pure over the
 * host-classified verdict enum; reads NO attribution field. `deny`/`escalate`
 * are the two acting outcomes a plugin can move toward (monotonic: never an
 * "allow"); error verdicts are host-minted; everything else is non-acting.
 */
function tallyBucket(
  verdict: PluginContributionVerdict,
): keyof Omit<PluginContributionTally, "total"> {
  if (PLUGIN_ERROR_VERDICTS.has(verdict)) return "plugin_errors";
  if (verdict === "deny") return "enforced_denies";
  if (verdict === "escalate") return "escalations_to_inbox";
  // `observe` / `no_objection`: weighed in but non-acting.
  return "observed";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/** A contribution array stapled onto an audit entry, defended for shape. */
function contributionsOf(entry: AuditEntry): readonly PluginContribution[] {
  const raw: unknown = entry.contributors;
  if (!Array.isArray(raw)) return [];
  return raw.filter(
    (c): c is PluginContribution =>
      isRecord(c) && typeof c.plugin_id === "string" && typeof c.verdict === "string",
  );
}

interface PluginAccumulator {
  pluginId: string;
  tally: PluginContributionTally;
  latestMs: number | null;
  latest: PluginContributionDisplay | null;
}

function emptyTally(): PluginContributionTally {
  return {
    total: 0,
    enforced_denies: 0,
    escalations_to_inbox: 0,
    observed: 0,
    plugin_errors: 0,
  };
}

/**
 * Evaluate the status of one plugin's accumulated tally. PURE over counts + the
 * integrity flag: it reads NO attribution field (the invariant-1 boundary). A
 * tainted read forces `unknown`; a meaningful host-minted error rate forces
 * `fault`; activity is `active`; quiet is the non-green `unconfirmed` chip.
 */
export function evaluatePluginHealthStatus(args: {
  tally: PluginContributionTally;
  integrityOk: boolean;
  errorMinContributions?: number;
  errorFaultRate?: number;
}): { status: PluginRowStatus; basis: PluginHealthBasis } {
  const { tally, integrityOk } = args;
  const minContributions =
    args.errorMinContributions ?? DEFAULT_PLUGIN_ERROR_MIN_CONTRIBUTIONS;
  const faultRate = args.errorFaultRate ?? DEFAULT_PLUGIN_ERROR_FAULT_RATE;

  if (!integrityOk) {
    // "Never fake green" applied to the read path: a tainted read cannot render
    // green (or a trusted red), so fail closed to `unknown`.
    return { status: "unknown", basis: "integrity_tainted" };
  }
  // Host-minted error rate (design section 3.2): visible, and at/above threshold
  // over a meaningful sample it drives the row to `fault`. A plugin cannot dodge
  // a bad row by failing silently. Computed from COUNTS only.
  if (
    tally.total >= minContributions &&
    tally.plugin_errors / tally.total >= faultRate
  ) {
    return { status: "fault", basis: "plugin_error_rate" };
  }
  if (tally.total > 0) {
    return { status: "active", basis: "activity_in_window" };
  }
  // Quiet event-driven feature: distinct non-green `unconfirmed`, never green,
  // never a false red. Broken-zero is undetectable for a plugin.
  return { status: "unconfirmed", basis: "no_activity_event_driven" };
}

export interface BuildPluginHealthRowsInput {
  /**
   * The window's audit entries (the SAME read the native panel folds). The
   * builder filters to `egress_decision` L1 entries and folds their
   * `contributors`. Passing the shared read keeps this projection a pure fold
   * over the one chain (no second query, no second store).
   */
  entries: ReadonlyArray<AuditEntry>;
  originMachine: string;
  /**
   * Integrity verdict of the backing read. False forces EVERY plugin row to
   * `unknown` (invariant 2). The native panel computes this once; we reuse it.
   */
  integrityOk: boolean;
  /** Upper-bound clock for skew rejection on contribution timestamps. */
  now?: number;
  errorMinContributions?: number;
  errorFaultRate?: number;
}

/**
 * Fold the window's `egress_decision` contributions into one health row per
 * plugin. Pure over its inputs: no I/O, no second audit read, no enforcement
 * touch. Rows are returned sorted by `feature_id` for stable rendering.
 *
 * Mis-attribution defense (invariant 4): a contribution is bucketed strictly by
 * its own `plugin_id`, so two plugins on the same `egress_decision` entry never
 * cross-attribute. Each contribution is counted exactly once.
 */
export function buildPluginHealthRows(
  input: BuildPluginHealthRowsInput,
): PluginHealthRow[] {
  const now = input.now ?? Date.now();
  const byPlugin = new Map<string, PluginAccumulator>();

  for (const entry of input.entries) {
    if (
      entry.layer !== PLUGIN_CONTRIBUTION_AUDIT_LAYER ||
      entry.operation !== PLUGIN_CONTRIBUTION_AUDIT_OPERATION
    ) {
      continue;
    }
    const ts = Date.parse(entry.timestamp);
    // Reject future-dated evidence beyond nothing (strict): a contribution
    // stamped past `now` must not be treated as the freshest. An unparseable
    // timestamp still counts toward the tally (the chain owns malformed-entry
    // detection) but carries no `latestMs`.
    const tsValid = !Number.isNaN(ts) && ts <= now;
    for (const contribution of contributionsOf(entry)) {
      const pluginId = contribution.plugin_id;
      let acc = byPlugin.get(pluginId);
      if (acc === undefined) {
        acc = {
          pluginId,
          tally: emptyTally(),
          latestMs: null,
          latest: null,
        };
        byPlugin.set(pluginId, acc);
      }
      acc.tally.total += 1;
      acc.tally[tallyBucket(contribution.verdict)] += 1;
      if (tsValid && (acc.latestMs === null || ts > acc.latestMs)) {
        acc.latestMs = ts;
        // DISPLAY-ONLY echo: tainted attribution captured for rendering ONLY.
        // Never read by `evaluatePluginHealthStatus`.
        acc.latest = {
          verdict: contribution.verdict,
          confidence:
            typeof contribution.confidence === "number"
              ? contribution.confidence
              : null,
          rationale: contribution.rationale,
          at: entry.timestamp,
        };
      }
    }
  }

  const rows: PluginHealthRow[] = [];
  for (const acc of byPlugin.values()) {
    const { status, basis } = evaluatePluginHealthStatus({
      tally: acc.tally,
      integrityOk: input.integrityOk,
      ...(input.errorMinContributions !== undefined
        ? { errorMinContributions: input.errorMinContributions }
        : {}),
      ...(input.errorFaultRate !== undefined
        ? { errorFaultRate: input.errorFaultRate }
        : {}),
    });
    rows.push({
      origin_machine: input.originMachine,
      feature_id: pluginRowId(acc.pluginId),
      label: pluginRowLabel(acc.pluginId),
      liveness: "event_driven",
      status,
      basis,
      invocation_count: acc.tally.total,
      tally: acc.tally,
      last_evidence_at:
        acc.latestMs !== null ? new Date(acc.latestMs).toISOString() : null,
      // On a tainted read we still must not leak a stale display echo as if it
      // were confirmed; keep it (it is inert display text) but the row's status
      // is already `unknown`, so the UI renders it under the non-green chip.
      last_contribution: acc.latest,
      broken_zero_detectable: false,
      audit_integrity_ok: input.integrityOk,
    });
  }
  rows.sort((a, b) => a.feature_id.localeCompare(b.feature_id));
  return rows;
}

/**
 * Namespace prefix for a per-plugin row id, so a plugin id can NEVER collide
 * with a native registry `feature_id` (the row-key half of mutual exclusion).
 */
export const PLUGIN_ROW_ID_PREFIX = "plugin:" as const;

/** The namespaced row id for a plugin. */
export function pluginRowId(pluginId: string): string {
  return `${PLUGIN_ROW_ID_PREFIX}${pluginId}`;
}

/** A plain-English row label for a plugin row. */
export function pluginRowLabel(pluginId: string): string {
  return `Plugin: ${pluginId}`;
}

/**
 * Load-time mutual-exclusion check (invariant 4). The per-plugin matcher keys on
 * the `(layer, operation)` pair `(l1, egress_decision)`. Assert that NO native
 * registry row claims that operation on that layer, so a contribution entry can
 * never be double-counted as both a plugin row and a native row. Throws on a
 * collision, exactly as the native registry validates its own rows are mutually
 * exclusive. Pure; call once at load.
 */
export function assertPluginMatcherDisjoint(
  nativeRegistry: ReadonlyArray<NativeRegistryRowShape>,
): void {
  for (const feature of nativeRegistry) {
    if (feature.layer !== PLUGIN_CONTRIBUTION_AUDIT_LAYER) continue;
    const claimsOp =
      feature.invocationOps.has(PLUGIN_CONTRIBUTION_AUDIT_OPERATION) ||
      (feature.faultOps?.has(PLUGIN_CONTRIBUTION_AUDIT_OPERATION) ?? false) ||
      (feature.livenessOps?.has(PLUGIN_CONTRIBUTION_AUDIT_OPERATION) ?? false) ||
      (feature.standDownOps?.has(PLUGIN_CONTRIBUTION_AUDIT_OPERATION) ?? false);
    if (claimsOp) {
      throw new Error(
        `per-plugin matcher op "${PLUGIN_CONTRIBUTION_AUDIT_OPERATION}" collides ` +
          `with native feature "${feature.id}" on layer ` +
          `${PLUGIN_CONTRIBUTION_AUDIT_LAYER}`,
      );
    }
  }
}
