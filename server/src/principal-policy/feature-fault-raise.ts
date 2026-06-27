/**
 * Feature-fault OS-notification RAISE PATH (the 3 fault classes ONLY).
 *
 * The feature-health panel (`feature-health.ts` + the per-plugin rows in
 * `plugin-feature-health.ts`) is a read-only projection over the encrypted,
 * hash-chained audit log: it tells the operator which security features actually
 * fired and which look broken. That panel is dashboard-only. This module is the
 * thin layer that turns the SMALL set of genuine, operator-action-worthy faults
 * in that panel into ONE deduped, rate-limited operator notification each, by
 * feeding the existing unified-inbox bridge (the notification sink), reusing its
 * `(source_class, source_event_id)` dedup and its scheduler. It builds NO new
 * notification queue, NO new dedup engine, and NO new fault taxonomy.
 *
 * Scope honesty (do NOT overclaim): this raises alerts for exactly the three
 * fault classes ratified in the design (`castle_wall_fault`,
 * `feature_silently_off`, `plugin_failure_surge`). It is NOT a general alerting
 * framework, and it changes NO enforcement: it reads feature-health and emits a
 * notification, and feeds NOTHING back into any policy / gate / enforcement
 * decision (the same display-only, tainted boundary the per-plugin rows honor).
 *
 * Design discipline baked in (the adversarial-gate invariants, design 4.3 / 7):
 *
 *  - TIGHT fault set. Only the three classes raise; everything else stays
 *    dashboard-only. Alert-fatigue is the named availability attack: a
 *    notification is a high-signal "stop and look" event. We never raise an
 *    "info" / green-transition / quiet-event-driven notification.
 *
 *  - Integrity-finding to unknown, NEVER a green-masking notification. A row
 *    whose backing audit read was integrity-tainted (`audit_integrity_ok` false,
 *    forced to `unknown`) does NOT raise a "feature off" / all-clear. An attacker
 *    who can suppress audit must not be able to forge a false all-clear OR mute a
 *    real alarm into a wrong state: a tainted read raises nothing here, and the
 *    fault is surfaced on the dashboard as `unknown`.
 *
 *  - Attacker-influenced body text is INERT. No plugin `rationale` / `signals` /
 *    confidence ever reaches the notification body: the body is built from
 *    host-owned, enum-classified fields only (the fault class, the feature label,
 *    host counts). The feature label itself is escaped + length-bounded before it
 *    is placed in a summary, so even a hostile feature/plugin label can never be
 *    parsed into a threshold or injected into the rendered text.
 *
 *  - Heartbeat-spoofing resistance is INHERITED, not re-implemented. We detect
 *    faults from the SAME integrity-judged feature-health panel the dashboard
 *    reads (which rides the hash-chained audit ingestion). We add NO cheaper
 *    heartbeat / poll path: a missed heartbeat already renders the row
 *    `fault`/`dead_no_heartbeat` in the panel, which we raise as a
 *    `castle_wall_fault`. A feature cannot dodge an alert by going silent.
 *
 *  - DORMANT rules never fire. The route layer enumerates only the live rules in
 *    `FEATURE_FAULT_CLASS_RULES`; a rule whose `dormant` flag is true contributes
 *    no raise. Flipping a rule live is a deliberate per-rule act.
 *
 * The `deriveFeatureFaults` function is PURE over its two injected panels so it
 * unit-tests without a live server, a running daemon, or a real notification.
 */

import {
  FEATURE_FAULT_CLASS_RULES,
  type FeatureFaultClass,
  type FeatureHealthPanel,
  type FeatureHealthRow,
} from "./feature-health.js";
import type { PluginHealthRow } from "./plugin-feature-health.js";
import type { UnifiedInboxBridge, UnifiedInboxEntry } from "./unified-inbox-bridge.js";

/**
 * The native registry id of the Castle Wall row (the only self-reporting wall).
 *
 * SYNC WARNING: this MUST stay in sync with the `id` of the Castle Wall entry in
 * `SLICE1_FEATURE_REGISTRY` (`feature-health.ts`). It is a string literal mirror,
 * not a shared reference, so a rename of that registry id would silently break
 * `isCastleWallFault` matching and mute WALL-FAULT alerts (a fail-silent on the
 * highest-severity class). A registry-id-drift test in
 * `test/principal-policy/feature-fault-raise.test.ts` asserts the registry still
 * contains a feature with this exact id, so a future rename fails the test
 * instead of silently going dark.
 */
export const CASTLE_WALL_FEATURE_ID = "castle_wall_egress";

/**
 * Max characters of any attacker-influenceable label echoed into a notification
 * body. The body is otherwise host-owned text; this bound is belt-and-suspenders
 * against a hostile feature/plugin label, on top of the inbox summary's own
 * 240-char cap.
 */
export const FEATURE_FAULT_LABEL_MAX_CHARS = 80;

/**
 * One derived fault, ready to hand to the inbox sink. The `dedup_id` is the
 * stable per-fault key the bridge dedups on, so a persistent fault over multiple
 * evaluation cycles raises exactly one notification per window, not one per
 * cycle.
 */
export interface FeatureFaultSignal {
  /** Which of the 3 ratified fault classes this is. */
  fault_class: FeatureFaultClass;
  /** The panel row id the fault is attributed to (native id or `plugin:<id>`). */
  feature_id: string;
  /**
   * Stable dedup key: `<fault_class>|<feature_id>`. A persistent fault on the
   * same feature across cycles collapses to one notification (the bridge dedups
   * on `(source_class, source_event_id)`); a NEW fault class or a NEW feature is
   * a distinct, separately-raised signal.
   */
  dedup_id: string;
  /**
   * Host-owned, inert, length-bounded notification body. Built ONLY from the
   * fault class and an escaped feature label; never from any tainted attribution
   * field, never parsed.
   */
  summary: string;
  /** ISO8601 of the evidence behind this fault (host timestamp, never parsed). */
  observed_at: string;
}

/**
 * Render an attacker-influenceable label inert: replace control characters with a
 * space (so a hostile label can never inject a newline or terminal control
 * sequence), collapse whitespace, escape the HTML/inbox-significant characters,
 * and hard-bound the length. The result is display-only text; nothing downstream
 * parses it.
 */
export function inertLabel(raw: string): string {
  let stripped = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0) ?? 0;
    stripped += code < 0x20 || code === 0x7f ? " " : ch;
  }
  const collapsed = stripped.replace(/\s+/g, " ").trim();
  const escaped = collapsed
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
  if (escaped.length <= FEATURE_FAULT_LABEL_MAX_CHARS) return escaped;
  return escaped.slice(0, FEATURE_FAULT_LABEL_MAX_CHARS - 3) + "...";
}

/** Live (non-dormant) fault classes, read from the single source of truth. */
function liveFaultClasses(): Set<FeatureFaultClass> {
  return new Set(
    FEATURE_FAULT_CLASS_RULES.filter((rule) => !rule.dormant).map(
      (rule) => rule.class,
    ),
  );
}

function dedupId(faultClass: FeatureFaultClass, featureId: string): string {
  return `${faultClass}|${featureId}`;
}

/**
 * A native row is a Castle Wall fault when it is the Castle Wall row AND its
 * health read it as `fault` (a fresh not-enforcing event, or a missed-heartbeat
 * `dead_no_heartbeat`). An integrity-tainted row is forced to `unknown` by the
 * evaluator and so is excluded here by construction (it is never `fault`); the
 * explicit `audit_integrity_ok` check is belt-and-suspenders.
 */
function isCastleWallFault(row: FeatureHealthRow): boolean {
  return (
    row.feature_id === CASTLE_WALL_FEATURE_ID &&
    row.status === "fault" &&
    row.audit_integrity_ok
  );
}

/**
 * An ON->OFF transition: the feature was `active` (genuinely firing) in the
 * prior evaluation and is now `unconfirmed`/`unknown` (went silent) with NO
 * fault event of its own. This is the silent-disable signal. We require BOTH
 * reads to be integrity-clean: a tainted current read forces `unknown` for an
 * unrelated reason (we cannot verify the chain), so it must NOT be reported as a
 * silent disable (no false "feature off" on a suppressed-audit window).
 */
function isSilentlyOff(
  prev: FeatureHealthRow | undefined,
  current: FeatureHealthRow,
): boolean {
  if (prev === undefined) return false;
  if (!prev.audit_integrity_ok || !current.audit_integrity_ok) return false;
  if (prev.status !== "active") return false;
  // An OPT-IN expectation-floor breach is a DASHBOARD-ONLY "expected-but-quiet"
  // signal, NEVER an OS notification (event-floor slice invariant 5: the §4.3
  // raise path is the 3 fault classes only). A feature that met its floor one
  // cycle and dipped below it the next reads `unconfirmed`/`below_expected_floor`;
  // that is the operator's own declared expectation being unmet, not a
  // silent-disable fault, so it must NOT raise. Exclude it explicitly.
  if (current.basis === "below_expected_floor") return false;
  // A self-reporting fault is its OWN class (castle_wall_fault); silent-off is
  // the "went quiet without a fault event" case, so we exclude `fault` here.
  return current.status === "unconfirmed" || current.status === "unknown";
}

/**
 * A plugin row is a failure-surge when its host-minted error rate crossed the
 * fault threshold (`plugin_error_rate`). The row's `status`/`basis` are computed
 * WITHOUT reading any tainted attribution field (see `plugin-feature-health.ts`),
 * so this is a host-owned signal. Integrity-tainted plugin reads fail closed to
 * `unknown` and are excluded.
 */
function isPluginFailureSurge(row: PluginHealthRow): boolean {
  return (
    row.status === "fault" &&
    row.basis === "plugin_error_rate" &&
    row.audit_integrity_ok
  );
}

/**
 * Derive the set of raise-worthy faults from the prior and current feature-health
 * panels. PURE: no I/O, no notification, no enforcement read or write. The caller
 * (the evaluation cycle) hands the result to `raiseFeatureFaults`, which dedups
 * and rate-limits via the inbox bridge.
 *
 * `prev` may be undefined on the first evaluation after boot; the only class that
 * needs a prior is `feature_silently_off` (a transition), so the others still
 * raise on the first cycle.
 */
export function deriveFeatureFaults(
  current: FeatureHealthPanel,
  prev?: FeatureHealthPanel,
): FeatureFaultSignal[] {
  const live = liveFaultClasses();
  const out: FeatureFaultSignal[] = [];
  const observedAt = current.window_end;

  const prevRowById = new Map<string, FeatureHealthRow>();
  if (prev) {
    for (const row of prev.rows) prevRowById.set(row.feature_id, row);
  }

  for (const row of current.rows) {
    // castle_wall_fault
    if (live.has("castle_wall_fault") && isCastleWallFault(row)) {
      out.push({
        fault_class: "castle_wall_fault",
        feature_id: row.feature_id,
        dedup_id: dedupId("castle_wall_fault", row.feature_id),
        summary: `Castle Wall fault: ${inertLabel(row.label)} reported it is not enforcing.`,
        observed_at: row.last_evidence_at ?? observedAt,
      });
      continue; // a fault row is its own class; never also a silent-off
    }

    // feature_silently_off (ON->OFF transition; needs the prior evaluation)
    if (
      live.has("feature_silently_off") &&
      isSilentlyOff(prevRowById.get(row.feature_id), row)
    ) {
      out.push({
        fault_class: "feature_silently_off",
        feature_id: row.feature_id,
        dedup_id: dedupId("feature_silently_off", row.feature_id),
        summary: `Security feature went silent: ${inertLabel(row.label)} was active and is now off with no operator action.`,
        observed_at: observedAt,
      });
    }
  }

  // plugin_failure_surge (un-dormanted: its producer exists via #728/#753)
  if (live.has("plugin_failure_surge")) {
    for (const row of current.plugin_rows) {
      if (!isPluginFailureSurge(row)) continue;
      out.push({
        fault_class: "plugin_failure_surge",
        feature_id: row.feature_id,
        dedup_id: dedupId("plugin_failure_surge", row.feature_id),
        summary: `Security plugin failure surge: ${inertLabel(row.label)} crossed into sustained failure (${row.tally.plugin_errors}/${row.tally.total} errors).`,
        observed_at: row.last_evidence_at ?? observedAt,
      });
    }
  }

  return out;
}

/**
 * Severity for a feature fault. A configured-ON enforcing feature reporting a
 * fault, or going silently off, is `critical` (your firewall fell down). A
 * plugin failure-surge degrades a contribution but the host outcome is still
 * enforced, so it is `alert`.
 */
function severityFor(faultClass: FeatureFaultClass): "alert" | "critical" {
  return faultClass === "plugin_failure_surge" ? "alert" : "critical";
}

/**
 * Raise the derived faults to the notification sink (the unified-inbox bridge),
 * which dedups on `(source_class, source_event_id)` and rate-limits one entry
 * per fault per feature per window. Returns the entries actually emitted (a
 * deduped repeat returns null from the bridge and is skipped). This function
 * performs NO enforcement read or write; it only ingests notifications.
 */
export function raiseFeatureFaults(
  bridge: UnifiedInboxBridge,
  faults: ReadonlyArray<FeatureFaultSignal>,
): UnifiedInboxEntry[] {
  const raised: UnifiedInboxEntry[] = [];
  for (const fault of faults) {
    const entry = bridge.ingestFeatureFault({
      source_event_id: fault.dedup_id,
      severity: severityFor(fault.fault_class),
      summary: fault.summary,
      observed_at: fault.observed_at,
    });
    if (entry) raised.push(entry);
  }
  return raised;
}

/**
 * Server-side raise driver, wired into the existing posture/daemon evaluation
 * cadence (it does NOT own a timer; the caller ticks it). It holds the prior
 * feature-health panel so the `feature_silently_off` ON->OFF transition can be
 * computed across cycles, and it recomputes the current panel from the SAME
 * integrity-judged audit read the dashboard uses (the injected `buildPanel`
 * thunk wraps `buildFeatureHealthPanel` in the AuditLog eager-read scope), so it
 * adds no cheaper heartbeat/poll path that bypasses the hash chain.
 *
 * It is intentionally additive and display-only: it reads feature-health, raises
 * notifications via the inbox bridge, and feeds NOTHING back into enforcement.
 *
 * Alert latency (operator-facing honesty): this raiser owns no timer; it is
 * ticked by the existing UnifiedInboxScheduler (~60s cadence). A fault therefore
 * surfaces as a notification on a best-effort ~60s cycle, not instantly. This is
 * deliberate: it inherits the integrity-judged audit read and adds no cheaper
 * heartbeat/poll path.
 */
export class FeatureFaultRaiser {
  private prev: FeatureHealthPanel | undefined;

  constructor(
    private readonly deps: {
      bridge: UnifiedInboxBridge;
      /**
       * Recompute the current feature-health panel from the integrity-judged
       * audit read (wrap `buildFeatureHealthPanel` in `AuditLog.runEagerReads`).
       */
      buildPanel: () => Promise<FeatureHealthPanel>;
      /** Optional hook for tests/telemetry; never throws into the caller. */
      onRaised?: (entries: UnifiedInboxEntry[]) => void;
    },
  ) {}

  /**
   * One evaluation cycle: recompute the panel, raise any new faults (deduped by
   * the bridge), and retain the panel as the prior for the next cycle's
   * transition check. Returns the entries actually emitted this cycle. A panel
   * build failure is swallowed (never fails the caller's tick) and the prior
   * panel is left unchanged so a transient read error cannot manufacture a false
   * ON->OFF transition on recovery.
   */
  async evaluate(): Promise<UnifiedInboxEntry[]> {
    let current: FeatureHealthPanel;
    try {
      current = await this.deps.buildPanel();
    } catch {
      return [];
    }
    const raised = raiseFeatureFaults(
      this.deps.bridge,
      deriveFeatureFaults(current, this.prev),
    );
    this.prev = current;
    if (raised.length > 0 && this.deps.onRaised) {
      try {
        this.deps.onRaised(raised);
      } catch {
        // Telemetry hook must never break the evaluation cycle.
      }
    }
    return raised;
  }
}
