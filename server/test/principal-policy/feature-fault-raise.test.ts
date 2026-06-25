/**
 * Feature-fault OS-notification RAISE PATH merge-bar invariants.
 *
 * The raise path (`feature-fault-raise.ts`) turns the SMALL set of genuine,
 * operator-action-worthy faults in the feature-health panel into ONE deduped,
 * rate-limited notification each, for EXACTLY the 3 ratified fault classes
 * (`castle_wall_fault`, `feature_silently_off`, `plugin_failure_surge`). It reads
 * feature-health and emits a notification; it feeds NOTHING back into enforcement.
 *
 * These tests prove the design 7 adversarial-gate invariants:
 *   1. castle_wall_fault raises ONE notification; a persistent fault does NOT
 *      re-spam over multiple cycles (dedup + rate-limit via the inbox bridge).
 *   2. an ON->OFF transition raises feature_silently_off; an always-off feature
 *      does NOT (the state-transition requirement).
 *   3. plugin_failure_surge raises (proves the rule is un-dormanted + wired).
 *   4. integrity-tainted read -> the row does NOT raise a green/feature-off
 *      notification (no false all-clear, no suppressed alarm into a wrong state).
 *   5. a rule still flagged `dormant` raises nothing.
 *   6. an attacker-influenced label in a notification body is escaped + length-
 *      bounded + never parsed into a threshold.
 *   7. NO real OS notification is fired (the sink is the in-memory inbox bridge,
 *      injected) and no enforcement path reads the raise output.
 *
 * THE SINK IS MOCKED/INJECTED: every test injects either a fake bridge that
 * records ingests or a real in-memory `UnifiedInboxBridge`. NO test fires a real
 * OS notification; the codebase has no OS-banner sink and this layer never opens
 * one (it only ingests into the inbox bridge).
 */

import { describe, it, expect, vi } from "vitest";

import {
  AuditLog,
} from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  UnifiedInboxBridge,
  type FeatureFaultIngest,
  type UnifiedInboxEntry,
} from "../../src/principal-policy/unified-inbox-bridge.js";
import {
  type FeatureHealthPanel,
  type FeatureHealthRow,
  type FeatureHealthStatus,
  type FeatureHealthBasis,
} from "../../src/principal-policy/feature-health.js";
import type {
  PluginHealthRow,
  PluginRowStatus,
  PluginHealthBasis,
} from "../../src/principal-policy/plugin-feature-health.js";
import {
  deriveFeatureFaults,
  raiseFeatureFaults,
  inertLabel,
  CASTLE_WALL_FEATURE_ID,
  FEATURE_FAULT_LABEL_MAX_CHARS,
  FeatureFaultRaiser,
  type FeatureFaultSignal,
} from "../../src/principal-policy/feature-fault-raise.js";

const ORIGIN = "test_machine";
const WINDOW_START = "2026-06-25T00:00:00.000Z";
const WINDOW_END = "2026-06-25T01:00:00.000Z";

function nativeRow(over: Partial<FeatureHealthRow> & {
  feature_id: string;
  status: FeatureHealthStatus;
  basis: FeatureHealthBasis;
}): FeatureHealthRow {
  return {
    origin_machine: ORIGIN,
    feature_id: over.feature_id,
    label: over.label ?? over.feature_id,
    liveness: over.liveness ?? "self_reporting",
    status: over.status,
    basis: over.basis,
    invocation_count: over.invocation_count ?? 0,
    last_evidence_at: over.last_evidence_at ?? null,
    broken_zero_detectable: over.broken_zero_detectable ?? true,
    audit_integrity_ok: over.audit_integrity_ok ?? true,
    freshness_window_ms: over.freshness_window_ms ?? 300_000,
  };
}

function pluginRow(over: Partial<PluginHealthRow> & {
  feature_id: string;
  status: PluginRowStatus;
  basis: PluginHealthBasis;
}): PluginHealthRow {
  return {
    origin_machine: ORIGIN,
    feature_id: over.feature_id,
    label: over.label ?? over.feature_id,
    liveness: "event_driven",
    status: over.status,
    basis: over.basis,
    invocation_count: over.invocation_count ?? 0,
    tally: over.tally ?? {
      total: 0,
      enforced_denies: 0,
      escalations_to_inbox: 0,
      observed: 0,
      plugin_errors: 0,
    },
    last_evidence_at: over.last_evidence_at ?? null,
    last_contribution: over.last_contribution ?? null,
    broken_zero_detectable: false,
    audit_integrity_ok: over.audit_integrity_ok ?? true,
  };
}

function panel(over: Partial<FeatureHealthPanel> & {
  rows?: FeatureHealthRow[];
  plugin_rows?: PluginHealthRow[];
}): FeatureHealthPanel {
  return {
    origin_machine: ORIGIN,
    window_start: over.window_start ?? WINDOW_START,
    window_end: over.window_end ?? WINDOW_END,
    rows: over.rows ?? [],
    plugin_rows: over.plugin_rows ?? [],
    audit_integrity_ok: over.audit_integrity_ok ?? true,
    disclosure: over.disclosure ?? {
      broken_zero_undetectable_for_event_driven: true,
      castle_wall_silent_death_is_unknown_not_green: false,
      silent_death_distinguished_from_intentional_stop: true,
      broker_daemon_silent_death_detectable: true,
    },
  };
}

/** Real in-memory inbox bridge: the notification sink. NO OS banner is opened. */
function makeBridge(): UnifiedInboxBridge {
  const storage = new MemoryStorage();
  const masterKey = generateRandomKey();
  const auditLog = new AuditLog(storage, masterKey);
  return new UnifiedInboxBridge({
    auditLog,
    identityId: "identity_test",
    fortressId: "fortress_test",
  });
}

/** A FAKE sink that records ingests, proving NO real OS notification fires. */
function makeRecordingBridge(): {
  bridge: UnifiedInboxBridge;
  ingests: FeatureFaultIngest[];
} {
  const ingests: FeatureFaultIngest[] = [];
  const bridge = {
    ingestFeatureFault(input: FeatureFaultIngest): UnifiedInboxEntry | null {
      ingests.push(input);
      return {
        inbox_id: `mock-${ingests.length}`,
        source_class: "feature_fault",
        source_event_id: input.source_event_id,
        severity: input.severity,
        summary: input.summary,
        details_url: `/mock/${ingests.length}`,
        observed_at: input.observed_at,
        state: "active",
        fortress_id: "fortress_test",
      };
    },
  } as unknown as UnifiedInboxBridge;
  return { bridge, ingests };
}

describe("feature-fault raise path - the 3 fault classes only", () => {
  // ── Invariant 1: castle_wall_fault raises once, never re-spams ──────────
  it("raises ONE castle_wall_fault; a persistent fault over cycles does not re-spam", () => {
    const faultPanel = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          label: "Castle Wall",
          status: "fault",
          basis: "fault_evidence",
          last_evidence_at: WINDOW_END,
        }),
      ],
    });
    const bridge = makeBridge();

    // Cycle 1: the fault raises exactly one entry.
    const first = raiseFeatureFaults(bridge, deriveFeatureFaults(faultPanel));
    expect(first).toHaveLength(1);
    expect(first[0]?.source_class).toBe("feature_fault");

    // Cycles 2 and 3: the SAME persistent fault dedups to zero new entries.
    const second = raiseFeatureFaults(bridge, deriveFeatureFaults(faultPanel, faultPanel));
    const third = raiseFeatureFaults(bridge, deriveFeatureFaults(faultPanel, faultPanel));
    expect(second).toHaveLength(0);
    expect(third).toHaveLength(0);

    // Exactly one active inbox entry for the wall fault overall.
    expect(bridge.list({ sourceClass: "feature_fault" })).toHaveLength(1);
  });

  it("raises castle_wall_fault on a missed-heartbeat dead_no_heartbeat too", () => {
    const faults = deriveFeatureFaults(
      panel({
        rows: [
          nativeRow({
            feature_id: CASTLE_WALL_FEATURE_ID,
            status: "fault",
            basis: "dead_no_heartbeat",
          }),
        ],
      }),
    );
    expect(faults.map((f) => f.fault_class)).toEqual(["castle_wall_fault"]);
  });

  // ── Invariant 2: ON->OFF raises; always-off does NOT ────────────────────
  it("raises feature_silently_off on an ON->OFF transition only", () => {
    const prev = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "active",
          basis: "fresh_enforcement_evidence",
          invocation_count: 5,
        }),
      ],
    });
    const current = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "unconfirmed",
          basis: "no_activity_event_driven",
        }),
      ],
    });
    const faults = deriveFeatureFaults(current, prev);
    expect(faults.map((f) => f.fault_class)).toEqual(["feature_silently_off"]);
  });

  it("does NOT raise feature_silently_off for a feature that was always off", () => {
    const alwaysOff = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "unconfirmed",
          basis: "no_activity_event_driven",
        }),
      ],
    });
    // No prior evaluation: nothing transitioned, so nothing raises.
    expect(deriveFeatureFaults(alwaysOff)).toHaveLength(0);
    // Prior was ALSO off: still no transition, no raise.
    expect(deriveFeatureFaults(alwaysOff, alwaysOff)).toHaveLength(0);
  });

  // ── Invariant 3: plugin_failure_surge raises (un-dormanted + wired) ──────
  it("raises plugin_failure_surge when a plugin error rate crosses the fault threshold", () => {
    const faults = deriveFeatureFaults(
      panel({
        plugin_rows: [
          pluginRow({
            feature_id: "plugin:acme-egress-guard",
            label: "acme-egress-guard",
            status: "fault",
            basis: "plugin_error_rate",
            invocation_count: 10,
            tally: {
              total: 10,
              enforced_denies: 0,
              escalations_to_inbox: 0,
              observed: 3,
              plugin_errors: 7,
            },
            last_evidence_at: WINDOW_END,
          }),
        ],
      }),
    );
    expect(faults.map((f) => f.fault_class)).toEqual(["plugin_failure_surge"]);
    expect(faults[0]?.feature_id).toBe("plugin:acme-egress-guard");
    // A plugin row that is merely active (sub-threshold) does NOT raise.
    const activeOnly = deriveFeatureFaults(
      panel({
        plugin_rows: [
          pluginRow({
            feature_id: "plugin:acme-egress-guard",
            status: "active",
            basis: "activity_in_window",
            invocation_count: 10,
          }),
        ],
      }),
    );
    expect(activeOnly).toHaveLength(0);
  });

  // ── Invariant 4: integrity-tainted read -> no green/feature-off raise ────
  it("does NOT raise a feature_silently_off when the current read is integrity-tainted", () => {
    const prev = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "active",
          basis: "fresh_enforcement_evidence",
          invocation_count: 5,
        }),
      ],
    });
    // The wall is forced to `unknown` because the audit read was tainted, NOT
    // because it was silently disabled. An attacker who suppresses audit must not
    // be able to forge an ON->OFF "feature off" alarm or a false all-clear.
    const taintedCurrent = panel({
      audit_integrity_ok: false,
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "unknown",
          basis: "integrity_tainted",
          audit_integrity_ok: false,
        }),
      ],
    });
    expect(deriveFeatureFaults(taintedCurrent, prev)).toHaveLength(0);
  });

  it("does NOT raise plugin_failure_surge from an integrity-tainted plugin row", () => {
    const faults = deriveFeatureFaults(
      panel({
        audit_integrity_ok: false,
        plugin_rows: [
          pluginRow({
            // A tainted read forces `unknown`; even if basis somehow read as a
            // surge, the integrity gate excludes it.
            feature_id: "plugin:acme-egress-guard",
            status: "unknown",
            basis: "integrity_tainted",
            audit_integrity_ok: false,
          }),
        ],
      }),
    );
    expect(faults).toHaveLength(0);
  });

  // ── Invariant 5: dormant rules raise nothing ────────────────────────────
  it("only the 3 ratified classes can ever raise (tight fault set)", () => {
    // Build a panel that exercises every class plus noise rows that must NOT
    // raise (green active, unconfirmed-quiet, unknown-idle).
    const prev = panel({
      rows: [
        nativeRow({
          feature_id: "secret_broker",
          status: "active",
          basis: "activity_in_window",
          invocation_count: 2,
          liveness: "event_driven",
        }),
      ],
    });
    const current = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "fault",
          basis: "fault_evidence",
        }),
        // event went quiet -> silent_off (this one is a live class)
        nativeRow({
          feature_id: "secret_broker",
          status: "unconfirmed",
          basis: "no_activity_event_driven",
          liveness: "event_driven",
        }),
        // a green row: must NOT raise
        nativeRow({
          feature_id: "approval_gates",
          status: "active",
          basis: "activity_in_window",
          invocation_count: 9,
        }),
        // an unknown idle row with no prior active: must NOT raise
        nativeRow({
          feature_id: "secret_broker_daemon",
          status: "unknown",
          basis: "alive_no_recent_enforcement",
        }),
      ],
    });
    const classes = deriveFeatureFaults(current, prev).map((f) => f.fault_class);
    // Exactly the live classes fired; no speculative/info notification.
    expect(new Set(classes)).toEqual(
      new Set(["castle_wall_fault", "feature_silently_off"]),
    );
    // Every fault class is one of the 3 ratified classes.
    for (const c of classes) {
      expect([
        "castle_wall_fault",
        "feature_silently_off",
        "plugin_failure_surge",
      ]).toContain(c);
    }
  });

  // ── Invariant 6: attacker-influenced label is inert ─────────────────────
  it("renders an attacker-influenced label inert: escaped, length-bounded, never parsed", () => {
    const hostileLabel =
      '<img src=x onerror=alert(1)>"&\nthreshold=0.0 ' + "A".repeat(500);
    const faults = deriveFeatureFaults(
      panel({
        plugin_rows: [
          pluginRow({
            feature_id: "plugin:hostile",
            label: hostileLabel,
            status: "fault",
            basis: "plugin_error_rate",
            invocation_count: 6,
            tally: {
              total: 6,
              enforced_denies: 0,
              escalations_to_inbox: 0,
              observed: 0,
              plugin_errors: 6,
            },
          }),
        ],
      }),
    );
    expect(faults).toHaveLength(1);
    const body = faults[0]?.summary ?? "";
    // No raw HTML-significant or control characters survive into the body.
    expect(body).not.toContain("<img");
    expect(body).not.toContain("<");
    expect(body).not.toContain(">");
    expect(body).not.toContain("\n");
    // The escaped, bounded label appears; the bound is enforced.
    const bounded = inertLabel(hostileLabel);
    expect(bounded.length).toBeLessThanOrEqual(FEATURE_FAULT_LABEL_MAX_CHARS);
    expect(bounded).toContain("&lt;img");
    // The "threshold=0.0" text is inert echo only: nothing in the raise path
    // parses the body. The host counts in the summary come from the tally, NOT
    // from the label, so the count is the real 6/6, never the injected "0.0".
    expect(body).toContain("6/6 errors");
  });

  it("inertLabel strips control chars, escapes, and hard-bounds length", () => {
    expect(inertLabel("a\tb\r\nc")).toBe("a b c");
    expect(inertLabel("<b>&\"'")).toBe("&lt;b&gt;&amp;&quot;&#39;");
    const long = "x".repeat(200);
    expect(inertLabel(long).length).toBe(FEATURE_FAULT_LABEL_MAX_CHARS);
    expect(inertLabel(long).endsWith("...")).toBe(true);
  });

  // ── Invariant 7: no real OS notification + no enforcement coupling ───────
  it("the sink is injected: NO real OS notification fires, only inbox ingests", () => {
    const { bridge, ingests } = makeRecordingBridge();
    const faults: FeatureFaultSignal[] = deriveFeatureFaults(
      panel({
        rows: [
          nativeRow({
            feature_id: CASTLE_WALL_FEATURE_ID,
            status: "fault",
            basis: "fault_evidence",
          }),
        ],
      }),
    );
    const raised = raiseFeatureFaults(bridge, faults);
    expect(raised).toHaveLength(1);
    // The ONLY effect is an inbox ingest; no OS-banner API exists or is called.
    expect(ingests).toHaveLength(1);
    expect(ingests[0]?.severity).toBe("critical");
    expect(ingests[0]?.source_event_id).toBe(
      `castle_wall_fault|${CASTLE_WALL_FEATURE_ID}`,
    );
  });

  it("FeatureFaultRaiser drives derive+raise across cycles and holds the prior panel", async () => {
    const { bridge, ingests } = makeRecordingBridge();
    const activePanel = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "active",
          basis: "fresh_enforcement_evidence",
          invocation_count: 3,
        }),
      ],
    });
    const offPanel = panel({
      rows: [
        nativeRow({
          feature_id: CASTLE_WALL_FEATURE_ID,
          status: "unconfirmed",
          basis: "no_activity_event_driven",
        }),
      ],
    });
    const buildPanel = vi
      .fn<[], Promise<FeatureHealthPanel>>()
      .mockResolvedValueOnce(activePanel) // cycle 1: active, no fault
      .mockResolvedValueOnce(offPanel); // cycle 2: went off -> silent_off
    const raiser = new FeatureFaultRaiser({ bridge, buildPanel });

    await raiser.evaluate(); // cycle 1: no raise (and stores prior)
    expect(ingests).toHaveLength(0);
    await raiser.evaluate(); // cycle 2: ON->OFF transition raises
    expect(ingests).toHaveLength(1);
    expect(ingests[0]?.source_event_id).toBe(
      `feature_silently_off|${CASTLE_WALL_FEATURE_ID}`,
    );
  });

  it("FeatureFaultRaiser swallows a panel-build failure without raising or throwing", async () => {
    const { bridge, ingests } = makeRecordingBridge();
    const buildPanel = vi
      .fn<[], Promise<FeatureHealthPanel>>()
      .mockRejectedValue(new Error("audit read failed"));
    const raiser = new FeatureFaultRaiser({ bridge, buildPanel });
    await expect(raiser.evaluate()).resolves.toEqual([]);
    expect(ingests).toHaveLength(0);
  });
});
