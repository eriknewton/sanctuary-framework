import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildFeatureHealthPanel,
  evaluateFeatureHealth,
  assertExpectationFloorsWellFormed,
  SLICE1_FEATURE_REGISTRY,
  FEATURE_FAULT_CLASS_RULES,
  CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS,
  type FeatureHealthRow,
  type FeatureRegistryEntry,
} from "../../src/principal-policy/feature-health.js";
import { CASTLE_WALL_ENFORCEMENT_OPERATIONS } from "../../src/principal-policy/posture.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import { protectionSubjectForUid } from "../../src/castle-wall/subject-binding.js";

const FORTRESS = "fortress:test";

function newAuditLog(): { log: AuditLog } {
  const storage = new MemoryStorage();
  const log = new AuditLog(storage, generateRandomKey());
  return { log };
}

/** A Castle-Wall-originated L1 entry: carries the provenance marker. */
async function appendCW(
  log: AuditLog,
  operation: string,
  timestamp: string,
  result: "success" | "failure" = "success",
  identityId: string = FORTRESS,
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: identityId,
    result,
    details: { cw_source: "castle_wall_audit_consumer" },
    timestamp,
  });
}

function subjectForUid(uid: number): string {
  const subject = protectionSubjectForUid(FORTRESS, uid);
  if (subject === null) throw new Error("test subject could not be derived");
  return subject;
}

function row(panel: { rows: FeatureHealthRow[] }, id: string): FeatureHealthRow {
  const r = panel.rows.find((x) => x.feature_id === id);
  if (!r) throw new Error(`no row for ${id}`);
  return r;
}

describe("feature-health registry — integrity invariants", () => {
  it("matchers are mutually exclusive: no operation string appears in two features", () => {
    const seen = new Map<string, string>();
    for (const f of SLICE1_FEATURE_REGISTRY) {
      for (const op of f.invocationOps) {
        const prior = seen.get(op);
        expect(
          prior,
          `operation "${op}" is claimed by both ${prior} and ${f.id}`,
        ).toBeUndefined();
        seen.set(op, f.id);
      }
    }
  });

  it("the self-reporting features are Castle Wall + the broker daemon (process liveness); the rest are event-driven", () => {
    // Broker Option C added the `secret_broker_daemon` process-liveness row. It
    // is self_reporting (it has a heartbeat producer) but carries an EMPTY
    // invocationOps set, so it can never read green - unlike Castle Wall, which
    // has real live-adjudication invocation ops.
    const selfReporting = SLICE1_FEATURE_REGISTRY.filter(
      (f) => f.liveness === "self_reporting",
    );
    expect(selfReporting.map((f) => f.id).sort()).toEqual(
      ["castle_wall_egress", "secret_broker_daemon"].sort(),
    );
    const brokerDaemon = selfReporting.find(
      (f) => f.id === "secret_broker_daemon",
    );
    expect(brokerDaemon?.invocationOps.size).toBe(0);
  });

  it("only self-reporting features advertise broken-zero as detectable", () => {
    for (const f of SLICE1_FEATURE_REGISTRY) {
      expect(f.brokenZeroDetectable).toBe(f.liveness === "self_reporting");
    }
  });

  it("Castle Wall live-adjudication ops exclude policy_loaded (the honesty seam)", () => {
    expect(CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS.has("policy_loaded")).toBe(
      false,
    );
    expect(CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS.has("egress_allowed")).toBe(
      true,
    );
  });

  it("both readers share ONE live-adjudication set (drift guard: the banner and panel cannot diverge)", () => {
    // The honesty-seam fix collapsed the two formerly-separate sets into one
    // frozen object. If a future change re-forks them, this fails loudly.
    expect(CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS).toBe(
      CASTLE_WALL_ENFORCEMENT_OPERATIONS,
    );
    expect([...CASTLE_WALL_ENFORCEMENT_OPERATIONS].sort()).toEqual([
      "egress_allowed",
      "egress_blocked",
      "operator_decision",
    ]);
    expect(CASTLE_WALL_ENFORCEMENT_OPERATIONS.has("policy_loaded")).toBe(false);
  });

  it("the plugin_failure_surge fault class is now LIVE (producer #728/#753 + raise path built)", () => {
    const plugin = FEATURE_FAULT_CLASS_RULES.find(
      (r) => r.class === "plugin_failure_surge",
    );
    // Un-dormanted: its plugin_error producer exists (#728), the per-plugin rows
    // read it (#753), and the notification raise/dedup path is built
    // (feature-fault-raise.ts). Only this rule was flipped.
    expect(plugin?.dormant).toBe(false);
    // All three ratified classes are live; no other class exists to stay dormant.
    expect(
      FEATURE_FAULT_CLASS_RULES.filter((r) => !r.dormant).map((r) => r.class),
    ).toEqual([
      "castle_wall_fault",
      "feature_silently_off",
      "plugin_failure_surge",
    ]);
    // `dormant` remains a structural guard for any future class added here.
    expect(FEATURE_FAULT_CLASS_RULES.every((r) => r.dormant === false)).toBe(
      true,
    );
  });
});

describe("feature-health panel — the four mandatory color assertions", () => {
  it("(a) evidence-absent yields a NON-GREEN unconfirmed/unknown chip for EVERY feature, never active", async () => {
    const { log } = newAuditLog();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    expect(panel.rows.length).toBe(SLICE1_FEATURE_REGISTRY.length);
    for (const r of panel.rows) {
      expect(r.status).not.toBe("active");
      if (r.liveness === "self_reporting") {
        // No evidence → unknown, never green.
        expect(r.status).toBe("unknown");
        expect(r.basis).toBe("no_evidence_self_reporting");
      } else {
        // Event-driven quiet → distinct non-green unconfirmed chip.
        expect(r.status).toBe("unconfirmed");
        expect(r.basis).toBe("no_activity_event_driven");
        expect(r.broken_zero_detectable).toBe(false);
      }
    }
  });

  it("(b) a fresh Castle Wall fault op flips that feature to RED (fault)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "provider_unbound", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("fault_evidence");
  });

  it("labels manifest-present arm-lease-absent Castle Wall faults as enforcement_unavailable", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l1",
      operation: "provider_unbound",
      identity_id: FORTRESS,
      result: "failure",
      details: {
        manifest_received: true,
        arm_lease_received: false,
        cw_source: "castle_wall_audit_consumer",
      },
      timestamp: new Date(now - 60_000).toISOString(),
    });

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });

    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("enforcement_unavailable");
  });

  it("labels Castle Wall fault from the local enforcement_unavailable fallback when the audit log lacks the safe-mode entry", async () => {
    const { log } = newAuditLog();
    const now = Date.now();

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      enforcementAvailabilityStatus: {
        state: "enforcement_unavailable",
        reason: "manifest_present_arm_lease_missing",
        updated_at: new Date(now - 60_000).toISOString(),
        source: "macos_extension_provider_unbound",
        manifest_received: true,
        arm_lease_received: false,
      },
    });

    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("enforcement_unavailable");
  });

  it("lets newer live Castle Wall adjudication recover over an older local enforcement_unavailable fallback", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_allowed", new Date(now - 30_000).toISOString());

    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      enforcementAvailabilityStatus: {
        state: "enforcement_unavailable",
        reason: "manifest_present_arm_lease_missing",
        updated_at: new Date(now - 90_000).toISOString(),
        source: "macos_extension_provider_unbound",
        manifest_received: true,
        arm_lease_received: false,
      },
    });

    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("active");
    expect(cw.basis).toBe("fresh_enforcement_evidence");
  });

  it("(c) integrity-taint forces unknown for EVERY feature, even with fresh evidence present", () => {
    // Drive the pure evaluator with integrityOk=false and a fresh invocation:
    // it must still render unknown (a tainted read can never render green/red).
    const now = Date.now();
    const fresh: AuditEntry = {
      timestamp: new Date(now - 1000).toISOString(),
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "castle_wall_audit_consumer" },
    };
    for (const feature of SLICE1_FEATURE_REGISTRY) {
      const r = evaluateFeatureHealth({
        feature,
        entries: [fresh],
        originMachine: FORTRESS,
        now,
        freshnessWindowMs: 10 * 60 * 1000,
        integrityOk: false,
      });
      expect(r.status).toBe("unknown");
      expect(r.basis).toBe("integrity_tainted");
    }
  });

  it("(d) stale Castle Wall evidence → unknown, never green", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // 30 minutes ago, outside the 10-minute freshness window.
    await appendCW(
      log,
      "egress_allowed",
      new Date(now - 30 * 60_000).toISOString(),
    );
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("stale_evidence");
    expect(cw.invocation_count).toBe(1); // counted, but not fresh enough to arm
  });
});

describe("feature-health — green is earned correctly", () => {
  it("Castle Wall renders ACTIVE/green only on FRESH live-adjudication evidence", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "egress_blocked", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("active");
    expect(cw.basis).toBe("fresh_enforcement_evidence");
  });

  it("policy_loaded alone does NOT arm Castle Wall (the honesty seam — stays unknown)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(log, "policy_loaded", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("unknown");
    expect(cw.invocation_count).toBe(0); // policy_loaded is not an invocation op here
  });

  it("a forged L1 entry without the cw_source marker can NEVER arm Castle Wall", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l1",
      operation: "egress_allowed",
      identity_id: FORTRESS,
      result: "success",
      details: { cw_source: "not-castle-wall" },
      timestamp: new Date(now - 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("unknown");
    expect(cw.invocation_count).toBe(0);
  });

  it("event-driven features render ACTIVE on real activity in the window", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l3",
      operation: "broker_token_issued",
      identity_id: FORTRESS,
      result: "success",
      details: {},
      timestamp: new Date(now - 5 * 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const broker = row(panel, "secret_broker");
    expect(broker.status).toBe("active");
    expect(broker.basis).toBe("activity_in_window");
    expect(broker.invocation_count).toBe(1);
    // The other event-driven features remain non-green unconfirmed.
    expect(row(panel, "approval_gates").status).toBe("unconfirmed");
  });

  it("a failed audit read fails closed: every row is unknown, never an empty-but-green panel", async () => {
    const now = Date.now();
    const throwingLog = {
      query: async () => {
        throw new Error("storage unavailable");
      },
    } as unknown as AuditLog;
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: throwingLog,
      originMachine: FORTRESS,
      now,
    });
    expect(panel.audit_integrity_ok).toBe(false);
    for (const r of panel.rows) {
      expect(r.status).toBe("unknown");
      expect(r.basis).toBe("integrity_tainted");
    }
  });

  it("the panel always carries the honest disclosure flags", async () => {
    const { log } = newAuditLog();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    expect(panel.disclosure.broken_zero_undetectable_for_event_driven).toBe(true);
    // Slice 2: silent death is now DETECTED (a missing heartbeat reads
    // `fault`/red, not `unknown`), so this honesty caveat is now false.
    expect(
      panel.disclosure.castle_wall_silent_death_is_unknown_not_green,
    ).toBe(false);
  });

  it("future-dated Castle Wall evidence beyond skew does NOT keep the wall green", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // 10 minutes in the future — well beyond the 60s skew tolerance.
    await appendCW(
      log,
      "egress_allowed",
      new Date(now + 10 * 60_000).toISOString(),
    );
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    // The future entry is excluded from the window entirely (ts > now), so the
    // wall has no fresh evidence → unknown.
    expect(cw.status).toBe("unknown");
  });
});

describe("feature-health — custom registry edge cases", () => {
  it("a self-reporting feature with a fresh fault AND no fresh invocation is fault", () => {
    const feature: FeatureRegistryEntry = {
      id: "test_self",
      label: "Test self-reporting",
      layer: "l1",
      liveness: "self_reporting",
      invocationOps: new Set(["op_invoke"]),
      faultOps: new Set(["op_fault"]),
      brokenZeroDetectable: true,
    };
    const now = Date.now();
    const faultEntry: AuditEntry = {
      timestamp: new Date(now - 1000).toISOString(),
      layer: "l1",
      operation: "op_fault",
      identity_id: FORTRESS,
      result: "failure",
    };
    const r = evaluateFeatureHealth({
      feature,
      entries: [faultEntry],
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: 10 * 60 * 1000,
      integrityOk: true,
    });
    expect(r.status).toBe("fault");
  });
});

describe("feature-health — fault precedence + freshness completeness (codex 2026-06-13)", () => {
  const SELF: FeatureRegistryEntry = {
    id: "test_self",
    label: "Test self-reporting",
    layer: "l1",
    liveness: "self_reporting",
    invocationOps: new Set(["op_invoke"]),
    faultOps: new Set(["op_fault"]),
    brokenZeroDetectable: true,
  };
  const FRESH = 10 * 60 * 1000;
  const entry = (op: string, agoMs: number, now: number): AuditEntry => ({
    timestamp: new Date(now - agoMs).toISOString(),
    layer: "l1",
    operation: op,
    identity_id: FORTRESS,
    result: op === "op_fault" ? "failure" : "success",
  });

  it("HIGH regression: a fresh fault co-occurring with fresh invocation is fault, NEVER green", () => {
    const now = Date.now();
    // A later invocation must not bury an earlier fresh fault.
    const r = evaluateFeatureHealth({
      feature: SELF,
      entries: [entry("op_fault", 5000, now), entry("op_invoke", 1000, now)],
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: FRESH,
      integrityOk: true,
    });
    expect(r.status).toBe("fault");
    expect(r.basis).toBe("fault_evidence");
  });

  it("MEDIUM regression: an incomplete freshness scan cannot render green (fails closed to unknown)", () => {
    const now = Date.now();
    // Fresh invocation present, no fault seen — but the scan was truncated, so we
    // cannot prove a fault wasn't dropped. Must be unknown, never active.
    const r = evaluateFeatureHealth({
      feature: SELF,
      entries: [entry("op_invoke", 1000, now)],
      freshnessEntries: [entry("op_invoke", 1000, now)],
      freshnessComplete: false,
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: FRESH,
      integrityOk: true,
    });
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("freshness_scan_incomplete");
  });

  it("a fresh fault still wins even when the freshness scan is incomplete", () => {
    const now = Date.now();
    const r = evaluateFeatureHealth({
      feature: SELF,
      entries: [entry("op_invoke", 1000, now)],
      freshnessEntries: [entry("op_fault", 3000, now), entry("op_invoke", 1000, now)],
      freshnessComplete: false,
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: FRESH,
      integrityOk: true,
    });
    expect(r.status).toBe("fault");
    expect(r.basis).toBe("fault_evidence");
  });

  it("a fault seen only in the dedicated freshness scan still surfaces (separate window sets)", () => {
    const now = Date.now();
    // The digest window carries only invocations (fault dropped by truncation);
    // the dedicated freshness scan carries the fault. Fault must surface.
    const r = evaluateFeatureHealth({
      feature: SELF,
      entries: [entry("op_invoke", 1000, now)],
      freshnessEntries: [entry("op_fault", 2000, now)],
      freshnessComplete: true,
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: FRESH,
      integrityOk: true,
    });
    expect(r.status).toBe("fault");
  });
});

describe("feature-health — green-strict/fault-loose + activity honesty (codex round-2 2026-06-13)", () => {
  it("HIGH regression: a privacy CONFIG write alone does NOT render privacy_strips green", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // Administrative housekeeping (a config update), not an actual strip.
    await log.appendCritical({
      layer: "l2",
      operation: "query_anonymity_pii_config_updated",
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(now - 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const privacy = row(panel, "privacy_strips");
    expect(privacy.status).not.toBe("active");
    expect(privacy.status).toBe("unconfirmed");
  });

  it("an actual Tier 2 scrub (filter_tier:2) DOES render privacy_strips active", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // Rho-2.5: the live consent-gated redactor emits this op with
    // filter_tier:2 on a REAL scrub.
    await log.appendCritical({
      layer: "l2",
      operation: "intelligence_pii_redaction_event",
      identity_id: FORTRESS,
      result: "success",
      details: { filter_tier: 2, match_count: 1 },
      timestamp: new Date(now - 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    expect(row(panel, "privacy_strips").status).toBe("active");
  });

  it("a toggled-off passthrough (filter_tier:1) does NOT render privacy_strips green", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // The consent-gated redactor emits filter_tier:1 when Tier B is off /
    // unconsented. The provenanceMarker (filter_tier===2) must NOT count it,
    // so a quiet-Tier-B fortress can never read green from passthrough alone.
    await log.appendCritical({
      layer: "l2",
      operation: "intelligence_pii_redaction_event",
      identity_id: FORTRESS,
      result: "success",
      details: { filter_tier: 1, match_count: 0 },
      timestamp: new Date(now - 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const privacy = row(panel, "privacy_strips");
    expect(privacy.status).not.toBe("active");
    expect(privacy.status).toBe("unconfirmed");
  });

  it("MEDIUM regression: an UNMARKED Castle Wall fault still flips the wall to fault, even with fresh marked enforcement present", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // Fresh, properly-marked enforcement evidence (would otherwise be green)...
    await appendCW(log, "egress_allowed", new Date(now - 90_000).toISOString());
    // ...and a real fault written WITHOUT the cw_source marker (as the daemon
    // does for policy_validation_failed). The fault must NOT be dropped.
    await log.appendCritical({
      layer: "l1",
      operation: "policy_validation_failed",
      identity_id: FORTRESS,
      result: "failure",
      timestamp: new Date(now - 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("fault_evidence");
  });

  it("DOCUMENTED TRUST BOUNDARY: a correct-marker IN-PROCESS write DOES render green — this is exact posture.ts parity, not a new hole (codex HIGH 2026-06-13, accepted; audit-entry producer authenticity is a tracked system-level item)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // An in-process writer with AuditLog access can stamp the consumer's marker
    // and arm the wall green. This is the SAME trust boundary the shipped
    // posture.ts arm-state already lives with (in-process writers are trusted;
    // the wall's real anti-forgery anchor is the signed manifest, not this
    // read-side projection). This surface is no MORE permissive than posture.ts.
    // Closing this requires per-entry producer authenticity in the audit log —
    // a cross-cutting change that also hardens posture.ts, tracked separately.
    await appendCW(log, "egress_allowed", new Date(now - 60_000).toISOString());
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    // Behavior asserted explicitly so the boundary is visible and deliberate,
    // never an unexamined gap: a correctly-marked fresh entry renders green.
    expect(row(panel, "castle_wall_egress").status).toBe("active");
  });

  it("foreign subject-bound Castle Wall evidence does not render castle_wall_egress active", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendCW(
      log,
      "egress_allowed",
      new Date(now - 60_000).toISOString(),
      "success",
      subjectForUid(65),
    );
    const panel = await buildFeatureHealthPanel({
      auditLog: log,
      originMachine: FORTRESS,
      now,
      protectionClaimSubject: subjectForUid(503),
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("unknown");
    expect(cw.basis).toBe("subject_unbound_evidence");
  });
});

describe("feature-health - query-privacy header strip (Phase 2 Slice 1; the always-on feature that actually fires)", () => {
  // Context: the registry's OTHER privacy row (`privacy_strips`) counts the Tier
  // B PII-rewrite scrub (`intelligence_pii_redaction_event` gated on
  // filter_tier:2 since Rho-2.5), which is opt-in. The Tier A header strip, by
  // contrast, fires `query_anonymity_headers_stripped` on EVERY outbound
  // substrate call. These cases lock in that the header_strip row keys on its
  // OWN always-on op and does not borrow the Tier B op.

  it("the header_strip row exists, is event-driven, and keys on its own always-on op (not the Tier B op)", async () => {
    const { log } = newAuditLog();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    const hs = row(panel, "header_strip");
    expect(hs.liveness).toBe("event_driven");
    // Keys on the always-on header-strip event, never the Tier B scrub ops.
    const entry = SLICE1_FEATURE_REGISTRY.find((f) => f.id === "header_strip");
    expect(entry?.invocationOps.has("query_anonymity_headers_stripped")).toBe(
      true,
    );
    expect(entry?.invocationOps.has("query_anonymity_pii_rewritten")).toBe(false);
    expect(entry?.invocationOps.has("intelligence_pii_redaction_event")).toBe(
      false,
    );
  });

  it("HONESTY: the label describes metadata/header stripping and never claims anonymity or privacy guarantees", () => {
    const entry = SLICE1_FEATURE_REGISTRY.find((f) => f.id === "header_strip");
    expect(entry).toBeDefined();
    const label = entry!.label.toLowerCase();
    // Must name what it is: header / metadata stripping.
    expect(label).toMatch(/header|metadata/);
    // Must NOT overclaim. Header stripping is metadata hygiene; the provider
    // still sees the query content and the API key (Phase 2 design §2.1 C).
    expect(label).not.toContain("anonym");
    expect(label).not.toContain("private");
    expect(label).not.toMatch(/\bprivacy\b.*guarantee|guarantee.*privacy/);
  });

  it("a window with real header-strip evidence renders the row ACTIVE/green", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await log.appendCritical({
      layer: "l2",
      operation: "query_anonymity_headers_stripped",
      identity_id: FORTRESS,
      result: "success",
      details: { stripped_count: 22 },
      timestamp: new Date(now - 5 * 60_000).toISOString(),
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const hs = row(panel, "header_strip");
    expect(hs.status).toBe("active");
    expect(hs.basis).toBe("activity_in_window");
    expect(hs.invocation_count).toBe(1);
  });

  it("a QUIET window renders the row UNCONFIRMED (amber), never a fake green", async () => {
    const { log } = newAuditLog();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    const hs = row(panel, "header_strip");
    // Broken-zero is undetectable for an event-driven feature: absence of calls
    // is NOT evidence of health, so it stays non-green.
    expect(hs.status).toBe("unconfirmed");
    expect(hs.basis).toBe("no_activity_event_driven");
    expect(hs.status).not.toBe("active");
    expect(hs.broken_zero_detectable).toBe(false);
  });

  it("a tainted audit read forces the row to UNKNOWN, never green", async () => {
    const throwingLog = {
      query: async () => {
        throw new Error("storage unavailable");
      },
    } as unknown as AuditLog;
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: throwingLog,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    const hs = row(panel, "header_strip");
    expect(hs.status).toBe("unknown");
    expect(hs.basis).toBe("integrity_tainted");
  });
});

describe("feature-health - opt-in operator-declared expectation floors (event-driven)", () => {
  // The event-driven feature under test: the secret broker, which counts
  // `broker_token_issued` / `broker_token_denied`. We declare an OPT-IN floor
  // on it via a custom (injected) registry to model an operator/enterprise
  // policy opting THIS feature into a minimum-volume expectation.
  const FLOORED_BROKER: FeatureRegistryEntry = {
    id: "secret_broker",
    label: "Secret broker (selective disclosure)",
    layer: "l3",
    liveness: "event_driven",
    invocationOps: Object.freeze(
      new Set<string>(["broker_token_issued", "broker_token_denied"]),
    ),
    // The operator declares: I expect at least 3 broker decisions this window.
    expectationFloor: { minInvocations: 3 },
    brokenZeroDetectable: false,
  };

  // The SAME feature WITHOUT a floor (the conservative default), to prove the
  // no-regression invariant.
  const UNFLOORED_BROKER: FeatureRegistryEntry = {
    id: "secret_broker",
    label: "Secret broker (selective disclosure)",
    layer: "l3",
    liveness: "event_driven",
    invocationOps: Object.freeze(
      new Set<string>(["broker_token_issued", "broker_token_denied"]),
    ),
    brokenZeroDetectable: false,
  };

  async function appendBroker(
    log: AuditLog,
    n: number,
    now: number,
  ): Promise<void> {
    for (let i = 0; i < n; i += 1) {
      await log.appendCritical({
        layer: "l3",
        operation: "broker_token_issued",
        identity_id: FORTRESS,
        result: "success",
        details: {},
        timestamp: new Date(now - (i + 1) * 60_000).toISOString(),
      });
    }
  }

  // (1) WITH a declared floor + below-floor activity → unconfirmed/yellow (NOT
  // red, NOT green).
  it("below a declared floor reads unconfirmed/yellow, never fault or active", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendBroker(log, 1, now); // 1 < floor of 3
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [FLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    expect(broker.status).toBe("unconfirmed");
    expect(broker.basis).toBe("below_expected_floor");
    expect(broker.status).not.toBe("fault");
    expect(broker.status).not.toBe("active");
    expect(broker.invocation_count).toBe(1);
    expect(broker.expectation_floor).toBe(3);
  });

  // (2) The same feature MEETING its floor reads green.
  it("meeting a declared floor reads active/green (floor_met)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendBroker(log, 3, now); // exactly meets floor of 3
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [FLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    expect(broker.status).toBe("active");
    expect(broker.basis).toBe("floor_met");
    expect(broker.invocation_count).toBe(3);
    expect(broker.expectation_floor).toBe(3);
  });

  // (3) WITHOUT a declared floor + zero activity → green-neutral as before (the
  // conservative default; NO regression, silence never fires).
  it("no declared floor + zero activity keeps the conservative default (unconfirmed/no_activity, never red)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [UNFLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    expect(broker.status).toBe("unconfirmed");
    expect(broker.basis).toBe("no_activity_event_driven");
    expect(broker.status).not.toBe("fault");
    expect(broker.expectation_floor).toBeNull();
  });

  it("no declared floor + activity is active/activity_in_window exactly as before (no regression)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendBroker(log, 1, now);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [UNFLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    expect(broker.status).toBe("active");
    expect(broker.basis).toBe("activity_in_window");
    expect(broker.expectation_floor).toBeNull();
  });

  // (4) Integrity → unknown overrides a would-be below-floor yellow.
  it("an integrity finding forces unknown, overriding a below-floor yellow", () => {
    const now = Date.now();
    const belowFloorEntry: AuditEntry = {
      timestamp: new Date(now - 60_000).toISOString(),
      layer: "l3",
      operation: "broker_token_issued",
      identity_id: FORTRESS,
      result: "success",
      details: {},
    };
    const r = evaluateFeatureHealth({
      feature: FLOORED_BROKER,
      entries: [belowFloorEntry], // 1 < floor of 3 → would be below_expected_floor
      originMachine: FORTRESS,
      now,
      freshnessWindowMs: 10 * 60 * 1000,
      integrityOk: false, // tainted read wins
    });
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("integrity_tainted");
    expect(r.basis).not.toBe("below_expected_floor");
  });

  // (5) No auto-baselining: with NO operator-declared floor, no trailing-median
  // or computed threshold ever changes a status. The trailing volume is
  // descriptive-only.
  it("no auto-baselining: trailing volume is descriptive-only and never drives status without a declared floor", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    // A busy then quiet history: plenty of activity, so a trailing median exists,
    // but the UNFLOORED feature must still NOT manufacture a below-typical alarm.
    await appendBroker(log, 5, now);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [UNFLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    // Activity present → active/activity_in_window. A trailing median may be
    // surfaced for context, but it NEVER becomes an auto-threshold.
    expect(broker.status).toBe("active");
    expect(broker.basis).toBe("activity_in_window");
    expect(broker.expectation_floor).toBeNull();
    // Descriptive-only context may be present but never a status driver.
    expect(broker.basis).not.toBe("below_expected_floor");
    expect(broker.basis).not.toBe("floor_met");
  });

  it("the descriptive trailing_window_volume never appears as a basis or floor (no-auto-baselining boundary)", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendBroker(log, 4, now);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [UNFLOORED_BROKER],
    });
    const broker = row(panel, "secret_broker");
    // trailing_window_volume is surfaced (a number) but the feature has NO floor,
    // so it cannot have driven status: expectation_floor stays null and the basis
    // is the plain activity basis.
    expect(broker.expectation_floor).toBeNull();
    expect(typeof broker.trailing_window_volume === "number" || broker.trailing_window_volume === null).toBe(true);
    expect(broker.basis).toBe("activity_in_window");
  });

  // (6) The floor config is operator-declared (round-trips through the registry
  // config artifact) and is opt-in per feature.
  it("the floor round-trips through the registry config artifact and is opt-in per feature", async () => {
    const { log } = newAuditLog();
    const now = Date.now();
    await appendBroker(log, 2, now); // below floor of 3
    // Two features on the same panel: one floored, one not. ONLY the floored one
    // changes behavior; the unfloored one is untouched.
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now,
      registry: [
        FLOORED_BROKER,
        {
          id: "approval_gates",
          label: "Human-approval gates",
          layer: "l2",
          liveness: "event_driven",
          invocationOps: Object.freeze(
            new Set<string>(["cross_harness_approval_resolved"]),
          ),
          brokenZeroDetectable: false,
        } as FeatureRegistryEntry,
      ],
    });
    const broker = row(panel, "secret_broker");
    const approval = row(panel, "approval_gates");
    // The floored feature carries its declared floor and reads below-floor.
    expect(broker.expectation_floor).toBe(3);
    expect(broker.basis).toBe("below_expected_floor");
    // The unfloored feature is opt-OUT by default: null floor, conservative quiet.
    expect(approval.expectation_floor).toBeNull();
    expect(approval.basis).toBe("no_activity_event_driven");
  });

  it("the shipped Slice-1 registry declares NO floors (conservative default for every shipped feature)", () => {
    // The headline honesty: opt-in means the shipped product behaves exactly as
    // before. NO shipped feature carries a floor, so none changes its dashboard
    // behavior until an operator declares one.
    for (const f of SLICE1_FEATURE_REGISTRY) {
      expect(f.expectationFloor).toBeUndefined();
    }
  });

  it("registry validation rejects a floor on a self-reporting feature", () => {
    expect(() =>
      assertExpectationFloorsWellFormed([
        {
          id: "bad_self",
          label: "Bad self-reporting with floor",
          layer: "l1",
          liveness: "self_reporting",
          invocationOps: new Set(["op_invoke"]),
          expectationFloor: { minInvocations: 1 },
          brokenZeroDetectable: true,
        },
      ]),
    ).toThrow(/non-event_driven/);
  });

  it("registry validation rejects a non-positive / non-integer floor", () => {
    for (const bad of [0, -1, 1.5]) {
      expect(() =>
        assertExpectationFloorsWellFormed([
          {
            id: "bad_floor",
            label: "Bad floor value",
            layer: "l3",
            liveness: "event_driven",
            invocationOps: new Set(["op_invoke"]),
            expectationFloor: { minInvocations: bad },
            brokenZeroDetectable: false,
          },
        ]),
      ).toThrow(/positive integer/);
    }
  });

  it("a below-floor dip does NOT enter the OS-notification raise path (invariant 5)", async () => {
    // A feature that met its floor one cycle and dipped below it the next reads
    // unconfirmed/below_expected_floor. That transition must NOT be reported as a
    // `feature_silently_off` fault (the §4.3 raise path is the 3 fault classes
    // only). We assert directly against the raise-deriving logic.
    const { deriveFeatureFaults } = await import(
      "../../src/principal-policy/feature-fault-raise.js"
    );
    const now = Date.now();
    const { log: logPrev } = newAuditLog();
    await appendBroker(logPrev, 3, now); // meets floor
    const prevPanel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: logPrev,
      originMachine: FORTRESS,
      now,
      registry: [FLOORED_BROKER],
    });
    const { log: logCur } = newAuditLog();
    await appendBroker(logCur, 1, now); // dips below floor
    const curPanel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: logCur,
      originMachine: FORTRESS,
      now,
      registry: [FLOORED_BROKER],
    });
    expect(row(prevPanel, "secret_broker").status).toBe("active");
    expect(row(curPanel, "secret_broker").basis).toBe("below_expected_floor");
    const faults = deriveFeatureFaults(curPanel, prevPanel);
    // No silent-off (or any) fault should be raised for an opt-in floor breach.
    expect(
      faults.some((f) => f.feature_id === "secret_broker"),
    ).toBe(false);
  });
});
