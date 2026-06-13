import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/l2-operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildFeatureHealthPanel,
  evaluateFeatureHealth,
  SLICE1_FEATURE_REGISTRY,
  FEATURE_FAULT_CLASS_RULES,
  CASTLE_WALL_LIVE_ADJUDICATION_OPERATIONS,
  type FeatureHealthRow,
  type FeatureRegistryEntry,
} from "../../src/principal-policy/feature-health.js";
import type { AuditEntry } from "../../src/l2-operational/audit-log.js";

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
): Promise<void> {
  await log.appendCritical({
    layer: "l1",
    operation,
    identity_id: FORTRESS,
    result,
    details: { cw_source: "castle_wall_audit_consumer" },
    timestamp,
  });
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

  it("exactly one self-reporting feature (Castle Wall); the rest are event-driven", () => {
    const selfReporting = SLICE1_FEATURE_REGISTRY.filter(
      (f) => f.liveness === "self_reporting",
    );
    expect(selfReporting.map((f) => f.id)).toEqual(["castle_wall_egress"]);
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

  it("the plugin_failure_surge fault class is DORMANT (no #508 S4 producer yet)", () => {
    const plugin = FEATURE_FAULT_CLASS_RULES.find(
      (r) => r.class === "plugin_failure_surge",
    );
    expect(plugin?.dormant).toBe(true);
    // The other two classes have producers and are live.
    expect(
      FEATURE_FAULT_CLASS_RULES.filter((r) => !r.dormant).map((r) => r.class),
    ).toEqual(["castle_wall_fault", "feature_silently_off"]);
  });
});

describe("feature-health panel — the four mandatory color assertions", () => {
  it("(a) evidence-absent yields a NON-GREEN unconfirmed/unknown chip for EVERY feature, never active", async () => {
    const { log } = newAuditLog();
    const panel = await buildFeatureHealthPanel({
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
      auditLog: log,
      originMachine: FORTRESS,
      now,
    });
    const cw = row(panel, "castle_wall_egress");
    expect(cw.status).toBe("fault");
    expect(cw.basis).toBe("fault_evidence");
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
      auditLog: log,
      originMachine: FORTRESS,
      now: Date.now(),
    });
    expect(panel.disclosure.broken_zero_undetectable_for_event_driven).toBe(true);
    expect(
      panel.disclosure.castle_wall_silent_death_is_unknown_not_green,
    ).toBe(true);
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
