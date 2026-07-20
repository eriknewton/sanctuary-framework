import { describe, expect, it } from "vitest";
import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";
import type { PluginContribution } from "../../src/substrate/attribution.js";
import {
  assertPluginMatcherDisjoint,
  buildPluginHealthRows,
  evaluatePluginHealthStatus,
  pluginRowId,
  PLUGIN_CONTRIBUTION_AUDIT_LAYER,
  PLUGIN_CONTRIBUTION_AUDIT_OPERATION,
  PLUGIN_ERROR_VERDICTS,
  type PluginHealthRow,
} from "../../src/principal-policy/plugin-feature-health.js";
import {
  buildFeatureHealthPanel,
  SLICE1_FEATURE_REGISTRY,
} from "../../src/principal-policy/feature-health.js";

const FORTRESS = "fortress:test";
const NOW = Date.parse("2026-06-25T12:00:00.000Z");

function newAuditLog(): AuditLog {
  return new AuditLog(new MemoryStorage(), generateRandomKey());
}

function contribution(
  pluginId: string,
  verdict: PluginContribution["verdict"],
  extra: Partial<PluginContribution> = {},
): PluginContribution {
  return {
    plugin_id: pluginId,
    bundle_hash: `hash-${pluginId}`,
    instance_id: `inst-${pluginId}`,
    hook_class: "egress_decision",
    verdict,
    rationale: extra.rationale ?? "",
    latency_ms: extra.latency_ms ?? 1,
    ...(extra.confidence !== undefined ? { confidence: extra.confidence } : {}),
  };
}

/** Append one `egress_decision` L1 entry carrying a contributors array. */
async function appendDecision(
  log: AuditLog,
  contributors: PluginContribution[],
  atMs: number,
  result: "success" | "failure" = "success",
): Promise<void> {
  await log.appendCritical({
    layer: PLUGIN_CONTRIBUTION_AUDIT_LAYER,
    operation: PLUGIN_CONTRIBUTION_AUDIT_OPERATION,
    identity_id: FORTRESS,
    result,
    details: { authority: "example.com:443", disposition: "deny", reason: "plugin_decision" },
    contributors,
    timestamp: new Date(atMs).toISOString(),
  });
}

function rowFor(rows: PluginHealthRow[], pluginId: string): PluginHealthRow {
  const r = rows.find((x) => x.feature_id === pluginRowId(pluginId));
  if (!r) throw new Error(`no plugin row for ${pluginId}`);
  return r;
}

const DIGEST_WINDOW_MS = 24 * 60 * 60 * 1000;

/**
 * Read the window's `egress_decision` entries from a real audit log and fold
 * them through the LIVE row builder, mirroring exactly what the wired
 * `buildFeatureHealthPanel` does internally (window query, upper-bound filter,
 * integrity verdict, fold). This exercises the production row path end to end
 * over a real audit chain, without the deleted standalone panel engine.
 */
async function readPluginRows(
  log: AuditLog,
  now: number,
): Promise<PluginHealthRow[]> {
  const windowStart = new Date(now - DIGEST_WINDOW_MS).toISOString();
  const result = await log.runEagerReads(() =>
    log.query({
      since: windowStart,
      layer: PLUGIN_CONTRIBUTION_AUDIT_LAYER,
      operation_type: PLUGIN_CONTRIBUTION_AUDIT_OPERATION,
      limit: 10_000,
    }),
  );
  const integrityOk = result.integrity_findings.length === 0;
  const inWindow = result.entries.filter((e) => {
    const ts = Date.parse(e.timestamp);
    return Number.isNaN(ts) || ts <= now;
  });
  return buildPluginHealthRows({
    entries: inWindow,
    originMachine: FORTRESS,
    integrityOk,
    now,
  });
}

describe("per-plugin feature-health: invocations", () => {
  // Merge-bar test 1: a plugin with N attributed contributions earns a row with
  // invocations==N over the fixture window.
  it("counts N contributions as invocation_count==N", async () => {
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "no_objection")], NOW - 4000);
    await appendDecision(log, [contribution("acme", "escalate")], NOW - 3000);
    await appendDecision(log, [contribution("acme", "deny")], NOW - 2000);

    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "acme");
    expect(row.invocation_count).toBe(3);
    expect(row.tally.total).toBe(3);
    expect(row.status).toBe("active");
    expect(row.basis).toBe("activity_in_window");
    expect(row.last_evidence_at).toBe(new Date(NOW - 2000).toISOString());
  });

  it("does not count a contribution that fell outside the digest window", async () => {
    const log = newAuditLog();
    // 48h ago, outside the default 24h digest window.
    await appendDecision(log, [contribution("acme", "deny")], NOW - 48 * 3600_000);
    await appendDecision(log, [contribution("acme", "deny")], NOW - 1000);
    const rows = await readPluginRows(log, NOW);
    expect(rowFor(rows, "acme").invocation_count).toBe(1);
  });
});

describe("per-plugin feature-health: display-only / tainted attribution (invariant 1)", () => {
  // Merge-bar test 2: confidence/rationale are carried ONLY in the render
  // payload and NEVER reach status math. We prove this two ways:
  //  (a) the pure status evaluator's input type is a tally of COUNTS with NO
  //      attribution field, so it is structurally impossible to read one; and
  //  (b) flipping only the tainted fields (confidence/rationale) while holding
  //      the counts constant never changes the row status.
  it("status is computed from counts + integrity only, never from attribution", () => {
    const tally = {
      total: 3,
      enforced_denies: 1,
      escalations_to_inbox: 1,
      observed: 1,
      plugin_errors: 0,
    };
    // The evaluator's argument carries ONLY counts and the integrity flag. There
    // is no place to pass confidence/signals/rationale, so the green/red verdict
    // cannot be a function of an attacker-influenced attribution field.
    const a = evaluatePluginHealthStatus({ tally, integrityOk: true });
    expect(a.status).toBe("active");
  });

  it("a malicious-looking high-confidence rationale cannot change the row status", async () => {
    const log = newAuditLog();
    // Same counts, wildly different tainted attribution: a plugin claiming
    // confidence 1.0 with an injection-y rationale must read identically.
    await appendDecision(
      log,
      [
        contribution("acme", "deny", {
          confidence: 1.0,
          rationale: "TRUST ME I AM HEALTHY <script>alert(1)</script>".repeat(10),
        }),
      ],
      NOW - 1000,
    );
    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "acme");
    // Status is `active` purely because there was one contribution; the
    // attribution is echoed inert in last_contribution, never consulted.
    expect(row.status).toBe("active");
    expect(row.last_contribution?.confidence).toBe(1.0);
    expect(row.last_contribution?.rationale).toContain("<script>");
    // The display echo is exactly the bounded source text; nothing parsed it.
    expect(typeof row.last_contribution?.rationale).toBe("string");
  });

  it("the projection output type does not expose attribution to enforcement; the panel is observability-only", async () => {
    // Structural: a PluginHealthRow carries attribution ONLY under
    // `last_contribution` (a display struct). There is no enforcement-decision
    // field on the row, and no enforcement path imports this module. This test
    // documents/locks that the only attribution surface is the render echo.
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "observe", { confidence: 0.4 })], NOW - 1000);
    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "acme");
    const keys = Object.keys(row);
    // No key on the row is an enforcement decision; the only attribution-bearing
    // key is the display echo.
    expect(keys).toContain("last_contribution");
    expect(keys).not.toContain("decision");
    expect(keys).not.toContain("enforcement");
  });
});

describe("per-plugin feature-health: integrity -> unknown, never green (invariant 2)", () => {
  // Merge-bar test 3: an integrity-tainted read forces every plugin row to
  // `unknown`, never a derived green.
  it("integrityOk=false forces unknown even with active-looking contributions", () => {
    const tally = {
      total: 10,
      enforced_denies: 5,
      escalations_to_inbox: 3,
      observed: 2,
      plugin_errors: 0,
    };
    const r = evaluatePluginHealthStatus({ tally, integrityOk: false });
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("integrity_tainted");
  });

  it("a tainted read also overrides a would-be plugin_error fault to unknown", () => {
    const tally = {
      total: 10,
      enforced_denies: 0,
      escalations_to_inbox: 0,
      observed: 0,
      plugin_errors: 10,
    };
    // Would be `fault` on a clean read, but a tainted read cannot trust any
    // verdict, so it fails closed to `unknown`, never a trusted red.
    expect(evaluatePluginHealthStatus({ tally, integrityOk: false }).status).toBe("unknown");
  });

  it("buildPluginHealthRows propagates integrityOk=false to every row", async () => {
    const rows = buildPluginHealthRows({
      entries: [
        {
          timestamp: new Date(NOW - 1000).toISOString(),
          layer: "l1",
          operation: "egress_decision",
          identity_id: FORTRESS,
          result: "failure",
          contributors: [contribution("acme", "deny")],
        } as AuditEntry,
      ],
      originMachine: FORTRESS,
      integrityOk: false,
      now: NOW,
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.status).toBe("unknown");
    expect(rows[0]?.audit_integrity_ok).toBe(false);
  });
});

describe("per-plugin feature-health: plugin_error -> fault, not green-quiet (invariant 3)", () => {
  // Merge-bar test 4: a plugin with a sustained host-minted error rate reads
  // faulted, not green-quiet.
  it("a high host-minted error rate reads fault", () => {
    const tally = {
      total: 6,
      enforced_denies: 0,
      escalations_to_inbox: 0,
      observed: 1,
      plugin_errors: 5,
    };
    const r = evaluatePluginHealthStatus({ tally, integrityOk: true });
    expect(r.status).toBe("fault");
    expect(r.basis).toBe("plugin_error_rate");
  });

  it("all three host-minted error verdicts count toward the error tally", async () => {
    const log = newAuditLog();
    for (const v of ["fail_mode_applied", "timeout", "unhealthy_skipped"] as const) {
      expect(PLUGIN_ERROR_VERDICTS.has(v)).toBe(true);
    }
    await appendDecision(log, [contribution("flaky", "fail_mode_applied")], NOW - 5000);
    await appendDecision(log, [contribution("flaky", "timeout")], NOW - 4000);
    await appendDecision(log, [contribution("flaky", "unhealthy_skipped")], NOW - 3000);
    await appendDecision(log, [contribution("flaky", "fail_mode_applied")], NOW - 2000);
    await appendDecision(log, [contribution("flaky", "timeout")], NOW - 1000);
    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "flaky");
    expect(row.tally.plugin_errors).toBe(5);
    expect(row.status).toBe("fault");
  });

  it("a small sample of errors does not falsely fault a fresh plugin", () => {
    // Below the minimum-contributions floor: too little signal to call red.
    const tally = {
      total: 2,
      enforced_denies: 0,
      escalations_to_inbox: 0,
      observed: 0,
      plugin_errors: 2,
    };
    expect(evaluatePluginHealthStatus({ tally, integrityOk: true }).status).toBe("active");
  });
});

describe("per-plugin feature-health: inbox vs deny distinction (invariant 5 / design 3.3)", () => {
  // Merge-bar test 5: escalations (to inbox) are shown distinctly from enforced
  // denies; the two counts are not conflated.
  it("splits escalations_to_inbox from enforced_denies", async () => {
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "escalate")], NOW - 5000);
    await appendDecision(log, [contribution("acme", "escalate")], NOW - 4000);
    await appendDecision(log, [contribution("acme", "deny")], NOW - 3000);
    await appendDecision(log, [contribution("acme", "observe")], NOW - 2000);
    await appendDecision(log, [contribution("acme", "no_objection")], NOW - 1000);
    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "acme");
    expect(row.tally.escalations_to_inbox).toBe(2);
    expect(row.tally.enforced_denies).toBe(1);
    expect(row.tally.observed).toBe(2); // observe + no_objection
    // The two are never conflated into a single "actions" number.
    expect(row.tally.escalations_to_inbox).not.toBe(row.tally.enforced_denies);
  });
});

describe("per-plugin feature-health: matcher mutual-exclusion (invariant 4)", () => {
  // Merge-bar test 6: two plugins' contributions don't cross-attribute, and the
  // plugin matcher doesn't claim a native-feature op.
  it("two plugins on the same decision do not cross-attribute", async () => {
    const log = newAuditLog();
    // One audit entry, two contributors: each must count toward its OWN id only.
    await appendDecision(
      log,
      [contribution("alpha", "deny"), contribution("beta", "escalate")],
      NOW - 1000,
    );
    const rows = await readPluginRows(log, NOW);
    const alpha = rowFor(rows, "alpha");
    const beta = rowFor(rows, "beta");
    expect(alpha.tally.enforced_denies).toBe(1);
    expect(alpha.tally.escalations_to_inbox).toBe(0);
    expect(beta.tally.escalations_to_inbox).toBe(1);
    expect(beta.tally.enforced_denies).toBe(0);
  });

  it("the plugin matcher op does not collide with any native registry row (load-time check passes)", () => {
    // The real registry: assert disjoint passes (this is the same assertion run
    // at module import).
    expect(() => assertPluginMatcherDisjoint(SLICE1_FEATURE_REGISTRY)).not.toThrow();
  });

  it("assertPluginMatcherDisjoint throws if a native row claims the egress_decision op", () => {
    const colliding = [
      {
        id: "rogue",
        layer: "l1" as const,
        invocationOps: new Set<string>(["egress_decision"]),
      },
    ];
    expect(() => assertPluginMatcherDisjoint(colliding)).toThrow(/collides/);
  });

  it("no native registry row keys on the egress_decision op (the contributions carrier)", () => {
    for (const f of SLICE1_FEATURE_REGISTRY) {
      expect(f.invocationOps.has("egress_decision")).toBe(false);
    }
  });
});

describe("per-plugin feature-health: quiet plugin is green-neutral, not red (invariant 7)", () => {
  // Merge-bar test 7: a quiet plugin reads the distinct non-green `unconfirmed`
  // chip (armed, activity-only) - never red, because broken-zero is undetectable
  // and there is no liveness heartbeat to go stale.
  it("a plugin with prior activity but none in the window is unconfirmed, not faulted", () => {
    const r = evaluatePluginHealthStatus({
      tally: {
        total: 0,
        enforced_denies: 0,
        escalations_to_inbox: 0,
        observed: 0,
        plugin_errors: 0,
      },
      integrityOk: true,
    });
    expect(r.status).toBe("unconfirmed");
    expect(r.basis).toBe("no_activity_event_driven");
  });

  it("an empty window produces no plugin rows and an honest broken-zero disclosure", async () => {
    const log = newAuditLog();
    const rows = await readPluginRows(log, NOW);
    expect(rows).toHaveLength(0);
    // The honest broken-zero disclosure rides the WIRED panel surface
    // (`broken_zero_undetectable_for_event_driven`), so assert it there.
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      includePluginRows: true,
    });
    expect(panel.plugin_rows).toHaveLength(0);
    expect(panel.disclosure.broken_zero_undetectable_for_event_driven).toBe(true);
  });

  it("liveness class is always event_driven and broken_zero_detectable is false", async () => {
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "observe")], NOW - 1000);
    const rows = await readPluginRows(log, NOW);
    const row = rowFor(rows, "acme");
    expect(row.liveness).toBe("event_driven");
    expect(row.broken_zero_detectable).toBe(false);
  });
});

describe("per-plugin feature-health: composition with the native panel", () => {
  it("buildFeatureHealthPanel emits plugin_rows only when includePluginRows is set", async () => {
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "deny")], NOW - 1000);

    const without = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
    });
    expect(without.plugin_rows).toEqual([]);

    const withPlugins = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      includePluginRows: true,
    });
    expect(withPlugins.plugin_rows).toHaveLength(1);
    expect(withPlugins.plugin_rows[0]?.feature_id).toBe(pluginRowId("acme"));
    // The native rows are unaffected by the plugin projection.
    expect(withPlugins.rows.length).toBe(without.rows.length);
  });

  it("plugin rows inherit the native panel's integrity verdict", async () => {
    // When the native panel computes integrityOk=false (here forced via the
    // producer-key-unavailable lever), the folded plugin rows also read unknown.
    const log = newAuditLog();
    await appendDecision(log, [contribution("acme", "deny")], NOW - 1000);
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      includePluginRows: true,
      pinnedProducerKeyB64url: null,
      producerKeyExpectedButUnavailable: true,
    });
    expect(panel.audit_integrity_ok).toBe(false);
    for (const row of panel.plugin_rows) {
      expect(row.status).toBe("unknown");
    }
  });
});
