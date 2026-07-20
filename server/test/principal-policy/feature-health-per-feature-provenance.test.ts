/**
 * Per-feature provenance gate - the generalization proof.
 *
 * The feature-health provenance gate used to hardcode a boolean
 * `requireCastleWallProvenance` that did two things at once: gate evidence on the
 * Castle Wall `cw_source` marker AND route it through the Castle Wall
 * producer-signature re-verify path. This refactor splits those into:
 *
 *   - an optional per-feature `provenanceMarker: { key, value }` (the marker
 *     pre-filter, any feature can declare its own), and
 *   - an optional per-feature `producerSignatureScheme` (the signature re-verify
 *     teeth, declared ONLY by a feature whose producer cryptographically signs).
 *
 * Castle Wall declares BOTH, so its behavior is byte-for-byte unchanged (proven
 * by the unchanged `feature-health*.test.ts` suites). This file pins the NEW
 * capability the split unlocks: a feature that declares a `provenanceMarker` but
 * NO signature scheme - the shape the always-on broker liveness heartbeat will
 * use next - is gated on the channel/marker basis ONLY, exactly as a genuine
 * Castle Wall heartbeat already is on a non-key-bearing host.
 *
 * No real new product feature is added (the broker row is a follow-up PR); the
 * synthetic feature below exercises the generalized gate in isolation.
 *
 * Honesty invariants pinned:
 *   1. A genuine channel-marker beat (marker present) COUNTS as liveness.
 *   2. A beat MISSING the marker does NOT count (the marker still defends against
 *      a foreign producer on the same layer reusing an operation name).
 *   3. The producer-signature re-verify path is NEVER attempted for a feature
 *      with no scheme - even for a `producer_signed`-claiming entry - so it
 *      cannot inherit Castle Wall's signature machinery by accident.
 *   4. With no `invocationOps`, the feature can NEVER read green; the marker beat
 *      can only ever move it to a non-green alive/dead distinction.
 */

import { describe, expect, it, vi } from "vitest";

import { AuditLog } from "../../src/operational/audit-log.js";
import { MemoryStorage } from "../../src/storage/memory.js";
import { generateRandomKey } from "../../src/core/random.js";
import {
  buildFeatureHealthPanel,
  evaluateFeatureHealth,
  type FeatureHealthRow,
  type FeatureRegistryEntry,
} from "../../src/principal-policy/feature-health.js";
import type { AuditEntry } from "../../src/operational/audit-log.js";

const FORTRESS = "fortress:test";
const NOW = 1_750_000_000_000;
const FRESH_TS = NOW - 1000; // inside the 10-minute freshness window
const STALE_TS = NOW - 30 * 60_000; // outside freshness, inside the 24h digest
const FRESH_MS = 10 * 60 * 1000;

/** A distinct marker, NOT the Castle Wall `cw_source` one - its own provenance. */
const BROKER_MARKER = { key: "broker_source", value: "secret_broker_daemon" } as const;
const BROKER_HEARTBEAT_OP = "broker_heartbeat";

/**
 * The synthetic channel-marker-only feature: self-reporting with a heartbeat,
 * its OWN provenance marker, and NO producer-signature scheme. Empty
 * `invocationOps`, so it can never read green - the broker liveness shape.
 */
const MARKER_ONLY_FEATURE: FeatureRegistryEntry = {
  id: "synthetic_marker_only",
  label: "Synthetic marker-only daemon",
  layer: "l3",
  liveness: "self_reporting",
  invocationOps: new Set<string>(), // never green by construction
  livenessOps: new Set<string>([BROKER_HEARTBEAT_OP]),
  provenanceMarker: BROKER_MARKER,
  // NO producerSignatureScheme: channel/marker basis only.
  brokenZeroDetectable: true,
};

function entry(
  op: string,
  tsMs: number,
  details: Record<string, unknown>,
): AuditEntry {
  return {
    timestamp: new Date(tsMs).toISOString(),
    layer: "l3",
    operation: op,
    identity_id: FORTRESS,
    result: "success",
    details,
  };
}

function evalMarkerOnly(
  entries: AuditEntry[],
  verifyProducerSignature?: ReturnType<typeof vi.fn>,
): FeatureHealthRow {
  return evaluateFeatureHealth({
    feature: MARKER_ONLY_FEATURE,
    entries,
    originMachine: FORTRESS,
    now: NOW,
    freshnessWindowMs: FRESH_MS,
    integrityOk: true,
    // A pinned key is present so that IF the signature path were (wrongly)
    // attempted, the re-verify would run and the spy would be called.
    pinnedProducerKeyB64url: "AAAA",
    ...(verifyProducerSignature ? { verifyProducerSignature } : {}),
  });
}

describe("per-feature provenance - a channel-marker-only feature counts genuine marked beats", () => {
  it("invariant 1: a fresh beat WITH the feature's own marker counts as liveness (alive-but-idle, never green)", () => {
    const r = evalMarkerOnly([
      entry(BROKER_HEARTBEAT_OP, FRESH_TS, {
        [BROKER_MARKER.key]: BROKER_MARKER.value,
      }),
    ]);
    // The marked beat counted: the feature is alive but has no adjudication
    // evidence (it has no invocationOps), so it is honest non-green alive-idle.
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("alive_no_recent_enforcement");
    // A heartbeat is not an invocation - it must not inflate the count.
    expect(r.invocation_count).toBe(0);
    expect(r.status).not.toBe("active");
  });

  it("invariant 1 (alarm): a STALE marked beat with no fresh beat reads silently-dead, not unknown", () => {
    const r = evalMarkerOnly([
      entry(BROKER_HEARTBEAT_OP, STALE_TS, {
        [BROKER_MARKER.key]: BROKER_MARKER.value,
      }),
    ]);
    // The producer was provably running (a stale marked beat), then stopped.
    expect(r.status).toBe("fault");
    expect(r.basis).toBe("dead_no_heartbeat");
  });
});

describe("per-feature provenance - the marker still defends against a foreign producer", () => {
  it("invariant 2: a beat MISSING the marker does NOT count (no liveness seen → no_evidence)", () => {
    const r = evalMarkerOnly([
      // Right operation, wrong/absent marker - a foreign L3 producer reusing the
      // op name. The marker gate drops it: no liveness is ever observed.
      entry(BROKER_HEARTBEAT_OP, FRESH_TS, { broker_source: "not-the-broker" }),
      entry(BROKER_HEARTBEAT_OP, STALE_TS, {}),
    ]);
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("no_evidence_self_reporting");
    expect(r.invocation_count).toBe(0);
  });
});

describe("per-feature provenance - the signature re-verify path is NEVER attempted without a scheme", () => {
  it("invariant 3: a producer_signed-claiming marked beat does not invoke the verify fn (no scheme declared)", () => {
    const verifySpy = vi.fn(() => ({ ok: true }) as never);
    const r = evalMarkerOnly(
      [
        entry(BROKER_HEARTBEAT_OP, FRESH_TS, {
          [BROKER_MARKER.key]: BROKER_MARKER.value,
          // Castle Wall signature fields present - a feature WITH a scheme would
          // re-verify these. The marker-only feature must ignore them entirely.
          cw_evidence_basis: "producer_signed",
          cw_producer_sig: "AAAA",
          cw_producer_kid: "cw-audit-producer-v1",
          cw_producer_signed_canonical: "{}",
          cw_producer_captured_at_ms: FRESH_TS,
          seq: 1,
        }),
      ],
      verifySpy,
    );
    // The verify fn was never called: the marker-only feature stays on the
    // channel/marker basis and never reaches the signature gate.
    expect(verifySpy).not.toHaveBeenCalled();
    // The beat still counted on the marker basis: alive-but-idle, never green.
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("alive_no_recent_enforcement");
    expect(r.status).not.toBe("active");
  });
});

describe("per-feature provenance - a marker-only feature can never read green", () => {
  it("invariant 4: even a marked entry under the heartbeat op stays non-green (no invocationOps)", () => {
    const r = evalMarkerOnly([
      entry(BROKER_HEARTBEAT_OP, FRESH_TS, {
        [BROKER_MARKER.key]: BROKER_MARKER.value,
      }),
    ]);
    expect(r.status).not.toBe("active");
    expect(r.broken_zero_detectable).toBe(true);
  });

  it("integrity-tainted read forces unknown for the marker-only feature too", () => {
    const r = evaluateFeatureHealth({
      feature: MARKER_ONLY_FEATURE,
      entries: [
        entry(BROKER_HEARTBEAT_OP, FRESH_TS, {
          [BROKER_MARKER.key]: BROKER_MARKER.value,
        }),
      ],
      originMachine: FORTRESS,
      now: NOW,
      freshnessWindowMs: FRESH_MS,
      integrityOk: false,
    });
    expect(r.status).toBe("unknown");
    expect(r.basis).toBe("integrity_tainted");
  });
});

describe("per-feature provenance - end-to-end through the panel builder with a custom registry", () => {
  it("the generalized gate works through buildFeatureHealthPanel (a marked beat reads alive-idle)", async () => {
    const log = new AuditLog(new MemoryStorage(), generateRandomKey());
    await log.appendCritical({
      layer: "l3",
      operation: BROKER_HEARTBEAT_OP,
      identity_id: FORTRESS,
      result: "success",
      timestamp: new Date(FRESH_TS).toISOString(),
      details: { [BROKER_MARKER.key]: BROKER_MARKER.value },
    });
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: log,
      originMachine: FORTRESS,
      now: NOW,
      registry: [MARKER_ONLY_FEATURE],
    });
    const r = panel.rows.find((x) => x.feature_id === MARKER_ONLY_FEATURE.id);
    expect(r).toBeDefined();
    expect(r!.status).toBe("unknown");
    expect(r!.basis).toBe("alive_no_recent_enforcement");
    expect(r!.status).not.toBe("active");
  });
});
