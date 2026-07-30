/**
 * F2 round-4 HIGH-1 (2026-07-14; fixed 2026-07-15) REGRESSION.
 *
 * `verified_suffix_only` arises on an armed box: the operator uid cannot read
 * the root-owned sealed history, so the chain is untampered-at-this-privilege
 * but NOT fully verified. The round-4 gate found that the arm-state and
 * feature-health surfaces collapsed this to a green/active state indistinct
 * from a full `verified`, presenting it as affirmative integrity evidence.
 *
 * The fix keeps the OPERATIONAL gate on `untampered` (so a correctly-armed
 * fortress is NOT crying-wolf'd to unknown — `audit_integrity_ok` stays true and
 * the arm gate is not blocked), and adds an honest amber caveat field
 * `sealed_region_unverified_at_privilege` so the evidence surface says the
 * sealed region was not re-verified here rather than presenting a bare green.
 * (The dashboard cognitive false-green — "State encrypted at rest" /
 * memory_attest_ready — is covered separately in test/dashboard/aggregator.test.ts.)
 */

import { describe, expect, it } from "vitest";

import type { AuditLog, AuditEntry, SealedRegionVerdict } from "../../src/operational/audit-log.js";
import { buildFeatureHealthPanel } from "../../src/principal-policy/feature-health.js";
import { buildCastleWallPosture } from "../../src/principal-policy/posture.js";
import {
  CASTLE_WALL_AUDIT_PROVENANCE_KEY,
  CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
} from "../../src/castle-wall/constants.js";

const FORTRESS = "fortress:test";
const UNDETERMINED_AVAILABILITY = {
  status: "undetermined" as const,
  reason: "availability_not_queried",
  observed_at: null,
  freshness_window_ms: 30_000,
  active_connection_count: 0,
};

/** A fresh Castle Wall enforcement entry that arms the wall on the channel basis
 * (no producer key configured, macOS floor). */
function freshEnforcementEntry(now: number): AuditEntry {
  return {
    timestamp: new Date(now - 60_000).toISOString(),
    layer: "l1",
    operation: "egress_allowed",
    identity_id: FORTRESS,
    result: "success",
    details: {
      [CASTLE_WALL_AUDIT_PROVENANCE_KEY]: CASTLE_WALL_AUDIT_PROVENANCE_VALUE,
    },
  } as unknown as AuditEntry;
}

/** A mock AuditLog whose sealed region is `unreadable` at this privilege (the
 * armed-box operator-uid case), folding to `verified_suffix_only`. */
function suffixOnlyAuditLog(entries: AuditEntry[]): AuditLog {
  return {
    query: async () => ({ entries, total: entries.length, integrity_findings: [] }),
    // feature-health folds this directly.
    verifySealedRegion: async (): Promise<SealedRegionVerdict> => ({
      status: "unreadable",
      note: "operator uid cannot read root-owned sealed history (EACCES)",
    }),
    // posture consumes the already-folded verdict.
    getAuditChainVerdict: async () => ({
      status: "verified_suffix_only",
      routine_finding_count: 0,
      sealed_region: {
        status: "unreadable",
        note: "operator uid cannot read root-owned sealed history (EACCES)",
      },
    }),
  } as unknown as AuditLog;
}

describe("F2 HIGH-1: verified_suffix_only renders amber, not affirmative green", () => {
  it("feature-health: sets the amber caveat but keeps audit_integrity_ok true (no crying wolf)", async () => {
    const now = Date.now();
    const panel = await buildFeatureHealthPanel({
      protectionClaimSubject: FORTRESS,
      auditLog: suffixOnlyAuditLog([]),
      originMachine: FORTRESS,
      now,
    });
    // The operational gate stays untampered: a correctly-armed fortress is NOT
    // flagged tainted just because operator-uid cannot read the sealed region.
    expect(panel.audit_integrity_ok).toBe(true);
    // The honest amber caveat is surfaced so no reader mistakes this for a
    // fully-verified sealed region.
    expect(panel.sealed_region_unverified_at_privilege).toBe(true);
  });

  it("posture: arm gate is NOT blocked by suffix-only, and the amber caveat is set", async () => {
    const now = Date.now();
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
      auditLog: suffixOnlyAuditLog([freshEnforcementEntry(now)]),
      originMachine: FORTRESS,
      platform: "linux",
      now,
    });
    // Fresh enforcement evidence + suffix-only (untampered) => still armed. The
    // integrity gate must not flip a correctly-armed box to unknown.
    expect(posture.arm_state).toBe("armed");
    expect(posture.audit_integrity_ok).toBe(true);
    // Amber caveat present so the green badge honestly says the sealed history
    // was not re-verified at this privilege.
    expect(posture.sealed_region_unverified_at_privilege).toBe(true);
  });

  it("posture: injected undetermined v3 availability overrides suffix-only fresh evidence", async () => {
    const now = Date.now();
    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
      auditLog: suffixOnlyAuditLog([freshEnforcementEntry(now)]),
      originMachine: FORTRESS,
      platform: "linux",
      now,
      enforcementAvailability: UNDETERMINED_AVAILABILITY,
    });

    expect(posture.arm_state).toBe("unknown");
    expect(posture.evidence_basis).toBe("no_evidence");
    expect(posture.sealed_region_unverified_at_privilege).toBe(true);
  });

  it("posture: a fully-verified chain does NOT set the amber caveat", async () => {
    const now = Date.now();
    const verifiedLog = {
      query: async () => ({
        entries: [freshEnforcementEntry(now)],
        total: 1,
        integrity_findings: [],
      }),
      getAuditChainVerdict: async () => ({
        status: "verified",
        routine_finding_count: 0,
        sealed_region: { status: "not_present" },
      }),
    } as unknown as AuditLog;

    const posture = await buildCastleWallPosture({
      protectionClaimSubject: FORTRESS,
      auditLog: verifiedLog,
      originMachine: FORTRESS,
      platform: "linux",
      now,
    });
    expect(posture.arm_state).toBe("armed");
    expect(posture.sealed_region_unverified_at_privilege).toBe(false);
  });
});
